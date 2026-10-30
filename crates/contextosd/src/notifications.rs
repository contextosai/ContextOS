//! Escalation notifications: signed webhooks that tell people a decision is waiting.
//!
//! The audit chain is the outbox. `escalation_opened` and `escalation_resolved` are
//! appended exactly when the transition commits, in order, and never change, so the
//! leader replica delivers them from each tenant's chain with a cursor per webhook
//! (`Escalation` document `delivery:<webhook>`). A notification is never sent for a
//! transition that did not happen, and none is lost. Delivery is at least once:
//! receivers drop duplicates by the event `id`. A webhook enabled later starts at the
//! chain's head; it does not replay history.
//!
//! Payloads are CloudEvents 1.0 (structured JSON) carrying identifiers, the capability,
//! reason codes and an optional link to the decision, never tool arguments. Each
//! request is signed: `ContextOS-Signature: t=<unix seconds>,v1=<hex HMAC-SHA256 of
//! "<t>.<body>">` under the webhook's secret. Notifications grant nothing; the
//! decision is made where approvers sign in (for example Tower).

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use contextos_audit::AuditWriter;
use contextos_contract::validation::is_contract_identifier;
use contextos_store::{AppendLog, DocKey, DocKind, DocumentStore};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::Config;
use crate::metrics::Metrics;

/// Audit entry kinds that become notifications.
pub const EVENT_KINDS: [&str; 2] = ["escalation_opened", "escalation_resolved"];

const MAX_WEBHOOKS: usize = 8;
const PAGE: usize = 100;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WebhookConfig {
    pub id: String,
    /// HTTPS endpoint (HTTP only in development).
    pub url: String,
    /// Environment variable holding the signing secret (at least 32 bytes).
    pub secret_env: String,
    /// Link to the decision, with `{escalation_id}`, `{run_id}` and `{tenant_id}`
    /// replaced (for example your Tower URL).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link_template: Option<String>,
    /// Attempts per event before it is given up (logged and counted).
    #[serde(default = "default_attempts")]
    pub max_attempts: u32,
}

fn default_attempts() -> u32 {
    12
}

/// Configuration check (no environment access).
pub fn check(config: &Config) -> Result<(), String> {
    let development = config.server.mode == crate::config::Mode::Development;
    if config.notifications.len() > MAX_WEBHOOKS {
        return Err(format!("at most {MAX_WEBHOOKS} notification webhooks"));
    }
    let mut ids = std::collections::HashSet::new();
    for hook in &config.notifications {
        if !is_contract_identifier(&hook.id) || !ids.insert(&hook.id) {
            return Err("notification webhook ids must be unique identifiers".into());
        }
        let url = url::Url::parse(&hook.url).map_err(|_| format!("notification webhook {}: invalid url", hook.id))?;
        if url.scheme() != "https" && !(development && url.scheme() == "http") {
            return Err(format!("notification webhook {}: url must use https", hook.id));
        }
        if !(1..=100).contains(&hook.max_attempts) {
            return Err(format!(
                "notification webhook {}: max_attempts must be 1..=100",
                hook.id
            ));
        }
        if hook.secret_env.is_empty() {
            return Err(format!("notification webhook {}: secret_env is required", hook.id));
        }
    }
    Ok(())
}

/// A webhook with its signing secret, read from the environment at startup.
#[derive(Clone)]
pub struct Webhook {
    pub config: WebhookConfig,
    secret: Arc<ring::hmac::Key>,
}

impl std::fmt::Debug for Webhook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Webhook")
            .field("id", &self.config.id)
            .finish_non_exhaustive()
    }
}

impl Webhook {
    /// A webhook signing with `secret` (at least 32 bytes).
    pub fn new(config: WebhookConfig, secret: &[u8]) -> Result<Self, String> {
        if secret.len() < 32 {
            return Err(format!("{} must hold at least 32 bytes", config.secret_env));
        }
        Ok(Self {
            config,
            secret: Arc::new(ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret)),
        })
    }
}

/// Reads every webhook's secret; a missing or short one stops startup.
pub fn webhooks(config: &Config) -> Result<Vec<Webhook>, String> {
    config
        .notifications
        .iter()
        .map(|hook| {
            let secret = std::env::var(&hook.secret_env).map_err(|_| format!("{} is not set", hook.secret_env))?;
            Webhook::new(hook.clone(), secret.as_bytes())
        })
        .collect()
}

/// `t=<timestamp>,v1=<hex HMAC-SHA256 of "<timestamp>.<body>">`.
#[must_use]
pub fn signature(key: &ring::hmac::Key, timestamp: u64, body: &[u8]) -> String {
    let mut message = format!("{timestamp}.").into_bytes();
    message.extend_from_slice(body);
    format!(
        "t={timestamp},v1={}",
        hex::encode(ring::hmac::sign(key, &message).as_ref())
    )
}

/// The CloudEvent for an audit entry, or `None` if it is not a notified kind.
#[must_use]
pub fn event(entry: &Value, link_template: Option<&str>) -> Option<Value> {
    let kind = entry["kind"].as_str()?;
    let transition = kind
        .strip_prefix("escalation_")
        .filter(|_| EVENT_KINDS.contains(&kind))?;
    let tenant = entry["tenant_id"].as_str()?;
    let payload = &entry["payload"];
    let escalation_id = payload["escalation_id"].as_str()?;
    let run_id = payload["run_id"].as_str().unwrap_or_default();
    let mut data = json!({"tenant_id": tenant, "escalation_id": escalation_id, "run_id": run_id,
        "audit_sequence": entry["sequence"]});
    if transition == "opened" {
        for field in [
            "capability_id",
            "operation_id",
            "action_digest",
            "policy_decision_id",
            "reason_codes",
        ] {
            data[field] = payload[field].clone();
        }
    } else {
        data["outcome"] = payload["outcome"].clone();
        data["by"] = payload["by"].clone();
    }
    if let Some(template) = link_template {
        data["link"] = json!(
            template
                .replace("{escalation_id}", escalation_id)
                .replace("{run_id}", run_id)
                .replace("{tenant_id}", tenant)
        );
    }
    Some(json!({
        "specversion": "1.0",
        "id": format!("{tenant}:{}", entry["sequence"]),
        "source": "contextosd",
        "type": format!("io.contextos.escalation.{transition}"),
        "subject": escalation_id,
        "time": entry["emitted_at"],
        "datacontenttype": "application/json",
        "data": data,
    }))
}

fn cursor_key(tenant: &str, webhook: &str) -> DocKey {
    DocKey::new(tenant, DocKind::Escalation, format!("delivery:{webhook}"))
}

fn unix_seconds() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// Where one webhook stands in one tenant's chain.
#[derive(Debug, Default)]
struct Backoff {
    attempts: u32,
    retry_at: Option<Instant>,
}

/// The leader's dispatcher.
#[allow(missing_debug_implementations)]
pub struct Dispatcher<S, L> {
    store: Arc<S>,
    audit: Arc<AuditWriter<L>>,
    metrics: Arc<Metrics>,
    client: reqwest::Client,
    webhooks: Vec<Webhook>,
    tenants: Vec<String>,
    backoff: HashMap<(String, String), Backoff>,
}

impl<S: DocumentStore + 'static, L: AppendLog + 'static> Dispatcher<S, L> {
    /// # Panics
    /// If the HTTP client cannot be built (no TLS backend).
    pub fn new(
        store: Arc<S>,
        audit: Arc<AuditWriter<L>>,
        metrics: Arc<Metrics>,
        webhooks: Vec<Webhook>,
        mut tenants: Vec<String>,
        development: bool,
    ) -> Self {
        tenants.sort();
        tenants.dedup();
        let client = reqwest::Client::builder()
            .https_only(!development)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(5))
            .build()
            .expect("http client");
        Self {
            store,
            audit,
            metrics,
            client,
            webhooks,
            tenants,
            backoff: HashMap::new(),
        }
    }

    /// Delivers what is due for every webhook and tenant.
    pub async fn tick(&mut self) {
        for hook in self.webhooks.clone() {
            for tenant in self.tenants.clone() {
                if let Err(error) = self.deliver(&hook, &tenant).await {
                    tracing::warn!(webhook = %hook.config.id, %error, "notification delivery failed; retrying");
                }
            }
        }
    }

    async fn deliver(&mut self, hook: &Webhook, tenant: &str) -> Result<(), String> {
        let state = (tenant.to_owned(), hook.config.id.clone());
        if self
            .backoff
            .get(&state)
            .and_then(|b| b.retry_at)
            .is_some_and(|at| Instant::now() < at)
        {
            return Ok(());
        }
        let key = cursor_key(tenant, &hook.config.id);
        let audit = self.audit.clone();
        let log = audit.log();
        let cursor = self.store.get(&key).await.map_err(|e| e.to_string())?;
        let (mut next, mut revision) = if let Some(doc) = cursor {
            (doc.body["next_sequence"].as_u64().unwrap_or(1), Some(doc.revision))
        } else {
            // Start at the head: a new webhook is told about new transitions only.
            let head = log.head(tenant).await.map_err(|e| e.to_string())?;
            let start = head.map_or(1, |row| row.sequence + 1);
            let created = self
                .store
                .create(&key, &json!({"next_sequence": start}))
                .await
                .map_err(|e| e.to_string())?;
            (start, Some(created.revision))
        };
        let rows = log.range(tenant, next, PAGE).await.map_err(|e| e.to_string())?;
        let mut saved = next;
        for row in rows {
            if let Some(event) = event(&row.body, hook.config.link_template.as_deref()) {
                if self.post(hook, &event).await {
                    self.metrics.notification(&hook.config.id, "delivered");
                } else {
                    let backoff = self.backoff.entry(state.clone()).or_default();
                    backoff.attempts += 1;
                    if backoff.attempts < hook.config.max_attempts {
                        self.metrics.notification(&hook.config.id, "failed");
                        let wait = Duration::from_secs(5u64 << backoff.attempts.min(6));
                        backoff.retry_at = Some(Instant::now() + wait);
                        break;
                    }
                    self.metrics.notification(&hook.config.id, "abandoned");
                    tracing::warn!(webhook = %hook.config.id, tenant, event_id = %event["id"],
                        "notification given up after max_attempts");
                }
                self.backoff.remove(&state);
                // Advance past each notified entry at once, so a crash resends at most one.
                next = row.sequence + 1;
                revision = Some(self.save(&key, revision, next).await?);
                saved = next;
            } else {
                next = row.sequence + 1;
            }
        }
        if next != saved {
            self.save(&key, revision, next).await?;
        }
        Ok(())
    }

    async fn save(&self, key: &DocKey, revision: Option<u64>, next: u64) -> Result<u64, String> {
        let body = json!({"next_sequence": next});
        let written = match revision {
            Some(revision) => self.store.compare_and_swap(key, revision, &body).await,
            None => self.store.create(key, &body).await,
        };
        written.map(|v| v.revision).map_err(|e| e.to_string())
    }

    async fn post(&self, hook: &Webhook, event: &Value) -> bool {
        let body = serde_json::to_vec(event).unwrap_or_default();
        let sent = self
            .client
            .post(&hook.config.url)
            .header("content-type", "application/cloudevents+json")
            .header("contextos-event-id", event["id"].as_str().unwrap_or_default())
            .header("contextos-signature", signature(&hook.secret, unix_seconds(), &body))
            .body(body)
            .send()
            .await;
        sent.is_ok_and(|r| r.status().is_success())
    }
}

/// Delivers on the leader replica every `interval`.
pub async fn run<S, L>(mut dispatcher: Dispatcher<S, L>, leader: Arc<AtomicBool>, interval: Duration)
where
    S: DocumentStore + 'static,
    L: AppendLog + 'static,
{
    if dispatcher.webhooks.is_empty() {
        return;
    }
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        if leader.load(Ordering::Relaxed) {
            dispatcher.tick().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn events_carry_identifiers_and_never_arguments() {
        let entry = json!({"kind": "escalation_opened", "tenant_id": "t1", "sequence": 42,
            "emitted_at": "2026-10-30T10:00:00.000000Z",
            "payload": {"escalation_id": "esc_1", "run_id": "run_1", "operation_id": "op_1",
                "capability_id": "adp_payments.issue_refund", "action_digest": "sha256:ab",
                "policy_decision_id": "dec_1", "reason_codes": ["policy_escalation"],
                "arguments": {"amount": 5}}});
        let event = event(
            &entry,
            Some("https://tower.example/escalations/{escalation_id}?run={run_id}"),
        )
        .unwrap();
        assert_eq!(event["id"], "t1:42");
        assert_eq!(event["type"], "io.contextos.escalation.opened");
        assert_eq!(
            event["data"]["link"],
            "https://tower.example/escalations/esc_1?run=run_1"
        );
        assert_eq!(event["data"]["reason_codes"], json!(["policy_escalation"]));
        assert!(!event.to_string().contains("amount"), "{event}");
        let resolved = json!({"kind": "escalation_resolved", "tenant_id": "t1", "sequence": 43,
            "payload": {"escalation_id": "esc_1", "run_id": "run_1", "outcome": "handled", "by": "ops", "reason": "done"}});
        let event_resolved = super::event(&resolved, None).unwrap();
        assert_eq!(event_resolved["type"], "io.contextos.escalation.resolved");
        assert_eq!(event_resolved["data"]["outcome"], "handled");
        assert!(super::event(&json!({"kind": "run_admitted", "tenant_id": "t1", "payload": {}}), None).is_none());
    }

    #[test]
    fn the_signature_is_hmac_sha256_over_timestamp_and_body() {
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, b"0123456789abcdef0123456789abcdef");
        let signed = signature(&key, 1_700_000_000, br#"{"a":1}"#);
        let expected = ring::hmac::sign(&key, br#"1700000000.{"a":1}"#);
        assert_eq!(signed, format!("t=1700000000,v1={}", hex::encode(expected.as_ref())));
    }
}
