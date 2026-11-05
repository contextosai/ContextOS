//! Audit sinks: every tenant's signed audit chain, delivered in order to a SIEM or
//! archive, with chosen payload fields masked.
//!
//! The chain is the outbox, as for notifications: the leader replica reads each
//! tenant's chain from a cursor per sink (`delivery` document `audit_sink:<id>`) and
//! POSTs batches of entries. A sink never skips an entry: a failed batch is retried,
//! with backoff, until it is accepted, and the cursor moves only past accepted entries.
//! Delivery is at least once; receivers drop duplicates by `(tenant_id, sequence)`.
//! A sink starts at the genesis entry unless `start = "head"`.
//!
//! Each entry is delivered whole (spine, signature and payload) except for the payload
//! fields `mask` names, which are replaced by `masked:hmac-sha256:<hex>`, a keyed HMAC
//! of the value's canonical JSON. Equal values give equal tokens within a sink, so a
//! SIEM can still correlate (one customer across entries) without seeing the value, and
//! without the sink's mask key a token cannot be tested against guesses. A masked entry
//! carries `masked: {scheme, paths}`; its record hash and signature still verify (the
//! spine covers the payload's digest, not the payload), so `ctx audit-verify` checks its
//! place in the chain and its signature, and reports that its payload is unverified.
//!
//! `mask` entries starting with `/` are JSON Pointers into the payload where `*` matches
//! any member or index (`/arguments/*/email`); any other entry is a member name masked
//! wherever it occurs (`email`). `kinds` limits a sink to some entry kinds; the cursor
//! still advances past the rest. Requests are signed as notifications are:
//! `ContextOS-Signature: t=<unix seconds>,v1=<hex HMAC-SHA256 of "<t>.<body>">`.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use contextos_audit::AuditWriter;
use contextos_contract::canonical::canonicalize;
use contextos_contract::validation::is_contract_identifier;
use contextos_store::{AppendLog, DocKey, DocKind, DocumentStore};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::Config;
use crate::metrics::Metrics;
use crate::notifications::signature;

const MAX_SINKS: usize = 8;
const MAX_MASKS: usize = 64;
const MAX_BATCH: usize = 500;
const MAX_BACKOFF: Duration = Duration::from_secs(300);
pub const MASK_SCHEME: &str = "hmac-sha256";

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuditSinkConfig {
    pub id: String,
    /// HTTPS endpoint (HTTP only in development).
    pub url: String,
    /// Environment variable holding the request signing secret (at least 32 bytes).
    pub secret_env: String,
    /// Entry kinds to deliver; every kind when empty.
    #[serde(default)]
    pub kinds: Vec<String>,
    /// Payload fields to mask (see the module documentation).
    #[serde(default)]
    pub mask: Vec<String>,
    /// Environment variable holding the masking key (at least 32 bytes); required with
    /// `mask`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mask_key_env: Option<String>,
    /// Entries per request.
    #[serde(default = "default_batch")]
    pub batch: usize,
    /// `genesis` (default): deliver each tenant's whole chain; `head`: from now on.
    #[serde(default)]
    pub start: Start,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Start {
    #[default]
    Genesis,
    Head,
}

fn default_batch() -> usize {
    100
}

/// Configuration check (no environment access).
pub fn check(config: &Config) -> Result<(), String> {
    let development = config.server.mode == crate::config::Mode::Development;
    if config.audit_sinks.len() > MAX_SINKS {
        return Err(format!("at most {MAX_SINKS} audit sinks"));
    }
    let mut ids = std::collections::HashSet::new();
    for sink in &config.audit_sinks {
        let id = &sink.id;
        if !is_contract_identifier(id) || !ids.insert(id) {
            return Err("audit sink ids must be unique identifiers".into());
        }
        let url = url::Url::parse(&sink.url).map_err(|_| format!("audit sink {id}: invalid url"))?;
        if url.scheme() != "https" && !(development && url.scheme() == "http") {
            return Err(format!("audit sink {id}: url must use https"));
        }
        if sink.secret_env.is_empty() {
            return Err(format!("audit sink {id}: secret_env is required"));
        }
        if !(1..=MAX_BATCH).contains(&sink.batch) {
            return Err(format!("audit sink {id}: batch must be 1..={MAX_BATCH}"));
        }
        if sink.mask.len() > MAX_MASKS || sink.mask.iter().any(|m| m.is_empty() || m == "/") {
            return Err(format!(
                "audit sink {id}: at most {MAX_MASKS} non-empty mask entries, none the whole payload"
            ));
        }
        if !sink.mask.is_empty() && sink.mask_key_env.as_deref().is_none_or(str::is_empty) {
            return Err(format!("audit sink {id}: mask needs mask_key_env"));
        }
    }
    Ok(())
}

/// What to mask, and the key masked values are tokenized under.
pub struct Masker {
    names: Vec<String>,
    pointers: Vec<Vec<String>>,
    key: Option<ring::hmac::Key>,
}

fn unescape(segment: &str) -> String {
    segment.replace("~1", "/").replace("~0", "~")
}

fn escape(segment: &str) -> String {
    segment.replace('~', "~0").replace('/', "~1")
}

impl std::fmt::Debug for Masker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Masker")
            .field("names", &self.names)
            .field("pointers", &self.pointers)
            .finish_non_exhaustive()
    }
}

impl Masker {
    /// # Errors
    /// When `mask` is not empty and `key` is shorter than 32 bytes.
    pub fn new(mask: &[String], key: Option<&[u8]>) -> Result<Self, String> {
        if !mask.is_empty() && key.is_none_or(|k| k.len() < 32) {
            return Err("the mask key must hold at least 32 bytes".into());
        }
        let (pointers, names): (Vec<&String>, Vec<&String>) = mask.iter().partition(|m| m.starts_with('/'));
        Ok(Self {
            names: names.into_iter().cloned().collect(),
            pointers: pointers
                .into_iter()
                .map(|p| p[1..].split('/').map(unescape).collect())
                .collect(),
            key: key.map(|k| ring::hmac::Key::new(ring::hmac::HMAC_SHA256, k)),
        })
    }

    fn token(&self, value: &Value) -> Value {
        let text = canonicalize(value).unwrap_or_else(|_| value.to_string());
        let tag = self
            .key
            .as_ref()
            .map(|key| hex::encode(ring::hmac::sign(key, text.as_bytes()).as_ref()))
            .unwrap_or_default();
        json!(format!("masked:{MASK_SCHEME}:{tag}"))
    }

    fn matches(&self, name: &str, path: &[String]) -> bool {
        self.names.iter().any(|n| n == name)
            || self
                .pointers
                .iter()
                .any(|p| p.len() == path.len() && p.iter().zip(path).all(|(want, got)| want == "*" || want == got))
    }

    fn walk(&self, value: &mut Value, path: &mut Vec<String>, masked: &mut Vec<String>) {
        let is_object = value.is_object();
        let children: Vec<(String, &mut Value)> = match value {
            Value::Object(fields) => fields.iter_mut().map(|(k, v)| (k.clone(), v)).collect(),
            Value::Array(items) => items.iter_mut().enumerate().map(|(i, v)| (i.to_string(), v)).collect(),
            _ => return,
        };
        for (segment, child) in children {
            path.push(segment.clone());
            // Member names match members only, not array indexes.
            if self.matches(if is_object { &segment } else { "" }, path) {
                *child = self.token(child);
                masked.push(format!(
                    "/{}",
                    path.iter().map(|s| escape(s)).collect::<Vec<_>>().join("/")
                ));
            } else {
                self.walk(child, path, masked);
            }
            path.pop();
        }
    }

    /// The payload with masked fields replaced, and the JSON Pointers of those fields.
    pub fn mask(&self, payload: &Value) -> (Value, Vec<String>) {
        let mut out = payload.clone();
        let mut masked = Vec::new();
        if !self.names.is_empty() || !self.pointers.is_empty() {
            self.walk(&mut out, &mut Vec::new(), &mut masked);
        }
        masked.sort();
        (out, masked)
    }
}

/// The copy of `entry` a sink delivers.
pub fn delivered(entry: &Value, masker: &Masker) -> Value {
    let (payload, paths) = masker.mask(&entry["payload"]);
    let mut out = entry.clone();
    if !paths.is_empty() {
        out["payload"] = payload;
        out["masked"] = json!({"scheme": MASK_SCHEME, "paths": paths});
    }
    out
}

/// A sink with its secrets, read from the environment at startup.
pub struct Sink {
    pub config: AuditSinkConfig,
    secret: ring::hmac::Key,
    masker: Masker,
}

impl std::fmt::Debug for Sink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sink")
            .field("id", &self.config.id)
            .finish_non_exhaustive()
    }
}

impl Sink {
    /// # Errors
    /// When a secret is shorter than 32 bytes.
    pub fn new(config: AuditSinkConfig, secret: &[u8], mask_key: Option<&[u8]>) -> Result<Self, String> {
        if secret.len() < 32 {
            return Err(format!("{} must hold at least 32 bytes", config.secret_env));
        }
        let masker = Masker::new(&config.mask, mask_key).map_err(|e| format!("audit sink {}: {e}", config.id))?;
        Ok(Self {
            secret: ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret),
            masker,
            config,
        })
    }
}

/// Reads every sink's secrets; a missing or short one stops startup.
pub fn sinks(config: &Config) -> Result<Vec<Sink>, String> {
    let env = |name: &str| std::env::var(name).map_err(|_| format!("{name} is not set"));
    config
        .audit_sinks
        .iter()
        .map(|sink| {
            let secret = env(&sink.secret_env)?;
            let mask_key = sink.mask_key_env.as_deref().map(env).transpose()?;
            Sink::new(sink.clone(), secret.as_bytes(), mask_key.as_deref().map(str::as_bytes))
        })
        .collect()
}

fn cursor_key(tenant: &str, sink: &str) -> DocKey {
    DocKey::new(tenant, DocKind::Escalation, format!("audit_sink:{sink}"))
}

#[derive(Debug, Default)]
struct Backoff {
    failures: u32,
    retry_at: Option<Instant>,
}

/// The leader's exporter.
#[allow(missing_debug_implementations)]
pub struct Exporter<S, L> {
    store: Arc<S>,
    audit: Arc<AuditWriter<L>>,
    metrics: Arc<Metrics>,
    client: reqwest::Client,
    sinks: Vec<Arc<Sink>>,
    tenants: Vec<String>,
    backoff: HashMap<(String, String), Backoff>,
}

impl<S: DocumentStore + 'static, L: AppendLog + 'static> Exporter<S, L> {
    /// # Panics
    /// If the HTTP client cannot be built (no TLS backend).
    pub fn new(
        store: Arc<S>,
        audit: Arc<AuditWriter<L>>,
        metrics: Arc<Metrics>,
        sinks: Vec<Sink>,
        mut tenants: Vec<String>,
        development: bool,
    ) -> Self {
        tenants.sort();
        tenants.dedup();
        let client = contextos_adapters::tls::builder()
            .https_only(!development)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(10))
            .build()
            .expect("http client");
        Self {
            store,
            audit,
            metrics,
            client,
            sinks: sinks.into_iter().map(Arc::new).collect(),
            tenants,
            backoff: HashMap::new(),
        }
    }

    /// Delivers what is due for every sink and tenant.
    pub async fn tick(&mut self) {
        for sink in self.sinks.clone() {
            for tenant in self.tenants.clone() {
                // Drain a backlog in successive batches until it is delivered or fails.
                loop {
                    match self.deliver(&sink, &tenant).await {
                        Ok(true) => {}
                        Ok(false) => break,
                        Err(error) => {
                            tracing::warn!(sink = %sink.config.id, %tenant, %error, "audit sink delivery failed; retrying");
                            break;
                        }
                    }
                }
            }
        }
    }

    /// Delivers one batch; `Ok(true)` when more entries may be waiting.
    async fn deliver(&mut self, sink: &Sink, tenant: &str) -> Result<bool, String> {
        let state = (tenant.to_owned(), sink.config.id.clone());
        if self
            .backoff
            .get(&state)
            .and_then(|b| b.retry_at)
            .is_some_and(|at| Instant::now() < at)
        {
            return Ok(false);
        }
        let key = cursor_key(tenant, &sink.config.id);
        let log = self.audit.log();
        let cursor = self.store.get(&key).await.map_err(|e| e.to_string())?;
        let (next, revision) = if let Some(doc) = cursor {
            (doc.body["next_sequence"].as_u64().unwrap_or(1), doc.revision)
        } else {
            let start = match sink.config.start {
                Start::Genesis => 1,
                Start::Head => log
                    .head(tenant)
                    .await
                    .map_err(|e| e.to_string())?
                    .map_or(1, |r| r.sequence + 1),
            };
            let created = self
                .store
                .create(&key, &json!({"next_sequence": start}))
                .await
                .map_err(|e| e.to_string())?;
            (start, created.revision)
        };
        let rows = log
            .range(tenant, next, sink.config.batch)
            .await
            .map_err(|e| e.to_string())?;
        let Some(last) = rows.last().map(|r| r.sequence) else {
            return Ok(false);
        };
        let full = rows.len() == sink.config.batch;
        let entries: Vec<Value> = rows
            .iter()
            .filter(|r| sink.config.kinds.is_empty() || sink.config.kinds.iter().any(|k| r.body["kind"] == **k))
            .map(|r| delivered(&r.body, &sink.masker))
            .collect();
        if !entries.is_empty() {
            let body = json!({"sink": sink.config.id, "tenant_id": tenant, "from_sequence": next,
                "to_sequence": last, "entries": entries});
            if !self.post(sink, &body).await {
                self.metrics.audit_sink(&sink.config.id, "failed");
                let backoff = self.backoff.entry(state).or_default();
                backoff.failures = backoff.failures.saturating_add(1);
                let wait = Duration::from_secs(2u64 << backoff.failures.min(8)).min(MAX_BACKOFF);
                backoff.retry_at = Some(Instant::now() + wait);
                return Err(format!("batch {next}..={last} not accepted"));
            }
            self.metrics.audit_sink(&sink.config.id, "delivered");
        }
        self.backoff.remove(&state);
        self.store
            .compare_and_swap(&key, revision, &json!({"next_sequence": last + 1}))
            .await
            .map_err(|e| e.to_string())?;
        Ok(full)
    }

    async fn post(&self, sink: &Sink, body: &Value) -> bool {
        let bytes = serde_json::to_vec(body).unwrap_or_default();
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
        let sent = self
            .client
            .post(&sink.config.url)
            .header("content-type", "application/json")
            .header("contextos-signature", signature(&sink.secret, timestamp, &bytes))
            .body(bytes)
            .send()
            .await;
        sent.is_ok_and(|r| r.status().is_success())
    }
}

/// Delivers on the leader replica every `interval`.
pub async fn run<S, L>(mut exporter: Exporter<S, L>, leader: Arc<AtomicBool>, interval: Duration)
where
    S: DocumentStore + 'static,
    L: AppendLog + 'static,
{
    if exporter.sinks.is_empty() {
        return;
    }
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        if leader.load(Ordering::Relaxed) {
            exporter.tick().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{Masker, delivered};

    fn masker(mask: &[&str]) -> Masker {
        let mask: Vec<String> = mask.iter().map(|m| (*m).to_owned()).collect();
        Masker::new(&mask, Some(&[7u8; 32])).unwrap()
    }

    #[test]
    fn names_mask_everywhere_and_pointers_where_they_point() {
        let payload = json!({"email": "a@example.com", "args": {"email": "b@example.com", "amount": 4200},
            "items": [{"card": "4111"}, {"card": "5500"}], "note": {"email": "c"}});
        let (out, paths) = masker(&["email", "/items/*/card"]).mask(&payload);
        assert_eq!(
            paths,
            ["/args/email", "/email", "/items/0/card", "/items/1/card", "/note/email"]
        );
        assert_eq!(out["args"]["amount"], 4200);
        let token = out["email"].as_str().unwrap();
        assert!(
            token.starts_with("masked:hmac-sha256:") && token.len() == 19 + 64,
            "{token}"
        );
        assert_ne!(out["email"], out["args"]["email"]);
        // Equal values give equal tokens.
        let (again, _) = masker(&["email"]).mask(&json!({"x": {"email": "a@example.com"}}));
        assert_eq!(again["x"]["email"], out["email"]);
    }

    #[test]
    fn a_whole_member_is_masked_and_indexes_are_not_names() {
        let (out, paths) = masker(&["args", "0"]).mask(&json!({"args": {"a": 1}, "list": ["x"]}));
        assert_eq!(paths, ["/args"]);
        assert_eq!(out["list"], json!(["x"]));
        let (out, paths) = masker(&["/a~1b"]).mask(&json!({"a/b": 1, "a": {"b": 2}}));
        assert_eq!(paths, ["/a~1b"]);
        assert_eq!(out["a"]["b"], 2);
    }

    #[test]
    fn entries_say_what_was_masked_and_keep_their_spine() {
        let entry = json!({"sequence": 3, "record_hash": "sha256:x", "payload_digest": "sha256:y",
            "payload": {"email": "a@example.com"}});
        let out = delivered(&entry, &masker(&["email"]));
        assert_eq!(out["masked"]["paths"], json!(["/email"]));
        assert_eq!(out["record_hash"], "sha256:x");
        assert_eq!(out["payload_digest"], "sha256:y");
        let untouched = delivered(&entry, &masker(&["phone"]));
        assert_eq!(untouched, entry);
    }

    #[test]
    fn a_mask_needs_a_long_key() {
        assert!(Masker::new(&["email".to_owned()], Some(&[1u8; 8])).is_err());
        assert!(Masker::new(&["email".to_owned()], None).is_err());
        assert!(Masker::new(&[], None).is_ok());
    }
}
