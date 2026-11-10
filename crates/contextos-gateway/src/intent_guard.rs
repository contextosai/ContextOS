//! Intent keys: one business request, one effect, across runs.
//!
//! The repeated-effect guard ([`crate::loop_guard`]) and provider idempotency keys are
//! scoped to a run, so a request redelivered into a new run (a queue redelivery, a
//! webhook retried, a user asking a second channel) is a new effect. A capability whose
//! manifest declares `intent.key_pointers` names the arguments that identify the
//! business request (an order and an amount, a ticket id). Their values, with the
//! tenant and capability, form the intent key, claimed by compare-and-swap after the
//! operation claim and before dispatch, in one tenant-wide document per key. A second
//! run sending the same request while the claim stands is refused with
//! `effect_repeated_across_runs` and pointed at the operation that holds it. Every
//! attempt claims the intent, a retry of the same operation too, so a retry never sends
//! while another run holds it. The claim is released only when the provider
//! definitively did not apply the effect (inline, or when reconciliation or an
//! attestation records it not applied, found through the operation's pointer
//! document), and it lapses after `window_seconds`, after which the same request is a
//! new one.
//!
//! Claim times come from each replica's clock: replicas must keep synchronized clocks
//! (NTP), or skew shortens or lengthens the effective window.

use contextos_contract::canonical::sha256_canonical;
use contextos_store::{DocKey, DocKind, DocumentStore, StoreError};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// At most this many pointers name the request.
pub const MAX_KEY_POINTERS: usize = 8;
/// A claim lasts one day unless the manifest says otherwise, and never beyond 90 days.
pub const DEFAULT_WINDOW_SECONDS: u64 = 86_400;
pub const MAX_WINDOW_SECONDS: u64 = 90 * 86_400;

/// A capability's intent key: which arguments identify the business request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentKey {
    /// JSON Pointers into the arguments; each must resolve to a string, number or
    /// boolean. A call without one of them is refused (`intent_key_missing`).
    pub key_pointers: Vec<String>,
    /// How long a claim stands; the same request after it is a new request.
    #[serde(default = "default_window")]
    pub window_seconds: u64,
    /// Derive the provider idempotency key from the intent key instead of the run's
    /// operation, so the provider's own deduplication also spans runs.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub provider_key: bool,
}

fn default_window() -> u64 {
    DEFAULT_WINDOW_SECONDS
}

impl IntentKey {
    pub(crate) fn validate(&self) -> Result<(), &'static str> {
        if self.key_pointers.is_empty() || self.key_pointers.len() > MAX_KEY_POINTERS {
            return Err("key_pointers must list 1 to 8 JSON Pointers");
        }
        if self.key_pointers.iter().any(|p| !p.starts_with('/')) {
            return Err("key_pointers must be JSON Pointers");
        }
        let distinct: std::collections::BTreeSet<_> = self.key_pointers.iter().collect();
        if distinct.len() != self.key_pointers.len() {
            return Err("key_pointers must be distinct");
        }
        if self.window_seconds == 0 || self.window_seconds > MAX_WINDOW_SECONDS {
            return Err("window_seconds must be between 1 second and 90 days");
        }
        Ok(())
    }
}

/// The intent digest of a call, or `None` when an argument the key names is absent or
/// is not a string, number or boolean.
pub(crate) fn digest(tenant_id: &str, capability_id: &str, intent: &IntentKey, arguments: &Value) -> Option<String> {
    let values = intent
        .key_pointers
        .iter()
        .map(|p| match arguments.pointer(p) {
            Some(v @ (Value::String(_) | Value::Number(_) | Value::Bool(_))) => Some(v.clone()),
            _ => None,
        })
        .collect::<Option<Vec<_>>>()?;
    sha256_canonical(&json!({"domain": "contextos.intent_key.v1", "tenant_id": tenant_id,
        "capability_id": capability_id, "values": values}))
    .ok()
}

pub(crate) fn key(tenant_id: &str, digest: &str) -> DocKey {
    DocKey::new(tenant_id, DocKind::IntentClaim, digest)
}

/// The pointer from a run's operation to the intent it claims, so recovery, which
/// has the operation but not its arguments, can release the claim.
fn operation_key(tenant_id: &str, run_id: &str, operation_id: &str) -> DocKey {
    use contextos_contract::canonical::{quote, sha256_text};
    let digest = sha256_text(&format!("[{},{}]", quote(run_id), quote(operation_id)));
    DocKey::new(tenant_id, DocKind::IntentClaim, format!("op:{}", &digest[7..]))
}

/// Records that `(run_id, operation_id)` claims the intent `digest`.
async fn point<S: DocumentStore>(
    store: &S,
    (tenant_id, run_id, operation_id): (&str, &str, &str),
    digest: &str,
) -> Result<(), StoreError> {
    let key = operation_key(tenant_id, run_id, operation_id);
    let body = json!({"run_id": run_id, "operation_id": operation_id, "intent_digest": digest});
    for _ in 0..32_u32 {
        let written = match store.get(&key).await? {
            Some(current) if current.body == body => return Ok(()),
            Some(current) => store.compare_and_swap(&key, current.revision, &body).await.map(|_| ()),
            None => store.create(&key, &body).await.map(|_| ()),
        };
        match written {
            Err(e) if e.is_conflict() => {}
            other => return other,
        }
    }
    Err(StoreError::Conflict {
        expected: None,
        actual: None,
    })
}

/// Releases the intent `(run_id, operation_id)` claimed, if it claimed one and still
/// holds it: recovery recorded its effect definitively not applied.
pub(crate) async fn release_operation<S: DocumentStore>(
    store: &S,
    (tenant_id, run_id, operation_id): (&str, &str, &str),
) -> Result<(), StoreError> {
    let Some(pointer) = store.get(&operation_key(tenant_id, run_id, operation_id)).await? else {
        return Ok(());
    };
    match pointer.body["intent_digest"].as_str() {
        Some(digest) => release(store, &key(tenant_id, digest), run_id, operation_id).await,
        None => Ok(()),
    }
}

/// The outcome of claiming an intent for an operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum IntentClaim {
    /// This operation holds the intent (newly, or already).
    Claimed,
    /// Another run's (or another operation's) claim stands.
    Held { run_id: String, operation_id: String },
}

fn holder(state: &Value) -> (&str, &str) {
    (
        state["run_id"].as_str().unwrap_or_default(),
        state["operation_id"].as_str().unwrap_or_default(),
    )
}

/// Claims the intent at `key` for `(run_id, operation_id)`, atomically: of operations
/// racing for one intent, exactly one gets [`IntentClaim::Claimed`]. A claim older than
/// its window is replaced.
pub(crate) async fn claim<S: DocumentStore>(
    store: &S,
    key: &DocKey,
    run_id: &str,
    operation_id: &str,
    now_seconds: u64,
    window_seconds: u64,
) -> Result<IntentClaim, StoreError> {
    let body = json!({"run_id": run_id, "operation_id": operation_id, "claimed_at": now_seconds,
        "expires_at": now_seconds.saturating_add(window_seconds), "released": false});
    for attempt in 0..32_u32 {
        if attempt > 0 {
            tokio::time::sleep(std::time::Duration::from_micros(50 << attempt.min(8))).await;
        }
        let written = match store.get(key).await? {
            None => store.create(key, &body).await.map(|_| ()),
            Some(current) => {
                let state = &current.body;
                let (run, operation) = holder(state);
                if run == run_id && operation == operation_id && !state["released"].as_bool().unwrap_or(false) {
                    return Ok(IntentClaim::Claimed);
                }
                let lapsed = state["expires_at"].as_u64().is_none_or(|t| now_seconds >= t);
                if !lapsed && !state["released"].as_bool().unwrap_or(false) {
                    return Ok(IntentClaim::Held {
                        run_id: run.to_owned(),
                        operation_id: operation.to_owned(),
                    });
                }
                store.compare_and_swap(key, current.revision, &body).await.map(|_| ())
            }
        };
        match written {
            Ok(()) => return Ok(IntentClaim::Claimed),
            Err(e) if e.is_conflict() => {}
            Err(e) => return Err(e),
        }
    }
    Err(StoreError::Conflict {
        expected: None,
        actual: None,
    })
}

/// Releases `(run_id, operation_id)`'s claim (the provider definitively did not apply
/// the effect), so the request may be sent again from any run.
pub(crate) async fn release<S: DocumentStore>(
    store: &S,
    key: &DocKey,
    run_id: &str,
    operation_id: &str,
) -> Result<(), StoreError> {
    for _ in 0..32_u32 {
        let Some(current) = store.get(key).await? else {
            return Ok(());
        };
        if holder(&current.body) != (run_id, operation_id) {
            return Ok(());
        }
        let mut body = current.body.clone();
        body["released"] = json!(true);
        match store.compare_and_swap(key, current.revision, &body).await {
            Ok(_) => return Ok(()),
            Err(e) if e.is_conflict() => {}
            Err(e) => return Err(e),
        }
    }
    Err(StoreError::Conflict {
        expected: None,
        actual: None,
    })
}

/// The provider idempotency key derived from an intent (`intent.provider_key`): the
/// same request gets the same key from every run, so the provider's own deduplication
/// spans runs too. Domain-separated from run-scoped keys.
pub(crate) fn provider_key(tenant_id: &str, digest: &str) -> String {
    use contextos_contract::canonical::{quote, sha256_text};
    let digest = sha256_text(&format!(
        "[\"contextos.provider-key.intent.v1\",{},{}]",
        quote(tenant_id),
        quote(digest)
    ));
    format!("ctxos:v1:{}", &digest[7..])
}

/// Why a call was refused at its intent claim.
pub(crate) struct Refusal {
    pub(crate) reason: &'static str,
    /// The run and operation holding the intent, when another one does.
    pub(crate) holder: Option<Value>,
    pub(crate) message: String,
}

/// Claims a call's intent for `(tenant, run, operation)` at `now`: the claim's key when
/// this operation holds it, or the refusal. A store failure refuses (fails closed).
pub(crate) async fn claim_call<S: DocumentStore>(
    store: &S,
    (tenant_id, run_id, operation_id): (&str, &str, &str),
    intent: &IntentKey,
    digest: &str,
    now: &str,
) -> (Option<DocKey>, Option<Refusal>) {
    let pointed = point(store, (tenant_id, run_id, operation_id), digest).await;
    let key = key(tenant_id, digest);
    let now_seconds = contextos_contract::validation::elapsed_millis("1970-01-01T00:00:00Z", now).unwrap_or(0) / 1000;
    let claimed = match pointed {
        Ok(()) => claim(store, &key, run_id, operation_id, now_seconds, intent.window_seconds).await,
        Err(e) => Err(e),
    };
    match claimed {
        Ok(IntentClaim::Claimed) => (Some(key), None),
        Ok(IntentClaim::Held { run_id, operation_id }) => {
            let message = format!("This request was already sent from run {run_id} as operation {operation_id}.");
            let refusal = Refusal {
                reason: "effect_repeated_across_runs",
                holder: Some(json!({"run_id": run_id, "operation_id": operation_id})),
                message,
            };
            (None, Some(refusal))
        }
        Err(error) => {
            tracing::warn!(%error, "intent guard unavailable");
            let refusal = Refusal {
                reason: "intent_guard_unavailable",
                holder: None,
                message: "The intent guard is unavailable; the effect was not sent.".to_owned(),
            };
            (None, Some(refusal))
        }
    }
}

/// [`release`] when `claim` holds a key (the call claimed an intent).
pub(crate) async fn release_held<S: DocumentStore>(
    store: &S,
    claim: Option<&DocKey>,
    run_id: &str,
    operation_id: &str,
) -> Result<(), StoreError> {
    match claim {
        Some(key) => release(store, key, run_id, operation_id).await,
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use contextos_store::MemoryStore;

    fn intent(pointers: &[&str]) -> IntentKey {
        IntentKey {
            key_pointers: pointers.iter().map(|p| (*p).to_owned()).collect(),
            window_seconds: 60,
            provider_key: false,
        }
    }

    #[test]
    fn validation() {
        assert!(intent(&["/order_id"]).validate().is_ok());
        assert!(intent(&[]).validate().is_err());
        assert!(intent(&["order_id"]).validate().is_err());
        assert!(intent(&["/a", "/a"]).validate().is_err());
        let mut long = intent(&["/a"]);
        long.window_seconds = MAX_WINDOW_SECONDS + 1;
        assert!(long.validate().is_err());
        let parsed: IntentKey = serde_json::from_value(json!({"key_pointers": ["/a"]})).unwrap();
        assert_eq!(parsed.window_seconds, DEFAULT_WINDOW_SECONDS);
        assert_eq!(
            serde_json::to_value(&parsed).unwrap(),
            json!({"key_pointers": ["/a"], "window_seconds": 86400})
        );
    }

    #[test]
    fn digest_names_the_request_not_the_call() {
        let key = intent(&["/order_id", "/amount"]);
        let a = digest(
            "t",
            "pay.refund",
            &key,
            &json!({"order_id": "o1", "amount": 600, "note": "x"}),
        );
        let b = digest(
            "t",
            "pay.refund",
            &key,
            &json!({"amount": 600, "order_id": "o1", "note": "y"}),
        );
        assert!(a.is_some());
        assert_eq!(a, b, "arguments outside the key do not matter");
        assert_ne!(
            a,
            digest("t", "pay.refund", &key, &json!({"order_id": "o1", "amount": 601}))
        );
        assert_ne!(
            a,
            digest("u", "pay.refund", &key, &json!({"order_id": "o1", "amount": 600}))
        );
        assert_ne!(
            a,
            digest("t", "pay.credit", &key, &json!({"order_id": "o1", "amount": 600}))
        );
        assert_eq!(digest("t", "pay.refund", &key, &json!({"order_id": "o1"})), None);
        assert_eq!(
            digest("t", "pay.refund", &key, &json!({"order_id": {"id": 1}, "amount": 1})),
            None
        );
    }

    #[tokio::test]
    async fn one_claim_per_intent_until_released_or_lapsed() {
        let store = MemoryStore::new();
        let k = key("t", "sha256:abc");
        assert_eq!(
            claim(&store, &k, "r1", "op1", 100, 60).await.unwrap(),
            IntentClaim::Claimed
        );
        assert_eq!(
            claim(&store, &k, "r1", "op1", 101, 60).await.unwrap(),
            IntentClaim::Claimed,
            "idempotent"
        );
        let held = IntentClaim::Held {
            run_id: "r1".into(),
            operation_id: "op1".into(),
        };
        assert_eq!(claim(&store, &k, "r2", "op9", 120, 60).await.unwrap(), held);
        assert_eq!(
            claim(&store, &k, "r1", "op2", 120, 60).await.unwrap(),
            held,
            "another operation of the run"
        );
        release(&store, &k, "r2", "op9").await.unwrap();
        assert_eq!(
            claim(&store, &k, "r2", "op9", 121, 60).await.unwrap(),
            held,
            "only the holder releases"
        );
        release(&store, &k, "r1", "op1").await.unwrap();
        assert_eq!(
            claim(&store, &k, "r2", "op9", 122, 60).await.unwrap(),
            IntentClaim::Claimed
        );
        assert_eq!(
            claim(&store, &k, "r3", "op3", 181, 60).await.unwrap(),
            held_by("r2", "op9")
        );
        assert_eq!(
            claim(&store, &k, "r3", "op3", 182, 60).await.unwrap(),
            IntentClaim::Claimed,
            "lapsed"
        );
    }

    fn held_by(run: &str, op: &str) -> IntentClaim {
        IntentClaim::Held {
            run_id: run.into(),
            operation_id: op.into(),
        }
    }

    /// DISPATCH-13: of runs racing for one intent, exactly one claims it.
    #[tokio::test]
    async fn racing_runs_get_one_claim() {
        let store = std::sync::Arc::new(MemoryStore::new());
        let k = key("t", "sha256:race");
        let tasks: Vec<_> = (0..16)
            .map(|i| {
                let (store, k) = (store.clone(), k.clone());
                tokio::spawn(async move { claim(store.as_ref(), &k, &format!("r{i}"), "op", 10, 60).await.unwrap() })
            })
            .collect();
        let mut claimed = 0;
        for task in tasks {
            if task.await.unwrap() == IntentClaim::Claimed {
                claimed += 1;
            }
        }
        assert_eq!(claimed, 1);
    }
}
