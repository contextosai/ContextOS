//! Loop guard (the spec's turn budgets and loop guards: repeated identical tool calls
//! short-circuit with a structured `loop_detected` reason returned to the planner).
//!
//! A call's signature is the digest of its capability and canonical arguments. Each
//! run keeps a count per signature of new operations dispatched; a retry of an existing
//! operation (same operation key) is not counted. The count is read with the other
//! authorization facts and recorded while the provider works, so the guard adds no
//! serial latency; identical calls racing in parallel may overshoot the limit by their
//! concurrency, which bounds a loop rather than enforcing an exact quota.
//!
//! The same document holds, per signature, the operation that claimed an effect
//! (`effects`), so a second identical effect under another operation key is refused
//! (`effect_repeated`): a host that retries under a new key, or sends one effect
//! through two routes, cannot apply it twice. The claim is a compare-and-swap made
//! after the operation claim and before dispatch, so of identical effects racing in
//! parallel exactly one reaches the provider; it is released only if the provider
//! definitively did not apply the effect.

use contextos_contract::canonical::sha256_canonical;
use contextos_store::{DocKey, DocKind, DocumentStore, StoreError, Versioned};
use serde_json::{Value, json};

use crate::admission::RunAdmission;

/// Distinct call signatures tracked per run at most. A run that reaches it makes no
/// further new kinds of call (`loop_guard_saturated`): the guard fails closed, never
/// stops counting.
pub(crate) const MAX_SIGNATURES: usize = 1024;

pub(crate) fn key(admission: &RunAdmission) -> DocKey {
    DocKey::new(&admission.tenant_id, DocKind::LoopGuard, &admission.run_id)
}

/// 64 bits of the digest of capability and canonical arguments (keeps the per-run
/// document small; a collision only makes two calls share a count).
pub(crate) fn signature(capability_id: &str, arguments: &Value) -> String {
    let digest = sha256_canonical(&json!({"capability_id": capability_id, "arguments": arguments})).unwrap_or_default();
    digest.get(7..23).unwrap_or_default().to_owned()
}

/// Whether the run already tracks the maximum number of signatures and `signature` is
/// not one of them.
pub(crate) fn saturated(state: Option<&Value>, signature: &str) -> bool {
    state
        .and_then(|s| s["counts"].as_object())
        .is_some_and(|c| c.len() >= MAX_SIGNATURES && !c.contains_key(signature))
}

pub(crate) fn count(state: Option<&Value>, signature: &str) -> u64 {
    state.and_then(|s| s["counts"][signature].as_u64()).unwrap_or(0)
}

/// The operation that already applied (or may have applied) an identical effect.
pub(crate) fn applied_effect<'a>(state: Option<&'a Value>, signature: &str) -> Option<&'a str> {
    state.and_then(|s| s["effects"][signature].as_str())
}

/// Whether the run's effect table is full and `signature` is not in it: the guard
/// can no longer record effects, so it refuses new ones (fails closed).
pub(crate) fn effects_saturated(state: Option<&Value>, signature: &str) -> bool {
    state
        .and_then(|s| s["effects"].as_object())
        .is_some_and(|e| e.len() >= MAX_SIGNATURES && !e.contains_key(signature))
}

/// The outcome of claiming an effect's signature for an operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum EffectClaim {
    /// This operation holds the signature (newly, or already).
    Claimed,
    /// Another operation holds it.
    Held(String),
    /// The table is full: no new effect can be guarded.
    Saturated,
}

/// Claims the effect with `signature` for `operation_id`, atomically: of operations
/// racing for one signature, exactly one gets [`EffectClaim::Claimed`]. With `count`,
/// a successful new claim also counts the call for the loop guard in the same write.
/// `seen` is the document as read at authorization: the first attempt writes against
/// it without reading again (on a store where reads are round trips).
pub(crate) async fn claim_effect<S: DocumentStore>(
    store: &S,
    key: &DocKey,
    signature: &str,
    operation_id: &str,
    count: bool,
    seen: Option<&Versioned>,
) -> Result<EffectClaim, StoreError> {
    let outcome = std::sync::Mutex::new(EffectClaim::Claimed);
    update_from(store, key, First::Seen(seen), |state| {
        let effects = effects_mut(state)?;
        let (result, write) = match effects.get(signature).and_then(Value::as_str) {
            Some(holder) if holder == operation_id => (EffectClaim::Claimed, false),
            Some(holder) => (EffectClaim::Held(holder.to_owned()), false),
            None if effects.len() >= MAX_SIGNATURES => (EffectClaim::Saturated, false),
            None => {
                effects.insert(signature.to_owned(), json!(operation_id));
                (EffectClaim::Claimed, true)
            }
        };
        if write && count {
            let counts = state["counts"].as_object_mut().ok_or(StoreError::Integrity)?;
            if counts.contains_key(signature) || counts.len() < MAX_SIGNATURES {
                let next = counts.get(signature).and_then(Value::as_u64).unwrap_or(0) + 1;
                counts.insert(signature.to_owned(), json!(next));
            }
        }
        *outcome.lock().map_err(|_| StoreError::Integrity)? = result;
        Ok(write)
    })
    .await?;
    outcome.into_inner().map_err(|_| StoreError::Integrity)
}

/// Releases `operation_id`'s claim on `signature` (the provider definitively did not
/// apply the effect), so the effect may be attempted again.
pub(crate) async fn release_effect<S: DocumentStore>(
    store: &S,
    key: &DocKey,
    signature: &str,
    operation_id: &str,
) -> Result<(), StoreError> {
    update(store, key, |state| {
        let effects = effects_mut(state)?;
        if effects.get(signature).and_then(Value::as_str) != Some(operation_id) {
            return Ok(false);
        }
        effects.remove(signature);
        Ok(true)
    })
    .await
}

fn effects_mut(state: &mut Value) -> Result<&mut serde_json::Map<String, Value>, StoreError> {
    state
        .as_object_mut()
        .ok_or(StoreError::Integrity)?
        .entry("effects")
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .ok_or(StoreError::Integrity)
}

/// Counts one more new operation with `signature`.
pub(crate) async fn note<S: DocumentStore>(store: &S, key: &DocKey, signature: &str) -> Result<(), StoreError> {
    update(store, key, |state| {
        let counts = state["counts"].as_object_mut().ok_or(StoreError::Integrity)?;
        if !counts.contains_key(signature) && counts.len() >= MAX_SIGNATURES {
            // Refused at authorization; nothing to count.
            return Ok(false);
        }
        let next = counts.get(signature).and_then(Value::as_u64).unwrap_or(0) + 1;
        counts.insert(signature.to_owned(), json!(next));
        Ok(true)
    })
    .await
}

/// Applies `change` to the run's document with compare-and-swap; `change` returns
/// whether there is anything to write.
async fn update<S: DocumentStore>(
    store: &S,
    key: &DocKey,
    change: impl Fn(&mut Value) -> Result<bool, StoreError>,
) -> Result<(), StoreError> {
    update_from(store, key, First::Read, change).await
}

/// Where [`update_from`] starts: a fresh read, or the document as already seen (`None`
/// when it was absent).
enum First<'a> {
    Read,
    Seen(Option<&'a Versioned>),
}

/// As [`update`], starting from `first`.
async fn update_from<S: DocumentStore>(
    store: &S,
    key: &DocKey,
    first: First<'_>,
    change: impl Fn(&mut Value) -> Result<bool, StoreError>,
) -> Result<(), StoreError> {
    let mut seen = match first {
        First::Read => None,
        First::Seen(read) => Some(read),
    };
    for attempt in 0..32_u32 {
        if attempt > 0 {
            // Parallel calls of one run contend on its document: back off briefly.
            tokio::time::sleep(std::time::Duration::from_micros(50 << attempt.min(8))).await;
        }
        let current = match seen.take() {
            Some(read) => read.cloned(),
            None => store.get(key).await?,
        };
        let mut state = current
            .as_ref()
            .map_or_else(|| json!({"counts": {}}), |c| c.body.clone());
        if !change(&mut state)? {
            return Ok(());
        }
        let written = match &current {
            None => store.create(key, &state).await.map(|_| ()),
            Some(c) => store.compare_and_swap(key, c.revision, &state).await.map(|_| ()),
        };
        match written {
            Ok(()) => return Ok(()),
            Err(e) if e.is_conflict() => {}
            Err(e) => return Err(e),
        }
    }
    Err(StoreError::Conflict {
        expected: None,
        actual: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_full_table_refuses_new_kinds_of_call() {
        let counts: serde_json::Map<String, Value> =
            (0..MAX_SIGNATURES).map(|i| (format!("{i:016x}"), json!(1))).collect();
        let state = json!({"counts": counts});
        assert!(
            saturated(Some(&state), "ffffffffffffffff"),
            "a new signature is refused"
        );
        assert!(
            !saturated(Some(&state), &format!("{:016x}", 3)),
            "a tracked one is still counted"
        );
        assert_eq!(signature("a.b", &json!({"x": 1})).len(), 16);
        assert_eq!(signature("a.b", &json!({"x": 1})), signature("a.b", &json!({"x": 1.0})));
    }
}
