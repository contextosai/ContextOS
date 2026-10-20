//! Loop guard (the spec's turn budgets and loop guards: repeated identical tool calls
//! short-circuit with a structured `loop_detected` reason returned to the planner).
//!
//! A call's signature is the digest of its capability and canonical arguments. Each
//! run keeps a count per signature of new operations dispatched; a retry of an existing
//! operation (same operation key) is not counted. The count is read with the other
//! authorization facts and recorded while the provider works, so the guard adds no
//! serial latency; identical calls racing in parallel may overshoot the limit by their
//! concurrency, which bounds a loop rather than enforcing an exact quota.

use contextos_contract::canonical::sha256_canonical;
use contextos_store::{DocKey, DocKind, DocumentStore, StoreError};
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

/// Counts one more new operation with `signature`.
pub(crate) async fn note<S: DocumentStore>(store: &S, key: &DocKey, signature: &str) -> Result<(), StoreError> {
    for attempt in 0..32_u32 {
        if attempt > 0 {
            // Parallel calls of one run contend on its document: back off briefly.
            tokio::time::sleep(std::time::Duration::from_micros(50 << attempt.min(8))).await;
        }
        let current = store.get(key).await?;
        let mut state = current
            .as_ref()
            .map_or_else(|| json!({"counts": {}}), |c| c.body.clone());
        let counts = state["counts"].as_object_mut().ok_or(StoreError::Integrity)?;
        if !counts.contains_key(signature) && counts.len() >= MAX_SIGNATURES {
            // Refused at authorization; nothing to count.
            return Ok(());
        }
        let next = counts.get(signature).and_then(Value::as_u64).unwrap_or(0) + 1;
        counts.insert(signature.to_owned(), json!(next));
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
