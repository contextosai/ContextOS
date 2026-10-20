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

/// Distinct call signatures tracked per run at most; later new ones are not tracked.
const MAX_SIGNATURES: usize = 4096;

pub(crate) fn key(admission: &RunAdmission) -> DocKey {
    DocKey::new(&admission.tenant_id, DocKind::LoopGuard, &admission.run_id)
}

pub(crate) fn signature(capability_id: &str, arguments: &Value) -> String {
    sha256_canonical(&json!({"capability_id": capability_id, "arguments": arguments})).unwrap_or_default()
}

pub(crate) fn count(state: Option<&Value>, signature: &str) -> u64 {
    state.and_then(|s| s["counts"][signature].as_u64()).unwrap_or(0)
}

/// Counts one more new operation with `signature`.
pub(crate) async fn note<S: DocumentStore>(store: &S, key: &DocKey, signature: &str) -> Result<(), StoreError> {
    for _ in 0..8 {
        let current = store.get(key).await?;
        let mut state = current
            .as_ref()
            .map_or_else(|| json!({"counts": {}}), |c| c.body.clone());
        let counts = state["counts"].as_object_mut().ok_or(StoreError::Integrity)?;
        if !counts.contains_key(signature) && counts.len() >= MAX_SIGNATURES {
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
