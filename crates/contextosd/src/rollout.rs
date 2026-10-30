//! Staged rollout of Context Pack versions (the spec's rollout stages: shadow, 1%, 5%,
//! 25%, 100%, each with a kill switch).
//!
//! An operator sets, per tenant, a rollout from a baseline pack to a candidate pack at
//! a percentage. A run that asks for the baseline is admitted on the candidate when its
//! routing bucket (a hash of tenant and run id; a delegated child uses its parent's
//! run id, so a lane stays on its parent's pack) is below the percentage; the run pins
//! whichever pack it was admitted on. Routing is sticky and reproducible, and steerable:
//! the caller chooses the run id, so a rollout is a canary, never an enforcement point.
//!
//! With `shadow`, every run kept on the baseline is also compiled under the candidate
//! off the request path, and the governance difference (capabilities, policy, evidence
//! gates; see [`contextos_kernel::release_gate`]) is audited as `shadow_diff`: live
//! evidence for the next stage without affecting any outcome.
//!
//! Clearing the rollout returns all traffic to the baseline; revoking the candidate
//! pack (the kill switch) also refuses runs already routed to it.

use contextos_contract::canonical::sha256_canonical;
use contextos_store::{DocKey, DocKind, DocumentStore, StoreError};
use serde::Deserialize;
use serde_json::{Value, json};

/// Rollouts per tenant at most.
pub const MAX_ROLLOUTS: usize = 64;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RolloutChange {
    pub baseline: String,
    pub candidate: String,
    /// Share of the baseline's new runs admitted on the candidate, 0 to 100.
    pub percent: u8,
    #[serde(default)]
    pub shadow: bool,
    pub reason: String,
    /// Runs whose replay cases gate the candidate before it takes live traffic
    /// (`percent > 0`); every open feedback record's replay case is added to them.
    #[serde(default)]
    pub gate_runs: Vec<String>,
    /// Widenings the operator accepts, by the release gate's rules.
    #[serde(default)]
    pub acknowledge: contextos_kernel::release_gate::Acknowledgements,
}

/// Runs named to gate one rollout at most.
pub const MAX_GATE_RUNS: usize = 200;

#[derive(Debug, thiserror::Error)]
pub enum RolloutError {
    #[error("the tenant has the maximum number of rollouts")]
    TooMany,
    #[error(transparent)]
    Store(#[from] StoreError),
}

pub(crate) fn key(tenant_id: &str) -> DocKey {
    DocKey::new(tenant_id, DocKind::Rollouts, "rollouts")
}

/// The routing bucket of a run, `0..100`.
pub fn bucket(tenant_id: &str, routing_run_id: &str) -> u8 {
    let digest = sha256_canonical(&json!([tenant_id, routing_run_id])).unwrap_or_default();
    let hex = digest.strip_prefix("sha256:").unwrap_or_default();
    let n = u64::from_str_radix(hex.get(..12).unwrap_or("0"), 16).unwrap_or(0);
    u8::try_from(n % 100).unwrap_or(0)
}

/// Where a run asking for `requested` goes: `(pack to admit on, the rollout if one
/// applies)`.
pub fn route<'a>(
    rollouts: Option<&'a Value>,
    requested: &'a str,
    tenant_id: &str,
    routing_run_id: &str,
) -> (&'a str, Option<&'a Value>) {
    let rollout = rollouts
        .and_then(|r| r["rollouts"].as_array())
        .and_then(|list| list.iter().find(|r| r["baseline"] == requested));
    match rollout {
        Some(r) if u64::from(bucket(tenant_id, routing_run_id)) < r["percent"].as_u64().unwrap_or(0) => {
            (r["candidate"].as_str().unwrap_or(requested), Some(r))
        }
        other => (requested, other),
    }
}

/// Sets (`Some`) or clears (`None`, by baseline) a tenant's rollout; returns the new set.
pub async fn change<S: DocumentStore>(
    store: &S,
    tenant_id: &str,
    baseline: &str,
    set: Option<Value>,
) -> Result<Value, RolloutError> {
    let key = key(tenant_id);
    for _ in 0..8 {
        let current = store.get(&key).await?;
        let mut list = current
            .as_ref()
            .and_then(|c| c.body["rollouts"].as_array().cloned())
            .unwrap_or_default();
        list.retain(|r| r["baseline"] != baseline);
        if let Some(rollout) = &set {
            if list.len() >= MAX_ROLLOUTS {
                return Err(RolloutError::TooMany);
            }
            list.push(rollout.clone());
        }
        let state = json!({"rollouts": list});
        let written = match &current {
            None => store.create(&key, &state).await.map(|_| ()),
            Some(c) => store.compare_and_swap(&key, c.revision, &state).await.map(|_| ()),
        };
        match written {
            Ok(()) => return Ok(state),
            Err(e) if e.is_conflict() => {}
            Err(e) => return Err(e.into()),
        }
    }
    Err(StoreError::Conflict {
        expected: None,
        actual: None,
    }
    .into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routing_is_sticky_and_proportional() {
        let rollouts = json!({"rollouts": [{"baseline": "p@1", "candidate": "p@2", "percent": 25}]});
        let on_candidate = (0..10_000)
            .filter(|i| route(Some(&rollouts), "p@1", "t", &format!("run_{i}")).0 == "p@2")
            .count();
        assert!((2_200..2_800).contains(&on_candidate), "{on_candidate}");
        assert_eq!(
            route(Some(&rollouts), "p@1", "t", "run_7"),
            route(Some(&rollouts), "p@1", "t", "run_7")
        );
        // Other packs and an empty set are untouched; 0% and 100% are exact.
        assert_eq!(route(Some(&rollouts), "q@1", "t", "run_1"), ("q@1", None));
        assert_eq!(route(None, "p@1", "t", "run_1").0, "p@1");
        for (percent, expected) in [(0, "p@1"), (100, "p@2")] {
            let r = json!({"rollouts": [{"baseline": "p@1", "candidate": "p@2", "percent": percent}]});
            assert!((0..200).all(|i| route(Some(&r), "p@1", "t", &format!("r{i}")).0 == expected));
        }
    }
}
