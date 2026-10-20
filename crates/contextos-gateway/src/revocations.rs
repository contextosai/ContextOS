//! Kill switch (the spec's rollout kill switch, implemented as graph revocation).
//!
//! An operator revokes a target for a tenant: the whole `tenant`, a `pack` (release
//! tuple, by pack ref), an `agent`, an `adapter` or a `capability`. While revoked:
//!
//! - admission refuses new runs of a revoked tenant, pack or agent;
//! - dispatch refuses every effect of a run whose tenant, pack or agent is revoked,
//!   and every call to a revoked adapter or capability, before anything is claimed.
//!   The check is part of the concurrent authorization reads, so it adds no serial
//!   latency. A call already past authorization completes; nothing new starts.
//!
//! Revocations and restorations are audited with the operator and reason. The set is
//! one document per tenant, bounded by [`MAX_REVOCATIONS`].

use contextos_store::{AppendLog, DocKey, DocKind, DocumentStore};
use serde_json::{Value, json};

use crate::admission::RunAdmission;
use crate::{Gateway, GatewayError};

/// Targets revoked per tenant at most.
pub const MAX_REVOCATIONS: usize = 1024;

pub const REVOCATION_KINDS: [&str; 5] = ["tenant", "pack", "agent", "adapter", "capability"];

#[derive(Debug, thiserror::Error)]
pub enum RevocationError {
    #[error("unknown target kind, or an empty or oversized target or reason")]
    Invalid,
    #[error("the tenant has the maximum number of revocations")]
    TooMany,
    #[error(transparent)]
    Gateway(#[from] GatewayError),
}

pub(crate) fn revocations_key(tenant_id: &str) -> DocKey {
    DocKey::new(tenant_id, DocKind::Revocations, "revocations")
}

/// The first revoked target that applies, as a reason code (`revoked_<kind>`).
pub(crate) fn matching(revocations: Option<&Value>, targets: &[(&str, &str)]) -> Option<String> {
    let list = revocations?.get("revoked")?.as_array()?;
    targets.iter().find_map(|(kind, id)| {
        list.iter()
            .any(|r| r["kind"] == *kind && r["target"] == *id)
            .then(|| format!("revoked_{kind}"))
    })
}

/// What a run is bound to, for revocation: tenant, pack and agent.
pub(crate) fn run_targets(admission: &RunAdmission) -> [(&str, &str); 3] {
    [
        ("tenant", admission.tenant_id.as_str()),
        ("pack", admission.pack_ref.as_str()),
        ("agent", admission.actor["principal_id"].as_str().unwrap_or_default()),
    ]
}

impl<S: DocumentStore + 'static, L: AppendLog + 'static> Gateway<S, L> {
    /// The tenant's current revocations.
    pub async fn revocations(&self, tenant_id: &str) -> Result<Value, GatewayError> {
        Ok(self
            .store
            .get(&revocations_key(tenant_id))
            .await?
            .map_or_else(|| json!({"revoked": []}), |r| r.body))
    }

    /// The reason code if a new run of this tenant, pack and agent is revoked.
    pub async fn admission_revoked(
        &self,
        tenant_id: &str,
        pack_ref: &str,
        agent_id: &str,
    ) -> Result<Option<String>, GatewayError> {
        let current = self.store.get(&revocations_key(tenant_id)).await?;
        Ok(matching(
            current.as_ref().map(|r| &r.body),
            &[("tenant", tenant_id), ("pack", pack_ref), ("agent", agent_id)],
        ))
    }

    /// Revokes (`revoke = true`) or restores a target. Idempotent; audited either way.
    pub async fn set_revocation(
        &self,
        tenant_id: &str,
        kind: &str,
        target: &str,
        reason: &str,
        operator: &str,
        revoke: bool,
    ) -> Result<Value, RevocationError> {
        let sized = |s: &str, max: usize| !s.trim().is_empty() && s.len() <= max;
        if !REVOCATION_KINDS.contains(&kind) || !sized(target, 256) || !sized(reason, 1024) {
            return Err(RevocationError::Invalid);
        }
        let now = self.now();
        let key = revocations_key(tenant_id);
        let present = |list: &[Value]| list.iter().any(|r| r["kind"] == kind && r["target"] == target);
        let mut current = self.store.get(&key).await.map_err(GatewayError::from)?;
        let listed = |c: &Option<contextos_store::Versioned>| {
            c.as_ref()
                .and_then(|c| c.body["revoked"].as_array().cloned())
                .unwrap_or_default()
        };
        if present(&listed(&current)) == revoke {
            return Ok(json!({"revoked": listed(&current)}));
        }
        // Audited before it takes effect: the trail never misses a change.
        let change = json!({"kind": kind, "target": target, "reason": reason, "operator": operator});
        let event = if revoke { "revocation" } else { "revocation_restored" };
        self.audit
            .append(tenant_id, event, change.clone(), &now)
            .await
            .map_err(GatewayError::from)?;
        let applied = async {
            for _ in 0..8 {
                let mut list = listed(&current);
                if present(&list) == revoke {
                    return Ok(json!({"revoked": list}));
                }
                if revoke {
                    if list.len() >= MAX_REVOCATIONS {
                        return Err(RevocationError::TooMany);
                    }
                    list.push(json!({"kind": kind, "target": target, "reason": reason, "by": operator, "at": now}));
                } else {
                    list.retain(|r| !(r["kind"] == kind && r["target"] == target));
                }
                let state = json!({"revoked": list});
                let written = match &current {
                    None => self.store.create(&key, &state).await.map(|_| ()),
                    Some(c) => self.store.compare_and_swap(&key, c.revision, &state).await.map(|_| ()),
                };
                match written {
                    Ok(()) => return Ok(state),
                    Err(e) if e.is_conflict() => {
                        current = self.store.get(&key).await.map_err(GatewayError::from)?;
                    }
                    Err(e) => return Err(GatewayError::from(e).into()),
                }
            }
            Err(GatewayError::from(contextos_store::StoreError::Conflict {
                expected: None,
                actual: None,
            })
            .into())
        }
        .await;
        if let Err(error) = &applied {
            let mut entry = change;
            entry["error"] = json!(error.to_string());
            let _ = self
                .audit
                .append(tenant_id, &format!("{event}_not_applied"), entry, &now)
                .await;
        }
        applied
    }
}
