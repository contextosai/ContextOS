//! Kill switch (the spec's rollout kill switch, implemented as graph revocation).
//!
//! An operator revokes a target for a tenant: the whole `tenant`, a `pack` (release
//! tuple, by pack ref), an authenticated `principal` (the caller that admits runs, and
//! every run it admitted, or any actor on a run's delegation chain), an `agent` (the
//! agent id a run declares; to stop whoever runs it, revoke the principal), a `user`
//! (every run a delegated credential says acts for them, and new runs declaring them),
//! a `delegation` (one exact chain of actors for one user, by its digest; see
//! [`crate::delegation_chain`]), an `adapter` or a `capability`. A `global`
//! revocation (target `*`, set only by the principals the deployment lists) stops
//! every tenant of the runtime at once; it is kept apart from every tenant's set and
//! read with each. While revoked:
//!
//! - admission refuses new runs of a revoked tenant, pack or agent, audited as
//!   `revocation_refusal` (`stage: "admission"`) with the agent and the revoker;
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

pub const REVOCATION_KINDS: [&str; 9] = [
    "global",
    "tenant",
    "pack",
    "principal",
    "agent",
    "user",
    "delegation",
    "adapter",
    "capability",
];

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

/// Where the runtime-wide revocation lives: not a tenant id any caller can hold.
pub const GLOBAL_SCOPE: &str = "*";

pub(crate) fn global_key() -> DocKey {
    DocKey::new(GLOBAL_SCOPE, DocKind::Revocations, "revocations")
}

/// The global revocation, if one is in force.
pub(crate) fn global_matched(global: Option<&Value>) -> Option<Revoked> {
    matched(global, &[("global", GLOBAL_SCOPE)])
}

/// A revocation that applies to a run or a call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Revoked {
    /// `revoked_<kind>`.
    pub reason_code: String,
    pub kind: String,
    pub target: String,
    /// Who revoked it: an operator's principal, or `circuit_breaker:<id>` when a
    /// breaker tripped it.
    pub by: String,
}

impl Revoked {
    /// Who revoked it, as told to the caller: the breaker by id, an operator unnamed.
    pub fn revoker(&self) -> String {
        match self.by.strip_prefix("circuit_breaker:") {
            Some(id) => format!("circuit breaker {id}"),
            None => "an operator".to_owned(),
        }
    }

    /// The refusal's message, naming what is revoked and by whom.
    pub fn message(&self) -> String {
        format!("The {} has been revoked by {}.", self.kind, self.revoker())
    }
}

/// The first revoked target that applies.
pub(crate) fn matched(revocations: Option<&Value>, targets: &[(&str, &str)]) -> Option<Revoked> {
    let list = revocations?.get("revoked")?.as_array()?;
    targets.iter().find_map(|(kind, id)| {
        list.iter()
            .find(|r| r["kind"] == *kind && r["target"] == *id)
            .map(|r| Revoked {
                reason_code: format!("revoked_{kind}"),
                kind: (*kind).to_owned(),
                target: (*id).to_owned(),
                by: r["by"].as_str().unwrap_or_default().to_owned(),
            })
    })
}

/// What a run is bound to, for revocation: tenant, pack, admitting principal and agent,
/// and with a delegation chain its user, the chain and every actor on it.
pub fn run_targets(admission: &RunAdmission) -> Vec<(&str, &str)> {
    let mut targets = vec![
        ("tenant", admission.tenant_id.as_str()),
        ("pack", admission.pack_ref.as_str()),
        ("principal", admission.admitted_by.as_str()),
        ("agent", admission.actor["principal_id"].as_str().unwrap_or_default()),
    ];
    if let Some(chain) = &admission.delegation_chain {
        targets.push(("user", chain.user_id.as_str()));
        targets.push(("delegation", chain.digest.as_str()));
        targets.extend(chain.actors.iter().map(|a| ("principal", a.as_str())));
    }
    targets
}

/// What a new run would be bound to, for revocation at admission.
#[derive(Debug, Clone, Copy)]
pub struct AdmissionTargets<'a> {
    pub tenant_id: &'a str,
    pub pack_ref: &'a str,
    pub principal: &'a str,
    pub agent_id: &'a str,
    /// The user the run declares, verified or not.
    pub declared_user: Option<&'a str>,
    pub chain: Option<&'a crate::DelegationChain>,
    pub parent: Option<&'a RunAdmission>,
}

impl<S: DocumentStore + 'static, L: AppendLog + 'static> Gateway<S, L> {
    /// The tenant's current revocations, with a global one first when in force.
    pub async fn revocations(&self, tenant_id: &str) -> Result<Value, GatewayError> {
        let list = |doc: Option<contextos_store::Versioned>| {
            doc.and_then(|d| d.body["revoked"].as_array().cloned())
                .unwrap_or_default()
        };
        let mut revoked = list(self.store.get(&global_key()).await?);
        revoked.extend(list(self.store.get(&revocations_key(tenant_id)).await?));
        Ok(json!({"revoked": revoked}))
    }

    /// The revocation that applies if a new run of this tenant, pack, admitting
    /// principal, agent, declared user or delegation chain is revoked, or if the parent
    /// of a delegated run is. A refusal is audited (`revocation_refusal`, `stage:
    /// "admission"`) with the agent, the kind of target revoked and who revoked it.
    pub async fn admission_revoked(&self, new: &AdmissionTargets<'_>) -> Result<Option<Revoked>, GatewayError> {
        let current = self.store.get(&revocations_key(new.tenant_id)).await?;
        let global = self.store.get(&global_key()).await?;
        let mut targets = vec![
            ("tenant", new.tenant_id),
            ("pack", new.pack_ref),
            ("principal", new.principal),
            ("agent", new.agent_id),
        ];
        targets.extend(new.declared_user.map(|u| ("user", u)));
        if let Some(chain) = new.chain {
            targets.push(("user", chain.user_id.as_str()));
            targets.push(("delegation", chain.digest.as_str()));
            targets.extend(chain.actors.iter().map(|a| ("principal", a.as_str())));
        }
        if let Some(parent) = new.parent {
            targets.extend(run_targets(parent));
        }
        let Some(revoked) = global_matched(global.as_ref().map(|g| &g.body))
            .or_else(|| matched(current.as_ref().map(|r| &r.body), &targets))
        else {
            return Ok(None);
        };
        let refusal = json!({"stage": "admission", "agent_id": new.agent_id, "principal_id": new.principal,
            "pack_ref": new.pack_ref, "parent_run_id": new.parent.map(|p| &p.run_id),
            "reason_codes": [revoked.reason_code], "revoked_kind": revoked.kind, "revoked_by": revoked.by});
        self.audit
            .append(new.tenant_id, "revocation_refusal", refusal, &self.now())
            .await?;
        Ok(Some(revoked))
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
        if kind == "global" && target != GLOBAL_SCOPE {
            return Err(RevocationError::Invalid);
        }
        let now = self.now();
        let key = if kind == "global" {
            global_key()
        } else {
            revocations_key(tenant_id)
        };
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
