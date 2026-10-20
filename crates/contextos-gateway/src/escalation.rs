//! Policy escalations awaiting a human.
//!
//! When policy answers `escalate`, the call is blocked with `policy_escalation` and the
//! obligation `escalate`, and an escalation record is opened, one per operation of a
//! run, so the hand-off is tracked until a human handles it: the run, capability,
//! action digest, authorization decision and reasons. Opening and resolving are
//! audited. Resolving records what a human did with it; it grants nothing. A retry
//! after a human acted still goes through policy and approvals like any other call.

use contextos_contract::canonical::sha256_text;
use contextos_store::{AppendLog, DocKey, DocKind, DocumentStore};
use serde_json::{Value, json};

use crate::admission::RunAdmission;
use crate::{Gateway, GatewayError};

/// Open escalations per tenant at most; past it, escalations are still recorded and
/// audited but not listed until older ones are resolved.
const MAX_OPEN: usize = 10_000;

pub const RESOLUTIONS: [&str; 2] = ["handled", "dismissed"];

#[derive(Debug, thiserror::Error)]
pub enum EscalationError {
    #[error("resolution must be handled or dismissed, with a reason of 1..1024 bytes")]
    Invalid,
    #[error("no such escalation")]
    NotFound,
    #[error("the escalation is already resolved")]
    Resolved,
    #[error(transparent)]
    Gateway(#[from] GatewayError),
}

fn index_key(tenant_id: &str) -> DocKey {
    DocKey::new(tenant_id, DocKind::Escalation, "open")
}

fn record_key(tenant_id: &str, id: &str) -> DocKey {
    DocKey::new(tenant_id, DocKind::Escalation, format!("record:{id}"))
}

impl<S: DocumentStore + 'static, L: AppendLog + 'static> Gateway<S, L> {
    /// Opens the escalation for a blocked call, once per operation; returns its id.
    pub(crate) async fn open_escalation(&self, admission: &RunAdmission, facts: Value) -> Result<String, GatewayError> {
        let operation_id = facts["operation_id"].as_str().unwrap_or_default();
        let id = format!(
            "esc_{}",
            &sha256_text(&format!("{}\u{0}{operation_id}", admission.run_id))[7..31]
        );
        let key = record_key(&admission.tenant_id, &id);
        if self.store.get(&key).await?.is_some() {
            return Ok(id);
        }
        let now = self.now();
        let mut record = facts;
        record["escalation_id"] = json!(id);
        record["tenant_id"] = json!(admission.tenant_id);
        record["run_id"] = json!(admission.run_id);
        record["trace_id"] = json!(admission.trace_id);
        record["opened_at"] = json!(now);
        record["status"] = json!("open");
        self.audit
            .append(&admission.tenant_id, "escalation_opened", record.clone(), &now)
            .await?;
        // Listed before the record exists; an entry without one is dropped on listing.
        self.note_in_index(index_key(&admission.tenant_id), &id, MAX_OPEN)
            .await?;
        match self.store.create(&key, &record).await {
            Ok(_) => Ok(id),
            Err(e) if e.is_conflict() => Ok(id),
            Err(e) => Err(e.into()),
        }
    }

    /// The tenant's open escalations, oldest first.
    pub async fn open_escalations(&self, tenant_id: &str, limit: usize) -> Result<Vec<Value>, GatewayError> {
        let ids: Vec<String> = self
            .store
            .get(&index_key(tenant_id))
            .await?
            .and_then(|i| i.body["keys"].as_array().cloned())
            .unwrap_or_default()
            .iter()
            .filter_map(|v| v.as_str().map(str::to_owned))
            .collect();
        let mut open = Vec::new();
        for id in ids.iter().take(limit) {
            match self.store.get(&record_key(tenant_id, id)).await? {
                Some(r) if r.body["status"] == "open" => open.push(r.body),
                _ => self.drop_from_index(tenant_id, id).await?,
            }
        }
        Ok(open)
    }

    /// Records how a human resolved the escalation (once), audited.
    pub async fn resolve_escalation(
        &self,
        tenant_id: &str,
        id: &str,
        operator: &str,
        resolution: &str,
        reason: &str,
    ) -> Result<Value, EscalationError> {
        if !RESOLUTIONS.contains(&resolution) || reason.trim().is_empty() || reason.len() > 1024 {
            return Err(EscalationError::Invalid);
        }
        let key = record_key(tenant_id, id);
        let current = self
            .store
            .get(&key)
            .await
            .map_err(GatewayError::from)?
            .ok_or(EscalationError::NotFound)?;
        if current.body["status"] != "open" {
            self.drop_from_index(tenant_id, id).await?;
            return Err(EscalationError::Resolved);
        }
        let now = self.now();
        let mut resolved = current.body.clone();
        resolved["status"] = json!("resolved");
        resolved["resolution"] = json!({"outcome": resolution, "reason": reason, "by": operator, "at": now});
        // Takes effect first, so the chain never records a resolution that lost a race;
        // put back if it cannot be audited.
        match self.store.compare_and_swap(&key, current.revision, &resolved).await {
            Ok(_) => {}
            Err(e) if e.is_conflict() => return Err(EscalationError::Resolved),
            Err(e) => return Err(GatewayError::from(e).into()),
        }
        let audited = self
            .audit
            .append(
                tenant_id,
                "escalation_resolved",
                json!({"escalation_id": id, "run_id": resolved["run_id"], "outcome": resolution,
                    "reason": reason, "by": operator}),
                &now,
            )
            .await;
        if let Err(e) = audited {
            if let Ok(Some(now_resolved)) = self.store.get(&key).await {
                let _ = self
                    .store
                    .compare_and_swap(&key, now_resolved.revision, &current.body)
                    .await;
            }
            return Err(GatewayError::from(e).into());
        }
        self.drop_from_index(tenant_id, id).await?;
        Ok(resolved)
    }

    async fn drop_from_index(&self, tenant_id: &str, id: &str) -> Result<(), GatewayError> {
        let key = index_key(tenant_id);
        for _ in 0..8 {
            let Some(current) = self.store.get(&key).await? else {
                return Ok(());
            };
            let mut keys = current.body["keys"].as_array().cloned().unwrap_or_default();
            let before = keys.len();
            keys.retain(|k| k != id);
            if keys.len() == before {
                return Ok(());
            }
            match self
                .store
                .compare_and_swap(&key, current.revision, &json!({"keys": keys}))
                .await
            {
                Ok(_) => return Ok(()),
                Err(e) if e.is_conflict() => {}
                Err(e) => return Err(e.into()),
            }
        }
        Ok(())
    }
}
