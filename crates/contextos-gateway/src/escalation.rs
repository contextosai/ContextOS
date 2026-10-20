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

/// Escalations one run may list (it cannot crowd out every other run's).
const MAX_PER_RUN: usize = 100;

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
        let now = self.now();
        let mut record = facts;
        record["escalation_id"] = json!(id);
        record["tenant_id"] = json!(admission.tenant_id);
        record["run_id"] = json!(admission.run_id);
        record["trace_id"] = json!(admission.trace_id);
        record["opened_at"] = json!(now);
        // Claim the hand-off as `opening`: only the caller whose write lands audits it,
        // so concurrent escalations of one operation open it once.
        record["status"] = json!("opening");
        let claimed = match self.store.get(&key).await? {
            None => match self.store.create(&key, &record).await {
                Ok(created) => created.revision,
                Err(e) if e.is_conflict() => return Ok(id),
                Err(e) => return Err(e.into()),
            },
            Some(current) if current.body["status"] == "open" => return Ok(id),
            // A resolved escalation that recurs is a new hand-off (history kept); one
            // left `opening` by a failed audit is completed now.
            Some(current) => {
                if current.body["status"] == "resolved" {
                    let mut history = current.body["history"].as_array().cloned().unwrap_or_default();
                    history.push(
                        json!({"opened_at": current.body["opened_at"], "resolution": current.body["resolution"]}),
                    );
                    record["history"] = json!(history);
                } else {
                    record["history"] = current.body["history"].clone();
                }
                match self.store.compare_and_swap(&key, current.revision, &record).await {
                    Ok(written) => written.revision,
                    Err(e) if e.is_conflict() => return Ok(id),
                    Err(e) => return Err(e.into()),
                }
            }
        };
        self.audit
            .append(&admission.tenant_id, "escalation_opened", record.clone(), &now)
            .await?;
        record["status"] = json!("open");
        match self.store.compare_and_swap(&key, claimed, &record).await {
            Ok(_) => {}
            Err(e) if e.is_conflict() => return Ok(id),
            Err(e) => return Err(e.into()),
        }
        // Listed once open; one run may hold at most MAX_PER_RUN of the tenant's listing.
        let per_run = DocKey::new(
            &admission.tenant_id,
            DocKind::Escalation,
            format!("run:{}", admission.run_id),
        );
        if self.note_in_index(per_run, &id, MAX_PER_RUN).await? {
            self.note_in_index(index_key(&admission.tenant_id), &id, MAX_OPEN)
                .await?;
        }
        Ok(id)
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
                Some(r) if r.body["status"] == "resolved" => self.drop_from_index(tenant_id, id).await?,
                _ => {}
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
        if let Some(run_id) = resolved["run_id"].as_str() {
            self.drop_from(DocKey::new(tenant_id, DocKind::Escalation, format!("run:{run_id}")), id)
                .await?;
        }
        Ok(resolved)
    }

    async fn drop_from_index(&self, tenant_id: &str, id: &str) -> Result<(), GatewayError> {
        self.drop_from(index_key(tenant_id), id).await
    }

    async fn drop_from(&self, key: DocKey, id: &str) -> Result<(), GatewayError> {
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
