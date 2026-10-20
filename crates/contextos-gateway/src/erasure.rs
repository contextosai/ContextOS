//! Erasure of a run's personal content.
//!
//! A run's user-provided content lives in two documents: the replay case (the original
//! request, including the user's message and context) and the compiled context (the
//! task prompt and evidence blocks). Erasure overwrites both with a tombstone that
//! records who erased them, when, why, and the digest of what was removed, so the
//! erasure itself is provable and the content can never be re-created under the same
//! key. Only finished runs (completed, failed or cancelled) can be erased, since a live
//! run still compiles decisions against its context.
//!
//! Signed records are not rewritten: DecisionRecords and audit entries are hash-chained
//! evidence. Deployments keep personal data out of decision outputs and rationales
//! (cite evidence by reference); the audit chain records only that an erasure happened.

use contextos_contract::canonical::sha256_canonical;
use contextos_store::{AppendLog, DocKey, DocKind, DocumentStore};
use serde_json::{Value, json};

use crate::admission::RunAdmission;
use crate::{Gateway, GatewayError};

const TERMINAL: [&str; 3] = ["completed", "failed", "cancelled"];

#[derive(Debug, thiserror::Error)]
pub enum ErasureError {
    #[error("only a finished run can be erased")]
    RunActive,
    #[error("a reason is required")]
    Invalid,
    #[error(transparent)]
    Gateway(#[from] GatewayError),
}

/// True when a stored document is an erasure tombstone.
pub fn is_erased(body: &Value) -> bool {
    body["erased"] == true
}

impl<S: DocumentStore + 'static, L: AppendLog + 'static> Gateway<S, L> {
    /// Erases the run's personal content. Idempotent: an erased document stays erased.
    pub async fn erase_run(
        &self,
        admission: &RunAdmission,
        operator: &str,
        reason: &str,
    ) -> Result<Value, ErasureError> {
        if reason.trim().is_empty() || reason.len() > 1024 {
            return Err(ErasureError::Invalid);
        }
        let status = self
            .run_state(admission)
            .await?
            .map_or(Value::Null, |s| s["status"].clone());
        if !TERMINAL.iter().any(|t| status == *t) {
            return Err(ErasureError::RunActive);
        }
        let now = self.now();
        // What remains to erase, with digests of the content being removed.
        let mut pending = Vec::new();
        for kind in [DocKind::ReplayCase, DocKind::CompiledContext] {
            let key = DocKey::new(&admission.tenant_id, kind, &admission.run_id);
            if let Some(current) = self.store.get(&key).await.map_err(GatewayError::from)?
                && !is_erased(&current.body)
            {
                pending.push((kind, key, sha256_canonical(&current.body).unwrap_or_default()));
            }
        }
        let erased: Vec<Value> = pending
            .iter()
            .map(|(kind, _, digest)| json!({"document": kind.as_str(), "content_digest": digest}))
            .collect();
        let record = json!({"run_id": admission.run_id, "operator": operator, "reason": reason, "erased": erased});
        if pending.is_empty() {
            return Ok(record);
        }
        // Audited before the content goes: the trail never misses an erasure.
        self.audit
            .append(&admission.tenant_id, "run_data_erased", record.clone(), &now)
            .await
            .map_err(GatewayError::from)?;
        for (_, key, digest) in &pending {
            let tombstone = json!({"erased": true, "erased_at": now, "erased_by": operator, "reason": reason,
                "content_digest": digest});
            for _ in 0..8 {
                let Some(current) = self.store.get(key).await.map_err(GatewayError::from)? else {
                    break;
                };
                if is_erased(&current.body) {
                    break;
                }
                match self.store.compare_and_swap(key, current.revision, &tombstone).await {
                    Ok(_) => break,
                    Err(e) if e.is_conflict() => {}
                    Err(e) => return Err(GatewayError::from(e).into()),
                }
            }
        }
        Ok(record)
    }
}
