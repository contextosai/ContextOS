//! Erasure of a run's personal content.
//!
//! A run's user-provided content lives in the replay case (the original request,
//! including the user's message and context), the compiled context (the task prompt
//! and evidence blocks), the orchestrator's checkpoint, and any pending tool input
//! requests (what a tool asked the user; indexed per run when recorded). Operator
//! feedback filed against the run (indexed per run) has its free text redacted; its
//! status and replay obligation stay, so an operator still closes it explicitly.
//! Erasure overwrites the rest with a tombstone that
//! records who erased them, when, why, and the digest of what was removed, so the
//! erasure itself is provable and the content can never be re-created under the same
//! key. A run can be erased once it is finished (completed, failed or cancelled), past
//! its deadline, or was never started; a live run still decides against its context.
//!
//! Signed records are not rewritten: DecisionRecords and audit entries are hash-chained
//! evidence. Deployments keep personal data out of decision outputs and rationales
//! (cite evidence by reference); the audit chain records only that an erasure happened.

use contextos_contract::canonical::sha256_canonical;
use contextos_contract::validation::compare_contract_times;
use contextos_store::{AppendLog, DocKey, DocKind, DocumentStore};
use serde_json::{Value, json};

use crate::admission::RunAdmission;
use crate::{Gateway, GatewayError};

const TERMINAL: [&str; 3] = ["completed", "failed", "cancelled"];

/// Pending inputs indexed per run at most (one per operation that asked for input).
const MAX_PENDING_INDEX: usize = 4096;

/// Feedback records indexed per run at most.
const MAX_FEEDBACK_INDEX: usize = 4096;

/// Free-text fields of a feedback record, removed on erasure.
const FEEDBACK_TEXT: [&str; 2] = ["summary", "expected_outcome"];

fn feedback_index_key(admission: &RunAdmission) -> DocKey {
    DocKey::new(
        &admission.tenant_id,
        DocKind::Feedback,
        format!("run:{}", admission.run_id),
    )
}

fn pending_index_key(admission: &RunAdmission) -> DocKey {
    DocKey::new(
        &admission.tenant_id,
        DocKind::PendingInput,
        format!("run:{}", admission.run_id),
    )
}

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
    #[tracing::instrument(name = "contextos.erase", skip_all, fields(tenant_id = %admission.tenant_id, run_id = %admission.run_id, trace_id = %admission.trace_id))]
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
        let now = self.now();
        let expired = compare_contract_times(&admission.deadline, &now) == Some(std::cmp::Ordering::Less);
        if !(status.is_null() || expired || TERMINAL.iter().any(|t| status == *t)) {
            return Err(ErasureError::RunActive);
        }
        // What remains to erase, with digests of the content being removed.
        let mut pending = Vec::new();
        let inputs: Vec<DocKey> = self
            .store
            .get(&pending_index_key(admission))
            .await
            .map_err(GatewayError::from)?
            .and_then(|i| i.body["keys"].as_array().cloned())
            .unwrap_or_default()
            .iter()
            .filter_map(Value::as_str)
            .map(|id| DocKey::new(&admission.tenant_id, DocKind::PendingInput, id))
            .collect();
        let documents = [DocKind::ReplayCase, DocKind::CompiledContext, DocKind::Checkpoint]
            .into_iter()
            .map(|kind| DocKey::new(&admission.tenant_id, kind, &admission.run_id))
            .chain(inputs);
        for key in documents {
            let kind = key.kind;
            if let Some(current) = self.store.get(&key).await.map_err(GatewayError::from)?
                && !is_erased(&current.body)
            {
                pending.push((kind, key, sha256_canonical(&current.body).unwrap_or_default()));
            }
        }
        // Feedback keeps its record; only its free text goes.
        let feedback: Vec<DocKey> = self
            .store
            .get(&feedback_index_key(admission))
            .await
            .map_err(GatewayError::from)?
            .and_then(|i| i.body["keys"].as_array().cloned())
            .unwrap_or_default()
            .iter()
            .filter_map(Value::as_str)
            .map(|id| DocKey::new(&admission.tenant_id, DocKind::Feedback, id))
            .collect();
        let mut redact = Vec::new();
        for key in feedback {
            if let Some(current) = self.store.get(&key).await.map_err(GatewayError::from)?
                && current.body.get("content_erased").is_none()
            {
                let text: Value = FEEDBACK_TEXT
                    .iter()
                    .map(|f| ((*f).to_owned(), current.body[*f].clone()))
                    .collect::<serde_json::Map<_, _>>()
                    .into();
                redact.push((key, sha256_canonical(&text).unwrap_or_default()));
            }
        }
        let erased: Vec<Value> = pending
            .iter()
            .map(|(kind, _, digest)| json!({"document": kind.as_str(), "content_digest": digest}))
            .chain(
                redact
                    .iter()
                    .map(|(_, digest)| json!({"document": "feedback_text", "content_digest": digest})),
            )
            .collect();
        let record = json!({"run_id": admission.run_id, "operator": operator, "reason": reason, "erased": erased});
        if pending.is_empty() && redact.is_empty() {
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
        for (key, digest) in &redact {
            let marker = json!({"erased_at": now, "erased_by": operator, "reason": reason, "content_digest": digest});
            for _ in 0..8 {
                let Some(current) = self.store.get(key).await.map_err(GatewayError::from)? else {
                    break;
                };
                if current.body.get("content_erased").is_some() {
                    break;
                }
                let mut body = current.body.clone();
                for field in FEEDBACK_TEXT {
                    body[field] = Value::Null;
                }
                body["content_erased"] = marker.clone();
                match self.store.compare_and_swap(key, current.revision, &body).await {
                    Ok(_) => break,
                    Err(e) if e.is_conflict() => {}
                    Err(e) => return Err(GatewayError::from(e).into()),
                }
            }
        }
        Ok(record)
    }

    /// Records that the run has a feedback document (`DocKind::Feedback` id), so erasure
    /// can find it. Call before the document is created; fails rather than leave a
    /// document erasure would miss.
    pub async fn note_run_feedback(&self, admission: &RunAdmission, id: &str) -> Result<(), GatewayError> {
        if self
            .note_in_index(feedback_index_key(admission), id, MAX_FEEDBACK_INDEX)
            .await?
        {
            Ok(())
        } else {
            Err(contextos_store::StoreError::Conflict {
                expected: None,
                actual: None,
            }
            .into())
        }
    }

    /// Records that the run has a pending input document, so erasure can find it.
    pub(crate) async fn note_pending_input(&self, admission: &RunAdmission, id: &str) -> Result<(), GatewayError> {
        self.note_in_index(pending_index_key(admission), id, MAX_PENDING_INDEX)
            .await
            .map(|_| ())
    }

    /// Adds `id` to the index; false when the index is full or stayed contended.
    pub(crate) async fn note_in_index(&self, key: DocKey, id: &str, max: usize) -> Result<bool, GatewayError> {
        for _ in 0..8 {
            let current = self.store.get(&key).await?;
            let mut keys = current
                .as_ref()
                .and_then(|c| c.body["keys"].as_array().cloned())
                .unwrap_or_default();
            if keys.iter().any(|k| k == id) {
                return Ok(true);
            }
            if keys.len() >= max {
                return Ok(false);
            }
            keys.push(json!(id));
            let state = json!({"keys": keys});
            let written = match &current {
                None => self.store.create(&key, &state).await.map(|_| ()),
                Some(c) => self.store.compare_and_swap(&key, c.revision, &state).await.map(|_| ()),
            };
            match written {
                Ok(()) => return Ok(true),
                Err(e) if e.is_conflict() => {}
                Err(e) => return Err(e.into()),
            }
        }
        Ok(false)
    }
}
