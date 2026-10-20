//! Orchestrator checkpoints (the spec's orchestration: a checkpoint is persisted after
//! every Critic verdict, so a run resumes where it was after executor failover).
//!
//! The orchestrator's own state (plan, step pointer, last verdict, working notes) is
//! opaque to the runtime, which keeps it durable and governed: only the run's current
//! executor may write (generation fencing at the API), writes are optimistic on the
//! checkpoint revision so two writers cannot silently overwrite each other, each
//! checkpoint is content-addressed and audited by digest, and it is bounded in size. A
//! new executor reads the latest checkpoint after takeover. Checkpoints can hold
//! personal content and are erased with the run.

use contextos_contract::canonical::{canonicalize, sha256_canonical};
use contextos_store::{AppendLog, DocKey, DocKind, DocumentStore};
use serde_json::{Value, json};

use crate::admission::RunAdmission;
use crate::{Gateway, GatewayError};

/// Canonical size of one checkpoint's state at most.
pub const MAX_CHECKPOINT_BYTES: usize = 256 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum CheckpointRefusal {
    #[error("the checkpoint state is too large or not plain JSON")]
    Invalid,
    #[error("the run is past its deadline or its content was erased")]
    Closed,
    #[error("the checkpoint changed since revision {expected}; current revision {current}")]
    RevisionConflict { expected: u64, current: u64 },
    #[error(transparent)]
    Gateway(#[from] GatewayError),
}

pub(crate) fn key(admission: &RunAdmission) -> DocKey {
    DocKey::new(&admission.tenant_id, DocKind::Checkpoint, &admission.run_id)
}

impl<S: DocumentStore + 'static, L: AppendLog + 'static> Gateway<S, L> {
    /// Saves the run's checkpoint as revision `expected_revision + 1` (0 for the first).
    pub async fn save_checkpoint(
        &self,
        admission: &RunAdmission,
        executor_generation: u64,
        expected_revision: u64,
        state: Value,
    ) -> Result<Value, CheckpointRefusal> {
        if canonicalize(&state).map_or(true, |text| text.len() > MAX_CHECKPOINT_BYTES) {
            return Err(CheckpointRefusal::Invalid);
        }
        let key = key(admission);
        let current = self.store.get(&key).await.map_err(GatewayError::from)?;
        // Erased content stays erased, and a run past its deadline writes nothing new.
        let expired = contextos_contract::validation::compare_contract_times(&admission.deadline, &self.now())
            == Some(std::cmp::Ordering::Less);
        if expired || current.as_ref().is_some_and(|c| crate::erasure::is_erased(&c.body)) {
            return Err(CheckpointRefusal::Closed);
        }
        let current_revision = current.as_ref().and_then(|c| c.body["revision"].as_u64()).unwrap_or(0);
        if current_revision != expected_revision {
            return Err(CheckpointRefusal::RevisionConflict {
                expected: expected_revision,
                current: current_revision,
            });
        }
        let now = self.now();
        let revision = expected_revision + 1;
        let digest = sha256_canonical(&json!({"domain": "contextos.orchestrator_checkpoint.v1",
            "run_id": admission.run_id, "revision": revision, "state": state}))
        .unwrap_or_default();
        let record = json!({"run_id": admission.run_id, "revision": revision, "digest": digest,
            "executor_generation": executor_generation, "saved_at": now});
        // Audited before it is kept (by digest; the state itself stays out of the chain).
        self.audit
            .append(&admission.tenant_id, "checkpoint_saved", record.clone(), &now)
            .await
            .map_err(GatewayError::from)?;
        let mut body = record.clone();
        body["state"] = state;
        let written = match &current {
            None => self.store.create(&key, &body).await.map(|_| ()),
            Some(c) => self.store.compare_and_swap(&key, c.revision, &body).await.map(|_| ()),
        };
        match written {
            Ok(()) => Ok(record),
            Err(e) if e.is_conflict() => {
                let latest = self.store.get(&key).await.map_err(GatewayError::from)?;
                Err(CheckpointRefusal::RevisionConflict {
                    expected: expected_revision,
                    current: latest.and_then(|l| l.body["revision"].as_u64()).unwrap_or(0),
                })
            }
            Err(e) => Err(GatewayError::from(e).into()),
        }
    }

    /// The run's latest checkpoint, if any.
    pub async fn latest_checkpoint(&self, admission: &RunAdmission) -> Result<Option<Value>, GatewayError> {
        Ok(self.store.get(&key(admission)).await?.map(|c| c.body))
    }
}
