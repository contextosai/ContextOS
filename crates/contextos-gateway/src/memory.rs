//! Memory lifecycle governance.
//!
//! Agent memory changes (propose, promote, correct, delete) are lifecycle operations,
//! not plain writes. The run submits a `MemoryLifecycleRecord`; the deployment's
//! memory-governance service supplies the trusted context for it (allowed readers and
//! operations, which operations need review, maximum retention, trusted observers,
//! the verified access observation and the data-flow request and policy for writing
//! into memory). The caller never supplies that context.
//!
//! The record must be bound to the run (contract, run, tenant) and the context to the
//! run's tenant. The kernel's `validate_memory_lifecycle` decides, including review
//! currency and binding, retention limits, reader scope, data-flow policy and, for
//! deletion, verified propagation across derived copies. Every decision is audited;
//! only allowed records become the memory's current lifecycle state.

use contextos_contract::canonical::sha256_canonical;
use contextos_kernel::execution_boundary::{DataFlowDecision, validate_memory_lifecycle};
use contextos_store::{AppendLog, DocKey, DocKind, DocumentStore};
use serde_json::{Value, json};

use crate::{Gateway, GatewayError, PortError, RunAdmission};

/// The trusted context for one memory lifecycle record.
#[async_trait::async_trait]
pub trait MemoryPolicyProvider: Send + Sync {
    async fn memory_context(&self, admission: &RunAdmission, record: &Value) -> Result<Value, PortError>;
}

/// Fields fixed when a memory record is first created.
const IDENTITY: [&str; 4] = ["tenant_id", "owner_id", "namespace", "memory_ref"];

fn refused(reason: &str, now: &str) -> DataFlowDecision {
    DataFlowDecision {
        allowed: false,
        reason_codes: vec![reason.to_owned()],
        evaluation_time: now.to_owned(),
        policy_ref: None,
        artifact_refs: vec![],
        classification: None,
        unsatisfied_obligations: vec![],
        contract_id: None,
        run_id: None,
        operation_id: None,
        action_digest: None,
        propagation_status: None,
        completion_verified: None,
    }
}

impl<S: DocumentStore + 'static, L: AppendLog + 'static> Gateway<S, L> {
    /// Governs one memory lifecycle operation of the run.
    #[tracing::instrument(name = "contextos.memory", skip_all, fields(tenant_id = %admission.tenant_id, run_id = %admission.run_id, trace_id = %admission.trace_id))]
    pub async fn govern_memory(
        &self,
        admission: &RunAdmission,
        record: &Value,
    ) -> Result<DataFlowDecision, GatewayError> {
        let now = self.now();
        let Some(provider) = &self.ports.memory else {
            return Ok(refused("memory_policy_unavailable", &now));
        };
        let bound = record["contract_id"] == admission.contract_id.as_str()
            && record["run_id"] == admission.run_id.as_str()
            && record["tenant_id"] == admission.tenant_id.as_str();
        let Some(id) = record["record_id"].as_str().filter(|_| bound) else {
            return Ok(refused("memory_binding_mismatch", &now));
        };
        let key = DocKey::new(&admission.tenant_id, DocKind::MemoryRecord, id);
        let current = self.store.get(&key).await?;
        if let Some(current) = &current {
            // A record id names one memory: its identity is fixed at creation, deletion
            // is terminal, and a proposal only creates.
            let stored = &current.body["record"];
            if IDENTITY.iter().any(|field| stored[*field] != record[*field]) {
                return Ok(refused("memory_identity_mismatch", &now));
            }
            if stored["operation"] == "delete" {
                return Ok(refused("memory_deleted", &now));
            }
            if record["operation"] == "propose" {
                return Ok(refused("memory_exists", &now));
            }
        }
        if let Some(Err(reasons)) = self.boundary_readiness(admission, &now).await {
            let mut decision = refused("boundary_not_ready", &now);
            decision.reason_codes = reasons;
            return Ok(decision);
        }
        let Ok(context) = provider.memory_context(admission, record).await else {
            return Ok(refused("memory_policy_unavailable", &now));
        };
        if context["tenant_id"] != admission.tenant_id.as_str() {
            return Ok(refused("memory_binding_mismatch", &now));
        }
        let decision = validate_memory_lifecycle(record, &context, &json!(now));
        let record_digest = sha256_canonical(record).unwrap_or_default();
        self.audit
            .append(
                &admission.tenant_id,
                "memory_lifecycle",
                json!({"run_id": admission.run_id, "record_id": id, "operation": record["operation"],
                    "record_digest": record_digest, "decision": decision}),
                &now,
            )
            .await?;
        if !decision.allowed {
            return Ok(decision);
        }
        let state = json!({"record": record, "decision": decision, "record_digest": record_digest});
        let written = match &current {
            None => self.store.create(&key, &state).await.map(|_| ()),
            Some(current) => self
                .store
                .compare_and_swap(&key, current.revision, &state)
                .await
                .map(|_| ()),
        };
        match written {
            Ok(()) => {
                self.note_memory_key(admission, id, record).await?;
                Ok(decision)
            }
            Err(e) if e.is_conflict() => {
                // The allowed decision above was not applied; say so in the trail.
                self.audit
                    .append(
                        &admission.tenant_id,
                        "memory_lifecycle_not_applied",
                        json!({"run_id": admission.run_id, "record_id": id, "record_digest": record_digest,
                            "reason_codes": ["memory_concurrent_update"]}),
                        &now,
                    )
                    .await?;
                Ok(refused("memory_concurrent_update", &now))
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Records which memory currently holds a key (`memory_ref.artifact_id`, compared
    /// case-insensitively): a promotion or correction takes it, a deletion releases it.
    async fn note_memory_key(&self, admission: &RunAdmission, id: &str, record: &Value) -> Result<(), GatewayError> {
        let Some(memory_key) = record["memory_ref"]["artifact_id"].as_str().map(str::to_lowercase) else {
            return Ok(());
        };
        let key = memory_key_doc(&admission.tenant_id, &memory_key);
        for _ in 0..8 {
            let current = self.store.get(&key).await?;
            let holder = current
                .as_ref()
                .and_then(|c| c.body["record_id"].as_str().map(str::to_owned));
            let next = match record["operation"].as_str() {
                Some("promote" | "correct") => json!({"record_id": id, "sha256": record["memory_ref"]["sha256"]}),
                Some("delete") if holder.as_deref() == Some(id) => json!({"record_id": null}),
                _ => return Ok(()),
            };
            let written = match &current {
                None => self.store.create(&key, &next).await.map(|_| ()),
                Some(c) => self.store.compare_and_swap(&key, c.revision, &next).await.map(|_| ()),
            };
            match written {
                Ok(()) => return Ok(()),
                Err(e) if e.is_conflict() => {}
                Err(e) => return Err(e.into()),
            }
        }
        Ok(())
    }

    /// The record currently holding a memory key, if any.
    pub async fn memory_key_holder(&self, tenant_id: &str, memory_key: &str) -> Result<Option<String>, GatewayError> {
        Ok(self
            .store
            .get(&memory_key_doc(tenant_id, &memory_key.to_lowercase()))
            .await?
            .and_then(|d| d.body["record_id"].as_str().map(str::to_owned)))
    }

    /// The memory's current lifecycle state, if any allowed record exists.
    pub async fn memory_state(&self, tenant_id: &str, record_id: &str) -> Result<Option<Value>, GatewayError> {
        Ok(self
            .store
            .get(&DocKey::new(tenant_id, DocKind::MemoryRecord, record_id))
            .await?
            .map(|r| r.body))
    }
}

fn memory_key_doc(tenant_id: &str, memory_key: &str) -> DocKey {
    DocKey::new(tenant_id, DocKind::MemoryRecord, format!("key:{memory_key}"))
}
