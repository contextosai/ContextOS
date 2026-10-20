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
        if !bound {
            return Ok(refused("memory_binding_mismatch", &now));
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
                json!({"run_id": admission.run_id, "record_id": record["record_id"], "operation": record["operation"],
                    "record_digest": record_digest, "decision": decision}),
                &now,
            )
            .await?;
        if decision.allowed {
            let id = record["record_id"].as_str().unwrap_or_default();
            let key = DocKey::new(&admission.tenant_id, DocKind::MemoryRecord, id);
            let state = json!({"record": record, "decision": decision, "record_digest": record_digest});
            match self.store.get(&key).await? {
                None => match self.store.create(&key, &state).await {
                    Ok(_) => {}
                    Err(e) if e.is_conflict() => return Ok(refused("memory_concurrent_update", &now)),
                    Err(e) => return Err(e.into()),
                },
                Some(current) => match self.store.compare_and_swap(&key, current.revision, &state).await {
                    Ok(_) => {}
                    Err(e) if e.is_conflict() => return Ok(refused("memory_concurrent_update", &now)),
                    Err(e) => return Err(e.into()),
                },
            }
        }
        Ok(decision)
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
