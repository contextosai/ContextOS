//! The ContextOS Tool Gateway.
//!
//! Every effect an agent requests passes one pipeline, immediately before dispatch:
//!
//! 1. **Surface** — the capability must be pinned and surfaced by this run's compiled
//!    context; cited evidence must be admitted evidence.
//! 2. **Bind** — an RFC 8785 action binding covers the complete proposal.
//! 3. **Authorize** — current authority ∧ composed policy ∧ independent constraints ∧
//!    (when required) an exactly bound, entitled approval, redeemed once by CAS.
//! 4. **Reserve** — budget is reserved in the run's conserved ledger.
//! 5. **Claim** — the operation is claimed in the operation ledger under the current
//!    executor generation; unsafe retries and in-flight duplicates are refused.
//! 6. **Dispatch** — the adapter is invoked with a deadline. A timeout is an
//!    *unknown* outcome, never a failure.
//! 7. **Observe & settle** — the outcome is recorded as a verified observation and the
//!    budget settled; unknown usage keeps its reservation.
//! 8. **Audit** — decision, claim and observation are appended to the signed chain.
//!
//! Every step fails closed. Nothing the model supplies can widen authority: the model
//! chooses a capability and arguments; manifests, admission, providers and the kernel
//! decide everything else.

pub mod admission;
pub mod manifest;
pub mod ports;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use contextos_audit::AuditWriter;
use contextos_contract::canonical::sha256_canonical;
use contextos_contract::schema::{SchemaDoc, SchemaTarget, validate};
use contextos_contract::validation::{add_contract_seconds, compare_contract_times};
use contextos_kernel::TransitionResult;
use contextos_kernel::authorization::{digest_action_binding, evaluate_authorization, transition_approval_redemption};
use contextos_kernel::budget_ledger::{reserve_budget, settle_budget, settlement_intent_digest};
use contextos_kernel::operation_ledger::{claim_operation, record_effect_observation};
use contextos_store::{AppendLog, Commit, DocKey, DocKind, DocumentStore, StoreError, transact};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

pub use admission::{AdmissionError, AdmissionRequest, BudgetLimits, RunAdmission, admit_run};
pub use manifest::{CapabilityManifest, ManifestError, RecoveryStrategy};
pub use ports::{
    Adapter, AdapterCall, AdapterResponse, ApprovalProvider, AuthorityFacts, AuthorityProvider, Clock,
    ConstraintProvider, EffectOutcome, IdSource, PolicyProvider, PortError,
};

/// How long the gateway's own observations remain valid.
pub const OBSERVATION_VALIDITY_SECONDS: u64 = 300;

/// Verified provider idempotency proof (`ProviderIdempotencyObservation`) for
/// capabilities whose recovery strategy is `idempotent_retry`.
#[async_trait::async_trait]
pub trait IdempotencyProvider: Send + Sync {
    async fn proof(
        &self,
        manifest: &CapabilityManifest,
        operation_id: &str,
        action_digest: &str,
        key: &str,
    ) -> Result<Option<Value>, PortError>;
}

/// Authorizes effects against the policy outcomes pinned at admission.
#[derive(Debug, Clone, Copy, Default)]
pub struct PinnedPolicy;

#[async_trait::async_trait]
impl PolicyProvider for PinnedPolicy {
    async fn outcomes(&self, admission: &RunAdmission, _binding: &Value) -> Result<Vec<Value>, PortError> {
        Ok(admission.policy_outcomes.clone())
    }
}

/// Deployment-supplied ports.
#[derive(Clone)]
pub struct Ports {
    pub clock: Arc<dyn Clock>,
    pub ids: Arc<dyn IdSource>,
    pub authority: Arc<dyn AuthorityProvider>,
    pub policy: Arc<dyn PolicyProvider>,
    pub constraints: Arc<dyn ConstraintProvider>,
    pub approvals: Arc<dyn ApprovalProvider>,
    pub idempotency: Option<Arc<dyn IdempotencyProvider>>,
}

impl std::fmt::Debug for Ports {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ports").finish_non_exhaustive()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum GatewayError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Audit(#[from] contextos_audit::AuditError),
    #[error(transparent)]
    Manifest(#[from] ManifestError),
}

/// Governance facts for a dispatch, alongside the tool result.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DispatchReport {
    pub status: String,
    pub action_digest: Option<String>,
    pub operation_id: Option<String>,
    pub attempt_id: Option<String>,
    pub reason_codes: Vec<String>,
    pub obligations: Vec<String>,
    pub approval_request_id: Option<String>,
    pub audit_sequences: Vec<u64>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DispatchOutcome {
    /// A `contextos.tool_result.v1` envelope.
    pub result: Value,
    pub report: DispatchReport,
}

pub struct Gateway<S, L> {
    store: Arc<S>,
    audit: Arc<AuditWriter<L>>,
    ports: Ports,
    adapters: HashMap<String, Arc<dyn Adapter>>,
    manifests: HashMap<String, CapabilityManifest>,
}

impl<S, L> std::fmt::Debug for Gateway<S, L> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Gateway")
            .field("capabilities", &self.manifests.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

struct Pipeline<'a> {
    admission: &'a RunAdmission,
    envelope: &'a Value,
    report: DispatchReport,
    started: std::time::Instant,
}

impl Pipeline<'_> {
    fn finish(
        mut self,
        status: &str,
        output: Map<String, Value>,
        error: Option<String>,
        mutations: Vec<String>,
    ) -> DispatchOutcome {
        status.clone_into(&mut self.report.status);
        let latency_ms = u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX);
        let mut metadata = Map::new();
        if let Some(digest) = &self.report.action_digest {
            metadata.insert("action_digest".into(), json!(digest));
        }
        if !self.report.reason_codes.is_empty() {
            metadata.insert("reason_codes".into(), json!(self.report.reason_codes));
        }
        if let Some(id) = &self.report.approval_request_id {
            metadata.insert("approval_request_id".into(), json!(id));
        }
        let result = json!({
            "envelope_version": "contextos.tool_result.v1",
            "tool_call_id": self.envelope["tool_call_id"],
            "run_id": self.admission.run_id,
            "trace_id": self.admission.trace_id,
            "capability_id": self.envelope["capability_id"],
            "status": status,
            "output": output,
            "error": error,
            "artifacts": [],
            "citations": [],
            "mutations": mutations,
            "risk_tags": [],
            "latency_ms": latency_ms,
            "metadata": metadata,
        });
        DispatchOutcome {
            result,
            report: self.report,
        }
    }

    fn stop(mut self, status: &str, reasons: Vec<String>, message: &str) -> DispatchOutcome {
        self.report.reason_codes.extend(reasons);
        self.finish(status, Map::new(), Some(message.to_owned()), vec![])
    }
}

/// Each operation has its own ledger document, so per-effect cost is independent of
/// how many effects the run has made and parallel operations never contend. The
/// kernel evaluates the projection holding just this operation; the cross-operation
/// checks it would otherwise perform hold by construction here: attempt ids are
/// fresh, provider idempotency keys derive from the operation id, and compensation
/// is not dispatched through this path.
pub fn operation_ledger_key(admission: &RunAdmission, operation_id: &str) -> DocKey {
    let digest = contextos_contract::canonical::sha256_text(&format!("{}\u{0}{operation_id}", admission.run_id));
    DocKey::new(
        &admission.tenant_id,
        DocKind::OperationLedger,
        format!("op_{}", &digest[7..39]),
    )
}

fn operation_ledger_template(admission: &RunAdmission, ledger_id: &str) -> Value {
    json!({
        "ledger_id": ledger_id, "contract_id": admission.contract_id, "run_id": admission.run_id,
        "tenant_id": admission.tenant_id, "revision": 0, "executor_generation": admission.executor_generation,
        "deadline": admission.deadline, "trusted_observers": [admission.gateway_observer], "operations": [],
    })
}

fn pointer_string(arguments: &Value, pointer: &str) -> Option<String> {
    arguments.pointer(pointer).and_then(Value::as_str).map(str::to_owned)
}

fn later(a: String, b: &str) -> String {
    if compare_contract_times(&a, b) == Some(std::cmp::Ordering::Less) {
        b.to_owned()
    } else {
        a
    }
}

impl<S: DocumentStore + 'static, L: AppendLog + 'static> Gateway<S, L> {
    pub fn new(store: Arc<S>, audit: Arc<AuditWriter<L>>, ports: Ports) -> Self {
        Self {
            store,
            audit,
            ports,
            adapters: HashMap::new(),
            manifests: HashMap::new(),
        }
    }

    pub fn register_adapter(&mut self, adapter_id: impl Into<String>, adapter: Arc<dyn Adapter>) {
        self.adapters.insert(adapter_id.into(), adapter);
    }

    /// Pins a reviewed capability manifest.
    pub fn pin_capability(&mut self, manifest: CapabilityManifest) -> Result<(), GatewayError> {
        manifest.validate()?;
        self.manifests.insert(manifest.capability_id.clone(), manifest);
        Ok(())
    }

    /// A pinned capability manifest.
    pub fn manifest(&self, capability_id: &str) -> Option<&CapabilityManifest> {
        self.manifests.get(capability_id)
    }

    /// The audit writer this gateway appends to.
    pub fn audit(&self) -> &Arc<AuditWriter<L>> {
        &self.audit
    }

    fn now(&self) -> String {
        self.ports.clock.now()
    }

    /// Governs one tool call end to end. Errors are infrastructure failures (store,
    /// audit); every governance outcome is a normal `DispatchOutcome`.
    pub async fn dispatch(&self, admission: &RunAdmission, envelope: &Value) -> Result<DispatchOutcome, GatewayError> {
        let mut p = Pipeline {
            admission,
            envelope,
            report: DispatchReport {
                status: String::new(),
                action_digest: None,
                operation_id: None,
                attempt_id: None,
                reason_codes: vec![],
                obligations: vec![],
                approval_request_id: None,
                audit_sequences: vec![],
            },
            started: std::time::Instant::now(),
        };

        // 1. Surface.
        if validate(
            &SchemaTarget::def(SchemaDoc::ToolEnvelope, "ToolCallEnvelope"),
            envelope,
        )
        .is_err()
            || envelope["run_id"] != admission.run_id.as_str()
            || envelope["trace_id"] != admission.trace_id.as_str()
        {
            return Ok(p.stop(
                "rejected",
                vec!["envelope_invalid".into()],
                "Tool call envelope is malformed or not bound to this run.",
            ));
        }
        let capability_id = envelope["capability_id"].as_str().unwrap_or_default();
        let Some(manifest) = self.manifests.get(capability_id) else {
            return Ok(p.stop(
                "rejected",
                vec!["capability_not_pinned".into()],
                "Capability is not pinned.",
            ));
        };
        if !admission.surfaced_capabilities.contains(capability_id) {
            return Ok(p.stop(
                "rejected",
                vec!["capability_not_surfaced".into()],
                "Capability was not surfaced for this run.",
            ));
        }
        let Some(adapter) = self.adapters.get(&manifest.adapter_id).cloned() else {
            return Ok(p.stop(
                "rejected",
                vec!["adapter_unavailable".into()],
                "No adapter is registered for this capability.",
            ));
        };
        let mut evidence_refs = Vec::new();
        for evidence_ref in envelope["evidence_refs"].as_array().into_iter().flatten() {
            match admission.evidence.get(evidence_ref.as_str().unwrap_or_default()) {
                Some(artifact) => evidence_refs.push(artifact.clone()),
                None => {
                    return Ok(p.stop(
                        "rejected",
                        vec!["evidence_not_admitted".into()],
                        "Cited evidence was not admitted for this run.",
                    ));
                }
            }
        }

        // 2. Bind.
        let arguments = envelope["args"].clone();
        let tool_call_id = envelope["tool_call_id"].as_str().unwrap_or_default().to_owned();
        let operation_id = envelope["idempotency_key"]
            .as_str()
            .map_or_else(|| tool_call_id.clone(), str::to_owned);
        p.report.operation_id = Some(operation_id.clone());
        let mut resource_ids = Vec::new();
        for pointer in &manifest.resource_pointers {
            match pointer_string(&arguments, pointer) {
                Some(id) => resource_ids.push(id),
                None => {
                    return Ok(p.stop(
                        "rejected",
                        vec!["binding_incomplete".into()],
                        "A required resource argument is missing.",
                    ));
                }
            }
        }
        let mut destination_ids = Vec::new();
        for pointer in &manifest.destination_pointers {
            match pointer_string(&arguments, pointer) {
                Some(id) => destination_ids.push(id),
                None => {
                    return Ok(p.stop(
                        "rejected",
                        vec!["binding_incomplete".into()],
                        "A required destination argument is missing.",
                    ));
                }
            }
        }
        let mut binding = json!({
            "binding_version": "contextos.action_binding.v1",
            "contract_id": admission.contract_id, "run_id": admission.run_id, "tenant_id": admission.tenant_id,
            // A retry of the same operation is the same proposal: its digest, approvals
            // and claims must match. Reusing the key with different arguments is
            // incompatible reuse and is rejected by the operation ledger.
            "operation_id": operation_id, "proposal_id": operation_id, "actor": admission.actor,
            "authority_refs": [], "purpose_id": manifest.purpose_id, "capability_id": manifest.capability_id,
            "capability_version": manifest.capability_version, "arguments": arguments,
            "resource_ids": resource_ids, "destination_ids": destination_ids, "evidence_refs": evidence_refs,
            "policy_refs": admission.policy_refs, "profile_refs": admission.profile_refs,
            "release_refs": admission.release_refs, "action_risk": manifest.action_risk,
        });
        if let Some(amount) = &manifest.amount {
            match envelope["args"]
                .pointer(&amount.minor_units_pointer)
                .and_then(Value::as_u64)
            {
                Some(minor_units) => {
                    binding["amount"] = json!({"minor_units": minor_units, "currency": amount.currency});
                }
                None => {
                    return Ok(p.stop(
                        "rejected",
                        vec!["binding_incomplete".into()],
                        "The monetary amount argument is missing or invalid.",
                    ));
                }
            }
        }

        // 3. Authorize.
        let facts = match self.ports.authority.authority(admission, &binding).await {
            Ok(facts) => facts,
            Err(e) => return Ok(p.stop("blocked", vec!["authority_unavailable".into()], &e.to_string())),
        };
        binding["authority_refs"] = Value::Array(facts.grants.iter().map(|g| g["verification_ref"].clone()).collect());
        let Ok(action_digest) = digest_action_binding(&binding) else {
            return Ok(p.stop(
                "rejected",
                vec!["binding_invalid".into()],
                "The action binding is invalid.",
            ));
        };
        p.report.action_digest = Some(action_digest.clone());
        let now = self.now();
        let policy_outcomes = match self.ports.policy.outcomes(admission, &binding).await {
            Ok(outcomes) => outcomes,
            Err(e) => return Ok(p.stop("blocked", vec!["policy_unavailable".into()], &e.to_string())),
        };
        let constraint_observations = match self
            .ports
            .constraints
            .observations(admission, &admission.required_controls, &action_digest)
            .await
        {
            Ok(observations) => observations,
            Err(e) => return Ok(p.stop("blocked", vec!["constraints_unavailable".into()], &e.to_string())),
        };
        let approval_material = match self.ports.approvals.approval(admission, &action_digest).await {
            Ok(material) => material,
            Err(e) => return Ok(p.stop("blocked", vec!["approval_unavailable".into()], &e.to_string())),
        };
        let mut approval_input = Value::Null;
        let mut redemption_key = None;
        if let Some(Value::Object(mut material)) = approval_material {
            let request_id = material
                .get("request")
                .and_then(|r| r["approval_request_id"].as_str())
                .unwrap_or_default()
                .to_owned();
            let key = DocKey::new(&admission.tenant_id, DocKind::ApprovalRedemption, &request_id);
            let state = if let Some(read) = self.store.get(&key).await? {
                read.body
            } else {
                let initial = json!({"approval_request_id": request_id, "revision": 0, "operation_id": null, "action_digest": null});
                match self.store.create(&key, &initial).await {
                    Ok(created) => created.body,
                    Err(e) if e.is_conflict() => self.store.get(&key).await?.map(|r| r.body).unwrap_or(initial),
                    Err(e) => return Err(e.into()),
                }
            };
            material.insert("binding".into(), binding.clone());
            material.insert("redemption_state".into(), state);
            material.insert("evaluation_time".into(), json!(now));
            approval_input = Value::Object(material);
            redemption_key = Some(key);
        }
        let decision_id = self.ports.ids.new_id("authz");
        let authorization = evaluate_authorization(&json!({
            "decision_id": decision_id,
            "authority": {
                "binding": binding, "authenticated": facts.authenticated, "leaf_grant_ref": facts.leaf_grant_ref,
                "grants": facts.grants, "observations": facts.observations, "run_links": facts.run_links,
                "evaluation_time": now,
            },
            "policy_outcomes": policy_outcomes,
            "approval": approval_input,
            "required_constraints": admission.required_controls,
            "constraint_observations": constraint_observations,
        }));
        let decision = serde_json::to_value(&authorization.decision).unwrap_or(Value::Null);
        let entry = self
            .audit
            .append(&admission.tenant_id, "authorization_decision", decision, &now)
            .await?;
        p.report.audit_sequences.push(entry.sequence);
        p.report.reason_codes.clone_from(&authorization.decision.reason_codes);
        match authorization.verdict.as_str() {
            "allow" => {}
            "require_approval" => {
                return Ok(
                    match self.ports.approvals.request(admission, &binding, &action_digest).await {
                        Ok(id) => {
                            p.report.approval_request_id = Some(id);
                            p.report.obligations.push("await_approval".into());
                            p.finish(
                                "paused",
                                Map::new(),
                                Some("Approval is required before this effect.".into()),
                                vec![],
                            )
                        }
                        Err(e) => p.stop("blocked", vec!["approval_unavailable".into()], &e.to_string()),
                    },
                );
            }
            "escalate" => return Ok(p.stop("blocked", vec![], "Policy requires escalation.")),
            _ => return Ok(p.stop("blocked", vec![], "Authorization denied.")),
        }
        if let Some(key) = redemption_key {
            let approval = approval_input.clone();
            let commit = transact(self.store.as_ref(), &key, |state| {
                let mut approval = approval.clone();
                approval["redemption_state"] = state.clone();
                let result = transition_approval_redemption(
                    &json!({"approval": approval, "expected_revision": state["revision"]}),
                );
                match result.status.as_str() {
                    "redeem" => TransitionResult::accepted(result.state.unwrap_or(Value::Null), vec![]),
                    "existing" => TransitionResult::accepted(state.clone(), vec![]),
                    _ => TransitionResult {
                        status: "rejected".into(),
                        state: state.clone(),
                        obligations: None,
                        reason_codes: Some(result.reason_codes),
                    },
                }
            })
            .await?;
            if let Commit::Rejected { reason_codes } = commit {
                return Ok(p.stop(
                    "blocked",
                    reason_codes,
                    "Approval could not be redeemed for this operation.",
                ));
            }
        }

        // Fast path: an operation with an attempt in flight or an applied effect cannot
        // be claimed again, so turn the duplicate away before it contends on the budget
        // ledger. The claim below remains the authoritative, atomic check.
        let operations_key = operation_ledger_key(admission, &operation_id);
        if let Some(read) = self.store.get(&operations_key).await? {
            let existing = read.body["operations"]
                .as_array()
                .into_iter()
                .flatten()
                .find(|op| op["intent"]["operation_id"] == operation_id.as_str());
            if let Some(op) = existing {
                let in_flight = op["attempts"]
                    .as_array()
                    .and_then(|a| a.last())
                    .is_some_and(|a| a["dispatch_state"] == "claimed");
                let reason = if in_flight {
                    Some("operation_in_flight")
                } else if op["intent"]["action_digest"] != action_digest.as_str() {
                    None // incompatible reuse: let the claim reject it with its exact reason
                } else if matches!(op["outcome"].as_str(), Some("confirmed" | "partial")) || op["conflict"] == true {
                    Some("retry_unsafe")
                } else {
                    None
                };
                if let Some(reason) = reason {
                    p.report.obligations.push("reconcile_existing_operation".into());
                    return Ok(p.stop(
                        "paused",
                        vec![reason.to_owned()],
                        "The operation cannot be dispatched now.",
                    ));
                }
            }
        }

        // 4. Reserve.
        let attempt_id = self.ports.ids.new_id("attempt");
        p.report.attempt_id = Some(attempt_id.clone());
        let budget_key = DocKey::new(&admission.tenant_id, DocKind::BudgetLedger, &admission.budget_ledger_id);
        let reservation_id = format!("reservation:{attempt_id}");
        let cost_unit = json!({"currency": "USD", "units_per_cent": 100});
        let reserve_request = json!({
            "ledger_id": admission.budget_ledger_id, "contract_id": admission.contract_id,
            "parent_run_id": admission.run_id, "tenant_id": admission.tenant_id,
            "mutation_id": format!("reserve:{attempt_id}"), "reservation_id": reservation_id, "scope": "run",
            "run_id": admission.run_id, "cost_unit": cost_unit, "allocation": manifest.reservation,
            "deadline": admission.deadline, "expected_revision": 0,
            "executor_generation": admission.executor_generation, "evaluation_time": now,
        });
        let commit = transact(self.store.as_ref(), &budget_key, |ledger| {
            let mut request = reserve_request.clone();
            request["expected_revision"] = ledger["revision"].clone();
            reserve_budget(ledger, &request)
        })
        .await?;
        if let Commit::Rejected { reason_codes } = commit {
            return Ok(p.stop("blocked", reason_codes, "Budget could not be reserved."));
        }

        // 5. Claim.
        let idempotency = manifest.recovery.idempotency.as_ref();
        let provider_key = idempotency.map(|_| format!("ctxos:{operation_id}"));
        let proof = match (&self.ports.idempotency, &provider_key) {
            (Some(provider), Some(key)) => match provider.proof(manifest, &operation_id, &action_digest, key).await {
                Ok(proof) => proof.unwrap_or(Value::Null),
                Err(_) => Value::Null,
            },
            _ => Value::Null,
        };
        let claim = json!({
            "contract_id": admission.contract_id, "run_id": admission.run_id, "tenant_id": admission.tenant_id,
            "operation_id": operation_id, "action_digest": action_digest, "adapter_ref": manifest.adapter_ref,
            "capability_ref": manifest.capability_ref, "desired_effect": manifest.desired_effect,
            "recovery_strategy": manifest.recovery.strategy.as_str(),
            "idempotency_key": provider_key, "idempotency_scope": idempotency.map(|i| i.scope.clone()),
            "provider_idempotency_ref": idempotency.map(|i| i.provider_contract_ref.clone()),
            "max_attempts": manifest.recovery.max_attempts, "retry_delays_seconds": manifest.recovery.retry_delays_seconds,
            "deadline": admission.deadline, "compensates_operation_id": null,
            "attempt": {"attempt_id": attempt_id, "operation_id": operation_id,
                "executor_generation": admission.executor_generation, "started_at": now,
                "dispatch_state": "claimed", "last_observation_ref": null},
            "evaluation_time": now, "provider_observation": proof,
        });
        if self.store.get(&operations_key).await?.is_none() {
            match self
                .store
                .create(
                    &operations_key,
                    &operation_ledger_template(admission, &operations_key.id),
                )
                .await
            {
                Ok(_) => {}
                Err(e) if e.is_conflict() => {}
                Err(e) => return Err(e.into()),
            }
        }
        let commit = transact(self.store.as_ref(), &operations_key, |ledger| {
            claim_operation(
                ledger,
                &claim,
                &ledger["revision"],
                &json!(admission.executor_generation),
            )
        })
        .await?;
        match commit {
            Commit::Rejected { reason_codes } => {
                self.release_reservation(admission, &budget_key, &reservation_id, &attempt_id, &now)
                    .await?;
                let status = if reason_codes
                    .iter()
                    .any(|r| matches!(r.as_str(), "retry_unsafe" | "operation_in_flight" | "retry_not_due"))
                {
                    p.report.obligations.push("reconcile_existing_operation".into());
                    "paused"
                } else {
                    "rejected"
                };
                return Ok(p.stop(status, reason_codes, "The operation cannot be dispatched now."));
            }
            Commit::Unchanged { obligations } | Commit::Written { obligations, .. } => {
                p.report.obligations.extend(obligations);
            }
        }
        let claim_entry = self
            .audit
            .append(
                &admission.tenant_id,
                "operation_claim",
                json!({"operation_id": operation_id, "attempt_id": attempt_id, "action_digest": action_digest}),
                &now,
            )
            .await?;
        p.report.audit_sequences.push(claim_entry.sequence);

        // 6. Dispatch.
        let deadline = add_contract_seconds(&now, manifest.timeout_ms.div_ceil(1000))
            .unwrap_or_else(|| admission.deadline.clone());
        let call = AdapterCall {
            tenant_id: admission.tenant_id.clone(),
            run_id: admission.run_id.clone(),
            trace_id: admission.trace_id.clone(),
            operation_id: operation_id.clone(),
            attempt_id: attempt_id.clone(),
            action_digest: action_digest.clone(),
            protocol_tool: manifest.protocol_tool.clone(),
            arguments: envelope["args"].clone(),
            idempotency_key: provider_key,
            deadline,
        };
        let response = tokio::time::timeout(
            Duration::from_millis(manifest.timeout_ms),
            adapter.invoke(manifest, &call),
        )
        .await
        .unwrap_or_else(|_| AdapterResponse::unknown());

        // 7. Observe & settle.
        let observed_at = later(self.now(), &now);
        let valid_until =
            add_contract_seconds(&observed_at, OBSERVATION_VALIDITY_SECONDS).unwrap_or_else(|| observed_at.clone());
        let observation_id = self.ports.ids.new_id("observation");
        let response_digest =
            sha256_canonical(&serde_json::to_value(&response).unwrap_or(Value::Null)).unwrap_or_default();
        let evidence_ref = json!({"artifact_type": "effect_observation", "artifact_id": observation_id, "version": "1", "sha256": response_digest});
        let observation = json!({
            "observation_id": observation_id, "contract_id": admission.contract_id, "run_id": admission.run_id,
            "tenant_id": admission.tenant_id, "operation_id": operation_id, "attempt_id": attempt_id,
            "action_digest": action_digest, "executor_generation": admission.executor_generation,
            "outcome": response.outcome.as_str(),
            "finality": if response.definitive && response.outcome != EffectOutcome::Unknown { "definitive" } else { "provisional" },
            "external_ref": response.external_ref, "evidence_ref": evidence_ref, "verification_status": "verified",
            "observer": admission.gateway_observer, "observed_at": observed_at, "valid_until": valid_until,
            "evaluation_time": observed_at,
        });
        let commit = transact(self.store.as_ref(), &operations_key, |ledger| {
            record_effect_observation(ledger, &observation, &ledger["revision"])
        })
        .await?;
        if let Commit::Written { obligations, .. } | Commit::Unchanged { obligations } = commit {
            p.report.obligations.extend(obligations);
        }
        let entry = self
            .audit
            .append(
                &admission.tenant_id,
                "effect_observation",
                observation.clone(),
                &observed_at,
            )
            .await?;
        p.report.audit_sequences.push(entry.sequence);
        let known = response.definitive && response.outcome != EffectOutcome::Unknown;
        let allocation = manifest.reservation;
        let usage = json!({
            "tokens": 0, "tool_calls": allocation.tool_calls.min(1), "replans": 0,
            "cost_units": response.cost_units.unwrap_or(allocation.cost_units).min(allocation.cost_units),
        });
        self.settle(
            admission,
            &budget_key,
            &reservation_id,
            &attempt_id,
            &observed_at,
            &valid_until,
            &evidence_ref,
            &usage,
            known,
        )
        .await?;

        // 8. Result.
        let mutations = if matches!(response.outcome, EffectOutcome::Confirmed | EffectOutcome::Partial) {
            vec![operation_id.clone()]
        } else {
            vec![]
        };
        let read_only = manifest.action_risk.effect == contextos_contract::types::ActionEffect::None;
        Ok(match (response.outcome, known) {
            (EffectOutcome::Confirmed, true) => p.finish(
                if read_only { "ok" } else { "completed" },
                response.output,
                None,
                mutations,
            ),
            (EffectOutcome::NotApplied | EffectOutcome::NotDispatched, true) => p.finish(
                "failed",
                response.output,
                Some("The provider did not apply the effect.".into()),
                vec![],
            ),
            _ => {
                p.report.obligations.push("reconcile_effect_before_retry".into());
                p.finish(
                    "paused",
                    response.output,
                    Some("The effect outcome is unresolved and must be reconciled.".into()),
                    mutations,
                )
            }
        })
    }

    async fn release_reservation(
        &self,
        admission: &RunAdmission,
        budget_key: &DocKey,
        reservation_id: &str,
        attempt_id: &str,
        now: &str,
    ) -> Result<(), GatewayError> {
        let valid_until = add_contract_seconds(now, OBSERVATION_VALIDITY_SECONDS).unwrap_or_else(|| now.to_owned());
        let evidence_ref = json!({"artifact_type": "budget_release", "artifact_id": attempt_id, "version": "1",
            "sha256": sha256_canonical(&json!({"released": attempt_id})).unwrap_or_default()});
        let zero = json!({"tokens": 0, "tool_calls": 0, "replans": 0, "cost_units": 0});
        self.settle(
            admission,
            budget_key,
            reservation_id,
            attempt_id,
            now,
            &valid_until,
            &evidence_ref,
            &zero,
            true,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn settle(
        &self,
        admission: &RunAdmission,
        budget_key: &DocKey,
        reservation_id: &str,
        attempt_id: &str,
        now: &str,
        valid_until: &str,
        evidence_ref: &Value,
        usage: &Value,
        known: bool,
    ) -> Result<(), GatewayError> {
        let mut request = json!({
            "ledger_id": admission.budget_ledger_id, "contract_id": admission.contract_id,
            "parent_run_id": admission.run_id, "tenant_id": admission.tenant_id,
            "mutation_id": format!("settle:{attempt_id}"), "reservation_id": reservation_id, "scope": "run",
            "run_id": admission.run_id, "cost_unit": {"currency": "USD", "units_per_cent": 100}, "usage": usage,
            "usage_status": if known { "known" } else { "unknown" },
            "execution_status": if known { "completed" } else { "unknown" },
            "expected_revision": 0, "executor_generation": admission.executor_generation, "evaluation_time": now,
            "usage_observation": {"intent_digest": "", "verification_status": "verified", "observer": admission.gateway_observer,
                "evidence_ref": evidence_ref, "observed_at": now, "valid_until": valid_until},
        });
        request["usage_observation"]["intent_digest"] = json!(settlement_intent_digest(&request).unwrap_or_default());
        transact(self.store.as_ref(), budget_key, |ledger| {
            let mut request = request.clone();
            request["expected_revision"] = ledger["revision"].clone();
            settle_budget(ledger, &request)
        })
        .await?;
        Ok(())
    }
}
