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
mod attestation;
mod checkpoints;
mod compensation;
mod coordination;
mod decisions;
mod delegation;
mod erasure;
mod escalation;
mod findings;
mod findings_api;
mod input;
mod lifecycle;
mod loop_guard;
pub mod manifest;
mod memory;
mod ownership;
pub mod ports;
mod reconcile;
mod retired;
mod revocations;
mod scores;
mod shared_guarantees;
mod shared_inspection;
pub mod task_authorization;
mod usage;

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use contextos_audit::AuditWriter;
use contextos_contract::canonical::sha256_canonical;
use contextos_contract::schema::{SchemaDoc, SchemaTarget, validate};
use contextos_contract::types::ActionEffect;
use contextos_contract::validation::{add_contract_seconds, compare_contract_times};
use contextos_kernel::TransitionResult;
use contextos_kernel::authorization::{digest_action_binding, evaluate_authorization, transition_approval_redemption};
use contextos_kernel::budget_compaction::compact_budget_ledger;
use contextos_kernel::budget_ledger::{reserve_budget, settle_budget, settlement_intent_digest};
use contextos_kernel::execution_boundary::evaluate_data_flow;
use contextos_kernel::operation_ledger::{claim_operation, record_effect_observation};
use contextos_store::{
    AppendLog, Commit, DocKey, DocKind, DocumentStore, StoreError, transact, transact_from, transact_state,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

pub use admission::{AdmissionError, AdmissionRequest, BudgetLimits, RunAdmission, admit_run};
pub use attestation::{ATTESTATION_MARGIN_SECONDS, DISPATCH_STALL_SECONDS};
pub use checkpoints::{CheckpointRefusal, MAX_CHECKPOINT_BYTES};
pub use compensation::{COMPENSATION_OPERATION_PREFIX, MAX_COMPENSABLE_EFFECTS, compensation_operation_id};
pub use coordination::{MAX_WORK_BOARD_BYTES, MAX_WORK_TASKS, WorkCommand, WorkError, WorkEvidence, WorkTaskInput};
pub use decisions::{DecisionRefusal, DecisionReport, MAX_DECISIONS_PER_RUN, RecordedDecision, ReportedToolCall};
pub use delegation::{CloseDecision, CloseOutcome, Lineage, RunLink, delegation_reservation_id};
pub use erasure::{ErasureError, is_erased};
pub use escalation::EscalationError;
pub use findings::{
    BasisInput, FindingInput, FindingKind, MAX_FINDINGS, MAX_FINDINGS_BYTES, MAX_NOTICES, MAX_STATEMENT_BYTES,
    NOTICES_PER_RESULT,
};
pub use input::{Continuation, MAX_INPUT_RESPONSE_BYTES};
pub use lifecycle::{LifecycleOutcome, MAX_UNRESOLVED_EFFECTS};
pub use manifest::{
    CapabilityManifest, Compensation, CompletionCheck, ManifestError, RecoveryStrategy, is_path_segment,
};
pub use memory::MemoryPolicyProvider;
pub use ownership::Ownership;
pub use ports::{
    Adapter, AdapterCall, AdapterResponse, ApprovalProvider, AuthorityFacts, AuthorityProvider, Clock,
    ConstraintProvider, EffectOutcome, IdSource, PolicyProvider, PortError,
};
pub use reconcile::{ReconcileOutcome, Resolution};
pub use revocations::{MAX_REVOCATIONS, REVOCATION_KINDS, RevocationError, run_targets};
pub use scores::{MAX_SCORES_PER_DECISION, ScoreRefusal, ScoreReport};
pub use shared_guarantees::{EXPOSURE_RECEIPT_RETENTION_SECONDS, SharedGuarantee};
pub use shared_inspection::MAX_INSPECTION_SCAN;
pub use task_authorization::{Amount, Change, OutOfScope, ReadOnly, TaskAuthorization, TaskLimits};
pub use usage::{UsageKind, UsageRefusal};

/// Receipts at which the run's budget ledger is compacted before the next
/// reservation (ADR-0003). Keeps the ledger, and its per-effect validation cost, small,
/// and lifts the 128-receipt (about 64-effect) ceiling of a single ledger.
pub const BUDGET_COMPACT_AT: usize = 32;

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
    /// Data-governance facts. When present, every capability that sends data to a
    /// destination must pass the kernel's data-flow evaluation.
    pub data_flow: Option<Arc<dyn DataFlowProvider>>,
    /// Execution-boundary controller. When present, run start, resume and every
    /// dispatch require the kernel to find the run's boundary active now.
    pub boundary: Option<Arc<dyn BoundaryProvider>>,
    /// Memory-governance context for memory lifecycle operations.
    pub memory: Option<Arc<dyn MemoryPolicyProvider>>,
}

/// The run's `BoundaryRequirement` and the controller's current verified
/// `BoundaryObservation` for it.
#[async_trait::async_trait]
pub trait BoundaryProvider: Send + Sync {
    async fn boundary(&self, admission: &RunAdmission) -> Result<(Value, Value), PortError>;
}

/// The facts a data-governance service supplies for one authorized action: a
/// `DataFlowRequest` describing the data the action sends and the pinned
/// `DataFlowPolicy` that governs it. `None` means the provider knows of no data
/// leaving with this action; for a capability that sends data, that blocks.
#[async_trait::async_trait]
pub trait DataFlowProvider: Send + Sync {
    async fn data_flow(
        &self,
        admission: &RunAdmission,
        binding: &Value,
        action_digest: &str,
    ) -> Result<Option<(Value, Value)>, PortError>;
}

impl std::fmt::Debug for Ports {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ports").finish_non_exhaustive()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum GatewayError {
    #[error("shared guarantee: {0}")]
    Guarantee(String),
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
    /// Replaced versions, read only for operations claimed under them (see [`retired`]).
    retired: Vec<CapabilityManifest>,
    schemas: HashMap<String, contextos_contract::schema::ArgumentSchema>,
    output_schemas: HashMap<String, contextos_contract::schema::ArgumentSchema>,
    /// Schemas delegated runs' results must meet, by `output_schema_ref`.
    result_schemas: HashMap<String, contextos_contract::schema::ArgumentSchema>,
    /// Identical tool calls (same capability and arguments, new operation) a run may
    /// make before the loop guard refuses the next; `None` disables it.
    loop_limit: Option<u64>,
    /// Refuse a new operation whose effect is identical to one the run already applied
    /// (see [`loop_guard`]); capabilities marked `repeatable` are exempt.
    refuse_repeated_effects: bool,
    /// Tokens every model-call reservation covers at least.
    model_call_floor: u64,
    /// Scores every effectful decision needs from an independent evaluator before the
    /// run may complete (`policy`, `safety` floors); `None` requires none.
    completion_floor: Option<(f64, f64)>,
    /// Refuse delegations that name no registered result schema, even before any is
    /// registered (production).
    require_result_schemas: bool,
    shared_guarantees: Vec<SharedGuarantee>,
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
    /// The action's risk (from its manifest) and whether a human approved it.
    risk_tags: Vec<String>,
    /// The authorization decision the result rests on.
    policy_decision_id: Option<String>,
    /// The escalation opened for a call policy escalated.
    escalation_id: Option<String>,
    /// The operation this call compensates.
    compensates: Option<String>,
}

impl<'a> Pipeline<'a> {
    fn new(admission: &'a RunAdmission, envelope: &'a Value) -> Self {
        Pipeline {
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
            risk_tags: Vec::new(),
            policy_decision_id: None,
            escalation_id: None,
            compensates: None,
        }
    }

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
        if let Some(id) = &self.escalation_id {
            metadata.insert("escalation_id".into(), json!(id));
        }
        if let Some(id) = &self.compensates {
            metadata.insert("compensates_operation_id".into(), json!(id));
        }
        // Tool output is evidence, never instructions: it cannot grant authority.
        metadata.insert("instruction_treatment".into(), json!("data_only"));
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
            "risk_tags": self.risk_tags,
            "policy_decision_id": self.policy_decision_id,
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

/// The provider idempotency key for a new operation. Operation ids are unique only
/// within a run, so the key is a domain-separated digest of tenant, run and operation:
/// distinct operations stay independent in a provider namespace shared across runs and
/// tenants, and the key exposes none of those identifiers. The `v1` label versions the
/// derivation; retries reuse the key persisted with the operation instead.
pub fn provider_idempotency_key(tenant_id: &str, run_id: &str, operation_id: &str) -> String {
    use contextos_contract::canonical::{quote, sha256_text};
    // JSON strings are self-delimiting, so no identifier can shift a field boundary.
    let digest = sha256_text(&format!(
        "[\"contextos.provider-key.v1\",{},{},{}]",
        quote(tenant_id),
        quote(run_id),
        quote(operation_id)
    ));
    format!("ctxos:v1:{}", &digest[7..])
}

/// Each operation has its own ledger document, so per-effect cost is independent of
/// how many effects the run has made and parallel operations never contend. The
/// kernel evaluates the projection holding just this operation; the cross-operation
/// checks it would otherwise perform hold by construction here: attempt ids are
/// fresh, provider idempotency keys derive from the run-scoped operation identity, and a
/// compensation's claim is evaluated with its original operation alongside (see
/// [`compensation`]).
pub fn operation_ledger_key(admission: &RunAdmission, operation_id: &str) -> DocKey {
    run_operation_key(&admission.tenant_id, &admission.run_id, operation_id)
}

fn run_operation_key(tenant_id: &str, run_id: &str, operation_id: &str) -> DocKey {
    let digest = contextos_contract::canonical::sha256_text(&format!("{run_id}\u{0}{operation_id}"));
    DocKey::new(tenant_id, DocKind::OperationLedger, format!("op_{}", &digest[7..39]))
}

/// An attempt's dispatch gate, created once: `started` by the dispatch before the
/// provider is called (for a shared guarantee, before its receipt is marked started),
/// or `aborted` by a reconciliation recording that an
/// attempt claimed without any fact was never sent. Of a stranded dispatch resuming
/// and an operator resolving it, exactly one creates the gate, so the attempt is either
/// sent or provably not sent.
pub fn dispatch_gate_key(admission: &RunAdmission, attempt_id: &str) -> DocKey {
    let digest = contextos_contract::canonical::sha256_text(&format!("{}\u{0}{attempt_id}", admission.run_id));
    DocKey::new(
        &admission.tenant_id,
        DocKind::DispatchGate,
        format!("gate_{}", &digest[7..39]),
    )
}

/// The budget reservation of one attempt of an operation. It names the operation, so
/// a retry can find a reservation that a crash left without its claim.
pub(crate) fn attempt_reservation_id(admission: &RunAdmission, operation_id: &str, attempt_id: &str) -> String {
    format!("{}{attempt_id}", reservation_prefix(admission, operation_id))
}

fn reservation_prefix(admission: &RunAdmission, operation_id: &str) -> String {
    let digest = contextos_contract::canonical::sha256_text(&format!("{}\u{0}{operation_id}", admission.run_id));
    format!("reservation:{}:", &digest[7..23])
}

/// Whether `id` is the reservation of this attempt, including the form used before
/// reservation ids named their operation (`reservation:<attempt_id>`).
pub(crate) fn is_attempt_reservation(id: &str, admission: &RunAdmission, operation_id: &str, attempt_id: &str) -> bool {
    id == attempt_reservation_id(admission, operation_id, attempt_id) || id == format!("reservation:{attempt_id}")
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
            retired: Vec::new(),
            schemas: HashMap::new(),
            output_schemas: HashMap::new(),
            result_schemas: HashMap::new(),
            loop_limit: None,
            refuse_repeated_effects: false,
            model_call_floor: 0,
            completion_floor: None,
            require_result_schemas: false,
            shared_guarantees: Vec::new(),
        }
    }

    /// Enables the loop guard: after `limit` identical tool calls in a run, the next is
    /// refused with `loop_detected` (see [`loop_guard`]).
    pub fn set_loop_limit(&mut self, limit: Option<u64>) {
        self.loop_limit = limit;
    }

    /// Refuses a new operation (a new operation key) whose effect is identical to one
    /// the run already applied or may have applied: same capability and canonical
    /// arguments, `effect_repeated`. Capabilities whose manifest is `repeatable` are
    /// exempt (see [`loop_guard`]).
    pub fn set_refuse_repeated_effects(&mut self, refuse: bool) {
        self.refuse_repeated_effects = refuse;
    }

    /// Sets the tokens every model-call reservation covers at least (see
    /// [`Gateway::reserve_usage`]).
    pub fn set_model_call_floor(&mut self, tokens: u64) {
        self.model_call_floor = tokens;
    }

    /// Requires every decision that applied an effect to hold an independent score with
    /// `policy` and `safety` at or above these floors before the run completes.
    pub fn set_completion_floor(&mut self, floor: Option<(f64, f64)>) {
        self.completion_floor = floor;
    }

    /// Requires every delegation to name a registered result schema.
    pub fn require_result_schemas(&mut self, required: bool) {
        self.require_result_schemas = required;
    }

    pub fn register_adapter(&mut self, adapter_id: impl Into<String>, adapter: Arc<dyn Adapter>) {
        self.adapters.insert(adapter_id.into(), adapter);
    }

    /// Registers the schema a delegation's `output_schema_ref` names: an accepted child's
    /// recorded decision outputs must conform to it.
    pub fn register_result_schema(&mut self, schema_ref: &str, schema: &Value) -> Result<(), String> {
        let compiled = contextos_contract::schema::ArgumentSchema::compile(schema)?;
        self.result_schemas.insert(schema_ref.to_owned(), compiled);
        Ok(())
    }

    /// Pins a reviewed capability manifest.
    pub fn pin_capability(&mut self, manifest: CapabilityManifest) -> Result<(), GatewayError> {
        manifest.validate()?;
        if let Some(schema) = &manifest.input_schema {
            let compiled = contextos_contract::schema::ArgumentSchema::compile(schema)
                .map_err(|e| ManifestError::InputSchema(manifest.capability_id.clone(), e))?;
            self.schemas.insert(manifest.capability_id.clone(), compiled);
        }
        if let Some(schema) = &manifest.output_schema {
            let compiled = contextos_contract::schema::ArgumentSchema::compile(schema)
                .map_err(|e| ManifestError::OutputSchema(manifest.capability_id.clone(), e))?;
            self.output_schemas.insert(manifest.capability_id.clone(), compiled);
        }
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

    /// True when a memory-governance service decides memory lifecycle operations.
    pub fn governs_memory(&self) -> bool {
        self.ports.memory.is_some()
    }

    /// The current time by the gateway's clock port.
    pub fn now(&self) -> String {
        self.ports.clock.now()
    }

    /// A fresh unique id by the gateway's id port.
    pub fn new_id(&self, prefix: &str) -> String {
        self.ports.ids.new_id(prefix)
    }

    /// Governs one tool call end to end. Errors are infrastructure failures (store,
    /// audit); every governance outcome is a normal `DispatchOutcome`.
    #[tracing::instrument(
        name = "contextos.dispatch",
        skip_all,
        fields(
            tenant_id = %admission.tenant_id,
            run_id = %admission.run_id,
            trace_id = %admission.trace_id,
            capability_id = envelope["capability_id"].as_str().unwrap_or_default(),
            tool_call_id = envelope["tool_call_id"].as_str().unwrap_or_default(),
            operation_id = tracing::field::Empty,
            action_digest = tracing::field::Empty,
            status = tracing::field::Empty,
            reason_codes = tracing::field::Empty,
        )
    )]
    pub async fn dispatch(&self, admission: &RunAdmission, envelope: &Value) -> Result<DispatchOutcome, GatewayError> {
        let outcome = self.dispatch_inner(admission, envelope, None, None, None).await;
        let span = tracing::Span::current();
        match &outcome {
            Ok(outcome) => {
                let report = &outcome.report;
                if let Some(id) = &report.operation_id {
                    span.record("operation_id", id.as_str());
                }
                if let Some(digest) = &report.action_digest {
                    span.record("action_digest", digest.as_str());
                }
                span.record("status", report.status.as_str());
                span.record("reason_codes", report.reason_codes.join(",").as_str());
                tracing::info!(status = %report.status, "governed dispatch");
            }
            Err(error) => tracing::error!(%error, "governed dispatch failed"),
        }
        outcome
    }

    /// [`Gateway::dispatch`] for an executor fenced at `executor_generation` (see
    /// [`Gateway::open_run`]): refused with `executor_stale` once another executor has
    /// taken the run over.
    pub async fn dispatch_as(
        &self,
        admission: &RunAdmission,
        envelope: &Value,
        executor_generation: u64,
    ) -> Result<DispatchOutcome, GatewayError> {
        self.dispatch_inner(admission, envelope, None, Some(executor_generation), None)
            .await
    }

    /// Continues an operation whose tool asked for input (`input_required`). The tool
    /// call must be the same operation with the same action digest; it is governed
    /// again end to end, and the answers are validated against the pending requests.
    #[tracing::instrument(
        name = "contextos.continue",
        skip_all,
        fields(run_id = %admission.run_id, operation_id = %continuation.operation_id, status = tracing::field::Empty)
    )]
    pub async fn continue_with_input(
        &self,
        admission: &RunAdmission,
        envelope: &Value,
        continuation: &Continuation,
    ) -> Result<DispatchOutcome, GatewayError> {
        let outcome = self
            .dispatch_inner(
                admission,
                envelope,
                Some(continuation),
                continuation.executor_generation,
                None,
            )
            .await;
        if let Ok(outcome) = &outcome {
            tracing::Span::current().record("status", outcome.report.status.as_str());
        }
        outcome
    }

    async fn dispatch_inner(
        &self,
        admission: &RunAdmission,
        envelope: &Value,
        continuation: Option<&Continuation>,
        fence: Option<u64>,
        compensates: Option<&Value>,
    ) -> Result<DispatchOutcome, GatewayError> {
        let mut p = Pipeline::new(admission, envelope);
        let compensates_id = compensates.map(|op| op["intent"]["operation_id"].clone());
        p.compensates = compensates_id.as_ref().and_then(Value::as_str).map(str::to_owned);

        // 0. Fence: only the run's current executor may start work.
        // One read of the run state serves ownership, status and the unresolved count.
        let run_state = self.run_state(admission).await?;
        if let Some(generation) = fence
            && let Ownership::Refused(reason) = ownership::ownership_in(run_state.as_ref(), generation)
        {
            return Ok(p.stop("rejected", vec![reason.into()], "The executor does not own this run."));
        }
        if run_state.as_ref().is_some_and(|s| s["status"] != "running") {
            return Ok(p.stop("rejected", vec!["run_not_running".into()], "The run is not running."));
        }
        let unresolved = run_state
            .as_ref()
            .and_then(|s| s["outstanding_effects"].as_array().map(Vec::len))
            .unwrap_or(0);

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
        let risk = serde_json::to_value(&manifest.action_risk).unwrap_or(Value::Null);
        p.risk_tags = ["effect", "reversibility"]
            .iter()
            .filter_map(|k| risk[*k].as_str().map(str::to_owned))
            .collect();
        if !admission.surfaced_capabilities.contains(capability_id) {
            return Ok(p.stop(
                "rejected",
                vec!["capability_not_surfaced".into()],
                "Capability was not surfaced for this run.",
            ));
        }
        // The envelope's claims must agree with what the runtime knows. Neither decides
        // anything (authority comes from the admitted actor, approval from policy), but a
        // call that misstates who acts or the capability's ceiling is refused, not
        // carried into records.
        let acting = envelope["principal_chain"].as_array().and_then(|c| c.last());
        if !acting.is_some_and(|a| a["kind"] == "agent" && a["id"] == admission.actor["principal_id"]) {
            return Ok(p.stop(
                "rejected",
                vec!["principal_chain_mismatch".into()],
                "The principal chain does not end with the run's agent.",
            ));
        }
        let mode =
            |key: &str| serde_json::from_value::<contextos_contract::types::ApprovalMode>(envelope[key].clone()).ok();
        let (highest, effective) = (mode("approval_mode_highest"), mode("approval_mode_effective"));
        if highest != Some(manifest.approval_mode) || effective.is_none_or(|e| Some(e) > highest) {
            return Ok(p.stop(
                "rejected",
                vec!["approval_mode_mismatch".into()],
                "The call misstates the capability's approval mode.",
            ));
        }
        let Some(adapter) = self.adapters.get(&manifest.adapter_id).cloned() else {
            return Ok(p.stop(
                "rejected",
                vec!["adapter_unavailable".into()],
                "No adapter is registered for this capability.",
            ));
        };
        if let Some(schema) = self.schemas.get(capability_id)
            && let Err(paths) = schema.check(&envelope["args"])
        {
            p.report.obligations.push(format!("fix_arguments:{}", paths.join(",")));
            return Ok(p.stop(
                "rejected",
                vec!["arguments_invalid".into()],
                "The arguments do not match the capability's input schema.",
            ));
        }
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
        // Compensations are requested by naming the effect, never by a tool call.
        if compensates.is_none() && operation_id.starts_with(COMPENSATION_OPERATION_PREFIX) {
            return Ok(p.stop(
                "rejected",
                vec!["operation_id_reserved".into()],
                "Operation ids beginning with compensation: are reserved.",
            ));
        }
        let pending_key = {
            let key = operation_ledger_key(admission, &operation_id);
            DocKey::new(&admission.tenant_id, DocKind::PendingInput, key.id)
        };
        let mut adapter_input = None;
        if let Some(continuation) = continuation {
            if continuation.operation_id != operation_id {
                return Ok(p.stop(
                    "rejected",
                    vec!["operation_binding_mismatch".into()],
                    "The tool call is not the operation awaiting input.",
                ));
            }
            let pending = self.store.get(&pending_key).await?.map(|r| r.body);
            let latest = self
                .store
                .get(&operation_ledger_key(admission, &operation_id))
                .await?
                .and_then(|r| {
                    r.body["operations"][0]["attempts"].as_array()?.last()?["attempt_id"]
                        .as_str()
                        .map(str::to_owned)
                });
            match input::validate_continuation(pending.as_ref(), latest.as_deref(), continuation) {
                Ok((input, digest)) => adapter_input = Some((input, digest)),
                Err(reason) => {
                    return Ok(p.stop(
                        "rejected",
                        vec![reason.into()],
                        "The input does not answer the pending request.",
                    ));
                }
            }
        }
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
        if compensates.is_none() && !compensation::plannable(manifest, &arguments) {
            return Ok(p.stop(
                "rejected",
                vec!["compensation_binding_incomplete".into()],
                "An argument the capability's compensation needs is missing.",
            ));
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
            "policy_refs": admission.binding_policy_refs(), "profile_refs": admission.profile_refs,
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
        // Policy, constraint and approval facts are independent of each other (and of
        // the operation ledger read used by the duplicate fast path): fetch them at once.
        let operations_key = operation_ledger_key(admission, &operation_id);
        let revocations_key = revocations::revocations_key(&admission.tenant_id);
        let call_signature = loop_guard::signature(&manifest.capability_id, &binding["arguments"]);
        let loop_key = loop_guard::key(admission);
        let (policy_outcomes, constraint_observations, approval_material, existing_ledger, boundary, revoked, loops) = tokio::join!(
            self.ports.policy.outcomes(admission, &binding),
            self.ports
                .constraints
                .observations(admission, &admission.required_controls, &action_digest),
            self.ports.approvals.approval(admission, &action_digest),
            self.store.get(&operations_key),
            self.boundary_readiness(admission, &now),
            self.store.get(&revocations_key),
            async {
                if self.loop_limit.is_some() || self.refuse_repeated_effects {
                    self.store.get(&loop_key).await
                } else {
                    Ok(None)
                }
            },
        );
        // Kill switch: a revoked tenant, pack, agent, adapter or capability stops here,
        // before anything is reserved or claimed.
        let revoked = revoked?;
        let mut targets = revocations::run_targets(admission).to_vec();
        targets.extend([
            ("adapter", manifest.adapter_id.as_str()),
            ("capability", manifest.capability_id.as_str()),
        ]);
        if let Some(reason) = revocations::matching(revoked.as_ref().map(|r| &r.body), &targets) {
            let entry = self
                .audit
                .append(
                    &admission.tenant_id,
                    "revocation_refusal",
                    json!({"run_id": admission.run_id, "operation_id": operation_id, "reason_codes": [reason]}),
                    &now,
                )
                .await?;
            p.report.audit_sequences.push(entry.sequence);
            return Ok(p.stop("blocked", vec![reason], "This action has been revoked by an operator."));
        }
        if let Some(Err(reasons)) = boundary {
            let entry = self
                .audit
                .append(
                    &admission.tenant_id,
                    "boundary_refusal",
                    json!({"run_id": admission.run_id,
                    "operation_id": operation_id, "reason_codes": reasons}),
                    &now,
                )
                .await?;
            p.report.audit_sequences.push(entry.sequence);
            return Ok(p.stop("blocked", reasons, "The run's execution boundary is not active."));
        }
        let existing_ledger = existing_ledger?;
        // Loop guard: a new operation repeating an identical call too often is refused
        // with a structured reason for the planner (a retry of an operation is not new).
        let loops = loops?;
        let loop_state = loops.as_ref().map(|l| &l.body);
        if let Some(limit) = self.loop_limit
            && existing_ledger.is_none()
            && (loop_guard::count(loop_state, &call_signature) >= limit
                || loop_guard::saturated(loop_state, &call_signature))
        {
            let reason = if loop_guard::saturated(loop_state, &call_signature) {
                "loop_guard_saturated"
            } else {
                "loop_detected"
            };
            let entry = self
                .audit
                .append(
                    &admission.tenant_id,
                    reason,
                    json!({"run_id": admission.run_id, "operation_id": operation_id,
                        "capability_id": manifest.capability_id, "call_signature": call_signature, "limit": limit}),
                    &now,
                )
                .await?;
            p.report.audit_sequences.push(entry.sequence);
            p.report.obligations.push("change_approach".into());
            return Ok(p.stop(
                "blocked",
                vec![reason.into()],
                "This call repeats too often, or the run has made too many kinds of call.",
            ));
        }
        // Repeated effect: the same effect under another operation key (a host retrying
        // with a fresh key, or one effect sent through two routes) is not applied twice.
        let guards_effect =
            self.refuse_repeated_effects && manifest.action_risk.effect != ActionEffect::None && !manifest.repeatable;
        if guards_effect && existing_ledger.is_none() {
            let applied = loop_guard::applied_effect(loop_state, &call_signature);
            if applied.is_some() || loop_guard::effects_saturated(loop_state, &call_signature) {
                let reason = if applied.is_some() {
                    "effect_repeated"
                } else {
                    "effect_guard_saturated"
                };
                let entry = self
                    .audit
                    .append(
                        &admission.tenant_id,
                        "repeated_effect_refusal",
                        json!({"run_id": admission.run_id, "operation_id": operation_id,
                            "capability_id": manifest.capability_id, "call_signature": call_signature,
                            "applied_operation_id": applied, "reason_codes": [reason]}),
                        &now,
                    )
                    .await?;
                p.report.audit_sequences.push(entry.sequence);
                p.report.obligations.push("reconcile_existing_operation".into());
                return Ok(p.stop(
                    "blocked",
                    vec![reason.into()],
                    &applied.map_or_else(
                        || "The run has recorded too many distinct effects to guard another.".to_owned(),
                        |op| format!("An identical effect was already requested in this run as operation {op}."),
                    ),
                ));
            }
        }
        let new_operation = existing_ledger.is_none();
        let mut policy_outcomes = match policy_outcomes {
            Ok(outcomes) => outcomes,
            Err(e) => return Ok(p.stop("blocked", vec!["policy_unavailable".into()], &e.to_string())),
        };
        // What the principal authorized, checked on the actual binding: an action
        // outside it is denied or needs an exact approval, whatever the request stated.
        // A task's limits are read here to refuse the sequential case early; the charge
        // before dispatch is authoritative.
        let mut outside_task = Vec::new();
        let amount = binding.get("amount").cloned();
        let mut task_limits = Vec::new();
        for (index, task) in admission.task_authorizations.iter().enumerate() {
            let mut exceeds = false;
            if let Some(limits) = &task.limits
                && manifest.action_risk.effect != ActionEffect::None
            {
                let key =
                    task_authorization::exposure_key(&admission.tenant_id, admission.task_authorization_origin(index));
                let used = self.store.get(&key).await?;
                exceeds = limits.exceeded_by(used.as_ref().map(|u| &u.body), &operation_id, amount.as_ref());
                // Past a limit, only an approval of this exact action (`ask`) may exceed it.
                task_limits.push((key, limits, exceeds));
            }
            let checked = task.check(&admission.run_id, &binding, manifest.action_risk.effect, exceeds);
            policy_outcomes.push(checked.outcome);
            for code in checked.reason_codes {
                if !outside_task.contains(&code) {
                    outside_task.push(code);
                }
            }
        }
        let constraint_observations = match constraint_observations {
            Ok(observations) => observations,
            Err(e) => return Ok(p.stop("blocked", vec!["constraints_unavailable".into()], &e.to_string())),
        };
        let approval_material = match approval_material {
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
        p.policy_decision_id = Some(decision_id.clone());
        // For delegated runs the gateway, which created the lineage, attests the run
        // links up to the root; links the broker supplied take precedence.
        let mut run_links = facts.run_links.clone();
        run_links.extend(delegation::attested_links(admission, &now, &facts.run_links));
        let authorization = evaluate_authorization(&json!({
            "decision_id": decision_id,
            "authority": {
                "binding": binding, "authenticated": facts.authenticated, "leaf_grant_ref": facts.leaf_grant_ref,
                "grants": facts.grants, "observations": facts.observations,
                "run_links": run_links,
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
        p.report.reason_codes.extend(outside_task);
        // Policy obligations go back to the orchestrator whatever the verdict; they are
        // discharged independently of it.
        p.report
            .obligations
            .extend(authorization.decision.obligations.iter().cloned());
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
            "escalate" => {
                // A structured hand-off, not a bare stop: the orchestrator routes the run
                // to a human with the audited decision.
                if !p.report.obligations.iter().any(|o| o == "escalate") {
                    p.report.obligations.push("escalate".into());
                }
                let facts = json!({"operation_id": operation_id, "capability_id": manifest.capability_id,
                    "action_digest": action_digest, "policy_decision_id": decision_id,
                    "reason_codes": authorization.decision.reason_codes});
                p.escalation_id = Some(self.open_escalation(admission, facts).await?);
                return Ok(p.stop(
                    "blocked",
                    vec!["policy_escalation".into()],
                    "Policy requires escalation to a human.",
                ));
            }
            _ => return Ok(p.stop("blocked", vec![], "Authorization denied.")),
        }
        // Data permissions are part of the conjunction: with a data-governance
        // provider, data sent to a destination must pass the kernel's flow policy.
        if let Some(provider) = &self.ports.data_flow
            && (manifest.sends_data || !manifest.destination_pointers.is_empty())
        {
            let refused = |p: Pipeline<'_>, reasons: Vec<String>| {
                Ok(p.stop("blocked", reasons, "The data this action sends is not permitted."))
            };
            let facts = match provider.data_flow(admission, &binding, &action_digest).await {
                Ok(Some(facts)) => facts,
                Ok(None) => return refused(p, vec!["data_flow_unknown".into()]),
                Err(_) => return refused(p, vec!["data_flow_unavailable".into()]),
            };
            let (request, policy) = facts;
            // The flow is judged for the recipient the arguments name; a capability with
            // a fixed recipient names it by its adapter. One request covers one
            // recipient, so a call naming several distinct recipients is refused.
            let mut recipients: Vec<&str> = binding["destination_ids"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .collect();
            recipients.sort_unstable();
            recipients.dedup();
            let recipient = match recipients.as_slice() {
                [] => manifest.adapter_id.as_str(),
                [one] => one,
                _ => return refused(p, vec!["data_flow_multiple_destinations".into()]),
            };
            // The provider supplies facts; it cannot redirect them to another action.
            let bound = request["contract_id"] == admission.contract_id.as_str()
                && request["run_id"] == admission.run_id.as_str()
                && request["tenant_id"] == admission.tenant_id.as_str()
                && request["operation_id"] == operation_id.as_str()
                && request["action_digest"] == action_digest.as_str()
                && request["purpose_id"] == manifest.purpose_id.as_str()
                && request["destination_id"] == recipient;
            if !bound {
                return refused(p, vec!["data_flow_binding_mismatch".into()]);
            }
            let flow = evaluate_data_flow(&request, &policy, &json!(now));
            let entry = self
                .audit
                .append(
                    &admission.tenant_id,
                    "data_flow_decision",
                    serde_json::to_value(&flow).unwrap_or(Value::Null),
                    &now,
                )
                .await?;
            p.report.audit_sequences.push(entry.sequence);
            if !flow.allowed {
                p.report.obligations.extend(flow.unsatisfied_obligations.clone());
                return refused(p, flow.reason_codes);
            }
        }
        let approved = redemption_key.is_some();
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
            p.risk_tags.push("human_approved".into());
        }

        // Fast path: an operation with an attempt in flight or an applied effect cannot
        // be claimed again, so turn the duplicate away before it contends on the budget
        // ledger. The claim below remains the authoritative, atomic check.
        // Remote stores seed the claim from this read instead of reading again.
        let seed_transitions = !self.store.reads_are_cheap();
        let ledger_exists = existing_ledger.is_some();
        // A retry recovers the provider key persisted with its operation unchanged, so a
        // derivation change can never mint a second key for an unresolved operation.
        let mut persisted_key = None;
        let mut claim_seed = existing_ledger
            .as_ref()
            .filter(|_| seed_transitions)
            .map(|r| (r.revision, r.body.clone()));
        if let Some(read) = existing_ledger {
            let existing = read.body["operations"]
                .as_array()
                .into_iter()
                .flatten()
                .find(|op| op["intent"]["operation_id"] == operation_id.as_str());
            if let Some(op) = existing {
                persisted_key = op["intent"]["idempotency_key"].as_str().map(str::to_owned);
                // A process that crashed after recording the attempt's outcome left what
                // it held unsettled: settle it before deciding about this retry.
                if let Some(sequence) = self.complete_recorded(admission, &operation_id, op).await? {
                    p.report.audit_sequences.push(sequence);
                }
                if op["outcome"] != "unknown" && self.has_shared_guarantee(&manifest.capability_id) {
                    p.report
                        .audit_sequences
                        .extend(self.settle_shared_exposure(admission, &operation_id).await?);
                }
                if op["outcome"] == "unknown" && self.has_shared_guarantee(&manifest.capability_id) {
                    p.report.obligations.push("reconcile_existing_operation".into());
                    return Ok(p.stop(
                        "paused",
                        vec!["shared_guarantee_unresolved".into()],
                        "Reconcile the shared exposure before retrying this operation.",
                    ));
                }
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

        if unresolved >= MAX_UNRESOLVED_EFFECTS {
            p.report.obligations.push("reconcile_effect_before_retry".into());
            return Ok(p.stop(
                "paused",
                vec!["too_many_unresolved_effects".into()],
                "Too many effects of this run are unresolved; reconcile them first.",
            ));
        }

        // 4. Reserve.
        let attempt_id = self.ports.ids.new_id("attempt");
        p.report.attempt_id = Some(attempt_id.clone());
        let budget_key = DocKey::new(&admission.tenant_id, DocKind::BudgetLedger, &admission.budget_ledger_id);
        let reservation_id = attempt_reservation_id(admission, &operation_id, &attempt_id);
        let cost_unit = json!({"currency": "USD", "units_per_cent": 100});
        let reserve_request = json!({
            "ledger_id": admission.budget_ledger_id, "contract_id": admission.contract_id,
            "parent_run_id": admission.run_id, "tenant_id": admission.tenant_id,
            "mutation_id": format!("reserve:{attempt_id}"), "reservation_id": reservation_id, "scope": "run",
            "run_id": admission.run_id, "cost_unit": cost_unit, "allocation": manifest.reservation,
            "deadline": admission.deadline, "expected_revision": 0,
            "executor_generation": admission.executor_generation, "evaluation_time": now,
        });
        let prefix = reservation_prefix(admission, &operation_id);
        let mut unclaimed: Vec<String> = Vec::new();
        let (commit, reserved) = transact_state(
            self.store.as_ref(),
            &budget_key,
            |ledger| {
                // Open reservations of this operation have no live claim yet: a crash
                // may have left them behind (reclaimed once this attempt is claimed).
                unclaimed = ledger["reservations"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter(|r| r["status"] != "settled")
                    .filter_map(|r| r["reservation_id"].as_str())
                    .filter_map(|id| id.strip_prefix(prefix.as_str()).map(str::to_owned))
                    .collect();
                let mut request = reserve_request.clone();
                request["expected_revision"] = ledger["revision"].clone();
                reserve_budget(ledger, &request)
            },
            |ledger| seed_transitions || ledger["mutations"].as_array().map_or(0, Vec::len) >= BUDGET_COMPACT_AT,
        )
        .await?;
        if let Commit::Rejected { reason_codes } = commit {
            return Ok(p.stop("blocked", reason_codes, "Budget could not be reserved."));
        }
        // What compensating this effect will need is recorded before it can be sent.
        let recorded = if compensates.is_none() {
            self.record_compensation(admission, manifest, &operation_id, &action_digest, &arguments)
                .await
        } else {
            Ok(Ok(()))
        };
        let recorded = match recorded {
            Ok(recorded) => recorded,
            Err(error) => {
                self.release_reservation(admission, &budget_key, &reservation_id, &attempt_id, &now)
                    .await?;
                return Err(error);
            }
        };
        if let Err(reason) = recorded {
            self.release_reservation(admission, &budget_key, &reservation_id, &attempt_id, &now)
                .await?;
            return Ok(p.stop(
                "rejected",
                vec![reason.into()],
                "The effect could not be made compensable as its capability declares.",
            ));
        }
        // Compact from the state just written instead of reading it back; otherwise the
        // state seeds the settlement.
        let mut settle_seed = None;
        if let Some((revision, ledger)) = reserved {
            if ledger["mutations"].as_array().map_or(0, Vec::len) >= BUDGET_COMPACT_AT {
                self.compact_budget_if_due(admission, &budget_key, revision, &ledger, &now)
                    .await?;
            } else if seed_transitions {
                settle_seed = Some((revision, ledger));
            }
        }

        // 5. Claim.
        let idempotency = manifest.recovery.idempotency.as_ref();
        let provider_key = idempotency.map(|_| {
            persisted_key
                .unwrap_or_else(|| provider_idempotency_key(&admission.tenant_id, &admission.run_id, &operation_id))
        });
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
            "deadline": admission.deadline, "compensates_operation_id": compensates_id,
            "attempt": {"attempt_id": attempt_id, "operation_id": operation_id,
                "executor_generation": admission.executor_generation, "started_at": now,
                "dispatch_state": "claimed", "last_observation_ref": null},
            "evaluation_time": now, "provider_observation": proof,
        });
        if !ledger_exists {
            match self
                .store
                .create(
                    &operations_key,
                    &operation_ledger_template(admission, &operations_key.id),
                )
                .await
            {
                Ok(created) if seed_transitions => claim_seed = Some((created.revision, created.body)),
                Ok(_) => {}
                Err(e) if e.is_conflict() => {}
                Err(e) => return Err(e.into()),
            }
        }
        let original = match compensates {
            Some(original) => Some(self.current_original(admission, original).await?),
            None => None,
        };
        let (commit, claimed) = transact_from(
            self.store.as_ref(),
            &operations_key,
            claim_seed,
            |ledger| {
                if self.has_shared_guarantee(&manifest.capability_id)
                    && ledger["operations"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .any(|op| op["intent"]["operation_id"] == operation_id && op["outcome"] == "unknown")
                {
                    return TransitionResult::rejected(ledger.clone(), "shared_guarantee_unresolved");
                }
                match &original {
                    Some(original) => compensation::claim_with_original(ledger, &claim, original, admission),
                    None => claim_operation(
                        ledger,
                        &claim,
                        &ledger["revision"],
                        &json!(admission.executor_generation),
                    ),
                }
            },
            |_| seed_transitions,
        )
        .await?;
        match commit {
            Commit::Rejected { reason_codes } => {
                self.release_reservation(admission, &budget_key, &reservation_id, &attempt_id, &now)
                    .await?;
                // A refused claim also returns reservations a crash left: otherwise an
                // operation never claimed again would hold them, and its run could not
                // complete.
                self.reclaim_unclaimed(
                    admission,
                    &operations_key,
                    &budget_key,
                    &operation_id,
                    &attempt_id,
                    &unclaimed,
                    &now,
                )
                .await?;
                let status = if reason_codes.iter().any(|r| {
                    matches!(
                        r.as_str(),
                        "retry_unsafe" | "operation_in_flight" | "retry_not_due" | "shared_guarantee_unresolved"
                    )
                }) {
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
        self.reclaim_unclaimed(
            admission,
            &operations_key,
            &budget_key,
            &operation_id,
            &attempt_id,
            &unclaimed,
            &now,
        )
        .await?;
        let claim_entry = self
            .audit
            .append(
                &admission.tenant_id,
                "operation_claim",
                json!({"run_id": admission.run_id, "operation_id": operation_id, "attempt_id": attempt_id,
                    "capability_id": manifest.capability_id, "action_digest": action_digest}),
                &now,
            )
            .await?;
        p.report.audit_sequences.push(claim_entry.sequence);

        // Ownership is re-checked after the claim commits and before dispatch: this is
        // the linearization point against a concurrent takeover. If the run changed
        // hands, the attempt is recorded as definitively not dispatched and its budget
        // released, so nothing claimed after a takeover reaches a provider; anything
        // claimed before it is in the operation ledger for the new executor.
        if let Some(generation) = fence
            && let Ownership::Refused(reason) = self.check_owner(admission, generation).await?
        {
            self.withhold_dispatch(
                admission,
                &operations_key,
                &operation_id,
                &attempt_id,
                &action_digest,
                &now,
                reason,
            )
            .await?;
            self.release_reservation(admission, &budget_key, &reservation_id, &attempt_id, &now)
                .await?;
            return Ok(p.stop(
                "rejected",
                vec![reason.into()],
                "The executor lost ownership of this run.",
            ));
        }
        // The effect's signature is claimed after the operation claim and before dispatch:
        // of identical effects racing under different keys, exactly one is sent. The
        // check at authorization only refuses the sequential case early.
        if guards_effect && new_operation {
            let claimed_effect = loop_guard::claim_effect(
                self.store.as_ref(),
                &loop_key,
                &call_signature,
                &operation_id,
                self.loop_limit.is_some(),
                loops.as_ref(),
            )
            .await;
            let refusal = match claimed_effect {
                Ok(loop_guard::EffectClaim::Claimed) => None,
                Ok(loop_guard::EffectClaim::Held(holder)) => Some((
                    "effect_repeated",
                    Some(holder.clone()),
                    format!("An identical effect was already requested in this run as operation {holder}."),
                )),
                Ok(loop_guard::EffectClaim::Saturated) => Some((
                    "effect_guard_saturated",
                    None,
                    "The run has recorded too many distinct effects to guard another.".to_owned(),
                )),
                Err(error) => {
                    tracing::warn!(%error, "repeated-effect guard unavailable");
                    Some((
                        "effect_guard_unavailable",
                        None,
                        "The repeated-effect guard is unavailable; the effect was not sent.".to_owned(),
                    ))
                }
            };
            if let Some((reason, holder, message)) = refusal {
                self.withhold_dispatch(
                    admission,
                    &operations_key,
                    &operation_id,
                    &attempt_id,
                    &action_digest,
                    &now,
                    reason,
                )
                .await?;
                self.release_reservation(admission, &budget_key, &reservation_id, &attempt_id, &now)
                    .await?;
                let entry = self
                    .audit
                    .append(
                        &admission.tenant_id,
                        "repeated_effect_refusal",
                        json!({"run_id": admission.run_id, "operation_id": operation_id,
                            "capability_id": manifest.capability_id, "call_signature": call_signature,
                            "applied_operation_id": holder, "reason_codes": [reason]}),
                        &now,
                    )
                    .await?;
                p.report.audit_sequences.push(entry.sequence);
                if holder.is_some() {
                    p.report.obligations.push("reconcile_existing_operation".into());
                }
                return Ok(p.stop("blocked", vec![reason.into()], &message));
            }
        }
        // The task's limits are charged after the operation claim and before dispatch:
        // of effects racing for the last of a limit, exactly one is sent.
        let mut task_charges = Vec::new();
        for (key, limits, exceeded) in &task_limits {
            let over_limit = *exceeded && approved;
            let charged = task_authorization::charge(
                self.store.as_ref(),
                key,
                limits,
                &operation_id,
                amount.as_ref(),
                over_limit,
            )
            .await;
            let reason = match charged {
                Ok(task_authorization::Charge::Charged) => {
                    task_charges.push(key.clone());
                    continue;
                }
                Ok(task_authorization::Charge::Exceeded) => "task_scope_extent",
                Ok(task_authorization::Charge::Saturated) => "task_limits_saturated",
                Err(error) => {
                    tracing::warn!(%error, "task limits unavailable");
                    "task_limits_unavailable"
                }
            };
            self.release_task_charges(&task_charges, &operation_id).await?;
            self.withhold_dispatch(
                admission,
                &operations_key,
                &operation_id,
                &attempt_id,
                &action_digest,
                &now,
                reason,
            )
            .await?;
            self.release_reservation(admission, &budget_key, &reservation_id, &attempt_id, &now)
                .await?;
            if guards_effect && new_operation {
                loop_guard::release_effect(self.store.as_ref(), &loop_key, &call_signature, &operation_id).await?;
            }
            let entry = self
                .audit
                .append(
                    &admission.tenant_id,
                    "task_limit_refusal",
                    json!({"run_id": admission.run_id, "operation_id": operation_id,
                        "capability_id": manifest.capability_id, "action_digest": action_digest,
                        "task_exposure_id": key.id, "reason_codes": [reason]}),
                    &now,
                )
                .await?;
            p.report.audit_sequences.push(entry.sequence);
            let mut reasons = vec![reason.to_owned()];
            if reason == "task_scope_extent" {
                reasons.insert(0, "outside_task_authorization".into());
            }
            return Ok(p.stop(
                "blocked",
                reasons,
                "The task's limits would be exceeded; this effect was not sent.",
            ));
        }
        if let (Some(continuation), Some((_, digest))) = (continuation, &adapter_input) {
            let entry = self
                .audit
                .append(
                    &admission.tenant_id,
                    "input_response",
                    json!({"operation_id": operation_id, "attempt_id": attempt_id,
                        "responder_id": continuation.responder_id, "responses_digest": digest}),
                    &now,
                )
                .await?;
            p.report.audit_sequences.push(entry.sequence);
        }

        // Shared business capacity is conserved across independent runs and agents.
        // Keep this after all existing gates, immediately before the provider call.
        match self
            .reserve_shared_exposure(
                admission,
                &manifest.capability_id,
                &envelope["args"],
                &operation_id,
                &attempt_id,
                &action_digest,
            )
            .await?
        {
            Ok(sequences) => p.report.audit_sequences.extend(sequences),
            Err(reason) => {
                self.withhold_dispatch(
                    admission,
                    &operations_key,
                    &operation_id,
                    &attempt_id,
                    &action_digest,
                    &now,
                    reason,
                )
                .await?;
                self.release_reservation(admission, &budget_key, &reservation_id, &attempt_id, &now)
                    .await?;
                if guards_effect && new_operation {
                    loop_guard::release_effect(self.store.as_ref(), &loop_key, &call_signature, &operation_id).await?;
                }
                self.release_task_charges(&task_charges, &operation_id).await?;
                let entry = self
                    .audit
                    .append(
                        &admission.tenant_id,
                        "shared_guarantee_refused",
                        json!({"run_id":admission.run_id,"operation_id":operation_id,"attempt_id":attempt_id,
                        "action_digest":action_digest,"capability_id":manifest.capability_id,"reason_codes":[reason]}),
                        &now,
                    )
                    .await?;
                p.report.audit_sequences.push(entry.sequence);
                return Ok(p.stop(
                    "blocked",
                    vec![reason.into()],
                    "The shared business guarantee withheld this effect.",
                ));
            }
        }

        // The dispatch gate decides once whether this attempt is sent: if reconciliation
        // already recorded it as never sent, or a retry reclaimed its reservation, the
        // gate is closed and nothing goes out.
        {
            let gate = dispatch_gate_key(admission, &attempt_id);
            match self
                .store
                .create(&gate, &json!({"state": "started", "operation_id": operation_id}))
                .await
            {
                Ok(_) => {}
                Err(e) if e.is_conflict() => {
                    // Nothing was sent, so record it: the attempt would otherwise stay
                    // claimed, in flight, until an operator resolved it. When the
                    // attempt is already resolved, the kernel refuses this and it is a
                    // no-op.
                    self.withhold_dispatch(
                        admission,
                        &operations_key,
                        &operation_id,
                        &attempt_id,
                        &action_digest,
                        &now,
                        "dispatch_aborted",
                    )
                    .await?;
                    self.release_reservation(admission, &budget_key, &reservation_id, &attempt_id, &now)
                        .await?;
                    if guards_effect && new_operation {
                        loop_guard::release_effect(self.store.as_ref(), &loop_key, &call_signature, &operation_id)
                            .await?;
                    }
                    self.release_task_charges(&task_charges, &operation_id).await?;
                    return Ok(p.stop(
                        "blocked",
                        vec!["dispatch_aborted".into()],
                        "This attempt was recorded as never sent; it was not sent.",
                    ));
                }
                Err(e) => return Err(e.into()),
            }
        }

        // Marking the shared receipt started is the last write before the provider
        // call. A store failure before it leaves the receipt not started, which
        // reconciliation can release as never sent; a reconciliation that aborted the
        // receipt first wins this transition, and nothing goes out.
        if self.has_shared_guarantee(&manifest.capability_id)
            && let Err(reasons) = self
                .transition_shared_dispatch(admission, &operation_id, &attempt_id, "start")
                .await?
        {
            self.withhold_dispatch(
                admission,
                &operations_key,
                &operation_id,
                &attempt_id,
                &action_digest,
                &now,
                "shared_guarantee_dispatch_closed",
            )
            .await?;
            self.release_reservation(admission, &budget_key, &reservation_id, &attempt_id, &now)
                .await?;
            if guards_effect && new_operation {
                loop_guard::release_effect(self.store.as_ref(), &loop_key, &call_signature, &operation_id).await?;
            }
            self.release_task_charges(&task_charges, &operation_id).await?;
            return Ok(p.stop("blocked", reasons, "The shared reservation was closed before dispatch."));
        }

        // 6. Dispatch.
        let deadline = add_contract_seconds(&now, manifest.timeout_ms.div_ceil(1000))
            .unwrap_or_else(|| admission.deadline.clone());
        if self.dispatch_stalled(&now) {
            // Not sent: an attestation of absence may already have released what the
            // attempt holds.
            self.withhold_dispatch(
                admission,
                &operations_key,
                &operation_id,
                &attempt_id,
                &action_digest,
                &now,
                "dispatch_stalled",
            )
            .await?;
            self.release_reservation(admission, &budget_key, &reservation_id, &attempt_id, &now)
                .await?;
            if guards_effect && new_operation {
                loop_guard::release_effect(self.store.as_ref(), &loop_key, &call_signature, &operation_id).await?;
            }
            self.release_task_charges(&task_charges, &operation_id).await?;
            p.report
                .audit_sequences
                .extend(self.settle_shared_exposure(admission, &operation_id).await?);
            return Ok(p.stop(
                "blocked",
                vec!["dispatch_stalled".into()],
                "The dispatch stalled before sending; it was not sent.",
            ));
        }
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
            input: adapter_input.map(|(input, _)| input),
            executor_generation: fence,
        };
        // The loop guard's count is recorded while the provider works.
        let (response, counted) = tokio::join!(
            tokio::time::timeout(
                Duration::from_millis(manifest.timeout_ms),
                adapter.invoke(manifest, &call)
            ),
            async {
                // A guarded effect was counted with its claim, in one write.
                if self.loop_limit.is_some() && new_operation && !guards_effect {
                    loop_guard::note(self.store.as_ref(), &loop_key, &call_signature).await
                } else {
                    Ok(())
                }
            },
        );
        let response = response.unwrap_or_else(|_| AdapterResponse::unknown());
        // The claim stays for every effect that may have applied; one the provider
        // definitively did not apply is released, so it may be attempted again.
        let not_applied = response.definitive
            && matches!(
                response.outcome,
                EffectOutcome::NotApplied | EffectOutcome::NotDispatched
            );
        if guards_effect
            && new_operation
            && not_applied
            && let Err(error) =
                loop_guard::release_effect(self.store.as_ref(), &loop_key, &call_signature, &operation_id).await
        {
            // Still claimed: a new attempt of this effect is refused (fails closed).
            tracing::warn!(%error, "repeated-effect claim not released");
            self.audit
                .append(
                    &admission.tenant_id,
                    "effect_guard_release_lost",
                    json!({"run_id": admission.run_id, "operation_id": operation_id, "call_signature": call_signature}),
                    &now,
                )
                .await?;
        }
        if not_applied && let Err(error) = self.release_task_charges(&task_charges, &operation_id).await {
            // Still charged: the task's limits stay lower than they need be (fails closed).
            tracing::warn!(%error, "task limit charge not returned");
            self.audit
                .append(
                    &admission.tenant_id,
                    "task_limit_release_lost",
                    json!({"run_id": admission.run_id, "operation_id": operation_id}),
                    &now,
                )
                .await?;
        }
        if let Err(error) = counted {
            // A lost count weakens the guard; make it visible in the evidence.
            tracing::warn!(%error, "loop guard count not recorded");
            self.audit
                .append(
                    &admission.tenant_id,
                    "loop_guard_count_lost",
                    json!({"run_id": admission.run_id, "operation_id": operation_id, "call_signature": call_signature}),
                    &now,
                )
                .await?;
        }

        let input_required = response.output.get("result_type").and_then(Value::as_str) == Some("input_required");
        if input_required {
            let record = input::pending_record(
                &operation_id,
                &attempt_id,
                response.output.get("result").unwrap_or(&Value::Null),
                &now,
            );
            self.note_pending_input(admission, &pending_key.id).await?;
            match self.store.get(&pending_key).await? {
                None => match self.store.create(&pending_key, &record).await {
                    Ok(_) => {}
                    Err(e) if e.is_conflict() => {}
                    Err(e) => return Err(e.into()),
                },
                Some(existing) => {
                    self.store
                        .compare_and_swap(&pending_key, existing.revision, &record)
                        .await?;
                }
            }
        }

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
        let (commit, _) = transact_from(
            self.store.as_ref(),
            &operations_key,
            claimed,
            |ledger| {
                if self.has_shared_guarantee(&manifest.capability_id) {
                    shared_guarantees::record_shared_observation(ledger, &observation)
                } else {
                    record_effect_observation(ledger, &observation, &ledger["revision"])
                }
            },
            |_| false,
        )
        .await?;
        if matches!(&commit, Commit::Rejected { .. }) && self.has_shared_guarantee(&manifest.capability_id) {
            if let Commit::Rejected { reason_codes } = &commit {
                self.shared_observation_refused(admission, &observation, reason_codes)
                    .await?;
            }
            return Err(GatewayError::Guarantee("shared_guarantee_observation_rejected".into()));
        }
        if let Commit::Written { obligations, .. } | Commit::Unchanged { obligations } = commit {
            p.report.obligations.extend(obligations);
        }
        // Unresolved outcomes are tracked for completion checks; the response says which.
        if response.outcome == EffectOutcome::Partial {
            self.note_effect(admission, &operation_id, "partial").await?;
        } else if response.outcome == EffectOutcome::Confirmed && response.definitive {
            self.note_applied_effect(admission, &operation_id).await?;
        } else if !(response.definitive && response.outcome != EffectOutcome::Unknown) {
            self.note_effect(admission, &operation_id, "unknown").await?;
        }
        let known = response.definitive && response.outcome != EffectOutcome::Unknown;
        let allocation = manifest.reservation;
        let usage = json!({
            "tokens": 0, "tool_calls": allocation.tool_calls.min(1), "replans": 0,
            "cost_units": response.cost_units.unwrap_or(allocation.cost_units).min(allocation.cost_units),
        });
        // The observation is already recorded in the operation ledger; auditing it and
        // settling the budget are independent.
        let settle_mutation = format!("settle:{attempt_id}");
        let (entry, settled) = tokio::join!(
            self.audit.append(
                &admission.tenant_id,
                "effect_observation",
                observation.clone(),
                &observed_at,
            ),
            self.settle_scoped(
                admission,
                &budget_key,
                &reservation_id,
                &settle_mutation,
                ("run", &admission.run_id),
                &observed_at,
                &valid_until,
                &evidence_ref,
                &usage,
                known,
                settle_seed,
            ),
        );
        p.report.audit_sequences.push(entry?.sequence);
        settled?;
        if self.has_shared_guarantee(&manifest.capability_id) {
            p.report
                .audit_sequences
                .extend(self.settle_shared_exposure(admission, &operation_id).await?);
        }

        // 8. Result.
        let mutations = if matches!(response.outcome, EffectOutcome::Confirmed | EffectOutcome::Partial) {
            vec![operation_id.clone()]
        } else {
            vec![]
        };
        let read_only = manifest.action_risk.effect == contextos_contract::types::ActionEffect::None;
        // With a reviewed output schema, nothing outside it reaches the agent: an input
        // request is reduced to its input requests, a confirmed result is checked below,
        // and the raw output of any other outcome is withheld.
        let schema = self.output_schemas.get(&manifest.capability_id);
        let mut response = response;
        if schema.is_some() && input_required {
            let requests = response
                .output
                .get("result")
                .map_or(Value::Null, |r| r["inputRequests"].clone());
            response.output = Map::from_iter([
                ("result_type".to_owned(), json!("input_required")),
                ("result".to_owned(), json!({"inputRequests": requests})),
            ]);
        } else if schema.is_some() && !(matches!(response.outcome, EffectOutcome::Confirmed) && known) {
            response.output = Map::new();
        }
        if input_required && known {
            p.report.obligations.push("provide_requested_input".into());
            return Ok(p.finish(
                "paused",
                response.output,
                Some("The tool needs input before it can run.".into()),
                vec![],
            ));
        }
        // Output the tool's reviewed schema does not allow never reaches the agent; the
        // effect itself stands (it is recorded and settled above).
        if matches!(response.outcome, EffectOutcome::Confirmed)
            && known
            && let Some(schema) = schema
            && let Err(paths) = schema.check(&Value::Object(response.output.clone()))
        {
            let entry = self
                .audit
                .append(
                    &admission.tenant_id,
                    "output_schema_violation",
                    json!({"run_id": admission.run_id, "operation_id": operation_id,
                        "capability_id": manifest.capability_id, "paths": paths}),
                    &self.now(),
                )
                .await?;
            p.report.audit_sequences.push(entry.sequence);
            p.report.reason_codes.push("output_schema_violation".into());
            p.report.obligations.push("verify_effect_out_of_band".into());
            return Ok(p.finish(
                if read_only { "ok" } else { "completed" },
                Map::new(),
                Some("The effect was applied, but the tool's output did not match its schema and was withheld.".into()),
                mutations,
            ));
        }
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

    /// Compacts the run's budget ledger once it holds [`BUDGET_COMPACT_AT`] receipts.
    /// The archive is written first; its id derives from the ledger revision, and a
    /// revision has exactly one state, so a retried or concurrent compaction writes the
    /// same archive. Losing the ledger race is harmless: the next reservation re-reads.
    async fn compact_budget_if_due(
        &self,
        admission: &RunAdmission,
        budget_key: &DocKey,
        stored_revision: u64,
        ledger: &Value,
        now: &str,
    ) -> Result<(), GatewayError> {
        if ledger["mutations"].as_array().map_or(0, Vec::len) < BUDGET_COMPACT_AT {
            return Ok(());
        }
        let archive_id = format!("{}:archive:{}", admission.budget_ledger_id, ledger["revision"]);
        let Ok(compaction) = compact_budget_ledger(
            ledger,
            &archive_id,
            &ledger["revision"],
            &json!(admission.executor_generation),
        ) else {
            return Ok(());
        };
        let archive_key = DocKey::new(&admission.tenant_id, DocKind::BudgetArchive, &archive_id);
        match self.store.create(&archive_key, &compaction.archive).await {
            Ok(_) => {}
            Err(e) if e.is_conflict() => {}
            Err(e) => return Err(e.into()),
        }
        match self
            .store
            .compare_and_swap(budget_key, stored_revision, &compaction.ledger)
            .await
        {
            Ok(_) => {
                self.audit
                    .append(
                        &admission.tenant_id,
                        "budget_compaction",
                        json!({"ledger_id": admission.budget_ledger_id, "archive_id": archive_id,
                            "from_revision": compaction.archive["from_revision"],
                            "to_revision": compaction.archive["to_revision"],
                            "previous_ledger_digest": compaction.archive["previous_ledger_digest"],
                            "archive_digest": sha256_canonical(&compaction.archive).unwrap_or_default()}),
                        now,
                    )
                    .await?;
                Ok(())
            }
            Err(e) if e.is_conflict() => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    /// Returns the open reservations of `operation_id` whose attempts never claimed it:
    /// their processes crashed between reserving and claiming. An attempt recorded in
    /// the operation ledger is skipped (its claim settles it). Each orphan's dispatch
    /// gate is closed first, so if its process was only paused it can never send.
    #[allow(clippy::too_many_arguments)]
    async fn reclaim_unclaimed(
        &self,
        admission: &RunAdmission,
        operations_key: &DocKey,
        budget_key: &DocKey,
        operation_id: &str,
        own_attempt: &str,
        unclaimed: &[String],
        now: &str,
    ) -> Result<(), GatewayError> {
        let others: Vec<&String> = unclaimed.iter().filter(|a| a.as_str() != own_attempt).collect();
        if others.is_empty() {
            return Ok(());
        }
        let recorded: HashSet<String> = self
            .store
            .get(operations_key)
            .await?
            .map(|r| {
                r.body["operations"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter(|op| op["intent"]["operation_id"] == operation_id)
                    .flat_map(|op| op["attempts"].as_array().cloned().unwrap_or_default())
                    .filter_map(|a| a["attempt_id"].as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default();
        for orphan in others {
            if recorded.contains(orphan) {
                continue;
            }
            let gate = dispatch_gate_key(admission, orphan);
            match self
                .store
                .create(&gate, &json!({"state": "aborted", "operation_id": operation_id}))
                .await
            {
                Ok(_) => {}
                Err(e) if e.is_conflict() => {
                    if self
                        .store
                        .get(&gate)
                        .await?
                        .is_some_and(|g| g.body["state"] == "started")
                    {
                        continue;
                    }
                }
                Err(e) => return Err(e.into()),
            }
            let id = attempt_reservation_id(admission, operation_id, orphan);
            self.release_reservation(admission, budget_key, &id, orphan, now)
                .await?;
        }
        Ok(())
    }

    /// Returns `operation_id`'s charges to the task limits keyed by `keys`.
    async fn release_task_charges(&self, keys: &[DocKey], operation_id: &str) -> Result<(), GatewayError> {
        for key in keys {
            task_authorization::release(self.store.as_ref(), key, operation_id).await?;
        }
        Ok(())
    }

    /// Records that a claimed attempt was never sent to the provider.
    #[allow(clippy::too_many_arguments)]
    async fn withhold_dispatch(
        &self,
        admission: &RunAdmission,
        operations_key: &DocKey,
        operation_id: &str,
        attempt_id: &str,
        action_digest: &str,
        claimed_at: &str,
        reason: &str,
    ) -> Result<(), GatewayError> {
        let observed_at = later(self.now(), claimed_at);
        let valid_until =
            add_contract_seconds(&observed_at, OBSERVATION_VALIDITY_SECONDS).unwrap_or_else(|| observed_at.clone());
        let observation_id = self.ports.ids.new_id("observation");
        let evidence_ref = json!({"artifact_type": "dispatch_withheld", "artifact_id": observation_id, "version": "1",
            "sha256": sha256_canonical(&json!([operation_id, attempt_id, reason])).unwrap_or_default()});
        let observation = json!({
            "observation_id": observation_id, "contract_id": admission.contract_id, "run_id": admission.run_id,
            "tenant_id": admission.tenant_id, "operation_id": operation_id, "attempt_id": attempt_id,
            "action_digest": action_digest, "executor_generation": admission.executor_generation,
            "outcome": "not_dispatched", "finality": "definitive", "external_ref": null, "evidence_ref": evidence_ref,
            "verification_status": "verified", "observer": admission.gateway_observer, "observed_at": observed_at,
            "valid_until": valid_until, "evaluation_time": observed_at,
        });
        let shared = !self.shared_guarantees.is_empty() && self.has_exposure_link(admission, operation_id).await?;
        let commit = transact(self.store.as_ref(), operations_key, |ledger| {
            if shared {
                shared_guarantees::record_shared_observation(ledger, &observation)
            } else {
                record_effect_observation(ledger, &observation, &ledger["revision"])
            }
        })
        .await?;
        if let Commit::Rejected { reason_codes } = commit {
            if shared {
                self.shared_observation_refused(admission, &observation, &reason_codes)
                    .await?;
            }
            return Ok(());
        }
        self.audit
            .append(&admission.tenant_id, "effect_observation", observation, &observed_at)
            .await?;
        Ok(())
    }

    /// `None` without a boundary controller; otherwise the kernel's verdict on the
    /// run's boundary now (`Err` carries the reason codes).
    pub(crate) async fn boundary_readiness(
        &self,
        admission: &RunAdmission,
        now: &str,
    ) -> Option<Result<(), Vec<String>>> {
        let provider = self.ports.boundary.as_ref()?;
        let Ok((required, observed)) = provider.boundary(admission).await else {
            return Some(Err(vec!["boundary_unavailable".into()]));
        };
        let bound = |v: &Value| {
            v["contract_id"] == admission.contract_id.as_str()
                && v["run_id"] == admission.run_id.as_str()
                && v["tenant_id"] == admission.tenant_id.as_str()
        };
        if !bound(&required) || !bound(&observed) {
            return Some(Err(vec!["boundary_binding_mismatch".into()]));
        }
        let verdict =
            contextos_kernel::execution_boundary::evaluate_boundary_readiness(&required, &observed, &json!(now));
        Some(if verdict.allowed {
            Ok(())
        } else {
            Err(verdict.reason_codes)
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
            &format!("settle:{attempt_id}"),
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
        mutation_id: &str,
        now: &str,
        valid_until: &str,
        evidence_ref: &Value,
        usage: &Value,
        known: bool,
    ) -> Result<(), GatewayError> {
        self.settle_scoped(
            admission,
            budget_key,
            reservation_id,
            mutation_id,
            ("run", &admission.run_id),
            now,
            valid_until,
            evidence_ref,
            usage,
            known,
            None,
        )
        .await
        .map(|_| ())
    }

    /// Settles a reservation of `scope` (`run`, or `child` for a delegated run).
    #[allow(clippy::too_many_arguments)]
    async fn settle_scoped(
        &self,
        admission: &RunAdmission,
        budget_key: &DocKey,
        reservation_id: &str,
        mutation_id: &str,
        (scope, run_id): (&str, &str),
        now: &str,
        valid_until: &str,
        evidence_ref: &Value,
        usage: &Value,
        known: bool,
        seed: Option<(u64, Value)>,
    ) -> Result<Commit, GatewayError> {
        let mut request = json!({
            "ledger_id": admission.budget_ledger_id, "contract_id": admission.contract_id,
            "parent_run_id": admission.run_id, "tenant_id": admission.tenant_id,
            "mutation_id": mutation_id, "reservation_id": reservation_id, "scope": scope,
            "run_id": run_id, "cost_unit": {"currency": "USD", "units_per_cent": 100}, "usage": usage,
            "usage_status": if known { "known" } else { "unknown" },
            "execution_status": if known { "completed" } else { "unknown" },
            "expected_revision": 0, "executor_generation": admission.executor_generation, "evaluation_time": now,
            "usage_observation": {"intent_digest": "", "verification_status": "verified", "observer": admission.gateway_observer,
                "evidence_ref": evidence_ref, "observed_at": now, "valid_until": valid_until},
        });
        request["usage_observation"]["intent_digest"] = json!(settlement_intent_digest(&request).unwrap_or_default());
        let (commit, _) = transact_from(
            self.store.as_ref(),
            budget_key,
            seed,
            |ledger| {
                let mut request = request.clone();
                request["expected_revision"] = ledger["revision"].clone();
                settle_budget(ledger, &request)
            },
            |_| false,
        )
        .await?;
        Ok(commit)
    }
}
