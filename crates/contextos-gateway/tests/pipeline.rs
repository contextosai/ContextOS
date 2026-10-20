//! End-to-end governance through the gateway with deterministic fake ports.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use async_trait::async_trait;
use contextos_audit::{AuditSigner, AuditWriter, KeyRing, verify_tenant_chain};
use contextos_contract::canonical::sha256_canonical;
use contextos_contract::execution::WorkflowFeatureSet;
use contextos_contract::types::{CompiledContext, ContextPack, InvokeRequest, RunContext};
use contextos_gateway::*;
use contextos_kernel::{CompileDeps, ContextPackCompiler, STANDARD_PROFILE_REGISTRY};
use contextos_store::{DocKey, DocKind, DocumentStore, MemoryLog, MemoryStore};
use serde_json::{Value, json};

const TENANT: &str = "tenant_acme_prod";
const NOW: &str = "2026-10-20T10:00:00.000000Z";

fn artifact(kind: &str, id: &str) -> Value {
    json!({"artifact_type": kind, "artifact_id": id, "version": "1",
        "sha256": sha256_canonical(&json!({"artifact_type": kind, "artifact_id": id})).unwrap()})
}

fn principal(id: &str) -> Value {
    json!({"principal_id": id, "principal_type": "workload", "trust_domain": "contextos.test", "tenant_id": TENANT})
}

struct FixedClock;
impl Clock for FixedClock {
    fn now(&self) -> String {
        NOW.into()
    }
}

#[derive(Default)]
struct SeqIds(AtomicU64);
impl IdSource for SeqIds {
    fn new_id(&self, prefix: &str) -> String {
        format!("{prefix}_{}", self.0.fetch_add(1, Ordering::SeqCst))
    }
}

/// Grants exactly what the binding asks for, as a trusted mandate broker would after
/// verifying a real grant; the kernel still checks scope, freshness and linkage.
struct Authority;
#[async_trait]
impl AuthorityProvider for Authority {
    async fn authority(&self, admission: &RunAdmission, binding: &Value) -> Result<AuthorityFacts, PortError> {
        let mut scope = json!({
            "root_run_id": admission.run_id, "purpose_ids": [binding["purpose_id"]],
            "capability_ids": [binding["capability_id"]], "resource_ids": binding["resource_ids"],
            "destination_ids": binding["destination_ids"], "classification_labels": ["CONFIDENTIAL"],
            "argument_constraints": [{"pointer": "/amount_minor", "kind": "max_integer", "maximum": 500_000}],
        });
        if binding.get("amount").is_some() {
            scope["amount_ceiling"] = json!({"minor_units": 500_000, "currency": "INR"});
        }
        let grant = json!({
            "grant_id": "grant_refund", "grant_revision": "1", "issuer": principal("mandate_broker"),
            "subject": admission.actor, "audience": "gateway.test", "scope": scope,
            "not_before": "2026-10-20T00:00:00Z", "expires_at": "2026-10-21T00:00:00Z",
            "delegation_depth_remaining": 3, "verification_ref": artifact("authority_grant", "grant_refund"),
        });
        let observation = json!({
            "grant_id": "grant_refund", "grant_revision": "1",
            "grant_digest": sha256_canonical(&json!({"domain": "contextos.authority_grant.v1", "grant": grant})).unwrap(),
            "verification_ref": grant["verification_ref"], "verification_status": "verified",
            "observed_at": "2026-10-20T09:59:00Z", "valid_until": "2026-10-20T11:00:00Z",
            "revocation_status": "active", "observer": principal("grant_observer"),
        });
        Ok(AuthorityFacts {
            authenticated: json!({
                "principal": admission.actor, "audience": "gateway.test", "root_run_id": admission.run_id,
                "run_id": admission.run_id, "mandate_kind": "workload", "trusted_issuers": [principal("mandate_broker")],
                "trusted_observers": [principal("grant_observer")], "verification_status": "verified",
                "verification_ref": artifact("authentication", "agt_support"),
                "observed_at": "2026-10-20T09:59:00Z", "valid_until": "2026-10-20T11:00:00Z",
            }),
            leaf_grant_ref: json!({"grant_id": "grant_refund", "grant_revision": "1"}),
            grants: vec![grant],
            observations: vec![observation],
            run_links: vec![],
        })
    }
}

struct Policy(&'static str);
#[async_trait]
impl PolicyProvider for Policy {
    async fn outcomes(&self, admission: &RunAdmission, _binding: &Value) -> Result<Vec<Value>, PortError> {
        Ok(vec![
            json!({"category": "business", "priority": 10, "verdict": self.0, "rule_id": "refund_rule",
            "bundle_ref": admission.policy_refs[0], "obligations": ["audit"]}),
        ])
    }
}

struct Constraints;
#[async_trait]
impl ConstraintProvider for Constraints {
    async fn observations(
        &self,
        admission: &RunAdmission,
        required: &[Value],
        digest: &str,
    ) -> Result<Vec<Value>, PortError> {
        Ok(required
            .iter()
            .map(|control| json!({"control": control, "action_digest": digest, "policy_refs": admission.policy_refs,
                "verdict": "allow", "verification_status": "verified",
                "verification_ref": artifact("control_observation", control["control_id"].as_str().unwrap()),
                "observer": principal("grant_observer"), "observed_at": "2026-10-20T09:59:00Z", "valid_until": "2026-10-20T11:00:00Z"}))
            .collect())
    }
}

/// Records requested bindings; `approve` simulates a verified human approval.
#[derive(Default)]
struct Approvals(AtomicUsize, std::sync::Mutex<std::collections::HashMap<String, Value>>);

impl Approvals {
    fn approve(&self, digest: &str) {
        let mut store = self.1.lock().unwrap();
        let binding = store.get(digest).cloned().expect("requested binding");
        let proposal = json!({"request_id": "req_1", "proposal_id": binding["proposal_id"], "run_id": binding["run_id"],
            "tenant_id": TENANT, "operation_id": binding["operation_id"], "action_digest": digest,
            "policy_refs": binding["policy_refs"], "authority_refs": binding["authority_refs"],
            "not_before": "2026-10-20T09:00:00Z", "expires_at": "2026-10-20T11:00:00Z"});
        let approver = json!({"principal_id": "finance_lead", "principal_type": "person", "trust_domain": "contextos.test", "tenant_id": TENANT});
        let mut request = proposal.clone();
        let request_id = format!("approval_request:{}", &digest[7..19]);
        for (k, v) in [
            ("approval_request_id", json!(request_id)),
            ("requester", principal("agt_support")),
            ("eligible_approvers", json!([approver])),
            ("eligible_approver_roles", json!(["finance_lead"])),
            ("required_approvals", json!(1)),
            ("prohibit_self_approval", json!(true)),
            ("verification_ref", artifact("approval_request", &request_id)),
        ] {
            request[k] = v;
        }
        let mut decision = proposal.clone();
        for (k, v) in [
            ("approval_id", json!("approval_1")),
            ("approval_request_id", json!(request_id)),
            ("approver", approver.clone()),
            ("decision", json!("approved")),
            ("decided_at", json!("2026-10-20T09:30:00Z")),
            ("verification_ref", artifact("approval_decision", "approval_1")),
        ] {
            decision[k] = v;
        }
        let observed = json!({"approval_id": "approval_1",
            "decision_digest": sha256_canonical(&json!({"domain": "contextos.approval_decision.v1", "decision": decision})).unwrap(),
            "verification_ref": decision["verification_ref"], "verification_status": "verified", "observer": principal("grant_observer"),
            "observed_at": "2026-10-20T09:31:00Z", "valid_until": "2026-10-20T11:00:00Z"});
        let entitlement = json!({"approver": approver, "role_id": "finance_lead", "approval_request_id": request_id, "action_digest": digest,
            "observer": principal("grant_observer"), "verification_status": "verified", "verification_ref": artifact("entitlement", "finance_lead"),
            "observed_at": "2026-10-20T09:00:00Z", "valid_until": "2026-10-20T11:00:00Z"});
        store.insert(format!("approved:{digest}"), json!({"proposal": proposal, "request": request, "decisions": [decision],
            "verification_observations": [observed], "entitlements": [entitlement], "trusted_observers": [principal("grant_observer")]}));
    }
}

#[async_trait]
impl ApprovalProvider for Approvals {
    async fn approval(&self, _: &RunAdmission, digest: &str) -> Result<Option<Value>, PortError> {
        Ok(self.1.lock().unwrap().get(&format!("approved:{digest}")).cloned())
    }
    async fn request(&self, _: &RunAdmission, binding: &Value, digest: &str) -> Result<String, PortError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        self.1.lock().unwrap().insert(digest.to_owned(), binding.clone());
        Ok(format!("approval_request:{}", &digest[7..19]))
    }
}

#[derive(Clone, Copy)]
enum Behavior {
    Confirm,
    Hang,
}

struct Payments {
    calls: AtomicUsize,
    behavior: Behavior,
}
#[async_trait]
impl Adapter for Payments {
    async fn invoke(&self, _: &CapabilityManifest, call: &AdapterCall) -> AdapterResponse {
        self.calls.fetch_add(1, Ordering::SeqCst);
        match self.behavior {
            Behavior::Confirm => AdapterResponse {
                outcome: EffectOutcome::Confirmed,
                definitive: true,
                output: serde_json::from_value(json!({"refund_id": format!("rf_{}", call.operation_id)})).unwrap(),
                external_ref: Some("rf_1".into()),
                cost_units: Some(40),
            },
            Behavior::Hang => {
                tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                AdapterResponse::unknown()
            }
        }
    }
}

fn compiled() -> CompiledContext {
    let path = format!("{}/../../conformance/vectors/compiler.json", env!("CARGO_MANIFEST_DIR"));
    let vectors: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let case = vectors["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "grid:support.refund:true:4200:support_agent")
        .unwrap();
    let pack: ContextPack = serde_json::from_value(case["pack"].clone()).unwrap();
    let request: InvokeRequest = serde_json::from_value(case["request"].clone()).unwrap();
    let run: RunContext = serde_json::from_value(case["run_context"].clone()).unwrap();
    let deps = CompileDeps {
        evidence: case["deps"]["evidence"].as_array().unwrap().clone(),
        ..CompileDeps::default()
    };
    ContextPackCompiler::new(pack)
        .unwrap()
        .compile(&request, &run, &deps)
        .unwrap()
}

fn manifest() -> CapabilityManifest {
    serde_json::from_value(json!({
        "capability_id": "adp_payments.issue_refund", "capability_version": "3", "adapter_id": "adp_payments",
        "protocol_tool": "refunds.create", "purpose_id": "support.refund", "desired_effect": "refund_created",
        "action_risk": {"effect": "external_state", "authority": "service", "reversibility": "compensatable",
            "interaction": "api", "data_scope": "CONFIDENTIAL"},
        "approval_mode": "destructive", "resource_pointers": ["/order_id"], "destination_pointers": ["/customer_id"],
        "amount": {"minor_units_pointer": "/amount_minor", "currency": "INR"},
        "recovery": {"strategy": "manual_reconcile", "max_attempts": 2, "retry_delays_seconds": [5]},
        "timeout_ms": 200, "reservation": {"tokens": 0, "tool_calls": 1, "replans": 0, "cost_units": 100},
        "adapter_ref": artifact("adapter", "payments@3"), "capability_ref": artifact("capability", "issue_refund@3"),
    }))
    .unwrap()
}

struct Harness {
    gateway: Gateway<MemoryStore, MemoryLog>,
    admission: RunAdmission,
    store: Arc<MemoryStore>,
    audit: Arc<AuditWriter<MemoryLog>>,
    adapter: Arc<Payments>,
    approvals: Arc<Approvals>,
}

async fn harness(verdict: &'static str, behavior: Behavior) -> Harness {
    let store = Arc::new(MemoryStore::new());
    let audit = Arc::new(AuditWriter::new(
        MemoryLog::new(),
        AuditSigner::from_seed("gw-1", [3; 32]),
    ));
    let approvals = Arc::new(Approvals::default());
    let ports = Ports {
        clock: Arc::new(FixedClock),
        ids: Arc::new(SeqIds::default()),
        authority: Arc::new(Authority),
        policy: Arc::new(Policy(verdict)),
        constraints: Arc::new(Constraints),
        approvals: approvals.clone(),
        idempotency: None,
    };
    let adapter = Arc::new(Payments {
        calls: AtomicUsize::new(0),
        behavior,
    });
    let mut gateway = Gateway::new(store.clone(), audit.clone(), ports);
    gateway.register_adapter("adp_payments", adapter.clone());
    gateway.pin_capability(manifest()).unwrap();
    let registry = &*STANDARD_PROFILE_REGISTRY;
    let contract = json!({"envelope_version": "contextos.execution_contract.v1", "contract_id": "contract_1",
        "run_id": "run_1", "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736", "tenant_id": TENANT,
        "profiles": [{"profile_id": "contextos.core", "profile_version": "1"}], "required_controls": [],
        "optional_controls": [], "release_refs": [artifact("release", "runtime@0.1.0")]});
    let support = json!({"implementation_id": "contextos-rs", "implementation_version": "0.1.0",
        "supported_profiles": registry.profiles.iter().map(|p| &p.profile).collect::<Vec<_>>(),
        "supported_controls": registry.controls.iter().map(|c| &c.control).collect::<Vec<_>>()});
    let compiled = compiled();
    let admission = admit_run(
        store.as_ref(),
        AdmissionRequest {
            contract: &contract,
            support: &support,
            registry,
            features: WorkflowFeatureSet {
                external_effects: true,
                ..WorkflowFeatureSet::default()
            },
            compiled: &compiled,
            actor: principal("agt_support"),
            policy_refs: vec![artifact("policy_bundle", "refund_policy")],
            gateway_observer: principal("gateway"),
            deadline: "2026-10-20T11:00:00Z".into(),
            executor_generation: 1,
            limits: BudgetLimits {
                tokens: 10_000,
                tool_calls: 8,
                replans: 2,
                cost_cents: 25.0,
            },
        },
    )
    .await
    .unwrap();
    Harness {
        gateway,
        admission,
        store,
        audit,
        adapter,
        approvals,
    }
}

fn call(id: &str, idempotency_key: Option<&str>) -> Value {
    json!({"envelope_version": "contextos.tool_call.v1", "tool_call_id": id, "run_id": "run_1",
        "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736", "capability_id": "adp_payments.issue_refund",
        "args": {"order_id": "ord_881", "customer_id": "cus_77", "amount_minor": 420_000},
        "principal_chain": [{"kind": "agent", "id": "agt_support"}],
        "approval_mode_requested": "destructive", "approval_mode_effective": "destructive", "approval_mode_highest": "destructive",
        "evidence_refs": ["kg:order:ord_881#snapshot_kg_2026_05_03_T0930"], "idempotency_key": idempotency_key})
}

async fn ledger(h: &Harness, kind: DocKind, id: &str) -> Value {
    h.store.get(&DocKey::new(TENANT, kind, id)).await.unwrap().unwrap().body
}

fn keys() -> KeyRing {
    let mut ring = KeyRing::new();
    ring.insert("gw-1", AuditSigner::from_seed("gw-1", [3; 32]).verifying_key());
    ring
}

#[tokio::test]
async fn allowed_effect_is_dispatched_settled_and_audited() {
    let h = harness("allow", Behavior::Confirm).await;
    let out = h
        .gateway
        .dispatch(&h.admission, &call("tc_1", Some("refund_ord_881")))
        .await
        .unwrap();
    assert_eq!(out.result["status"], "completed", "{:?}", out.report);
    assert_eq!(out.result["mutations"], json!(["refund_ord_881"]));
    assert_eq!(h.adapter.calls.load(Ordering::SeqCst), 1);
    let budget = ledger(&h, DocKind::BudgetLedger, &h.admission.budget_ledger_id).await;
    assert_eq!(
        budget["used"],
        json!({"tokens": 0, "tool_calls": 1, "replans": 0, "cost_units": 40})
    );
    assert_eq!(budget["reserved"]["cost_units"], json!(0));
    let ops = ledger(&h, DocKind::OperationLedger, &h.admission.operation_ledger_id).await;
    assert_eq!(ops["operations"][0]["outcome"], "confirmed");
    assert_eq!(verify_tenant_chain(h.audit.log(), TENANT, &keys()).await.unwrap(), 3);
    contextos_contract::schema::validate(
        &contextos_contract::schema::SchemaTarget::def(
            contextos_contract::schema::SchemaDoc::ToolEnvelope,
            "ToolResultEnvelope",
        ),
        &out.result,
    )
    .unwrap();

    // Replaying the same operation after confirmation is refused without a second effect.
    let again = h
        .gateway
        .dispatch(&h.admission, &call("tc_2", Some("refund_ord_881")))
        .await
        .unwrap();
    assert_eq!(again.result["status"], "paused");
    assert_eq!(again.report.reason_codes, vec!["retry_unsafe".to_owned()]);
    assert_eq!(h.adapter.calls.load(Ordering::SeqCst), 1);
    let budget = ledger(&h, DocKind::BudgetLedger, &h.admission.budget_ledger_id).await;
    assert_eq!(
        budget["reserved"]["tool_calls"],
        json!(0),
        "refused claim releases its reservation"
    );
}

#[tokio::test]
async fn approval_required_pauses_without_dispatch() {
    let h = harness("require_approval", Behavior::Confirm).await;
    let out = h.gateway.dispatch(&h.admission, &call("tc_1", None)).await.unwrap();
    assert_eq!(out.result["status"], "paused");
    assert!(out.report.approval_request_id.is_some());
    assert_eq!(h.approvals.0.load(Ordering::SeqCst), 1);
    assert_eq!(h.adapter.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn exact_approval_is_redeemed_once_then_dispatches() {
    let h = harness("require_approval", Behavior::Confirm).await;
    let paused = h
        .gateway
        .dispatch(&h.admission, &call("tc_1", Some("refund_big")))
        .await
        .unwrap();
    assert_eq!(paused.result["status"], "paused");
    let digest = paused.report.action_digest.clone().unwrap();
    h.approvals.approve(&digest);

    // A different amount is a different action: the approval does not carry over.
    let mut changed = call("tc_2", Some("refund_other"));
    changed["args"]["amount_minor"] = json!(1);
    assert_eq!(
        h.gateway.dispatch(&h.admission, &changed).await.unwrap().result["status"],
        "paused"
    );

    let done = h
        .gateway
        .dispatch(&h.admission, &call("tc_3", Some("refund_big")))
        .await
        .unwrap();
    assert_eq!(done.result["status"], "completed", "{:?}", done.report);
    assert_eq!(done.report.action_digest.as_deref(), Some(digest.as_str()));
    let request_id = format!("approval_request:{}", &digest[7..19]);
    let redemption = h
        .store
        .get(&DocKey::new(TENANT, DocKind::ApprovalRedemption, &request_id))
        .await
        .unwrap()
        .unwrap()
        .body;
    assert_eq!(redemption["operation_id"], "refund_big");
    assert_eq!(redemption["action_digest"], json!(digest));
    assert_eq!(h.adapter.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn denied_effect_is_blocked_before_the_adapter() {
    let h = harness("deny", Behavior::Confirm).await;
    let out = h.gateway.dispatch(&h.admission, &call("tc_1", None)).await.unwrap();
    assert_eq!(out.result["status"], "blocked");
    assert!(out.report.reason_codes.contains(&"business_policy_denied".to_owned()));
    assert_eq!(h.adapter.calls.load(Ordering::SeqCst), 0);
    // The denial itself is on the audit chain.
    assert_eq!(verify_tenant_chain(h.audit.log(), TENANT, &keys()).await.unwrap(), 1);
}

#[tokio::test]
async fn timeout_is_unknown_and_blocks_blind_retry() {
    let h = harness("allow", Behavior::Hang).await;
    let out = h
        .gateway
        .dispatch(&h.admission, &call("tc_1", Some("refund_ord_881")))
        .await
        .unwrap();
    assert_eq!(out.result["status"], "paused");
    assert!(
        out.report
            .obligations
            .contains(&"reconcile_effect_before_retry".to_owned())
    );
    let budget = ledger(&h, DocKind::BudgetLedger, &h.admission.budget_ledger_id).await;
    assert_eq!(
        budget["reservations"][0]["status"], "usage_unknown",
        "unknown usage keeps its reservation"
    );
    let retry = h
        .gateway
        .dispatch(&h.admission, &call("tc_2", Some("refund_ord_881")))
        .await
        .unwrap();
    assert_eq!(retry.result["status"], "paused");
    assert_eq!(retry.report.reason_codes, vec!["retry_unsafe".to_owned()]);
    assert_eq!(h.adapter.calls.load(Ordering::SeqCst), 1, "no blind duplicate write");
    // Reusing the operation key for a different action is incompatible reuse.
    let mut changed = call("tc_3", Some("refund_ord_881"));
    changed["args"]["amount_minor"] = json!(1);
    let out = h.gateway.dispatch(&h.admission, &changed).await.unwrap();
    assert_eq!(out.result["status"], "rejected");
    assert_eq!(out.report.reason_codes, vec!["operation_binding_mismatch".to_owned()]);
}

#[tokio::test]
async fn unsurfaced_and_unadmitted_inputs_are_rejected() {
    let h = harness("allow", Behavior::Confirm).await;
    let mut other = call("tc_1", None);
    other["capability_id"] = json!("adp_crm.delete_customer");
    assert_eq!(
        h.gateway.dispatch(&h.admission, &other).await.unwrap().result["status"],
        "rejected"
    );
    let mut forged = call("tc_2", None);
    forged["evidence_refs"] = json!(["kg:forged"]);
    let out = h.gateway.dispatch(&h.admission, &forged).await.unwrap();
    assert_eq!(out.report.reason_codes, vec!["evidence_not_admitted".to_owned()]);
    let mut foreign = call("tc_3", None);
    foreign["run_id"] = json!("run_other");
    assert_eq!(
        h.gateway.dispatch(&h.admission, &foreign).await.unwrap().result["status"],
        "rejected"
    );
    assert_eq!(h.adapter.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn concurrent_duplicates_dispatch_once() {
    let h = Arc::new(harness("allow", Behavior::Confirm).await);
    let mut tasks = Vec::new();
    for i in 0..16 {
        let h = h.clone();
        tasks.push(tokio::spawn(async move {
            h.gateway
                .dispatch(&h.admission, &call(&format!("tc_{i}"), Some("refund_ord_881")))
                .await
                .unwrap()
        }));
    }
    let mut completed = 0;
    for task in tasks {
        if task.await.unwrap().result["status"] == "completed" {
            completed += 1;
        }
    }
    assert_eq!(completed, 1);
    assert_eq!(h.adapter.calls.load(Ordering::SeqCst), 1);
    let budget = ledger(&h, DocKind::BudgetLedger, &h.admission.budget_ledger_id).await;
    assert_eq!(budget["used"]["tool_calls"], json!(1));
    assert_eq!(budget["reserved"]["tool_calls"], json!(0));
}
