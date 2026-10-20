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
/// Runs while a dispatch is between its entry checks and its claim (to simulate a
/// takeover committed by another replica in that window).
type MidDispatchHook = Arc<dyn Fn() -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> + Send + Sync>;

#[derive(Default)]
struct Authority(std::sync::Mutex<Option<MidDispatchHook>>);
#[async_trait]
impl AuthorityProvider for Authority {
    async fn authority(&self, admission: &RunAdmission, binding: &Value) -> Result<AuthorityFacts, PortError> {
        let hook = self.0.lock().unwrap().take();
        if let Some(hook) = hook {
            hook().await;
        }
        let root_run_id = admission
            .lineage
            .as_ref()
            .map_or(admission.run_id.as_str(), |l| l.root_run_id.as_str());
        let mut scope = json!({
            "root_run_id": root_run_id, "purpose_ids": [binding["purpose_id"]],
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
        if admission.lineage.is_some() {
            return Ok(delegated_facts(admission, root_run_id, &scope));
        }
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

/// A broker's view of a delegated run: a root grant to the parent agent, and a
/// narrower grant from that agent to the child. The gateway is trusted to observe
/// run links because it creates the lineage.
fn delegated_facts(admission: &RunAdmission, root_run_id: &str, scope: &Value) -> AuthorityFacts {
    let grant = |id: &str, issuer: Value, subject: Value, depth: u64| {
        json!({
            "grant_id": id, "grant_revision": "1", "issuer": issuer, "subject": subject, "audience": "gateway.test",
            "scope": scope, "not_before": "2026-10-20T00:00:00Z", "expires_at": "2026-10-21T00:00:00Z",
            "delegation_depth_remaining": depth, "verification_ref": artifact("authority_grant", id),
        })
    };
    let root = grant("grant_root", principal("mandate_broker"), principal("agt_support"), 3);
    let mut leaf = grant("grant_child", principal("agt_support"), admission.actor.clone(), 2);
    leaf["parent_grant_ref"] = json!({"grant_id": "grant_root", "grant_revision": "1"});
    let observe = |g: &Value| {
        json!({
            "grant_id": g["grant_id"], "grant_revision": "1",
            "grant_digest": sha256_canonical(&json!({"domain": "contextos.authority_grant.v1", "grant": g})).unwrap(),
            "verification_ref": g["verification_ref"], "verification_status": "verified",
            "observed_at": "2026-10-20T09:59:00Z", "valid_until": "2026-10-20T11:00:00Z",
            "revocation_status": "active", "observer": principal("grant_observer"),
        })
    };
    AuthorityFacts {
        authenticated: json!({
            "principal": admission.actor, "audience": "gateway.test", "root_run_id": root_run_id,
            "run_id": admission.run_id, "mandate_kind": "workload", "trusted_issuers": [principal("mandate_broker")],
            "trusted_observers": [principal("grant_observer"), principal("gateway")], "verification_status": "verified",
            "verification_ref": artifact("authentication", "agt_research"),
            "observed_at": "2026-10-20T09:59:00Z", "valid_until": "2026-10-20T11:00:00Z",
        }),
        leaf_grant_ref: json!({"grant_id": "grant_child", "grant_revision": "1"}),
        observations: vec![observe(&root), observe(&leaf)],
        grants: vec![leaf, root],
        run_links: vec![],
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
    /// Returns an MCP-style task handle; the task completes on the second query.
    Task,
}

struct Payments {
    calls: AtomicUsize,
    queries: AtomicUsize,
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
            Behavior::Task => AdapterResponse {
                external_ref: Some("task_7f3a".into()),
                ..AdapterResponse::unknown()
            },
        }
    }

    async fn query(&self, _: &CapabilityManifest, call: &AdapterCall, external_ref: &str) -> Option<AdapterResponse> {
        if !matches!(self.behavior, Behavior::Task) {
            return None;
        }
        assert_eq!(external_ref, "task_7f3a");
        assert!(call.attempt_id.starts_with("query"), "queries use fresh request ids");
        if self.queries.fetch_add(1, Ordering::SeqCst) == 0 {
            return Some(AdapterResponse::unknown());
        }
        Some(AdapterResponse {
            outcome: EffectOutcome::Confirmed,
            definitive: true,
            output: serde_json::from_value(json!({"refund_id": "rf_task"})).unwrap(),
            external_ref: Some(external_ref.into()),
            cost_units: Some(40),
        })
    }
}

fn compiled() -> (CompiledContext, ContextPackCompiler, InvokeRequest, RunContext) {
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
    let compiler = ContextPackCompiler::new(pack).unwrap();
    let compiled = compiler.compile(&request, &run, &deps).unwrap();
    (compiled, compiler, request, run)
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
    authority: Arc<Authority>,
}

async fn harness(verdict: &'static str, behavior: Behavior) -> Harness {
    harness_with_limits(verdict, behavior, 8, 25.0).await
}

async fn harness_with_limits(verdict: &'static str, behavior: Behavior, tool_calls: u64, cost_cents: f64) -> Harness {
    let store = Arc::new(MemoryStore::new());
    let authority = Arc::new(Authority::default());
    let audit = Arc::new(AuditWriter::new(
        MemoryLog::new(),
        AuditSigner::from_seed("gw-1", [3; 32]),
    ));
    let approvals = Arc::new(Approvals::default());
    let ports = Ports {
        clock: Arc::new(FixedClock),
        ids: Arc::new(SeqIds::default()),
        authority: authority.clone(),
        policy: if verdict == "pinned" {
            Arc::new(PinnedPolicy)
        } else {
            Arc::new(Policy(verdict))
        },
        constraints: Arc::new(Constraints),
        approvals: approvals.clone(),
        idempotency: None,
    };
    let adapter = Arc::new(Payments {
        calls: AtomicUsize::new(0),
        queries: AtomicUsize::new(0),
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
    let (compiled, compiler, request, run_context) = compiled();
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
            compiler: &compiler,
            request: &request,
            run_context: &run_context,
            actor: principal("agt_support"),
            gateway_observer: principal("gateway"),
            deadline: "2026-10-20T11:00:00Z".into(),
            executor_generation: 1,
            limits: BudgetLimits {
                tokens: 10_000,
                tool_calls,
                replans: 2,
                cost_cents,
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
        authority,
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
    let key = operation_ledger_key(&h.admission, "refund_ord_881");
    let ops = h.store.get(&key).await.unwrap().unwrap().body;
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

#[tokio::test]
async fn pinned_pack_policy_governs_dispatch() {
    // The demo pack's R_HIGH_VALUE_REQUIRES_APPROVAL fired at compile time for this
    // support_agent refund above the threshold; admission pinned it.
    let h = harness("pinned", Behavior::Confirm).await;
    assert!(
        h.admission
            .policy_outcomes
            .iter()
            .any(|o| o["rule_id"] == "R_HIGH_VALUE_REQUIRES_APPROVAL" && o["verdict"] == "require_approval")
    );
    let out = h.gateway.dispatch(&h.admission, &call("tc_1", None)).await.unwrap();
    assert_eq!(out.result["status"], "paused");
    assert!(out.report.reason_codes.contains(&"approval_required".to_owned()));
    assert_eq!(h.adapter.calls.load(Ordering::SeqCst), 0);
}

fn operation_id_of(out: &DispatchOutcome) -> String {
    out.report.operation_id.clone().unwrap()
}

async fn operation(h: &Harness, operation_id: &str) -> Value {
    let key = operation_ledger_key(&h.admission, operation_id);
    h.store.get(&key).await.unwrap().unwrap().body["operations"][0].clone()
}

#[tokio::test]
async fn task_effects_are_reconciled_by_querying_the_provider() {
    let h = harness("allow", Behavior::Task).await;
    let out = h
        .gateway
        .dispatch(&h.admission, &call("tc_1", Some("refund_ord_881")))
        .await
        .unwrap();
    assert_eq!(out.result["status"], "paused");
    let op_id = operation_id_of(&out);

    let first = h
        .gateway
        .reconcile(&h.admission, &op_id, Resolution::Query)
        .await
        .unwrap();
    assert_eq!(first.status, "pending", "a running task stays unknown");
    assert_eq!(operation(&h, &op_id).await["outcome"], "unknown");

    let second = h
        .gateway
        .reconcile(&h.admission, &op_id, Resolution::Query)
        .await
        .unwrap();
    assert_eq!(second.status, "resolved");
    assert_eq!(second.outcome.as_deref(), Some("confirmed"));
    assert_eq!(second.output["refund_id"], "rf_task");
    let budget = ledger(&h, DocKind::BudgetLedger, &h.admission.budget_ledger_id).await;
    assert_eq!(budget["reservations"][0]["status"], "settled");
    assert_eq!(budget["reserved"]["cost_units"], 0, "the held reservation is released");

    let again = h
        .gateway
        .reconcile(&h.admission, &op_id, Resolution::Query)
        .await
        .unwrap();
    assert_eq!(again.status, "no_change");
    let retry = h
        .gateway
        .dispatch(&h.admission, &call("tc_2", Some("refund_ord_881")))
        .await
        .unwrap();
    assert_eq!(
        retry.report.reason_codes,
        vec!["retry_unsafe".to_owned()],
        "a confirmed effect is never redone"
    );
    assert_eq!(h.adapter.calls.load(Ordering::SeqCst), 1);
    verify_tenant_chain(h.audit.log(), TENANT, &keys()).await.unwrap();
}

#[tokio::test]
async fn lost_responses_need_an_operator_with_evidence() {
    let h = harness("allow", Behavior::Hang).await;
    let out = h
        .gateway
        .dispatch(&h.admission, &call("tc_1", Some("refund_ord_881")))
        .await
        .unwrap();
    let op_id = operation_id_of(&out);

    let query = h
        .gateway
        .reconcile(&h.admission, &op_id, Resolution::Query)
        .await
        .unwrap();
    assert_eq!(query.reason_codes, vec!["reconcile_requires_operator".to_owned()]);

    let unsupported = Resolution::Assert {
        outcome: EffectOutcome::NotApplied,
        evidence_ref: json!({"artifact_type": "ticket"}),
        principal_id: "ops_alice".into(),
    };
    let refused = h.gateway.reconcile(&h.admission, &op_id, unsupported).await.unwrap();
    assert_eq!(refused.reason_codes, vec!["reconcile_assertion_invalid".to_owned()]);
    assert_eq!(operation(&h, &op_id).await["outcome"], "unknown");

    let asserted = Resolution::Assert {
        outcome: EffectOutcome::NotApplied,
        evidence_ref: artifact("provider_ledger_extract", "payments-2026-10-20"),
        principal_id: "ops_alice".into(),
    };
    let resolved = h.gateway.reconcile(&h.admission, &op_id, asserted).await.unwrap();
    assert_eq!(resolved.status, "resolved");
    assert_eq!(resolved.outcome.as_deref(), Some("not_applied"));
    let budget = ledger(&h, DocKind::BudgetLedger, &h.admission.budget_ledger_id).await;
    assert_eq!(budget["reservations"][0]["status"], "settled");

    // A contradicting assertion cannot overwrite the recorded fact.
    let contradiction = Resolution::Assert {
        outcome: EffectOutcome::Confirmed,
        evidence_ref: artifact("provider_ledger_extract", "other"),
        principal_id: "ops_bob".into(),
    };
    assert_eq!(
        h.gateway
            .reconcile(&h.admission, &op_id, contradiction)
            .await
            .unwrap()
            .status,
        "no_change"
    );

    let rows = contextos_store::AppendLog::range(h.audit.log(), TENANT, 1, 100)
        .await
        .unwrap();
    let reconciliation = rows.iter().find(|r| r.body["kind"] == "effect_reconciliation").unwrap();
    assert_eq!(reconciliation.body["payload"]["principal_id"], "ops_alice");
    assert_eq!(reconciliation.body["payload"]["source"], "operator");
    verify_tenant_chain(h.audit.log(), TENANT, &keys()).await.unwrap();
}

#[tokio::test]
async fn long_runs_compact_their_budget_ledger() {
    let h = harness_with_limits("allow", Behavior::Confirm, 1_000, 100_000.0).await;
    for i in 0..150 {
        let out = h
            .gateway
            .dispatch(&h.admission, &call(&format!("tc_{i}"), Some(&format!("op_{i}"))))
            .await
            .unwrap();
        assert_eq!(
            out.result["status"], "completed",
            "effect {i}: {:?}",
            out.report.reason_codes
        );
    }
    let budget = ledger(&h, DocKind::BudgetLedger, &h.admission.budget_ledger_id).await;
    assert_eq!(budget["used"]["tool_calls"], 150, "every effect is accounted for");
    assert_eq!(budget["reserved"]["tool_calls"], 0);
    assert!(
        budget["mutations"].as_array().unwrap().len() <= BUDGET_COMPACT_AT,
        "the ledger stays small"
    );
    // The ledger names its latest archive, and every archive chains to its predecessor.
    let mut archive_id = budget["opening_usage_ref"]["artifact_id"].as_str().unwrap().to_owned();
    let mut archives = 0;
    while let Some(archive) = h
        .store
        .get(&DocKey::new(TENANT, DocKind::BudgetArchive, &archive_id))
        .await
        .unwrap()
    {
        archives += 1;
        match archive.body["previous_opening_usage_ref"]["artifact_id"].as_str() {
            Some(previous) if previous != h.admission.budget_ledger_id => previous.clone_into(&mut archive_id),
            _ => break,
        }
    }
    assert!(archives >= 8, "{archives} archives");
    verify_tenant_chain(h.audit.log(), TENANT, &keys()).await.unwrap();
}

fn envelope(h: &Harness, child: &str, capabilities: &[&str], policy: &str, max_tool_calls: u64) -> Value {
    json!({
        "envelope_version": "contextos.agent_delegation.v1", "delegation_id": format!("dlg_{child}"),
        "parent_run_id": "run_1", "child_run_id": child, "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736",
        "tenant_id": TENANT, "issuer": "agt_support", "subject": "agt_research",
        "principal_chain": [{"kind": "agent", "id": "agt_support"}, {"kind": "agent", "id": "agt_research"}],
        "scope": {"allowed_intents": [compiled().2.input.intent], "allowed_capabilities": capabilities,
            "data_classification_ceiling": "CONFIDENTIAL", "output_schema_ref": "schema://refund-evidence.v1"},
        "sub_budget": {"total_tokens": 100, "bucket_tokens": {}, "max_tool_calls": max_tool_calls, "max_replan_attempts": 0,
            "wall_clock_ms": 60_000, "max_cost_cents": 5},
        "effect_policy": policy, "issued_at": "2026-10-20T09:59:00Z", "expires_at": "2026-10-20T10:30:00Z",
        "parent_claim_hash": h.admission.compiled_context_hash,
    })
}

async fn delegate(h: &Harness, envelope: &Value) -> Result<RunAdmission, AdmissionError> {
    let child = envelope["child_run_id"].as_str().unwrap();
    let (_, compiler, request, mut run_context) = compiled();
    run_context.run_id = child.to_owned();
    let compiled = compiler
        .compile(
            &request,
            &run_context,
            &CompileDeps {
                evidence: compiled_evidence(),
                ..CompileDeps::default()
            },
        )
        .unwrap();
    let registry = &*STANDARD_PROFILE_REGISTRY;
    let contract = json!({"envelope_version": "contextos.execution_contract.v1", "contract_id": format!("contract_{child}"),
        "run_id": child, "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736", "tenant_id": TENANT,
        "profiles": [{"profile_id": "contextos.core", "profile_version": "1"}], "required_controls": [],
        "optional_controls": [], "release_refs": [artifact("release", "runtime@0.1.0")]});
    let support = json!({"implementation_id": "contextos-rs", "implementation_version": "0.1.0",
        "supported_profiles": registry.profiles.iter().map(|p| &p.profile).collect::<Vec<_>>(),
        "supported_controls": registry.controls.iter().map(|c| &c.control).collect::<Vec<_>>()});
    h.gateway
        .delegate(
            &h.admission,
            envelope,
            AdmissionRequest {
                contract: &contract,
                support: &support,
                registry,
                features: WorkflowFeatureSet {
                    external_effects: true,
                    ..WorkflowFeatureSet::default()
                },
                compiled: &compiled,
                compiler: &compiler,
                request: &request,
                run_context: &run_context,
                actor: principal("agt_research"),
                gateway_observer: principal("gateway"),
                deadline: String::new(),
                executor_generation: 1,
                limits: BudgetLimits {
                    tokens: 0,
                    tool_calls: 0,
                    replans: 0,
                    cost_cents: 0.0,
                },
            },
        )
        .await
}

fn child_call(run_id: &str, id: &str) -> Value {
    let mut c = call(id, Some(&format!("{run_id}:{id}")));
    c["run_id"] = json!(run_id);
    c
}

#[tokio::test]
async fn delegated_children_act_within_a_narrowed_lane_and_settle_into_the_parent() {
    let h = harness_with_limits("allow", Behavior::Confirm, 20, 100.0).await;
    let child = delegate(
        &h,
        &envelope(
            &h,
            "run_child",
            &["adp_payments.issue_refund"],
            "isolate_until_accepted",
            2,
        ),
    )
    .await
    .unwrap();
    assert_eq!(child.lineage.as_ref().unwrap().root_run_id, "run_1");
    let parent_budget = ledger(&h, DocKind::BudgetLedger, &h.admission.budget_ledger_id).await;
    assert_eq!(
        parent_budget["reserved"]["tool_calls"], 2,
        "the sub-budget is reserved from the parent first"
    );

    let out = h
        .gateway
        .dispatch(&child, &child_call("run_child", "tc_1"))
        .await
        .unwrap();
    assert_eq!(out.result["status"], "completed", "{:?}", out.report.reason_codes);
    let out = h
        .gateway
        .dispatch(&child, &child_call("run_child", "tc_2"))
        .await
        .unwrap();
    assert_eq!(out.result["status"], "completed");
    let out = h
        .gateway
        .dispatch(&child, &child_call("run_child", "tc_3"))
        .await
        .unwrap();
    assert_eq!(
        out.result["status"], "blocked",
        "the child cannot exceed its sub-budget"
    );

    let closed = h
        .gateway
        .close_delegation(&h.admission, &child, CloseDecision::Accept, "agt_support")
        .await
        .unwrap();
    assert_eq!(closed.status, "closed", "{:?}", closed.reason_codes);
    assert_eq!(closed.usage.as_ref().unwrap()["tool_calls"], 2);
    let parent_budget = ledger(&h, DocKind::BudgetLedger, &h.admission.budget_ledger_id).await;
    assert_eq!(
        parent_budget["used"]["tool_calls"], 2,
        "the child's usage is the parent's"
    );
    assert_eq!(parent_budget["reserved"]["tool_calls"], 0);
    let again = h
        .gateway
        .close_delegation(&h.admission, &child, CloseDecision::Accept, "agt_support")
        .await
        .unwrap();
    assert_eq!(
        again.status, "closed",
        "closing is idempotent: {:?}",
        again.reason_codes
    );
    let parent_budget = ledger(&h, DocKind::BudgetLedger, &h.admission.budget_ledger_id).await;
    assert_eq!(parent_budget["used"]["tool_calls"], 2, "and never double counts");
    verify_tenant_chain(h.audit.log(), TENANT, &keys()).await.unwrap();
}

#[tokio::test]
async fn closed_children_cannot_spend() {
    let h = harness_with_limits("allow", Behavior::Confirm, 20, 100.0).await;
    let child = delegate(
        &h,
        &envelope(
            &h,
            "run_child",
            &["adp_payments.issue_refund"],
            "isolate_until_accepted",
            5,
        ),
    )
    .await
    .unwrap();
    h.gateway
        .close_delegation(&h.admission, &child, CloseDecision::Reject, "agt_support")
        .await
        .unwrap();
    let out = h
        .gateway
        .dispatch(&child, &child_call("run_child", "tc_late"))
        .await
        .unwrap();
    assert_eq!(out.result["status"], "blocked");
    assert_eq!(h.adapter.calls.load(Ordering::SeqCst), 0);
    let parent_budget = ledger(&h, DocKind::BudgetLedger, &h.admission.budget_ledger_id).await;
    assert_eq!(
        parent_budget["reserved"]["tool_calls"], 0,
        "unused sub-budget returned to the parent"
    );
}

#[tokio::test]
async fn delegations_cannot_widen_the_parent() {
    let h = harness_with_limits("allow", Behavior::Confirm, 20, 100.0).await;
    let reason = |r: Result<RunAdmission, AdmissionError>| match r {
        Err(AdmissionError::Delegation(reasons)) => reasons,
        other => panic!("{other:?}"),
    };
    let mut e = envelope(
        &h,
        "run_c1",
        &["adp_payments.issue_refund", "adp_crm.delete_customer"],
        "read_only",
        1,
    );
    assert_eq!(reason(delegate(&h, &e).await), vec!["delegation_scope_expanded"]);
    e = envelope(&h, "run_c2", &["adp_payments.issue_refund"], "read_only", 1);
    e["expires_at"] = json!("2026-10-20T12:00:00Z");
    assert_eq!(
        reason(delegate(&h, &e).await),
        vec!["delegation_expired_or_exceeds_parent"]
    );
    e = envelope(&h, "run_c3", &["adp_payments.issue_refund"], "read_only", 1);
    e["parent_claim_hash"] = json!("sha256:forged");
    assert_eq!(reason(delegate(&h, &e).await), vec!["delegation_claim_mismatch"]);
    e = envelope(&h, "run_c4", &["adp_payments.issue_refund"], "read_only", 1);
    e["issuer"] = json!("agt_someone_else");
    assert_eq!(reason(delegate(&h, &e).await), vec!["delegation_principal_mismatch"]);
    let too_big = envelope(&h, "run_c5", &["adp_payments.issue_refund"], "read_only", 21);
    assert!(
        matches!(delegate(&h, &too_big).await, Err(AdmissionError::Delegation(_))),
        "sub-budget beyond the parent"
    );

    // A read-only child never sees effectful capabilities.
    let ro = delegate(
        &h,
        &envelope(&h, "run_ro", &["adp_payments.issue_refund"], "read_only", 1),
    )
    .await
    .unwrap();
    assert!(ro.surfaced_capabilities.is_empty());
    let out = h.gateway.dispatch(&ro, &child_call("run_ro", "tc_1")).await.unwrap();
    assert_eq!(out.report.reason_codes, vec!["capability_not_surfaced".to_owned()]);
}

fn compiled_evidence() -> Vec<Value> {
    let path = format!("{}/../../conformance/vectors/compiler.json", env!("CARGO_MANIFEST_DIR"));
    let vectors: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    vectors["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "grid:support.refund:true:4200:support_agent")
        .unwrap()["deps"]["evidence"]
        .as_array()
        .unwrap()
        .clone()
}

async fn running(h: &Harness) -> u64 {
    match h.gateway.open_run(&h.admission).await.unwrap() {
        Ownership::Current(generation) => generation,
        other @ Ownership::Refused(_) => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn runs_complete_only_when_every_effect_is_resolved() {
    let h = harness("allow", Behavior::Hang).await;
    let generation = running(&h).await;
    let out = h
        .gateway
        .dispatch_as(&h.admission, &call("tc_1", Some("refund_ord_881")), generation)
        .await
        .unwrap();
    assert_eq!(out.result["status"], "paused");
    let op_id = out.report.operation_id.clone().unwrap();

    let refused = h.gateway.complete_run(&h.admission, generation).await.unwrap();
    assert_eq!(
        refused.reason_codes,
        vec!["required_effect_unsatisfied".to_owned()],
        "an unknown effect blocks completion"
    );

    let resolved = h
        .gateway
        .reconcile(
            &h.admission,
            &op_id,
            Resolution::Assert {
                outcome: EffectOutcome::Confirmed,
                evidence_ref: artifact("provider_ledger_extract", "refund-ord-881"),
                principal_id: "ops_alice".into(),
            },
        )
        .await
        .unwrap();
    assert_eq!(resolved.status, "resolved");
    let stale = h.gateway.complete_run(&h.admission, generation - 1).await.unwrap();
    assert_eq!(stale.reason_codes, vec!["executor_stale".to_owned()]);
    let done = h.gateway.complete_run(&h.admission, generation).await.unwrap();
    assert_eq!(done.status, "completed", "{:?}", done.reason_codes);

    let after = h
        .gateway
        .dispatch(&h.admission, &call("tc_2", Some("op_after")))
        .await
        .unwrap();
    assert_eq!(after.report.reason_codes, vec!["run_not_running".to_owned()]);
    verify_tenant_chain(h.audit.log(), TENANT, &keys()).await.unwrap();
}

#[tokio::test]
async fn cancelling_a_parent_stops_and_settles_its_children() {
    let h = harness_with_limits("allow", Behavior::Confirm, 20, 100.0).await;
    let generation = running(&h).await;
    let child = delegate(
        &h,
        &envelope(
            &h,
            "run_child",
            &["adp_payments.issue_refund"],
            "isolate_until_accepted",
            3,
        ),
    )
    .await
    .unwrap();
    let child_generation = match h.gateway.open_run(&child).await.unwrap() {
        Ownership::Current(g) => g,
        other @ Ownership::Refused(_) => panic!("{other:?}"),
    };
    // The store holds admissions so cancellation can find children.
    h.store
        .create(
            &DocKey::new(TENANT, DocKind::RunAdmission, "run_child"),
            &serde_json::to_value(&child).unwrap(),
        )
        .await
        .unwrap();
    let out = h
        .gateway
        .dispatch_as(&child, &child_call("run_child", "tc_1"), child_generation)
        .await
        .unwrap();
    assert_eq!(out.result["status"], "completed");
    let parent_state = h.gateway.run_state(&h.admission).await.unwrap().unwrap();
    assert_eq!(parent_state["child_run_ids"], json!(["run_child"]));
    let refused = h.gateway.complete_run(&h.admission, generation).await.unwrap();
    assert_eq!(refused.reason_codes, vec!["children_unsettled".to_owned()]);

    let cancelled = h.gateway.cancel_run(&h.admission, "ops_alice").await.unwrap();
    assert_eq!(cancelled.status, "cancelled", "{cancelled:?}");
    let child_state = h.gateway.run_state(&child).await.unwrap().unwrap();
    assert_eq!(child_state["status"], "cancelled");
    let parent_budget = ledger(&h, DocKind::BudgetLedger, &h.admission.budget_ledger_id).await;
    assert_eq!(
        parent_budget["used"]["tool_calls"], 1,
        "the child's spend is settled into the parent"
    );
    assert_eq!(parent_budget["reserved"]["tool_calls"], 0);
    let late = h
        .gateway
        .dispatch_as(&child, &child_call("run_child", "tc_2"), child_generation)
        .await
        .unwrap();
    assert_eq!(late.result["status"], "rejected");
    let again = h.gateway.cancel_run(&h.admission, "ops_alice").await.unwrap();
    assert_eq!(again.status, "cancelled", "cancelling is idempotent in effect");
}

#[tokio::test]
async fn replayed_delegations_never_release_the_live_childs_budget() {
    let h = harness_with_limits("allow", Behavior::Confirm, 20, 100.0).await;
    let e = envelope(
        &h,
        "run_child",
        &["adp_payments.issue_refund"],
        "isolate_until_accepted",
        3,
    );
    delegate(&h, &e).await.unwrap();
    assert!(delegate(&h, &e).await.is_err(), "the child already exists");
    let parent_budget = ledger(&h, DocKind::BudgetLedger, &h.admission.budget_ledger_id).await;
    let reservation = parent_budget["reservations"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["reservation_id"] == "delegation:run_child")
        .cloned()
        .unwrap();
    assert_eq!(
        reservation["status"], "reserved",
        "the live child's allocation stays reserved"
    );
    assert_eq!(parent_budget["reserved"]["tool_calls"], 3);
}

#[tokio::test]
async fn a_takeover_mid_dispatch_stops_the_effect_before_the_provider() {
    let h = harness("allow", Behavior::Confirm).await;
    let generation = running(&h).await;
    // Another replica takes the run over while this dispatch is being authorized.
    let store = h.store.clone();
    let key = DocKey::new(TENANT, DocKind::RunState, &h.admission.run_id);
    *h.authority.0.lock().unwrap() = Some(Arc::new(move || {
        let store = store.clone();
        let key = key.clone();
        Box::pin(async move {
            let read = store.get(&key).await.unwrap().unwrap();
            let mut taken = read.body.clone();
            taken["executor_generation"] = json!(read.body["executor_generation"].as_u64().unwrap() + 2);
            store.compare_and_swap(&key, read.revision, &taken).await.unwrap();
        })
    }));
    let out = h
        .gateway
        .dispatch_as(&h.admission, &call("tc_1", Some("refund_ord_881")), generation)
        .await
        .unwrap();
    assert_eq!(out.report.reason_codes, vec!["executor_stale".to_owned()]);
    assert_eq!(
        h.adapter.calls.load(Ordering::SeqCst),
        0,
        "nothing reaches the provider"
    );
    let op = operation(&h, "refund_ord_881").await;
    assert_eq!(
        op["outcome"], "not_dispatched",
        "the withheld attempt is recorded definitively"
    );
    let budget = ledger(&h, DocKind::BudgetLedger, &h.admission.budget_ledger_id).await;
    assert_eq!(budget["reserved"]["tool_calls"], 0, "its reservation is released");
}

#[tokio::test]
async fn closing_a_child_ends_its_run() {
    let h = harness_with_limits("allow", Behavior::Confirm, 20, 100.0).await;
    running(&h).await;
    for (child_id, decision, ended) in [
        ("run_ok", CloseDecision::Accept, "completed"),
        ("run_no", CloseDecision::Reject, "cancelled"),
    ] {
        let child = delegate(
            &h,
            &envelope(
                &h,
                child_id,
                &["adp_payments.issue_refund"],
                "isolate_until_accepted",
                2,
            ),
        )
        .await
        .unwrap();
        let generation = match h.gateway.open_run(&child).await.unwrap() {
            Ownership::Current(g) => g,
            other @ Ownership::Refused(_) => panic!("{other:?}"),
        };
        let closed = h
            .gateway
            .close_delegation(&h.admission, &child, decision, "agt_support")
            .await
            .unwrap();
        assert_eq!(closed.status, "closed");
        assert_eq!(h.gateway.run_state(&child).await.unwrap().unwrap()["status"], ended);
        let late = h
            .gateway
            .dispatch_as(&child, &child_call(child_id, "tc_late"), generation)
            .await
            .unwrap();
        assert_eq!(late.result["status"], "rejected", "a closed child cannot act");
    }
    assert_eq!(h.adapter.calls.load(Ordering::SeqCst), 0);
}
