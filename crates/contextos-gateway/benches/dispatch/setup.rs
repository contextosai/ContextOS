//! The compiled pack, pinned capability, gateway wiring, run admission and tool calls.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use contextos_audit::{AuditSigner, AuditWriter};
use contextos_contract::canonical::sha256_canonical;
use contextos_contract::execution::WorkflowFeatureSet;
use contextos_contract::types::{CompiledContext, ContextPack, InvokeRequest, RunContext};
use contextos_gateway::*;
use contextos_kernel::{CompileDeps, ContextPackCompiler, STANDARD_PROFILE_REGISTRY};
use contextos_store::{AppendLog, DocumentStore};
use serde_json::{Value, json};

use crate::fakes::{Approvals, Authority, Behavior, Constraints, FixedClock, Payments, Policy, SeqIds};

pub(crate) const TENANT: &str = "tenant_acme_prod";
pub(crate) const NOW: &str = "2026-10-20T10:00:00.000000Z";

pub(crate) fn artifact(kind: &str, id: &str) -> Value {
    json!({"artifact_type": kind, "artifact_id": id, "version": "1",
        "sha256": sha256_canonical(&json!({"artifact_type": kind, "artifact_id": id})).unwrap()})
}

pub(crate) fn principal(id: &str) -> Value {
    json!({"principal_id": id, "principal_type": "workload", "trust_domain": "contextos.test", "tenant_id": TENANT})
}

pub(crate) fn compiled() -> (CompiledContext, ContextPackCompiler, InvokeRequest, RunContext) {
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

pub(crate) fn manifest() -> CapabilityManifest {
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

pub(crate) struct Setup<S, L> {
    pub(crate) gateway: Arc<Gateway<S, L>>,
    pub(crate) store: Arc<S>,
}

pub(crate) fn setup<S: DocumentStore + 'static, L: AppendLog + 'static>(store: Arc<S>, log: L) -> Setup<S, L> {
    let audit = Arc::new(AuditWriter::new(log, AuditSigner::from_seed("gw-1", [3; 32])));
    let ports = Ports {
        clock: Arc::new(FixedClock),
        ids: Arc::new(SeqIds::default()),
        authority: Arc::new(Authority),
        policy: Arc::new(Policy("allow")),
        constraints: Arc::new(Constraints),
        approvals: Arc::new(Approvals::default()),
        idempotency: None,
        data_flow: None,
        boundary: None,
        memory: None,
    };
    let adapter = Arc::new(Payments {
        calls: AtomicUsize::new(0),
        behavior: Behavior::Confirm,
    });
    let mut gateway = Gateway::new(store.clone(), audit, ports);
    // contextosd's default guards; CONTEXTOS_BENCH_GUARDS=off measures without them.
    if std::env::var("CONTEXTOS_BENCH_GUARDS").as_deref() != Ok("off") {
        gateway.set_loop_limit(Some(5));
        gateway.set_refuse_repeated_effects(true);
    }
    gateway.register_adapter("adp_payments", adapter);
    gateway.pin_capability(manifest()).unwrap();
    Setup {
        gateway: Arc::new(gateway),
        store,
    }
}

pub(crate) static RUNS: AtomicU64 = AtomicU64::new(0);

/// Admits a fresh run (unique id, so a persistent store can be reused).
pub(crate) async fn admit<S: DocumentStore + 'static>(store: &S) -> RunAdmission {
    let run_id = format!("run_{}_{}", std::process::id(), RUNS.fetch_add(1, Ordering::Relaxed));
    let registry = &*STANDARD_PROFILE_REGISTRY;
    let contract = json!({"envelope_version": "contextos.execution_contract.v1", "contract_id": format!("contract_{run_id}"),
        "run_id": run_id, "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736", "tenant_id": TENANT,
        "profiles": [{"profile_id": "contextos.core", "profile_version": "1"}], "required_controls": [],
        "optional_controls": [], "release_refs": [artifact("release", "runtime@0.1.0")]});
    let support = json!({"implementation_id": "contextos-rs", "implementation_version": "0.1.0",
        "supported_profiles": registry.profiles.iter().map(|p| &p.profile).collect::<Vec<_>>(),
        "supported_controls": registry.controls.iter().map(|c| &c.control).collect::<Vec<_>>()});
    let (compiled, compiler, request, mut run_context) = compiled();
    run_context.run_id.clone_from(&run_id);
    admit_run(
        store,
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
            admitted_at: "2026-10-20T10:00:00Z".into(),
            admitted_by: "svc_orchestrator".into(),
            executor_generation: 1,
            limits: BudgetLimits {
                tokens: 10_000,
                tool_calls: 1_000,
                replans: 2,
                cost_cents: 100_000.0,
            },
        },
    )
    .await
    .unwrap()
}

/// The `n`th refund of a run: a distinct amount each, so it is a distinct effect.
pub(crate) fn call(run_id: &str, id: &str, idempotency_key: &str, n: u64) -> Value {
    json!({"envelope_version": "contextos.tool_call.v1", "tool_call_id": id, "run_id": run_id,
        "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736", "capability_id": "adp_payments.issue_refund",
        "args": {"order_id": "ord_881", "customer_id": "cus_77", "amount_minor": 420_000 + n},
        "principal_chain": [{"kind": "agent", "id": "agt_support"}],
        "approval_mode_requested": "destructive", "approval_mode_effective": "destructive", "approval_mode_highest": "destructive",
        "evidence_refs": ["kg:order:ord_881#snapshot_kg_2026_05_03_T0930"], "idempotency_key": idempotency_key})
}
