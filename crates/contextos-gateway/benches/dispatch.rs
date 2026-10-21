//! Full governed dispatch latency (memory store, signed audit, instant fake
//! providers): what the gateway adds on top of the provider call.

#![allow(clippy::all, clippy::pedantic, dead_code)]

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use contextos_audit::{AuditSigner, AuditWriter};
use contextos_contract::canonical::sha256_canonical;
use contextos_contract::execution::WorkflowFeatureSet;
use contextos_contract::types::{CompiledContext, ContextPack, InvokeRequest, RunContext};
use contextos_gateway::*;
use contextos_kernel::{CompileDeps, ContextPackCompiler, STANDARD_PROFILE_REGISTRY};
use contextos_store::{
    AppendLog, DocKey, DocKind, DocumentStore, Encoded, MemoryLog, MemoryStore, ScanCursor, StoreError, Versioned,
};
use criterion::{Criterion, criterion_group, criterion_main};
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

struct Setup<S, L> {
    gateway: Arc<Gateway<S, L>>,
    store: Arc<S>,
}

fn setup<S: DocumentStore + 'static, L: AppendLog + 'static>(store: Arc<S>, log: L) -> Setup<S, L> {
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

static RUNS: AtomicU64 = AtomicU64::new(0);

/// Admits a fresh run (unique id, so a persistent store can be reused).
async fn admit<S: DocumentStore + 'static>(store: &S) -> RunAdmission {
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
fn call(run_id: &str, id: &str, idempotency_key: &str, n: u64) -> Value {
    json!({"envelope_version": "contextos.tool_call.v1", "tool_call_id": id, "run_id": run_id,
        "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736", "capability_id": "adp_payments.issue_refund",
        "args": {"order_id": "ord_881", "customer_id": "cus_77", "amount_minor": 420_000 + n},
        "principal_chain": [{"kind": "agent", "id": "agt_support"}],
        "approval_mode_requested": "destructive", "approval_mode_effective": "destructive", "approval_mode_highest": "destructive",
        "evidence_refs": ["kg:order:ord_881#snapshot_kg_2026_05_03_T0930"], "idempotency_key": idempotency_key})
}

/// Sequential effects within fresh runs: per-effect latency.
async fn sequential<S: DocumentStore + 'static, L: AppendLog + 'static>(s: &Setup<S, L>, iterations: u64) -> Duration {
    let mut total = Duration::ZERO;
    let mut done = 0;
    while done < iterations {
        let admission = admit(s.store.as_ref()).await;
        let batch = (iterations - done).min(50);
        for i in 0..batch {
            let envelope = call(&admission.run_id, &format!("tc_{i}"), &format!("op_{i}"), i);
            let started = Instant::now();
            let out = s.gateway.dispatch(&admission, &envelope).await.unwrap();
            total += started.elapsed();
            assert_eq!(out.result["status"], "completed");
        }
        done += batch;
    }
    total
}

/// `RUNS_IN_PARALLEL` runs of one tenant, `EFFECTS_PER_RUN` effects each, dispatching
/// at once through one gateway, store and audit writer. Reported time per effect is
/// wall time / effects, so its inverse is single-tenant throughput.
const RUNS_IN_PARALLEL: u64 = 32;
const EFFECTS_PER_RUN: u64 = 50;

async fn concurrent<S: DocumentStore + 'static, L: AppendLog + 'static>(s: &Setup<S, L>, iterations: u64) -> Duration {
    let mut admissions = Vec::new();
    for _ in 0..RUNS_IN_PARALLEL {
        admissions.push(admit(s.store.as_ref()).await);
    }
    let started = Instant::now();
    let mut tasks = Vec::new();
    for admission in admissions {
        let gateway = s.gateway.clone();
        tasks.push(tokio::spawn(async move {
            for i in 0..EFFECTS_PER_RUN {
                let envelope = call(&admission.run_id, &format!("tc_{i}"), &format!("op_{i}"), i);
                let out = gateway.dispatch(&admission, &envelope).await.unwrap();
                assert_eq!(out.result["status"], "completed");
            }
        }));
    }
    for task in tasks {
        task.await.unwrap();
    }
    let effects = EFFECTS_PER_RUN * RUNS_IN_PARALLEL;
    // Scale to the requested iteration count.
    started.elapsed().mul_f64(iterations as f64 / effects as f64)
}

/// Counts document-store operations, and reports reads as expensive so the gateway
/// takes the paths it takes on PostgreSQL, where every operation is a round trip.
struct Counting {
    inner: MemoryStore,
    reads: AtomicU64,
    writes: AtomicU64,
}

impl DocumentStore for Counting {
    async fn get(&self, key: &DocKey) -> Result<Option<Versioned>, StoreError> {
        self.reads.fetch_add(1, Ordering::Relaxed);
        self.inner.get(key).await
    }
    async fn create(&self, key: &DocKey, body: &Value) -> Result<Versioned, StoreError> {
        self.writes.fetch_add(1, Ordering::Relaxed);
        self.inner.create(key, body).await
    }
    async fn compare_and_swap(&self, key: &DocKey, expected: u64, body: &Value) -> Result<Versioned, StoreError> {
        self.writes.fetch_add(1, Ordering::Relaxed);
        self.inner.compare_and_swap(key, expected, body).await
    }
    async fn compare_and_swap_encoded(
        &self,
        key: &DocKey,
        expected: u64,
        body: Value,
        encoded: Encoded,
    ) -> Result<u64, StoreError> {
        self.writes.fetch_add(1, Ordering::Relaxed);
        self.inner.compare_and_swap_encoded(key, expected, body, encoded).await
    }
    async fn expiring(
        &self,
        kind: DocKind,
        before_us: u64,
        after: Option<&ScanCursor>,
        limit: usize,
    ) -> Result<Vec<ScanCursor>, StoreError> {
        self.inner.expiring(kind, before_us, after, limit).await
    }
}

/// `CONTEXTOS_BENCH_COUNT=1`: store reads and writes per sequential effect (round trips
/// on PostgreSQL, besides the audit batch), instead of timings.
fn count_round_trips(runtime: &tokio::runtime::Runtime) {
    let store = Arc::new(Counting { inner: MemoryStore::new(), reads: AtomicU64::new(0), writes: AtomicU64::new(0) });
    let s = setup(store.clone(), MemoryLog::new());
    runtime.block_on(async {
        let admission = admit(s.store.as_ref()).await;
        // The first effect creates the run's ledgers; count the steady state.
        let first = call(&admission.run_id, "tc_first", "op_first", 100);
        s.gateway.dispatch(&admission, &first).await.unwrap();
        let (reads, writes) = (store.reads.load(Ordering::Relaxed), store.writes.load(Ordering::Relaxed));
        for i in 0..10 {
            let envelope = call(&admission.run_id, &format!("tc_{i}"), &format!("op_{i}"), i);
            assert_eq!(s.gateway.dispatch(&admission, &envelope).await.unwrap().result["status"], "completed");
        }
        let per = |now: u64, then: u64| (now - then) as f64 / 10.0;
        println!(
            "store operations per effect: {:.1} reads, {:.1} writes",
            per(store.reads.load(Ordering::Relaxed), reads),
            per(store.writes.load(Ordering::Relaxed), writes)
        );
    });
}

fn bench(c: &mut Criterion) {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    if std::env::var("CONTEXTOS_BENCH_COUNT").is_ok() {
        count_round_trips(&runtime);
        return;
    }
    let memory = setup(Arc::new(MemoryStore::new()), MemoryLog::new());
    c.bench_function("gateway_dispatch_completed", |b| {
        b.to_async(&runtime).iter_custom(|n| sequential(&memory, n))
    });
    c.bench_function("gateway_dispatch_concurrent_32_runs", |b| {
        b.to_async(&runtime).iter_custom(|n| concurrent(&memory, n))
    });

    // PostgreSQL: set CONTEXTOS_BENCH_DATABASE_URL to a disposable database.
    if let Ok(url) = std::env::var("CONTEXTOS_BENCH_DATABASE_URL") {
        let store = runtime.block_on(async {
            let store = contextos_store::postgres::PostgresStore::connect(&url, 64)
                .await
                .unwrap();
            store.migrate().await.unwrap();
            store
        });
        let postgres = setup(Arc::new(store.clone()), store);
        let mut group = c.benchmark_group("postgres");
        group.sample_size(20);
        group.bench_function("gateway_dispatch_completed", |b| {
            b.to_async(&runtime).iter_custom(|n| sequential(&postgres, n))
        });
        group.bench_function("gateway_dispatch_concurrent_32_runs", |b| {
            b.to_async(&runtime).iter_custom(|n| concurrent(&postgres, n))
        });
        group.finish();
    }
}

#[global_allocator]
static ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;

criterion_group!(dispatch, bench);
criterion_main!(dispatch);
