//! Shared by the outcome suites: a refund provider that names its effects, an
//! effect-binding outcome contract, runtime processes over any store, and a store that
//! crashes at a chosen write.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use tokio::sync::Notify;

use async_trait::async_trait;
use contextos_gateway::outcomes::WitnessObservation;
use contextos_gateway::*;
use contextos_store::{DocKey, DocKind, DocumentStore, MemoryLog, StoreError, Versioned};
use serde_json::{Value, json};

use super::*;

pub const LEDGER: &str = "https://ledger.example.test";
pub const LATER: &str = "2026-10-20T10:30:00.000000Z";

/// A refund provider that names each effect by its own reference.
pub struct Provider {
    outcome: EffectOutcome,
    /// Fixed reference for every effect (a provider that reuses them); else per operation.
    reference: Option<&'static str>,
    calls: AtomicUsize,
}

#[async_trait]
impl Adapter for Provider {
    async fn invoke(&self, _: &CapabilityManifest, call: &AdapterCall) -> AdapterResponse {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let reference = self
            .reference
            .map_or_else(|| format!("rf_{}", call.operation_id), str::to_owned);
        AdapterResponse {
            outcome: self.outcome,
            definitive: self.outcome != EffectOutcome::Unknown,
            output: serde_json::Map::default(),
            external_ref: match self.outcome {
                EffectOutcome::Confirmed => Some(reference),
                // An accepted job the provider can be asked about.
                EffectOutcome::Unknown => Some(format!("job_{}", call.operation_id)),
                _ => None,
            },
            cost_units: Some(40),
        }
    }

    /// The job finished: the refund posted, under its own reference.
    async fn query(&self, _: &CapabilityManifest, call: &AdapterCall, job: &str) -> Option<AdapterResponse> {
        let operation = job.strip_prefix("job_")?;
        assert_eq!(operation, call.operation_id);
        Some(AdapterResponse {
            outcome: EffectOutcome::Confirmed,
            definitive: true,
            output: serde_json::Map::default(),
            external_ref: Some(format!("rf_{operation}")),
            cost_units: Some(40),
        })
    }
}

impl Provider {
    /// How many effects were sent to it.
    pub fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

pub fn provider(outcome: EffectOutcome, reference: Option<&'static str>) -> Arc<Provider> {
    Arc::new(Provider {
        outcome,
        reference,
        calls: AtomicUsize::new(0),
    })
}

pub struct Clocked(&'static str);
impl Clock for Clocked {
    fn now(&self) -> String {
        self.0.into()
    }
}

/// The refund capability with an effect-binding outcome contract.
pub fn outcome_manifest() -> CapabilityManifest {
    let mut m = serde_json::to_value(manifest()).unwrap();
    m["outcome"] =
        json!({"witness": LEDGER, "postcondition": "refund_posted", "within_seconds": 900, "binds": "effect"});
    m["recovery"]["reference_pointer"] = json!("/refund_id");
    serde_json::from_value(m).unwrap()
}

/// One process of the runtime over `store`.
pub fn process<S: DocumentStore + 'static>(
    store: Arc<S>,
    audit: &Arc<contextos_audit::AuditWriter<MemoryLog>>,
    adapter: Arc<dyn Adapter>,
    ids: u64,
    clock: &'static str,
) -> Gateway<S, MemoryLog> {
    let ports = Ports {
        clock: Arc::new(Clocked(clock)),
        ids: Arc::new(SeqIds(AtomicU64::new(ids))),
        authority: Arc::new(Authority::default()),
        policy: Arc::new(Policy("allow")),
        constraints: Arc::new(Constraints),
        approvals: Arc::new(Approvals::default()),
        idempotency: None,
        data_flow: None,
        boundary: None,
        memory: None,
    };
    let mut g = Gateway::new(store, audit.clone(), ports);
    g.register_adapter("adp_payments", adapter);
    g.pin_capability(outcome_manifest()).unwrap();
    g
}

pub fn audit() -> Arc<contextos_audit::AuditWriter<MemoryLog>> {
    Arc::new(contextos_audit::AuditWriter::new(
        MemoryLog::new(),
        contextos_audit::AuditSigner::from_seed("gw-1", [3; 32]),
    ))
}

pub fn seen(receipt: &str, digest: &str) -> WitnessObservation {
    WitnessObservation {
        issuer: LEDGER.into(),
        subject: "ord_881".into(),
        // After every effect in these tests, the restarted process's included.
        observed_at: "2026-10-20T10:45:00.000000Z".into(),
        valid_until: "2026-10-20T12:00:00.000000Z".into(),
        amount: Some(json!({"minor_units": 420_000, "currency": "INR"})),
        receipt: Some(receipt.into()),
        attestation_digest: format!("sha256:{digest}"),
    }
}

/// Admits and opens `run_1` on `store`, as contextosd does at admission.
pub async fn admitted<S: DocumentStore + 'static>(store: &Arc<S>) -> RunAdmission {
    let admission = admit_test_run(store.as_ref(), 8, 25.0).await;
    open(store, &admission).await;
    admission
}

pub async fn open<S: DocumentStore + 'static>(store: &Arc<S>, admission: &RunAdmission) {
    store
        .create(
            &DocKey::new(TENANT, DocKind::RunAdmission, &admission.run_id),
            &serde_json::to_value(admission).unwrap(),
        )
        .await
        .unwrap();
    process(
        store.clone(),
        &audit(),
        provider(EffectOutcome::Confirmed, None),
        1,
        NOW,
    )
    .open_run(admission)
    .await
    .unwrap();
}

pub fn refund_call(run_id: &str, key: &str) -> Value {
    let mut c = call("tc_1", Some(key));
    c["run_id"] = json!(run_id);
    if run_id != "run_1" {
        c["principal_chain"] = json!([{"kind": "agent", "id": "agt_independent"}]);
    }
    c
}

pub async fn operation<S: DocumentStore>(store: &S, admission: &RunAdmission, key: &str) -> Value {
    store
        .get(&operation_ledger_key(admission, key))
        .await
        .unwrap()
        .map_or(Value::Null, |d| d.body["operations"][0].clone())
}

/// A store whose process dies at its `crash_at`th write: before it commits, or
/// (`after_commit`) after it commits but before the caller learns so.
pub struct CrashStore<S> {
    inner: Arc<S>,
    pub writes: AtomicUsize,
    crash_at: usize,
    after_commit: bool,
    crashed: AtomicBool,
}

impl<S: DocumentStore> CrashStore<S> {
    pub fn new(inner: Arc<S>, crash_at: usize, after_commit: bool) -> Self {
        Self {
            inner,
            writes: AtomicUsize::new(0),
            crash_at,
            after_commit,
            crashed: AtomicBool::new(false),
        }
    }

    async fn write<T>(&self, commit: impl Future<Output = Result<T, StoreError>>) -> Result<T, StoreError> {
        if self.crashed.load(Ordering::SeqCst) {
            return Err(StoreError::Backend("process crashed".into()));
        }
        if self.writes.fetch_add(1, Ordering::SeqCst) != self.crash_at {
            return commit.await;
        }
        self.crashed.store(true, Ordering::SeqCst);
        if self.after_commit {
            let _ = commit.await;
        }
        Err(StoreError::Backend("process crashed".into()))
    }
}

impl<S: DocumentStore> DocumentStore for CrashStore<S> {
    async fn get(&self, k: &DocKey) -> Result<Option<Versioned>, StoreError> {
        if self.crashed.load(Ordering::SeqCst) {
            return Err(StoreError::Backend("process crashed".into()));
        }
        self.inner.get(k).await
    }
    async fn create(&self, k: &DocKey, b: &Value) -> Result<Versioned, StoreError> {
        self.write(self.inner.create(k, b)).await
    }
    async fn compare_and_swap(&self, k: &DocKey, r: u64, b: &Value) -> Result<Versioned, StoreError> {
        self.write(self.inner.compare_and_swap(k, r, b)).await
    }
    async fn compare_and_swap_encoded(
        &self,
        k: &DocKey,
        r: u64,
        b: Value,
        e: contextos_store::Encoded,
    ) -> Result<u64, StoreError> {
        self.write(self.inner.compare_and_swap_encoded(k, r, b, e)).await
    }
    async fn expiring(
        &self,
        k: DocKind,
        t: u64,
        a: Option<&contextos_store::ScanCursor>,
        l: usize,
    ) -> Result<Vec<contextos_store::ScanCursor>, StoreError> {
        self.inner.expiring(k, t, a, l).await
    }
}

/// A store whose process stops before the first write `pause_at` matches, until
/// released: a dispatcher paused between two of its steps.
pub struct PauseStore<S> {
    inner: Arc<S>,
    pause_at: fn(&DocKey, &Value) -> bool,
    taken: AtomicBool,
    pub paused: Notify,
    pub resume: Notify,
}

impl<S: DocumentStore> PauseStore<S> {
    pub fn new(inner: Arc<S>, pause_at: fn(&DocKey, &Value) -> bool) -> Self {
        Self {
            inner,
            pause_at,
            taken: AtomicBool::new(false),
            paused: Notify::new(),
            resume: Notify::new(),
        }
    }

    async fn gate(&self, k: &DocKey, b: &Value) {
        if (self.pause_at)(k, b) && !self.taken.swap(true, Ordering::SeqCst) {
            self.paused.notify_one();
            self.resume.notified().await;
        }
    }
}

impl<S: DocumentStore> DocumentStore for PauseStore<S> {
    async fn get(&self, k: &DocKey) -> Result<Option<Versioned>, StoreError> {
        self.inner.get(k).await
    }
    async fn create(&self, k: &DocKey, b: &Value) -> Result<Versioned, StoreError> {
        self.gate(k, b).await;
        self.inner.create(k, b).await
    }
    async fn compare_and_swap(&self, k: &DocKey, r: u64, b: &Value) -> Result<Versioned, StoreError> {
        self.gate(k, b).await;
        self.inner.compare_and_swap(k, r, b).await
    }
    async fn compare_and_swap_encoded(
        &self,
        k: &DocKey,
        r: u64,
        b: Value,
        e: contextos_store::Encoded,
    ) -> Result<u64, StoreError> {
        self.gate(k, &b).await;
        self.inner.compare_and_swap_encoded(k, r, b, e).await
    }
    async fn expiring(
        &self,
        k: DocKind,
        t: u64,
        a: Option<&contextos_store::ScanCursor>,
        l: usize,
    ) -> Result<Vec<contextos_store::ScanCursor>, StoreError> {
        self.inner.expiring(k, t, a, l).await
    }
}

/// Before the operation claim: the dispatcher has registered its outcome.
pub fn before_claim(k: &DocKey, _: &Value) -> bool {
    k.kind == DocKind::OperationLedger
}

/// After the operation claim, before the outcome is armed.
pub fn before_arming(k: &DocKey, b: &Value) -> bool {
    k.kind == DocKind::Outcome && b["armed"] == true
}

/// The open-outcome index of the tenant and of `run_1`.
pub async fn indexed<S: DocumentStore>(store: &S) -> (Vec<Value>, Vec<Value>) {
    let mut lists = Vec::new();
    for id in ["open", "run:run_1"] {
        lists.push(
            store
                .get(&DocKey::new(TENANT, DocKind::Outcome, id))
                .await
                .unwrap()
                .map_or_else(Vec::new, |d| d.body["keys"].as_array().cloned().unwrap_or_default()),
        );
    }
    let run = lists.pop().unwrap();
    (lists.pop().unwrap(), run)
}

/// A migrated PostgreSQL store in a schema of its own.
pub async fn fresh_schema(url: &str, n: u64) -> contextos_store::postgres::PostgresStore {
    use std::str::FromStr;
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let schema = format!("outcome_crash_{nanos}_{n}");
    let admin = sqlx::PgPool::connect(url).await.unwrap();
    sqlx::query(&format!("CREATE SCHEMA {schema}"))
        .execute(&admin)
        .await
        .unwrap();
    admin.close().await;
    let options = sqlx::postgres::PgConnectOptions::from_str(url)
        .unwrap()
        .options([("search_path", schema.as_str())]);
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .connect_with(options)
        .await
        .unwrap();
    let store = contextos_store::postgres::PostgresStore::from_pool(pool);
    store.migrate().await.unwrap();
    store
}

/// Another process of the harness's runtime (same audit, adapter, approvals and
/// authority) over `store`, at `clock`: a replica, or the process that restarts.
pub fn harness_process<S: DocumentStore + 'static>(
    h: &Harness,
    store: Arc<S>,
    ids: u64,
    clock: &'static str,
    capability: CapabilityManifest,
) -> Gateway<S, MemoryLog> {
    let ports = Ports {
        clock: Arc::new(Clocked(clock)),
        ids: Arc::new(SeqIds(AtomicU64::new(ids))),
        authority: h.authority.clone(),
        policy: Arc::new(Policy("allow")),
        constraints: Arc::new(Constraints),
        approvals: h.approvals.clone(),
        idempotency: None,
        data_flow: None,
        boundary: None,
        memory: None,
    };
    let mut g = Gateway::new(store, h.audit.clone(), ports);
    g.register_adapter("adp_payments", h.adapter.clone());
    g.pin_capability(capability).unwrap();
    g
}
