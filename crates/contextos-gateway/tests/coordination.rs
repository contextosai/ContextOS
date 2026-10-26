//! Peer coordination is advisory; these tests exercise protected board ownership.
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use contextos_audit::{AuditSigner, AuditWriter};
use contextos_gateway::{
    ApprovalProvider, AuthorityFacts, AuthorityProvider, Clock, ConstraintProvider, Gateway, IdSource, PolicyProvider,
    PortError, Ports, RunAdmission, WorkCommand, WorkTaskInput,
};
use contextos_store::{DocKey, DocKind, DocumentStore, MemoryLog, MemoryStore};
use serde_json::{Value, json};

const TENANT: &str = "team";
const NOW: &str = "2030-01-01T00:00:00Z";

struct Time(Mutex<String>);
impl Clock for Time {
    fn now(&self) -> String {
        self.0.lock().unwrap().clone()
    }
}
struct Unused;
impl IdSource for Unused {
    fn new_id(&self, _: &str) -> String {
        "unused".into()
    }
}
#[async_trait]
impl AuthorityProvider for Unused {
    async fn authority(&self, _: &RunAdmission, _: &Value) -> Result<AuthorityFacts, PortError> {
        Err(PortError::new("unused", "coordination does not authorize tools"))
    }
}
#[async_trait]
impl ConstraintProvider for Unused {
    async fn observations(&self, _: &RunAdmission, _: &[Value], _: &str) -> Result<Vec<Value>, PortError> {
        Err(PortError::new("unused", "not called"))
    }
}
#[async_trait]
impl ApprovalProvider for Unused {
    async fn approval(&self, _: &RunAdmission, _: &str) -> Result<Option<Value>, PortError> {
        Err(PortError::new("unused", "not called"))
    }
    async fn request(&self, _: &RunAdmission, _: &Value, _: &str) -> Result<String, PortError> {
        Err(PortError::new("unused", "not called"))
    }
}
#[async_trait]
impl PolicyProvider for Unused {
    async fn outcomes(&self, _: &RunAdmission, _: &Value) -> Result<Vec<Value>, PortError> {
        Err(PortError::new("unused", "not called"))
    }
}

struct World {
    store: Arc<MemoryStore>,
    audit: Arc<AuditWriter<MemoryLog>>,
    time: Arc<Time>,
    root: RunAdmission,
    a: RunAdmission,
    b: RunAdmission,
}
impl World {
    fn ports(&self) -> Ports {
        Ports {
            clock: self.time.clone(),
            ids: Arc::new(Unused),
            authority: Arc::new(Unused),
            constraints: Arc::new(Unused),
            approvals: Arc::new(Unused),
            policy: Arc::new(Unused),
            idempotency: None,
            data_flow: None,
            boundary: None,
            memory: None,
        }
    }
    fn gateway(&self) -> Gateway<MemoryStore, MemoryLog> {
        Gateway::new(
            self.store.clone(),
            self.audit.clone(),
            Ports {
                clock: self.time.clone(),
                ids: Arc::new(Unused),
                authority: Arc::new(Unused),
                constraints: Arc::new(Unused),
                approvals: Arc::new(Unused),
                policy: Arc::new(Unused),
                idempotency: None,
                data_flow: None,
                boundary: None,
                memory: None,
            },
        )
    }
    async fn state(&self, run: &str, status: &str, generation: u64) {
        let key = DocKey::new(TENANT, DocKind::RunState, run);
        let old = self.store.get(&key).await.unwrap().unwrap();
        self.store
            .compare_and_swap(
                &key,
                old.revision,
                &json!({"status":status,"executor_generation":generation}),
            )
            .await
            .unwrap();
    }
}

struct FaultStore {
    inner: Arc<MemoryStore>,
    fail_kind: Mutex<Option<DocKind>>,
    pause: Option<Arc<Pause>>,
}
struct Pause {
    entered: tokio::sync::Semaphore,
    resume: tokio::sync::Semaphore,
}
impl FaultStore {
    async fn before_write(&self, key: &DocKey) -> Result<(), contextos_store::StoreError> {
        if *self.fail_kind.lock().unwrap() == Some(key.kind) {
            return Err(contextos_store::StoreError::Backend("injected write failure".into()));
        }
        if key.kind == DocKind::WorkBoard
            && let Some(pause) = &self.pause
        {
            pause.entered.add_permits(1);
            pause.resume.acquire().await.unwrap().forget();
        }
        Ok(())
    }
}
impl DocumentStore for FaultStore {
    async fn get(&self, k: &DocKey) -> Result<Option<contextos_store::Versioned>, contextos_store::StoreError> {
        self.inner.get(k).await
    }
    async fn create(&self, k: &DocKey, b: &Value) -> Result<contextos_store::Versioned, contextos_store::StoreError> {
        self.before_write(k).await?;
        self.inner.create(k, b).await
    }
    async fn compare_and_swap(
        &self,
        k: &DocKey,
        r: u64,
        b: &Value,
    ) -> Result<contextos_store::Versioned, contextos_store::StoreError> {
        self.before_write(k).await?;
        self.inner.compare_and_swap(k, r, b).await
    }
    async fn compare_and_swap_encoded(
        &self,
        k: &DocKey,
        r: u64,
        b: Value,
        e: contextos_store::Encoded,
    ) -> Result<u64, contextos_store::StoreError> {
        self.before_write(k).await?;
        self.inner.compare_and_swap_encoded(k, r, b, e).await
    }
    async fn expiring(
        &self,
        k: DocKind,
        t: u64,
        a: Option<&contextos_store::ScanCursor>,
        l: usize,
    ) -> Result<Vec<contextos_store::ScanCursor>, contextos_store::StoreError> {
        self.inner.expiring(k, t, a, l).await
    }
}
#[derive(Debug, Default)]
struct FailingLog(MemoryLog);
impl contextos_store::AppendLog for FailingLog {
    async fn head(&self, t: &str) -> Result<Option<contextos_store::LogRow>, contextos_store::StoreError> {
        contextos_store::AppendLog::head(&self.0, t).await
    }
    async fn append_batch(&self, _: &str, _: &[contextos_store::AppendRow]) -> Result<(), contextos_store::StoreError> {
        Err(contextos_store::StoreError::Backend("injected audit failure".into()))
    }
    async fn range(
        &self,
        t: &str,
        f: u64,
        l: usize,
    ) -> Result<Vec<contextos_store::LogRow>, contextos_store::StoreError> {
        contextos_store::AppendLog::range(&self.0, t, f, l).await
    }
}

#[tokio::test]
async fn audit_or_store_failure_never_publishes_an_unaudited_task() {
    let w = world().await;
    let audit = Arc::new(AuditWriter::new(
        FailingLog::default(),
        AuditSigner::from_seed("bad", [9; 32]),
    ));
    let g = Gateway::new(w.store.clone(), audit, w.ports());
    assert_eq!(
        g.publish_work(&w.a, "principal-a", 2, task("audit", &[]))
            .await
            .unwrap_err()
            .code(),
        "work_unavailable"
    );
    let store = Arc::new(FaultStore {
        inner: w.store.clone(),
        fail_kind: Mutex::new(Some(DocKind::WorkBoard)),
        pause: None,
    });
    let g = Gateway::new(store, w.audit.clone(), w.ports());
    assert_eq!(
        g.publish_work(&w.a, "principal-a", 2, task("store", &[]))
            .await
            .unwrap_err()
            .code(),
        "work_unavailable"
    );
    assert!(
        w.store
            .get(&DocKey::new(TENANT, DocKind::WorkBoard, "root"))
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn board_erasure_precedes_replay_tombstone_and_partial_failure_can_be_retried() {
    let w = world().await;
    w.gateway()
        .publish_work(&w.a, "principal-a", 2, task("secret", &[]))
        .await
        .unwrap();
    let replay = DocKey::new(TENANT, DocKind::ReplayCase, "root");
    w.store.create(&replay, &json!({"personal":"content"})).await.unwrap();
    w.state("root", "completed", 3).await;
    let store = Arc::new(FaultStore {
        inner: w.store.clone(),
        fail_kind: Mutex::new(Some(DocKind::WorkBoard)),
        pause: None,
    });
    let g = Gateway::new(store.clone(), w.audit.clone(), w.ports());
    assert!(g.erase_run(&w.root, "operator", "retention").await.is_err());
    assert_ne!(w.store.get(&replay).await.unwrap().unwrap().body["erased"], true);
    *store.fail_kind.lock().unwrap() = Some(DocKind::ReplayCase);
    assert!(g.erase_run(&w.root, "operator", "retention").await.is_err());
    assert_eq!(
        w.store
            .get(&DocKey::new(TENANT, DocKind::WorkBoard, "root"))
            .await
            .unwrap()
            .unwrap()
            .body["erased"],
        true
    );
    assert_ne!(
        w.store.get(&replay).await.unwrap().unwrap().body["erased"],
        true,
        "retention's retry index survives"
    );
    *store.fail_kind.lock().unwrap() = None;
    g.erase_run(&w.root, "operator", "retention").await.unwrap();
    assert_eq!(w.store.get(&replay).await.unwrap().unwrap().body["erased"], true);
}

#[tokio::test]
async fn delayed_initial_publication_cannot_recreate_an_erased_board() {
    let w = world().await;
    let pause = Arc::new(Pause {
        entered: tokio::sync::Semaphore::new(0),
        resume: tokio::sync::Semaphore::new(0),
    });
    let store = Arc::new(FaultStore {
        inner: w.store.clone(),
        fail_kind: Mutex::new(None),
        pause: Some(pause.clone()),
    });
    let g = Gateway::new(store, w.audit.clone(), w.ports());
    let a = w.a.clone();
    let publishing = tokio::spawn(async move { g.publish_work(&a, "principal-a", 2, task("late", &[])).await });
    pause.entered.acquire().await.unwrap().forget();
    w.state("root", "completed", 3).await;
    w.gateway().erase_run(&w.root, "operator", "retention").await.unwrap();
    pause.resume.add_permits(1);
    assert!(publishing.await.unwrap().is_err());
    assert_eq!(
        w.store
            .get(&DocKey::new(TENANT, DocKind::WorkBoard, "root"))
            .await
            .unwrap()
            .unwrap()
            .body["erased"],
        true
    );
}

#[tokio::test]
async fn lifecycle_checks_do_not_claim_atomicity_with_board_commits() {
    let w = world().await;
    let pause = Arc::new(Pause {
        entered: tokio::sync::Semaphore::new(0),
        resume: tokio::sync::Semaphore::new(0),
    });
    let store = Arc::new(FaultStore {
        inner: w.store.clone(),
        fail_kind: Mutex::new(None),
        pause: Some(pause.clone()),
    });
    let g = Gateway::new(store, w.audit.clone(), w.ports());
    let a = w.a.clone();
    let publishing = tokio::spawn(async move { g.publish_work(&a, "principal-a", 2, task("admitted", &[])).await });
    pause.entered.acquire().await.unwrap().forget();
    w.state("worker-a", "cancelled", 3).await;
    pause.resume.add_permits(1);
    assert!(
        publishing.await.unwrap().is_ok(),
        "a pre-stop request may commit; it grants no effect authority"
    );
    assert_eq!(
        w.gateway().work_task(&w.b, "principal-b", 2, "admitted").await.unwrap()["data_only"],
        true
    );
}

#[tokio::test]
async fn root_erasure_receipt_includes_the_board_content_it_removed() {
    let w = world().await;
    let g = w.gateway();
    g.publish_work(&w.a, "principal-a", 2, task("team", &[])).await.unwrap();
    w.state("root", "completed", 3).await;
    let receipt = g.erase_run(&w.root, "operator", "retention").await.unwrap();
    assert!(
        receipt["erased"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["document"] == "work_board")
    );
}

#[tokio::test]
async fn board_capacity_completion_evidence_and_audit_content_are_bounded() {
    use contextos_store::AppendLog;
    let w = world().await;
    let g = w.gateway();
    g.publish_work(&w.a, "principal-a", 2, task("base", &[])).await.unwrap();
    g.update_work(&w.a, "principal-a", 2, "base", claim(1, 60))
        .await
        .unwrap();
    let invalid = command(json!({"action":"complete","expected_revision":2,"lease_epoch":1,"evidence_refs":[]}));
    assert_eq!(
        g.update_work(&w.a, "principal-a", 2, "base", invalid)
            .await
            .unwrap_err()
            .code(),
        "work_invalid"
    );
    assert_eq!(
        g.work_task(&w.a, "principal-a", 2, "base").await.unwrap()["task"]["revision"],
        2
    );
    let entries = w.audit.log().range(TENANT, 1, 100).await.unwrap();
    let audited = serde_json::to_string(&entries.iter().map(|e| &e.body).collect::<Vec<_>>()).unwrap();
    assert!(
        !audited.contains("The relevant checks pass."),
        "acceptance text is not permanent audit content"
    );
    let k = DocKey::new(TENANT, DocKind::WorkBoard, "root");
    let read = w.store.get(&k).await.unwrap().unwrap();
    let mut body = read.body.clone();
    for n in 0..255 {
        let id = format!("task_{n}");
        let mut t = body["tasks"]["base"].clone();
        t["task_id"] = json!(id);
        body["tasks"][&id] = t;
    }
    w.store.compare_and_swap(&k, read.revision, &body).await.unwrap();
    assert_eq!(
        g.publish_work(&w.a, "principal-a", 2, task("overflow", &[]))
            .await
            .unwrap_err()
            .code(),
        "work_full"
    );
}

#[tokio::test]
async fn competing_cas_writes_cannot_both_claim_the_same_revision() {
    let w = world().await;
    w.gateway()
        .publish_work(&w.root, "coordinator", 2, task("race", &[]))
        .await
        .unwrap();
    let pause = Arc::new(Pause {
        entered: tokio::sync::Semaphore::new(0),
        resume: tokio::sync::Semaphore::new(0),
    });
    let store = Arc::new(FaultStore {
        inner: w.store.clone(),
        fail_kind: Mutex::new(None),
        pause: Some(pause.clone()),
    });
    let first = Gateway::new(store.clone(), w.audit.clone(), w.ports());
    let second = Gateway::new(store, w.audit.clone(), w.ports());
    let a = w.a.clone();
    let b = w.b.clone();
    let a = tokio::spawn(async move { first.update_work(&a, "principal-a", 2, "race", claim(1, 60)).await });
    let b = tokio::spawn(async move { second.update_work(&b, "principal-b", 2, "race", claim(1, 60)).await });
    // Both writers have read revision 1 and reached the CAS, before either commits.
    pause.entered.acquire_many(2).await.unwrap().forget();
    pause.resume.add_permits(2);
    let a = a.await.unwrap();
    let b = b.await.unwrap();
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    assert_eq!(a.err().or(b.err()).unwrap().code(), "work_conflict");
}

#[tokio::test]
async fn postgres_replicas_share_claims_and_reopen_persistent_work() {
    let Ok(url) = std::env::var("CONTEXTOS_TEST_DATABASE_URL") else {
        eprintln!("skipped: CONTEXTOS_TEST_DATABASE_URL is unset");
        return;
    };
    let w = world().await;
    let first = Arc::new(
        contextos_store::postgres::PostgresStore::connect(&url, 4)
            .await
            .unwrap(),
    );
    first.migrate().await.unwrap();
    let tenant = format!(
        "peer_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let root = admission(first.as_ref(), &tenant, "root", "coordinator", None).await;
    let a = admission(first.as_ref(), &tenant, "a", "principal-a", Some("root")).await;
    let b = admission(first.as_ref(), &tenant, "b", "principal-b", Some("root")).await;
    let second = Arc::new(
        contextos_store::postgres::PostgresStore::connect(&url, 4)
            .await
            .unwrap(),
    );
    let g1 = Gateway::new(first, w.audit.clone(), w.ports());
    let g2 = Gateway::new(second, w.audit.clone(), w.ports());
    g1.publish_work(&root, "coordinator", 2, task("persistent", &[]))
        .await
        .unwrap();
    let (a, b) = tokio::join!(
        g1.update_work(&a, "principal-a", 2, "persistent", claim(1, 60)),
        g2.update_work(&b, "principal-b", 2, "persistent", claim(1, 60))
    );
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    assert_eq!(a.err().or(b.err()).unwrap().code(), "work_conflict");
    assert_eq!(
        g2.work_task(&root, "coordinator", 2, "persistent").await.unwrap()["task"]["revision"],
        2
    );
}
async fn admission<S: DocumentStore>(
    store: &S,
    tenant: &str,
    id: &str,
    principal: &str,
    root: Option<&str>,
) -> RunAdmission {
    let admission: RunAdmission = serde_json::from_value(json!({
        "tenant_id":tenant,"run_id":id,"trace_id":"trace","contract":{},"contract_id":"contract",
        "required_controls":[],"actor":{},"policy_refs":[],"policy_outcomes":[],"profile_refs":[],
        "release_refs":[],"surfaced_capabilities":[],"evidence":{},"operation_ledger_id":id,
        "budget_ledger_id":id,"executor_generation":2,"deadline":"2030-01-01T01:00:00Z",
        "gateway_observer":{},"admitted_by":principal,
        "lineage":root.map(|r|json!({"delegation_id":id,"root_run_id":r,"parent_run_id":r,
            "effect_policy":"isolate_until_accepted","links":[]}))
    }))
    .unwrap();
    store
        .create(
            &DocKey::new(tenant, DocKind::RunAdmission, id),
            &serde_json::to_value(&admission).unwrap(),
        )
        .await
        .unwrap();
    store
        .create(
            &DocKey::new(tenant, DocKind::RunState, id),
            &json!({"status":"running","executor_generation":2}),
        )
        .await
        .unwrap();
    admission
}
async fn world() -> World {
    let store = Arc::new(MemoryStore::new());
    let root = admission(store.as_ref(), TENANT, "root", "coordinator", None).await;
    let a = admission(store.as_ref(), TENANT, "worker-a", "principal-a", Some("root")).await;
    let b = admission(store.as_ref(), TENANT, "worker-b", "principal-b", Some("root")).await;
    World {
        store,
        root,
        a,
        b,
        time: Arc::new(Time(Mutex::new(NOW.into()))),
        audit: Arc::new(AuditWriter::new(
            MemoryLog::new(),
            AuditSigner::from_seed("work", [6; 32]),
        )),
    }
}
fn task(id: &str, dependencies: &[&str]) -> WorkTaskInput {
    serde_json::from_value(json!({"task_id":id,"title":format!("Implement {id}"),
        "acceptance_criteria":"The relevant checks pass.","dependencies":dependencies}))
    .unwrap()
}
fn command(value: Value) -> WorkCommand {
    serde_json::from_value(value).unwrap()
}
fn claim(revision: u64, seconds: u64) -> WorkCommand {
    command(json!({"action":"claim","expected_revision":revision,"lease_seconds":seconds}))
}
fn complete(revision: u64, epoch: u64) -> WorkCommand {
    command(
        json!({"action":"complete","expected_revision":revision,"lease_epoch":epoch,
        "evidence_refs":[{"artifact_type":"test_report","artifact_id":"report","sha256":format!("sha256:{}","a".repeat(64))}]}),
    )
}

#[tokio::test]
async fn two_replicas_have_one_claim_winner_and_conditional_retries_are_safe() {
    let w = world().await;
    let g = w.gateway();
    let created = g
        .publish_work(&w.root, "coordinator", 2, task("parser", &[]))
        .await
        .unwrap();
    assert_eq!(created["task"]["revision"], 1);
    assert_eq!(
        g.publish_work(&w.root, "coordinator", 2, task("parser", &[]))
            .await
            .unwrap(),
        created
    );
    let mut changed = task("parser", &[]);
    changed.title = "Different work".into();
    assert_eq!(
        g.publish_work(&w.root, "coordinator", 2, changed)
            .await
            .unwrap_err()
            .code(),
        "work_conflict"
    );
    let peer = w.gateway();
    let a_claim = claim(1, 60);
    let b_claim = claim(1, 60);
    let (a, b) = tokio::join!(
        g.update_work(&w.a, "principal-a", 2, "parser", a_claim),
        peer.update_work(&w.b, "principal-b", 2, "parser", b_claim)
    );
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    assert_eq!(a.err().or(b.err()).unwrap().code(), "work_conflict");
    let state = g.work_task(&w.root, "coordinator", 2, "parser").await.unwrap();
    assert_eq!(state["task"]["revision"], 2);
    assert_eq!(state["task"]["lease_epoch"], 1);
    assert_eq!(state["data_only"], true);
    assert_eq!(state["evidence_verified"], false);
    assert_eq!(
        g.update_work(&w.a, "principal-a", 2, "parser", claim(1, 60))
            .await
            .unwrap_err()
            .code(),
        "work_conflict"
    );
}

#[tokio::test]
async fn dependencies_expiry_and_stale_epoch_completion_preserve_new_owner() {
    let w = world().await;
    let g = w.gateway();
    g.publish_work(&w.root, "coordinator", 2, task("parse", &[]))
        .await
        .unwrap();
    g.publish_work(&w.root, "coordinator", 2, task("integrate", &["parse"]))
        .await
        .unwrap();
    assert_eq!(
        g.update_work(&w.a, "principal-a", 2, "integrate", claim(1, 60))
            .await
            .unwrap_err()
            .code(),
        "work_not_ready"
    );
    g.update_work(&w.a, "principal-a", 2, "parse", claim(1, 5))
        .await
        .unwrap();
    *w.time.0.lock().unwrap() = "2030-01-01T00:00:05Z".into();
    assert_eq!(
        g.update_work(&w.a, "principal-a", 2, "parse", complete(2, 1))
            .await
            .unwrap_err()
            .code(),
        "work_lease_expired"
    );
    let ready = g.work_task(&w.b, "principal-b", 2, "parse").await.unwrap();
    assert_eq!(ready["task"]["available"], true);
    let recovered = g
        .update_work(&w.b, "principal-b", 2, "parse", claim(2, 20))
        .await
        .unwrap();
    assert_eq!(recovered["task"]["previous_claim"]["run_id"], "worker-a");
    assert_eq!(recovered["task"]["lease_epoch"], 2);
    assert_eq!(
        g.update_work(&w.a, "principal-a", 2, "parse", complete(3, 1))
            .await
            .unwrap_err()
            .code(),
        "work_lease_stale"
    );
    g.update_work(&w.b, "principal-b", 2, "parse", complete(3, 2))
        .await
        .unwrap();
    g.update_work(&w.a, "principal-a", 2, "integrate", claim(1, 60))
        .await
        .unwrap();
    assert_eq!(
        g.update_work(&w.a, "principal-a", 2, "parse", claim(4, 60))
            .await
            .unwrap_err()
            .code(),
        "work_completed"
    );
}

#[tokio::test]
async fn same_tenant_impersonation_unrelated_roots_and_supplied_lineage_are_not_membership() {
    let w = world().await;
    let g = w.gateway();
    g.publish_work(&w.a, "principal-a", 2, task("private", &[]))
        .await
        .unwrap();
    assert_eq!(
        g.work_tasks(&w.a, "principal-b", 2, None, 100)
            .await
            .unwrap_err()
            .code(),
        "work_forbidden"
    );
    let mut stranger = admission(w.store.as_ref(), TENANT, "unrelated", "principal-a", None).await;
    stranger.lineage = w.a.lineage.clone(); // A caller-supplied admission cannot forge stored membership.
    let separate = g.work_tasks(&stranger, "principal-a", 2, None, 100).await.unwrap();
    assert_eq!(separate["root_run_id"], "unrelated");
    assert_eq!(separate["tasks"], json!([]));
    let other = admission(w.store.as_ref(), "other", "worker-a", "principal-a", None).await;
    assert_eq!(
        g.work_tasks(&other, "principal-a", 2, None, 100).await.unwrap()["tasks"],
        json!([])
    );
    assert_eq!(
        g.work_task(&w.a, "principal-a", 1, "private").await.unwrap_err().code(),
        "executor_stale"
    );
}

#[tokio::test]
async fn takeover_renew_release_and_deadlines_are_enforced() {
    let w = world().await;
    let g = w.gateway();
    g.publish_work(&w.a, "principal-a", 2, task("work", &[])).await.unwrap();
    g.update_work(&w.a, "principal-a", 2, "work", claim(1, 10))
        .await
        .unwrap();
    w.state("worker-a", "running", 4).await;
    assert_eq!(
        g.update_work(&w.a, "principal-a", 2, "work", complete(2, 1))
            .await
            .unwrap_err()
            .code(),
        "executor_stale"
    );
    g.update_work(&w.a, "principal-a", 4, "work", claim(2, 3600))
        .await
        .unwrap();
    let renewed = g
        .update_work(
            &w.a,
            "principal-a",
            4,
            "work",
            command(json!({"action":"renew",
        "expected_revision":3,"lease_epoch":2,"lease_seconds":3600})),
        )
        .await
        .unwrap();
    assert_eq!(renewed["task"]["claim"]["expires_at"], "2030-01-01T01:00:00Z");
    g.update_work(
        &w.a,
        "principal-a",
        4,
        "work",
        command(json!({"action":"release",
        "expected_revision":4,"lease_epoch":2})),
    )
    .await
    .unwrap();
    g.update_work(&w.b, "principal-b", 2, "work", claim(5, 60))
        .await
        .unwrap();
    w.state("root", "completed", 3).await;
    assert_eq!(
        g.work_tasks(&w.b, "principal-b", 2, None, 100)
            .await
            .unwrap_err()
            .code(),
        "work_closed"
    );
}

#[tokio::test]
async fn bounded_input_and_pagination_do_not_silently_drop_work() {
    let w = world().await;
    let g = w.gateway();
    assert!(
        serde_json::from_value::<WorkTaskInput>(json!({"task_id":"t","title":"t",
        "acceptance_criteria":"t","owner":"forged"}))
        .is_err()
    );
    assert_eq!(
        g.publish_work(&w.a, "principal-a", 2, task("../bad", &[]))
            .await
            .unwrap_err()
            .code(),
        "work_invalid"
    );
    assert_eq!(
        g.publish_work(&w.a, "principal-a", 2, task("cycle", &["cycle"]))
            .await
            .unwrap_err()
            .code(),
        "work_invalid"
    );
    assert_eq!(
        g.publish_work(&w.a, "principal-a", 2, task("missing", &["unknown"]))
            .await
            .unwrap_err()
            .code(),
        "work_not_found"
    );
    for id in ["a", "b", "c"] {
        g.publish_work(&w.a, "principal-a", 2, task(id, &[])).await.unwrap();
    }
    let first = g.work_tasks(&w.b, "principal-b", 2, None, 2).await.unwrap();
    assert_eq!(first["tasks"].as_array().unwrap().len(), 2);
    assert_eq!(first["next_cursor"], "b");
    let last = g.work_tasks(&w.b, "principal-b", 2, Some("b"), 2).await.unwrap();
    assert_eq!(last["tasks"][0]["task_id"], "c");
    assert!(last["next_cursor"].is_null());
    assert_eq!(
        g.work_tasks(&w.a, "principal-a", 2, None, 101)
            .await
            .unwrap_err()
            .code(),
        "work_invalid"
    );
    assert_eq!(
        g.update_work(&w.a, "principal-a", 2, "a", claim(1, 0))
            .await
            .unwrap_err()
            .code(),
        "work_invalid"
    );
}

#[tokio::test]
async fn root_erasure_fences_even_an_absent_board_and_children_do_not_erase_team_content() {
    let w = world().await;
    let g = w.gateway();
    w.state("root", "completed", 3).await;
    g.erase_run(&w.root, "operator", "retention").await.unwrap();
    assert_eq!(
        w.store
            .get(&DocKey::new(TENANT, DocKind::WorkBoard, "root"))
            .await
            .unwrap()
            .unwrap()
            .body["erased"],
        true
    );
    w.state("root", "running", 4).await; // Even a later restored lifecycle cannot resurrect erased content.
    assert_eq!(
        g.publish_work(&w.root, "coordinator", 4, task("late", &[]))
            .await
            .unwrap_err()
            .code(),
        "work_erased"
    );
    let w = world().await;
    let g = w.gateway();
    g.publish_work(&w.a, "principal-a", 2, task("team", &[])).await.unwrap();
    w.state("worker-a", "completed", 3).await;
    g.erase_run(&w.a, "operator", "child-only").await.unwrap();
    assert_eq!(
        g.work_task(&w.b, "principal-b", 2, "team").await.unwrap()["task"]["task_id"],
        "team"
    );
}
