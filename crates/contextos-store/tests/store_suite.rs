//! Store behavior every backend must satisfy, including linearizable kernel
//! transitions under contention. Runs on `MemoryStore` always and on PostgreSQL when
//! `CONTEXTOS_TEST_DATABASE_URL` is set.

use std::io::Read;
use std::sync::Arc;

use contextos_kernel::budget_ledger::reserve_child_budget;
use contextos_kernel::operation_ledger::claim_operation;
use contextos_store::{
    AppendLog, AppendRow, Commit, DocKey, DocKind, DocumentStore, LogRow, MemoryLog, MemoryStore, StoreError, transact,
};
use serde_json::{Value, json};

fn durable_vectors() -> Value {
    let path = format!(
        "{}/../../conformance/vectors/durable.json.gz",
        env!("CARGO_MANIFEST_DIR")
    );
    let mut text = String::new();
    flate2::read::GzDecoder::new(std::fs::File::open(path).unwrap())
        .read_to_string(&mut text)
        .unwrap();
    serde_json::from_str(&text).unwrap()
}

fn case<'a>(vectors: &'a Value, group: &str, name: &str) -> &'a Value {
    vectors[group]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == name)
        .unwrap_or_else(|| panic!("{name}"))
}

async fn basic_semantics<S: DocumentStore>(store: &S, tenant: &str) {
    let key = DocKey::new(tenant, DocKind::RunState, "run_basic");
    assert_eq!(store.get(&key).await.unwrap(), None);
    let created = store.create(&key, &json!({"b": 1, "a": [1.0, "x"]})).await.unwrap();
    assert_eq!(created.revision, 1);
    assert!(store.create(&key, &json!({})).await.unwrap_err().is_conflict());
    let read = store.get(&key).await.unwrap().unwrap();
    assert_eq!(read.body, json!({"a": [1, "x"], "b": 1}));
    assert_eq!(read.digest, created.digest);
    let next = store.compare_and_swap(&key, 1, &json!({"b": 2})).await.unwrap();
    assert_eq!(next.revision, 2);
    assert!(
        store
            .compare_and_swap(&key, 1, &json!({"b": 3}))
            .await
            .unwrap_err()
            .is_conflict()
    );
    let missing = DocKey::new(tenant, DocKind::RunState, "absent");
    assert_eq!(
        store.compare_and_swap(&missing, 1, &json!({})).await.unwrap_err(),
        StoreError::NotFound
    );
    // Tenants are isolated even for identical ids.
    let other = DocKey::new(format!("{tenant}_other"), DocKind::RunState, "run_basic");
    assert_eq!(store.get(&other).await.unwrap(), None);
}

async fn concurrent_budget_is_conserved<S: DocumentStore + 'static>(store: Arc<S>, tenant: &str) {
    let vectors = durable_vectors();
    let base = case(&vectors, "budgets", "reserve_child");
    let mut ledger = base["input"]["ledger"].clone();
    ledger["tenant_id"] = json!("tenant_acme_prod");
    let key = DocKey::new(tenant, DocKind::BudgetLedger, "budget_run_contract");
    store.create(&key, &ledger).await.unwrap();
    let request = base["input"]["request"].clone();
    let mut tasks = Vec::new();
    for i in 0..32 {
        let (store, key, mut request) = (store.clone(), key.clone(), request.clone());
        request["mutation_id"] = json!(format!("reserve_child_{i}"));
        request["reservation_id"] = json!(format!("reservation_child_{i}"));
        request["run_id"] = json!(format!("run_child_{i}"));
        tasks.push(tokio::spawn(async move {
            transact(store.as_ref(), &key, |ledger| {
                let mut request = request.clone();
                request["expected_revision"] = ledger["revision"].clone();
                reserve_child_budget(ledger, &request)
            })
            .await
            .unwrap()
        }));
    }
    let mut written = 0;
    for task in tasks {
        match task.await.unwrap() {
            Commit::Written { .. } => written += 1,
            Commit::Rejected { reason_codes } => assert_eq!(reason_codes, vec!["budget_exhausted".to_owned()]),
            Commit::Unchanged { .. } => panic!("unexpected unchanged commit"),
        }
    }
    // Ceiling allows 8 tool calls; each child reserves one.
    assert_eq!(written, 8);
    let final_ledger = store.get(&key).await.unwrap().unwrap().body;
    assert_eq!(final_ledger["reserved"]["tool_calls"], json!(8));
    assert_eq!(final_ledger["reservations"].as_array().unwrap().len(), 8);
}

async fn concurrent_claims_admit_one<S: DocumentStore + 'static>(store: Arc<S>, tenant: &str) {
    let vectors = durable_vectors();
    let base = case(&vectors, "ops", "fresh_claim");
    let key = DocKey::new(tenant, DocKind::OperationLedger, "operations_run_contract");
    store.create(&key, &base["input"]["ledger"]).await.unwrap();
    let mut tasks = Vec::new();
    for i in 0..32 {
        let (store, key, mut intent) = (store.clone(), key.clone(), base["input"]["intent"].clone());
        intent["attempt"]["attempt_id"] = json!(format!("attempt_{i}"));
        tasks.push(tokio::spawn(async move {
            transact(store.as_ref(), &key, |ledger| {
                claim_operation(ledger, &intent, &ledger["revision"], &json!(3))
            })
            .await
            .unwrap()
        }));
    }
    let mut written = 0;
    for task in tasks {
        match task.await.unwrap() {
            Commit::Written { .. } => written += 1,
            Commit::Rejected { reason_codes } => assert_eq!(reason_codes, vec!["operation_in_flight".to_owned()]),
            Commit::Unchanged { .. } => panic!("unexpected unchanged commit"),
        }
    }
    assert_eq!(written, 1, "exactly one attempt may be in flight");
}

async fn append_log_semantics<L: AppendLog>(log: &L, tenant: &str) {
    let row = |sequence: u64| {
        AppendRow::encode(&LogRow {
            sequence,
            record_hash: format!("sha256:{sequence:064x}"),
            body: json!({"s": sequence}),
        })
        .unwrap()
    };
    assert_eq!(log.head(tenant).await.unwrap(), None);
    assert!(
        log.append(tenant, &row(2)).await.unwrap_err().is_conflict(),
        "gap before genesis"
    );
    log.append(tenant, &row(1)).await.unwrap();
    assert!(
        log.append(tenant, &row(1)).await.unwrap_err().is_conflict(),
        "fork at sequence 1"
    );
    log.append(tenant, &row(2)).await.unwrap();
    assert!(log.append(tenant, &row(4)).await.unwrap_err().is_conflict(), "gap");
    assert_eq!(log.head(tenant).await.unwrap().unwrap().sequence, 2);
    let rows = log.range(tenant, 2, 10).await.unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!((rows[0].sequence, &rows[0].body), (2, &json!({"s": 2})));
}

fn now_us() -> u64 {
    u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_micros(),
    )
    .unwrap()
}

/// Retention finds documents of a kind by age, never erasure tombstones, in pages.
async fn expiry_semantics<S: DocumentStore>(store: &S, tenant: &str) {
    let key = |kind, id: &str| DocKey::new(tenant, kind, id);
    for id in ["exp_a", "exp_b", "exp_c", "exp_e"] {
        let body = if id == "exp_e" {
            // User content that merely mentions `erased` is not a tombstone.
            json!({"name": id, "request": {"context": {"erased": true, "content_digest": "x"}}})
        } else {
            json!({"name": id})
        };
        store.create(&key(DocKind::ReplayCase, id), &body).await.unwrap();
    }
    store
        .create(&key(DocKind::CompiledContext, "exp_d"), &json!({"x": 1}))
        .await
        .unwrap();
    let tombstone = json!({"erased": true, "erased_at": "2026-10-20T10:00:00Z", "erased_by": "ops", "reason": "r",
        "content_digest": format!("sha256:{}", "a".repeat(64))});
    assert!(contextos_store::is_tombstone(&tombstone));
    assert!(!contextos_store::is_tombstone(&json!({"erased": true})));
    store
        .compare_and_swap(&key(DocKind::ReplayCase, "exp_c"), 1, &tombstone)
        .await
        .unwrap();

    let cutoff = now_us() + 1_000_000;
    let ours = |found: Vec<contextos_store::ScanCursor>| -> Vec<String> {
        found
            .into_iter()
            .filter(|(_, k)| k.tenant_id == tenant)
            .map(|(_, k)| k.id)
            .collect()
    };
    let mut all = ours(
        store
            .expiring(DocKind::ReplayCase, cutoff, None, 100_000)
            .await
            .unwrap(),
    );
    all.sort();
    assert_eq!(all, ["exp_a", "exp_b", "exp_e"]);

    // Paging with a cursor visits the same documents in creation order.
    let mut paged = Vec::new();
    let mut cursor = None;
    loop {
        let page = store
            .expiring(DocKind::ReplayCase, cutoff, cursor.as_ref(), 1)
            .await
            .unwrap();
        let Some(last) = page.last().cloned() else { break };
        paged.extend(ours(page));
        cursor = Some(last);
    }
    paged.sort();
    assert_eq!(paged, all);
    assert!(
        ours(store.expiring(DocKind::ReplayCase, 1, None, 100).await.unwrap()).is_empty(),
        "nothing that old"
    );
}

/// One tenant's documents of one kind, by id, in pages; tombstones and other tenants'
/// and kinds' documents are not listed.
async fn listing_semantics<S: DocumentStore>(store: &S, tenant: &str) {
    for id in ["lst_c", "lst_a", "lst_b", "lst_d"] {
        let key = DocKey::new(tenant, DocKind::SharedExposure, id);
        store.create(&key, &json!({"held": 1})).await.unwrap();
    }
    store
        .create(&DocKey::new(tenant, DocKind::ExposureLink, "lst_x"), &json!({}))
        .await
        .unwrap();
    store
        .create(
            &DocKey::new(format!("{tenant}_other"), DocKind::SharedExposure, "lst_y"),
            &json!({}),
        )
        .await
        .unwrap();
    let tombstone = json!({"erased": true, "erased_at": "2026-10-20T10:00:00Z", "erased_by": "ops", "reason": "r",
        "content_digest": format!("sha256:{}", "b".repeat(64))});
    store
        .compare_and_swap(&DocKey::new(tenant, DocKind::SharedExposure, "lst_d"), 1, &tombstone)
        .await
        .unwrap();
    let all = store.list(tenant, DocKind::SharedExposure, None, 100).await.unwrap();
    assert_eq!(all, ["lst_a", "lst_b", "lst_c"]);
    let mut paged = Vec::new();
    let mut after: Option<String> = None;
    loop {
        let page = store
            .list(tenant, DocKind::SharedExposure, after.as_deref(), 2)
            .await
            .unwrap();
        assert!(page.len() <= 2);
        let Some(last) = page.last().cloned() else { break };
        paged.extend(page);
        after = Some(last);
    }
    assert_eq!(paged, all);
    assert_eq!(
        store
            .list(tenant, DocKind::SharedExposure, Some("lst_c"), 10)
            .await
            .unwrap(),
        Vec::<String>::new()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn memory_store_suite() {
    append_log_semantics(&MemoryLog::new(), "tenant_a").await;
    let store = Arc::new(MemoryStore::new());
    basic_semantics(store.as_ref(), "tenant_a").await;
    expiry_semantics(store.as_ref(), "tenant_a").await;
    listing_semantics(store.as_ref(), "tenant_a").await;
    concurrent_budget_is_conserved(store.clone(), "tenant_a").await;
    concurrent_claims_admit_one(store, "tenant_a").await;
}

#[cfg(feature = "postgres")]
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn postgres_store_suite() {
    let Ok(url) = std::env::var("CONTEXTOS_TEST_DATABASE_URL") else {
        eprintln!("skipped: CONTEXTOS_TEST_DATABASE_URL not set");
        return;
    };
    let store = contextos_store::postgres::PostgresStore::connect(&url, 16)
        .await
        .unwrap();
    store.migrate().await.unwrap();
    // Migrating records the version, so a role without DDL rights can start.
    assert!(store.schema_current().await.unwrap());
    let tenant = format!("tenant_{}", std::process::id());
    basic_semantics(&store, &tenant).await;
    expiry_semantics(&store, &tenant).await;
    listing_semantics(&store, &tenant).await;
    append_log_semantics(&store, &tenant).await;
    let store = Arc::new(store);
    concurrent_budget_is_conserved(store.clone(), &tenant).await;
    concurrent_claims_admit_one(store, &tenant).await;
}
