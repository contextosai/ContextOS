//! Outcome contracts under crashes: an applied effect with an outcome contract stays
//! owed until witnessed whichever write a crash interrupts, and keeps the deadline
//! counted from the effect. The matrix runs on the in-memory store, and on PostgreSQL
//! (a fresh schema per case) when `CONTEXTOS_TEST_DATABASE_URL` is set.

mod support;

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use contextos_contract::validation::add_contract_seconds;
use contextos_gateway::*;
use contextos_store::{DocumentStore, MemoryStore};
use serde_json::json;
use support::outcome::*;
use support::*;

/// Dispatches the refund in a process that crashes at write `crash_at`, then restarts
/// (a later clock) and checks the invariant: while the ledger says the effect may have
/// applied, the run cannot complete; once it applied, its outcome is pending with the
/// deadline counted from the ledger's observation, and only its own receipt closes it.
/// `retry` sends the same call again from the restarted process first. Returns the
/// number of writes the crashing process attempted.
async fn crash_case<S: DocumentStore + 'static>(
    store: Arc<S>,
    crash_at: usize,
    after_commit: bool,
    retry: bool,
) -> usize {
    let case = format!("crash_at={crash_at} after_commit={after_commit} retry={retry}");
    let admission = admitted(&store).await;
    let audit = audit();
    let adapter = provider(EffectOutcome::Confirmed, None);
    let crashing = Arc::new(CrashStore::new(store.clone(), crash_at, after_commit));
    let first = process(crashing.clone(), &audit, adapter.clone(), 10_000, NOW);
    let _ = first.dispatch(&admission, &refund_call("run_1", "crash_refund")).await;
    let restarted = process(store.clone(), &audit, adapter.clone(), 20_000, LATER);
    if retry {
        let _ = restarted
            .dispatch(&admission, &refund_call("run_1", "crash_refund"))
            .await;
    }
    let op = operation(store.as_ref(), &admission, "crash_refund").await;
    let applied = matches!(op["outcome"].as_str(), Some("confirmed" | "partial"));
    let resolved_not_applied = matches!(op["outcome"].as_str(), Some("not_applied" | "not_dispatched"));
    let completion = restarted.complete_run(&admission, 2).await.unwrap();
    if op.is_null() || resolved_not_applied {
        assert!(
            !completion.reason_codes.contains(&"outcome_pending".to_owned()),
            "{case}: no effect, no outcome owed: {completion:?}"
        );
        return crashing.writes.load(Ordering::SeqCst);
    }
    assert_ne!(
        completion.status, "completed",
        "{case}: an effect that may have applied is owed"
    );
    if !applied {
        return crashing.writes.load(Ordering::SeqCst);
    }
    let record = restarted.outcome(&admission, "crash_refund").await.unwrap().unwrap();
    assert_eq!(record["state"], "pending", "{case}: {record}");
    let first_seen = op["observations"]
        .as_array()
        .unwrap()
        .iter()
        .find(|o| o["outcome"] == "confirmed")
        .unwrap()["observed_at"]
        .clone();
    assert_eq!(
        record["effect_at"], first_seen,
        "{case}: the clock starts at the effect, not the restart"
    );
    assert_eq!(
        record["due_at"],
        json!(add_contract_seconds(first_seen.as_str().unwrap(), 900)),
        "{case}"
    );
    // Another effect's receipt does not close it; its own does, once.
    let wrong = restarted
        .witness_outcome(&admission, "crash_refund", &seen("rf_other", "aa"))
        .await
        .unwrap();
    assert_eq!(wrong, Err("outcome_receipt_mismatch"), "{case}");
    let closed = restarted
        .witness_outcome(&admission, "crash_refund", &seen("rf_crash_refund", "bb"))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(closed["state"], "witnessed", "{case}");
    let done = restarted.complete_run(&admission, 2).await.unwrap();
    assert!(
        !done.reason_codes.contains(&"outcome_pending".to_owned()),
        "{case}: witnessed: {done:?}"
    );
    crashing.writes.load(Ordering::SeqCst)
}

/// Dispatches the refund (the provider leaves it unknown), then reconciles it by
/// asking the provider, in a process that crashes at write `crash_at`; a restarted
/// process (`retry`: reconciling again first) checks the same invariant as
/// [`crash_case`]. Returns the writes the crashing process attempted.
async fn reconcile_case<S: DocumentStore + 'static>(
    store: Arc<S>,
    crash_at: usize,
    after_commit: bool,
    retry: bool,
) -> usize {
    let case = format!("reconcile crash_at={crash_at} after_commit={after_commit} retry={retry}");
    let admission = admitted(&store).await;
    let audit = audit();
    let adapter = provider(EffectOutcome::Unknown, None);
    process(store.clone(), &audit, adapter.clone(), 10_000, NOW)
        .dispatch(&admission, &refund_call("run_1", "late_refund"))
        .await
        .unwrap();
    let crashing = Arc::new(CrashStore::new(store.clone(), crash_at, after_commit));
    let _ = process(crashing.clone(), &audit, adapter.clone(), 20_000, NOW)
        .reconcile(&admission, "late_refund", Resolution::Query)
        .await;
    let restarted = process(store.clone(), &audit, adapter, 30_000, LATER);
    if retry {
        let _ = restarted.reconcile(&admission, "late_refund", Resolution::Query).await;
    }
    let op = operation(store.as_ref(), &admission, "late_refund").await;
    let completion = restarted.complete_run(&admission, 2).await.unwrap();
    assert_ne!(
        completion.status, "completed",
        "{case}: an effect that may have applied is owed"
    );
    if op["outcome"] != "confirmed" {
        return crashing.writes.load(Ordering::SeqCst);
    }
    let record = restarted.outcome(&admission, "late_refund").await.unwrap().unwrap();
    assert_eq!(record["state"], "pending", "{case}: {record}");
    let first_seen = op["observations"]
        .as_array()
        .unwrap()
        .iter()
        .find(|o| o["outcome"] == "confirmed")
        .unwrap()["observed_at"]
        .clone();
    assert_eq!(record["effect_at"], first_seen, "{case}");
    let closed = restarted
        .witness_outcome(&admission, "late_refund", &seen("rf_late_refund", "ee"))
        .await
        .unwrap();
    assert!(closed.is_ok(), "{case}: {closed:?}");
    crashing.writes.load(Ordering::SeqCst)
}

/// Runs the whole matrix on stores from `fresh`.
async fn crash_matrix<S, F, Fut>(fresh: F)
where
    S: DocumentStore + 'static,
    F: Fn() -> Fut,
    Fut: Future<Output = Arc<S>>,
{
    let writes = crash_case(fresh().await, usize::MAX, false, false).await;
    assert!(writes > 4, "the clean dispatch writes {writes} times");
    for crash_at in 0..writes {
        for after_commit in [false, true] {
            for retry in [false, true] {
                crash_case(fresh().await, crash_at, after_commit, retry).await;
            }
        }
    }
    let writes = reconcile_case(fresh().await, usize::MAX, false, false).await;
    assert!(writes > 2, "the clean reconciliation writes {writes} times");
    for crash_at in 0..writes {
        for after_commit in [false, true] {
            for retry in [false, true] {
                reconcile_case(fresh().await, crash_at, after_commit, retry).await;
            }
        }
    }
}

#[tokio::test]
async fn an_applied_effect_stays_owed_whichever_write_a_crash_interrupts() {
    crash_matrix(|| async { Arc::new(MemoryStore::new()) }).await;
}

#[tokio::test]
async fn an_applied_effect_stays_owed_on_postgresql_whichever_write_a_crash_interrupts() {
    let Ok(url) = std::env::var("CONTEXTOS_TEST_DATABASE_URL") else {
        eprintln!("skipped: CONTEXTOS_TEST_DATABASE_URL is unset");
        return;
    };
    let counter = Arc::new(AtomicU64::new(0));
    crash_matrix(|| {
        let url = url.clone();
        let counter = counter.clone();
        async move { Arc::new(fresh_schema(&url, counter.fetch_add(1, Ordering::SeqCst)).await) }
    })
    .await;
}

/// A migrated PostgreSQL store in a schema of its own.
async fn fresh_schema(url: &str, n: u64) -> contextos_store::postgres::PostgresStore {
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

#[tokio::test]
async fn a_witness_crash_closes_the_outcome_once_on_retry() {
    let store = Arc::new(MemoryStore::new());
    let admission = admitted(&store).await;
    let audit = audit();
    let adapter = provider(EffectOutcome::Confirmed, None);
    let g = process(store.clone(), &audit, adapter.clone(), 10_000, NOW);
    g.dispatch(&admission, &refund_call("run_1", "op_w")).await.unwrap();
    for crash_at in 0..4 {
        for after_commit in [false, true] {
            let crashing = Arc::new(CrashStore::new(store.clone(), crash_at, after_commit));
            let p = process(crashing, &audit, adapter.clone(), 30_000, NOW);
            let _ = p.witness_outcome(&admission, "op_w", &seen("rf_op_w", "cc")).await;
        }
    }
    let closed = g
        .witness_outcome(&admission, "op_w", &seen("rf_op_w", "cc"))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(closed["state"], "witnessed");
    assert!(
        !g.complete_run(&admission, 2)
            .await
            .unwrap()
            .reason_codes
            .contains(&"outcome_pending".to_owned())
    );
}
