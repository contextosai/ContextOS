//! Outcome records fenced to their attempt: a retry keeps its obligation whatever an
//! earlier attempt's result lets the sweep read meanwhile; a registration whose
//! dispatcher stopped releases its capacity, and that dispatcher, resumed, sends
//! nothing. Each interleaving is paused deterministically and runs on the in-memory
//! store, and on PostgreSQL when `CONTEXTOS_TEST_DATABASE_URL` is set.

mod support;

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use contextos_gateway::*;
use contextos_store::{DocKey, DocKind, DocumentStore, MemoryStore};
use support::outcome::*;
use support::*;

/// Past the arming grace of a dispatcher that started at `NOW`.
const STALE: &str = "2026-10-20T10:20:00.000000Z";
/// When a dispatch is retried after an abandoned one (the call's facts still hold).
const RETRY: &str = LATER;

fn blocked(codes: &[String]) -> bool {
    codes.contains(&"outcome_pending".to_owned())
}

/// Attempt A is definitively not applied; retry B pauses at `pause_at` while a sweeper
/// examines the run (A's negative result is in the ledger); B resumes and applies.
/// The outcome stays owed by B until B's own receipt is witnessed.
async fn retry_case<S: DocumentStore + 'static>(store: Arc<S>, pause_at: fn(&DocKey, &serde_json::Value) -> bool) {
    let admission = admitted(&store).await;
    let audit = audit();
    let refused = process(
        store.clone(),
        &audit,
        provider(EffectOutcome::NotApplied, None),
        10_000,
        NOW,
    );
    refused
        .dispatch(&admission, &refund_call("run_1", "retry_refund"))
        .await
        .unwrap();
    let retired = refused.outcome(&admission, "retry_refund").await.unwrap().unwrap();
    assert_eq!(retired["state"], "not_applicable", "{retired}");

    let paused = Arc::new(PauseStore::new(store.clone(), pause_at));
    let retry = process(
        paused.clone(),
        &audit,
        provider(EffectOutcome::Confirmed, None),
        20_000,
        LATER,
    );
    let sent = {
        let admission = admission.clone();
        tokio::spawn(async move { retry.dispatch(&admission, &refund_call("run_1", "retry_refund")).await })
    };
    paused.paused.notified().await;

    let sweeper = process(
        store.clone(),
        &audit,
        provider(EffectOutcome::Confirmed, None),
        30_000,
        LATER,
    );
    sweeper.escalate_missed_outcomes(TENANT, 1000).await.unwrap();
    let completion = sweeper.complete_run(&admission, 2).await.unwrap();
    assert_ne!(completion.status, "completed", "B is in flight: {completion:?}");
    let owed = sweeper.outcome(&admission, "retry_refund").await.unwrap().unwrap();
    assert_eq!(
        owed["state"], "awaiting_effect",
        "A's result does not retire B's: {owed}"
    );
    assert_ne!(owed["attempt_id"], retired["attempt_id"], "{owed}");

    paused.resume.notify_one();
    let b = sent.await.unwrap().unwrap();
    assert_eq!(b.result["status"], "completed", "{}", b.result);
    let pending = sweeper.outcome(&admission, "retry_refund").await.unwrap().unwrap();
    assert_eq!(pending["state"], "pending", "{pending}");
    let (open, run) = indexed(store.as_ref()).await;
    assert_eq!((open.len(), run.len()), (1, 1), "tracked for completion");
    assert!(blocked(
        &sweeper.complete_run(&admission, 2).await.unwrap().reason_codes
    ));
    let closed = sweeper
        .witness_outcome(&admission, "retry_refund", &seen("rf_retry_refund", "r1"))
        .await
        .unwrap();
    assert!(closed.is_ok(), "{closed:?}");
    assert!(!blocked(
        &sweeper.complete_run(&admission, 2).await.unwrap().reason_codes
    ));
}

/// A first dispatch pauses at `pause_at` past its arming grace; the sweep abandons its
/// outcome and releases its capacity. Resumed, it sends nothing; a later retry is
/// owed again.
async fn abandoned_case<S: DocumentStore + 'static>(store: Arc<S>, pause_at: fn(&DocKey, &serde_json::Value) -> bool) {
    let admission = admitted(&store).await;
    let audit = audit();
    let paused = Arc::new(PauseStore::new(store.clone(), pause_at));
    let adapter = provider(EffectOutcome::Confirmed, None);
    let delayed = process(paused.clone(), &audit, adapter.clone(), 10_000, NOW);
    let sent = {
        let admission = admission.clone();
        tokio::spawn(async move { delayed.dispatch(&admission, &refund_call("run_1", "slow_refund")).await })
    };
    paused.paused.notified().await;
    assert_eq!(indexed(store.as_ref()).await.0.len(), 1, "registered");

    let sweeper = process(store.clone(), &audit, adapter.clone(), 30_000, STALE);
    sweeper.escalate_missed_outcomes(TENANT, 1000).await.unwrap();
    assert_eq!(indexed(store.as_ref()).await, (vec![], vec![]), "capacity released");

    paused.resume.notify_one();
    let refused = sent.await.unwrap().unwrap();
    assert_eq!(refused.result["status"], "rejected", "{}", refused.result);
    assert_eq!(refused.report.reason_codes, ["outcome_not_armed"]);
    assert_eq!(adapter.calls(), 0, "nothing was sent");
    let op = operation(store.as_ref(), &admission, "slow_refund").await;
    assert_eq!(op["outcome"], "not_dispatched", "{op}");

    let retry = process(store.clone(), &audit, adapter.clone(), 40_000, RETRY);
    let sent = retry
        .dispatch(&admission, &refund_call("run_1", "slow_refund"))
        .await
        .unwrap();
    assert_eq!(sent.result["status"], "completed", "{}", sent.result);
    let pending = retry.outcome(&admission, "slow_refund").await.unwrap().unwrap();
    assert_eq!(pending["state"], "pending", "{pending}");
    assert_eq!(indexed(store.as_ref()).await.0.len(), 1, "owed again");
    let closed = retry
        .witness_outcome(&admission, "slow_refund", &seen("rf_slow_refund", "s1"))
        .await
        .unwrap();
    assert!(closed.is_ok(), "{closed:?}");
    // The abandoned record owes nothing.
    let completion = retry.complete_run(&admission, 2).await.unwrap();
    assert_eq!(completion.status, "completed", "{completion:?}");
}

/// A dispatch that crashes at write `crash_at`, then a sweep past the arming grace:
/// the indexes hold only outcomes some armed attempt may still owe, each with its
/// record. Returns the writes the crashing process attempted.
async fn interrupted_case<S: DocumentStore + 'static>(store: Arc<S>, crash_at: usize, after_commit: bool) -> usize {
    let case = format!("crash_at={crash_at} after_commit={after_commit}");
    let admission = admitted(&store).await;
    let audit = audit();
    let adapter = provider(EffectOutcome::Unknown, None);
    let crashing = Arc::new(CrashStore::new(store.clone(), crash_at, after_commit));
    let _ = process(crashing.clone(), &audit, adapter.clone(), 10_000, NOW)
        .dispatch(&admission, &refund_call("run_1", "cut_refund"))
        .await;
    let sweeper = process(store.clone(), &audit, adapter, 30_000, STALE);
    sweeper.escalate_missed_outcomes(TENANT, 1000).await.unwrap();
    let _ = sweeper.complete_run(&admission, 2).await.unwrap();
    let (open, run) = indexed(store.as_ref()).await;
    for id in open.iter().chain(&run) {
        let record = store
            .get(&DocKey::new(TENANT, DocKind::Outcome, id.as_str().unwrap()))
            .await
            .unwrap()
            .unwrap_or_else(|| panic!("{case}: {id} indexed without its record"))
            .body;
        assert_eq!(record["armed"], true, "{case}: unarmed past its grace: {record}");
    }
    crashing.writes.load(Ordering::SeqCst)
}

async fn fencing_suite<S, F, Fut>(fresh: F)
where
    S: DocumentStore + 'static,
    F: Fn() -> Fut,
    Fut: Future<Output = Arc<S>>,
{
    for pause_at in [before_claim, before_arming] {
        retry_case(fresh().await, pause_at).await;
        abandoned_case(fresh().await, pause_at).await;
    }
    let writes = interrupted_case(fresh().await, usize::MAX, false).await;
    assert!(writes > 4, "the clean dispatch writes {writes} times");
    for crash_at in 0..writes {
        for after_commit in [false, true] {
            interrupted_case(fresh().await, crash_at, after_commit).await;
        }
    }
}

#[tokio::test]
async fn outcomes_are_fenced_to_their_attempt() {
    fencing_suite(|| async { Arc::new(MemoryStore::new()) }).await;
}

#[tokio::test]
async fn outcomes_are_fenced_to_their_attempt_on_postgresql() {
    let Ok(url) = std::env::var("CONTEXTOS_TEST_DATABASE_URL") else {
        eprintln!("skipped: CONTEXTOS_TEST_DATABASE_URL is unset");
        return;
    };
    let counter = Arc::new(AtomicU64::new(0));
    fencing_suite(|| {
        let url = url.clone();
        let counter = counter.clone();
        async move { Arc::new(fresh_schema(&url, counter.fetch_add(1, Ordering::SeqCst)).await) }
    })
    .await;
}
