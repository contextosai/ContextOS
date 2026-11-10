//! Intent claims across retries and recovery: a retried operation claims its intent
//! again before it is sent, and an effect recorded not applied by recovery releases
//! the claim, so the request can be redelivered into a new run.

mod support;

use std::sync::atomic::Ordering;

use contextos_gateway::{EffectOutcome, Resolution};
use contextos_store::{DocKey, DocKind, DocumentStore};
use serde_json::{Value, json};
use support::*;

/// Pins the harness's refund capability with an intent key on order and amount, retryable at once.
fn with_intent(h: &mut Harness) {
    let mut pinned = manifest();
    pinned.intent = Some(
        serde_json::from_value(json!({"key_pointers": ["/order_id", "/amount_minor"], "window_seconds": 3600}))
            .unwrap(),
    );
    pinned.recovery.retry_delays_seconds = vec![0];
    h.gateway.pin_capability(pinned).unwrap();
}

/// The one intent claim document the run's calls wrote.
async fn intent_claim(h: &Harness) -> (DocKey, u64, Value) {
    let ids = h.store.list(TENANT, DocKind::IntentClaim, None, 100).await.unwrap();
    let digests: Vec<_> = ids.iter().filter(|id| id.starts_with("sha256:")).collect();
    assert_eq!(digests.len(), 1, "{ids:?}");
    let key = DocKey::new(TENANT, DocKind::IntentClaim, digests[0]);
    let read = h.store.get(&key).await.unwrap().unwrap();
    (key, read.revision, read.body)
}

/// Another run takes the released claim, as its own dispatch would.
async fn taken_by_another_run(h: &Harness) {
    let (key, revision, body) = intent_claim(h).await;
    assert_eq!(body["released"], true, "{body}");
    let taken = json!({"run_id": "run_other", "operation_id": "refund_other", "claimed_at": 0,
        "expires_at": u64::MAX / 2, "released": false});
    h.store.compare_and_swap(&key, revision, &taken).await.unwrap();
}

#[tokio::test]
async fn a_retry_after_release_is_refused_while_another_run_holds_the_intent() {
    let mut h = harness("allow", Behavior::RefuseInjected).await;
    with_intent(&mut h);
    let first = h
        .gateway
        .dispatch(&h.admission, &call("tc_1", Some("refund_x")))
        .await
        .unwrap();
    assert_eq!(first.result["status"], "failed", "{:?}", first.report);
    assert_eq!(h.adapter.calls.load(Ordering::SeqCst), 1);

    taken_by_another_run(&h).await;
    let retry = h
        .gateway
        .dispatch(&h.admission, &call("tc_2", Some("refund_x")))
        .await
        .unwrap();
    assert_eq!(
        retry.report.reason_codes,
        ["effect_repeated_across_runs"],
        "{:?}",
        retry.report
    );
    assert_eq!(h.adapter.calls.load(Ordering::SeqCst), 1, "the retry is not sent");
}

#[tokio::test]
async fn a_retry_reclaims_its_own_released_intent() {
    let mut h = harness("allow", Behavior::RefuseInjected).await;
    with_intent(&mut h);
    for id in ["tc_1", "tc_2"] {
        h.gateway
            .dispatch(&h.admission, &call(id, Some("refund_x")))
            .await
            .unwrap();
    }
    assert_eq!(h.adapter.calls.load(Ordering::SeqCst), 2, "nobody else holds it");
    let (_, _, body) = intent_claim(&h).await;
    assert_eq!(body["run_id"], h.admission.run_id);
    assert_eq!(body["released"], true, "not applied again: released again");
}

#[tokio::test]
async fn recovery_recording_not_applied_releases_the_intent() {
    let mut h = harness("allow", Behavior::Hang).await;
    with_intent(&mut h);
    let out = h
        .gateway
        .dispatch(&h.admission, &call("tc_1", Some("refund_x")))
        .await
        .unwrap();
    assert_eq!(out.report.status, "paused", "{:?}", out.report);
    let (_, _, body) = intent_claim(&h).await;
    assert_eq!(body["released"], false, "an unknown outcome keeps the claim");

    let resolved = h
        .gateway
        .reconcile(
            &h.admission,
            "refund_x",
            Resolution::Assert {
                outcome: EffectOutcome::NotApplied,
                evidence_ref: artifact("provider_ledger", "no_refund"),
                principal_id: "oncall".into(),
            },
        )
        .await
        .unwrap();
    assert_eq!(resolved.status, "resolved", "{resolved:?}");
    let (_, _, body) = intent_claim(&h).await;
    assert_eq!(body["released"], true, "{body}");
}
