//! Intent claims across retries and recovery: a retried operation claims its intent
//! again before it is sent, and an effect recorded not applied by recovery releases
//! the claim (reconciled or attested), so the request can be redelivered into a new
//! run.

mod support;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use contextos_gateway::{CapabilityManifest, EffectOutcome, Resolution};
use contextos_store::{DocKey, DocKind, DocumentStore, MemoryStore, ScanCursor, StoreError, Versioned};
use serde_json::{Value, json};
use support::outcome::harness_process;
use support::*;

/// The harness's refund capability with an intent key on order and amount, retryable at once.
fn intent_manifest() -> CapabilityManifest {
    let mut pinned = manifest();
    pinned.intent = Some(
        serde_json::from_value(json!({"key_pointers": ["/order_id", "/amount_minor"], "window_seconds": 3600}))
            .unwrap(),
    );
    pinned.recovery.retry_delays_seconds = vec![0];
    pinned
}

fn with_intent(h: &mut Harness) {
    h.gateway.pin_capability(intent_manifest()).unwrap();
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

/// A store whose process dies right after it opens a dispatch gate: the attempt is
/// recorded as being sent, but nothing reached the provider.
struct DiesAtGate {
    inner: Arc<MemoryStore>,
    dead: AtomicBool,
}

impl DiesAtGate {
    fn alive(&self) -> Result<(), StoreError> {
        if self.dead.load(Ordering::SeqCst) {
            return Err(StoreError::Backend("process crashed".into()));
        }
        Ok(())
    }
}

impl DocumentStore for DiesAtGate {
    async fn get(&self, k: &DocKey) -> Result<Option<Versioned>, StoreError> {
        self.alive()?;
        self.inner.get(k).await
    }
    async fn create(&self, k: &DocKey, b: &Value) -> Result<Versioned, StoreError> {
        self.alive()?;
        let created = self.inner.create(k, b).await?;
        if k.kind == DocKind::DispatchGate {
            self.dead.store(true, Ordering::SeqCst);
            return Err(StoreError::Backend("process crashed".into()));
        }
        Ok(created)
    }
    async fn compare_and_swap(&self, k: &DocKey, r: u64, b: &Value) -> Result<Versioned, StoreError> {
        self.alive()?;
        self.inner.compare_and_swap(k, r, b).await
    }
    async fn compare_and_swap_encoded(
        &self,
        k: &DocKey,
        r: u64,
        b: Value,
        e: contextos_store::Encoded,
    ) -> Result<u64, StoreError> {
        self.alive()?;
        self.inner.compare_and_swap_encoded(k, r, b, e).await
    }
    async fn expiring(
        &self,
        k: DocKind,
        t: u64,
        a: Option<&ScanCursor>,
        l: usize,
    ) -> Result<Vec<ScanCursor>, StoreError> {
        self.inner.expiring(k, t, a, l).await
    }
}

#[tokio::test]
async fn an_attested_absence_releases_the_intent() {
    let h = harness("allow", Behavior::Confirm).await;
    let dying = Arc::new(DiesAtGate {
        inner: h.store.clone(),
        dead: AtomicBool::new(false),
    });
    let crashed = harness_process(&h, dying, 10_000, NOW, intent_manifest());
    let lost = crashed.dispatch(&h.admission, &call("tc_1", Some("refund_x"))).await;
    assert!(lost.is_err(), "the process died before sending");
    assert_eq!(h.adapter.calls.load(Ordering::SeqCst), 0);
    let (_, _, body) = intent_claim(&h).await;
    assert_eq!(body["released"], false, "a crashed attempt keeps the claim");

    // Ten minutes on, an attester checked the provider's records: never sent.
    let later = harness_process(
        &h,
        h.store.clone(),
        20_000,
        "2026-10-20T10:10:00.000000Z",
        intent_manifest(),
    );
    later.open_run(&h.admission).await.unwrap();
    let attested = later
        .attest_absence(
            &h.admission,
            "refund_x",
            artifact("provider_ledger", "export_1"),
            "2026-10-20T10:06:00.000000Z",
            "attester",
        )
        .await
        .unwrap();
    assert_eq!(
        (attested.status.as_str(), attested.outcome.as_deref()),
        ("resolved", Some("not_applied")),
        "{:?}",
        attested.reason_codes
    );
    let (_, _, body) = intent_claim(&h).await;
    assert_eq!(body["released"], true, "redeliverable into a new run: {body}");
}
