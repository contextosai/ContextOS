//! A hold by subject covers every run about that subject, however large the subject's
//! index grows (T52).

mod support;

use contextos_gateway::ErasureError;
use contextos_gateway::privacy::{HoldRequest, RUNS_PER_PAGE, subject_digest};
use contextos_store::{DocKey, DocKind, DocumentStore};
use serde_json::json;
use support::*;

fn hold(id: &str, subject: &str) -> HoldRequest {
    HoldRequest {
        hold_id: id.into(),
        reason: "litigation hold LH-7".into(),
        run_ids: vec![],
        subjects: vec![subject.into()],
        tenant_wide: false,
    }
}

async fn full_page(h: &Harness, subject: &str, truncated: bool) {
    let runs: Vec<String> = (0..RUNS_PER_PAGE).map(|i| format!("run_old_{i}")).collect();
    let key = DocKey::new(TENANT, DocKind::SubjectIndex, subject_digest(subject));
    h.store
        .create(&key, &json!({"runs": runs, "truncated": truncated}))
        .await
        .unwrap();
}

#[tokio::test]
async fn a_run_past_a_full_page_is_indexed_and_held() {
    let mut h = harness("allow", Behavior::Confirm).await;
    h.gateway
        .set_subject_pointers(vec!["/input/context/customer_id".into()]);
    full_page(&h, "cus_77", false).await;

    let request = json!({"input": {"context": {"customer_id": "cus_77"}}});
    h.gateway
        .remember_replay_case(&h.admission, &request, &json!({}), &json!({}))
        .await
        .unwrap();
    let (runs, truncated) = h.gateway.subject_runs(TENANT, "cus_77").await.unwrap();
    assert_eq!(runs.len(), RUNS_PER_PAGE + 1);
    assert_eq!(runs.last().map(String::as_str), Some(h.admission.run_id.as_str()));
    assert!(!truncated);

    h.gateway
        .place_hold(TENANT, &hold("lh_7", "cus_77"), "legal")
        .await
        .unwrap();
    let refused = h.gateway.erase_run(&h.admission, "dpo", "retention sweep").await;
    assert!(
        matches!(refused, Err(ErasureError::Held(ref id)) if id == "lh_7"),
        "{refused:?}"
    );
}

#[tokio::test]
async fn a_run_is_held_by_its_own_subject_record_without_the_index() {
    let mut h = harness("allow", Behavior::Confirm).await;
    h.gateway
        .set_subject_pointers(vec!["/input/context/customer_id".into()]);
    let request = json!({"input": {"context": {"customer_id": "cus_80"}}});
    h.gateway
        .remember_replay_case(&h.admission, &request, &json!({}), &json!({}))
        .await
        .unwrap();
    // Even with the index gone, the run's own record names its subject.
    let page = DocKey::new(TENANT, DocKind::SubjectIndex, subject_digest("cus_80"));
    let current = h.store.get(&page).await.unwrap().unwrap();
    h.store
        .compare_and_swap(&page, current.revision, &json!({"runs": []}))
        .await
        .unwrap();
    h.gateway
        .place_hold(TENANT, &hold("lh_80", "cus_80"), "legal")
        .await
        .unwrap();
    let refused = h.gateway.erase_run(&h.admission, "dpo", "retention sweep").await;
    assert!(matches!(refused, Err(ErasureError::Held(_))), "{refused:?}");

    // A hold on another subject does not cover it.
    h.gateway
        .place_hold(TENANT, &hold("lh_other", "cus_81"), "legal")
        .await
        .unwrap();
    let released = h
        .gateway
        .release_hold(TENANT, "lh_80", "case LH-80 closed", "legal")
        .await;
    assert!(released.is_ok());
    assert!(
        h.gateway
            .erase_run(&h.admission, "dpo", "retention sweep")
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn a_run_without_a_subject_record_is_held_while_the_index_is_truncated() {
    let h = harness("allow", Behavior::Confirm).await;
    // A run indexed before runs kept their own subject record: it is not listed, and
    // the subject's index is truncated, so it cannot be ruled out.
    full_page(&h, "cus_90", true).await;
    h.gateway
        .place_hold(TENANT, &hold("lh_90", "cus_90"), "legal")
        .await
        .unwrap();
    let refused = h.gateway.erase_run(&h.admission, "dpo", "retention sweep").await;
    assert!(
        matches!(refused, Err(ErasureError::Held(ref id)) if id == "lh_90"),
        "{refused:?}"
    );
}

#[tokio::test]
async fn a_run_without_a_subject_record_is_not_held_by_a_complete_index_that_omits_it() {
    let h = harness("allow", Behavior::Confirm).await;
    full_page(&h, "cus_91", false).await;
    h.gateway
        .place_hold(TENANT, &hold("lh_91", "cus_91"), "legal")
        .await
        .unwrap();
    assert!(
        h.gateway
            .erase_run(&h.admission, "dpo", "retention sweep")
            .await
            .is_ok()
    );
}
