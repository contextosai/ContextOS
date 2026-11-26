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

#[tokio::test]
async fn a_subject_key_keeps_unkeyed_digests_out_of_the_audit_chain() {
    use contextos_gateway::privacy::keyed_subject_digest;
    use contextos_store::AppendLog;
    let mut h = harness("allow", Behavior::Confirm).await;
    h.gateway
        .set_subject_pointers(vec!["/input/context/customer_id".into()]);
    // A run indexed before the deployment set a subject key.
    let request = json!({"input": {"context": {"customer_id": "cus_77"}}});
    h.gateway
        .remember_replay_case(&h.admission, &request, &json!({}), &json!({}))
        .await
        .unwrap();

    // Keyed, without matching unkeyed digests: the older run is not found.
    let key = [7; 32];
    h.gateway.set_subject_key(Some(key), false);
    assert_eq!(
        h.gateway.subject_digest_of("cus_77"),
        keyed_subject_digest(&key, "cus_77")
    );
    assert_eq!(
        h.gateway.subject_runs(TENANT, "cus_77").await.unwrap().0,
        Vec::<String>::new()
    );

    // While migrating, lookups and holds also match the unkeyed digest.
    h.gateway.set_subject_key(Some(key), true);
    let (runs, _) = h.gateway.subject_runs(TENANT, "cus_77").await.unwrap();
    assert_eq!(runs, vec![h.admission.run_id.clone()]);
    h.gateway
        .place_hold(TENANT, &hold("lh_key", "cus_77"), "legal")
        .await
        .unwrap();
    let refused = h.gateway.erase_run(&h.admission, "dpo", "retention sweep").await;
    assert!(
        matches!(refused, Err(ErasureError::Held(ref id)) if id == "lh_key"),
        "{refused:?}"
    );

    // The audit chain carries the keyed digest only.
    let entries = h.audit.log().range(TENANT, 1, 1000).await.unwrap();
    let placed = entries.iter().find(|e| e.body["kind"] == "legal_hold_placed").unwrap();
    let text = placed.body.to_string();
    assert!(text.contains(&keyed_subject_digest(&key, "cus_77")), "{text}");
    assert!(!text.contains(&subject_digest("cus_77")), "{text}");
}
