//! Outcome contracts bound to their effect: equal effects need their own evidence, one
//! attestation closes one effect, effects never applied release their outcome, and no
//! outcome can starve an overdue one.

mod support;

use std::sync::Arc;

use contextos_gateway::*;
use contextos_store::{DocKey, DocKind, DocumentStore, MemoryStore};
use serde_json::{Value, json};
use support::outcome::*;
use support::*;

#[tokio::test]
async fn equal_effects_on_one_resource_each_need_their_own_evidence() {
    let h = harness("allow", Behavior::Confirm).await;
    let audit = audit();
    open(&h.store, &h.admission).await;
    let other = independent_run(&h, "run_b").await;
    open(&h.store, &other).await;
    // Distinct references: each effect's receipt closes only that effect.
    let g = process(
        h.store.clone(),
        &audit,
        provider(EffectOutcome::Confirmed, None),
        10_000,
        NOW,
    );
    g.dispatch(&h.admission, &refund_call("run_1", "refund_a"))
        .await
        .unwrap();
    let b = g.dispatch(&other, &refund_call("run_b", "refund_b")).await.unwrap();
    assert_eq!(b.result["status"], "completed", "{}", b.result);
    let token_a = seen("rf_refund_a", "a1");
    assert!(
        g.witness_outcome(&h.admission, "refund_a", &token_a)
            .await
            .unwrap()
            .is_ok()
    );
    assert_eq!(
        g.witness_outcome(&other, "refund_b", &token_a).await.unwrap(),
        Err("outcome_receipt_mismatch")
    );
    // Reposting to its own operation is idempotent.
    assert!(
        g.witness_outcome(&h.admission, "refund_a", &token_a)
            .await
            .unwrap()
            .is_ok()
    );
    assert!(
        g.witness_outcome(&other, "refund_b", &seen("rf_refund_b", "b1"))
            .await
            .unwrap()
            .is_ok()
    );
}

#[tokio::test]
async fn one_attestation_closes_one_effect_even_when_references_repeat() {
    let h = harness("allow", Behavior::Confirm).await;
    let audit = audit();
    open(&h.store, &h.admission).await;
    let other = independent_run(&h, "run_b").await;
    open(&h.store, &other).await;
    let g = process(
        h.store.clone(),
        &audit,
        provider(EffectOutcome::Confirmed, Some("rf_same")),
        10_000,
        NOW,
    );
    g.dispatch(&h.admission, &refund_call("run_1", "refund_a"))
        .await
        .unwrap();
    let b = g.dispatch(&other, &refund_call("run_b", "refund_b")).await.unwrap();
    assert_eq!(b.result["status"], "completed", "{}", b.result);
    let token = seen("rf_same", "d1");
    assert!(
        g.witness_outcome(&h.admission, "refund_a", &token)
            .await
            .unwrap()
            .is_ok()
    );
    assert_eq!(
        g.witness_outcome(&other, "refund_b", &token).await.unwrap(),
        Err("outcome_attestation_reused")
    );
    assert!(
        g.witness_outcome(&h.admission, "refund_a", &token)
            .await
            .unwrap()
            .is_ok()
    );
    assert!(
        g.witness_outcome(&other, "refund_b", &seen("rf_same", "d2"))
            .await
            .unwrap()
            .is_ok()
    );
}

async fn open_outcomes(store: &MemoryStore) -> Vec<Value> {
    store
        .get(&DocKey::new(TENANT, DocKind::Outcome, "open"))
        .await
        .unwrap()
        .map_or_else(Vec::new, |d| d.body["keys"].as_array().cloned().unwrap_or_default())
}

#[tokio::test]
async fn an_effect_never_applied_releases_its_outcome_and_an_unknown_one_keeps_it() {
    let store = Arc::new(MemoryStore::new());
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
        .dispatch(&admission, &refund_call("run_1", "refund_refused"))
        .await
        .unwrap();
    let record = refused.outcome(&admission, "refund_refused").await.unwrap().unwrap();
    assert_eq!(record["state"], "not_applicable", "{record}");
    assert!(
        open_outcomes(&store).await.is_empty(),
        "the tenant's capacity is released"
    );
    let completion = refused.complete_run(&admission, 2).await.unwrap();
    assert_eq!(completion.status, "completed", "{completion:?}");

    let store = Arc::new(MemoryStore::new());
    let admission = admitted(&store).await;
    let unknown = process(
        store.clone(),
        &audit,
        provider(EffectOutcome::Unknown, None),
        10_000,
        NOW,
    );
    let _ = unknown
        .dispatch(&admission, &refund_call("run_1", "refund_unknown"))
        .await;
    let record = unknown.outcome(&admission, "refund_unknown").await.unwrap().unwrap();
    assert_eq!(record["state"], "awaiting_effect");
    assert_eq!(
        open_outcomes(&store).await.len(),
        1,
        "an effect that may have applied keeps its obligation"
    );
    assert_ne!(unknown.complete_run(&admission, 2).await.unwrap().status, "completed");
}

#[tokio::test]
async fn an_overdue_outcome_escalates_behind_a_thousand_that_are_not_due() {
    let store = Arc::new(MemoryStore::new());
    let admission = admitted(&store).await;
    let audit = audit();
    let g = process(
        store.clone(),
        &audit,
        provider(EffectOutcome::Confirmed, None),
        10_000,
        NOW,
    );
    let mut keys = Vec::new();
    for i in 0..1000 {
        let id = format!("rec_future_{i:04}");
        store
            .create(
                &DocKey::new(TENANT, DocKind::Outcome, &id),
                &json!({"run_id": "run_1", "operation_id": format!("op_{i}"), "state": "pending",
                    "due_at": "2026-10-21T10:00:00.000000Z", "capability_id": "adp_payments.issue_refund"}),
            )
            .await
            .unwrap();
        keys.push(json!(id));
    }
    store
        .create(
            &DocKey::new(TENANT, DocKind::Outcome, "rec_overdue"),
            &json!({"run_id": "run_1", "operation_id": "op_late", "state": "pending",
                "due_at": "2026-10-20T09:00:00.000000Z", "capability_id": "adp_payments.issue_refund",
                "witness": LEDGER, "postcondition": "refund_posted", "action_digest": "sha256:00"}),
        )
        .await
        .unwrap();
    keys.push(json!("rec_overdue"));
    store
        .create(&DocKey::new(TENANT, DocKind::Outcome, "open"), &json!({"keys": keys}))
        .await
        .unwrap();
    let mut passes = 0;
    while store
        .get(&DocKey::new(TENANT, DocKind::Outcome, "rec_overdue"))
        .await
        .unwrap()
        .unwrap()
        .body["state"]
        == "pending"
    {
        passes += 1;
        assert!(passes <= 2, "escalated within ceil(1001 / 1000) passes");
        g.escalate_missed_outcomes(TENANT, 1000).await.unwrap();
    }
    let _ = admission;
    assert_eq!(passes, 2);
}

#[test]
fn an_effect_contract_needs_the_providers_reference_and_every_contract_says_what_it_binds() {
    let mut m = serde_json::to_value(outcome_manifest()).unwrap();
    assert!(
        serde_json::from_value::<CapabilityManifest>(m.clone())
            .unwrap()
            .validate()
            .is_ok()
    );
    m["recovery"].as_object_mut().unwrap().remove("reference_pointer");
    let refused = serde_json::from_value::<CapabilityManifest>(m.clone())
        .unwrap()
        .validate()
        .unwrap_err();
    assert!(refused.to_string().contains("reference_pointer"), "{refused}");
    m["outcome"]["binds"] = json!("state");
    assert!(
        serde_json::from_value::<CapabilityManifest>(m.clone())
            .unwrap()
            .validate()
            .is_ok()
    );
    m["outcome"].as_object_mut().unwrap().remove("binds");
    assert!(
        serde_json::from_value::<CapabilityManifest>(m).is_err(),
        "binds is required"
    );
}
