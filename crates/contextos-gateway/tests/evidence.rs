//! A run's evidence package follows the budget archive chain only as far as it is
//! sound: a chain that loops is reported as corrupt instead of walked forever.

mod support;

use contextos_gateway::GatewayError;
use contextos_store::{DocKey, DocKind, DocumentStore, StoreError};
use serde_json::json;
use support::*;

#[tokio::test]
async fn a_cyclic_budget_archive_chain_is_an_integrity_error() {
    let h = harness("allow", Behavior::Confirm).await;
    assert!(h.gateway.run_evidence(&h.admission).await.is_ok());

    // Two archives that name each other, and a ledger that opens from one of them.
    for (id, previous) in [("arch_a", "arch_b"), ("arch_b", "arch_a")] {
        let archive = json!({"previous_opening_usage_ref": {"artifact_id": previous}});
        h.store
            .create(&DocKey::new(TENANT, DocKind::BudgetArchive, id), &archive)
            .await
            .unwrap();
    }
    let key = DocKey::new(TENANT, DocKind::BudgetLedger, &h.admission.budget_ledger_id);
    let ledger = h.store.get(&key).await.unwrap().unwrap();
    let mut body = ledger.body.clone();
    body["opening_usage_ref"] = json!({"artifact_id": "arch_a"});
    h.store.compare_and_swap(&key, ledger.revision, &body).await.unwrap();

    let error = h.gateway.run_evidence(&h.admission).await.unwrap_err();
    assert!(matches!(error, GatewayError::Store(StoreError::Integrity)), "{error:?}");
}
