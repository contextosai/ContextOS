//! Erasure removes the user a run acted for from its admission record.

mod support;

use contextos_gateway::DelegationChain;
use contextos_store::{AppendLog, DocKey, DocKind, DocumentStore};
use support::*;

#[tokio::test]
async fn erasure_removes_the_delegation_chain_from_the_admission_record() {
    let mut h = harness("allow", Behavior::Confirm).await;
    let mut chain = DelegationChain::new("u-alice", &["sa-support".into()]);
    chain.user_roles = Some(vec!["support_lead".into()]);
    h.admission.delegation_chain = Some(chain);
    let key = DocKey::new(TENANT, DocKind::RunAdmission, &h.admission.run_id);
    h.store
        .create(&key, &serde_json::to_value(&h.admission).unwrap())
        .await
        .unwrap();

    let erased = h
        .gateway
        .erase_run(&h.admission, "dpo", "subject request 12")
        .await
        .unwrap();
    assert!(
        erased["erased"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["document"] == "delegation_chain"),
        "{erased}"
    );
    let stored = h.store.get(&key).await.unwrap().unwrap().body;
    assert!(stored.get("delegation_chain").is_none(), "{stored}");
    assert_eq!(stored["delegation_chain_erased"]["erased_by"], "dpo");
    assert!(!stored.to_string().contains("u-alice"), "{stored}");
    assert_eq!(stored["run_id"], h.admission.run_id, "the rest of the record stays");

    // Audited before it goes, and idempotent.
    let entries = h.audit.log().range(TENANT, 1, 1000).await.unwrap();
    let audited = entries
        .iter()
        .filter(|e| e.body["kind"] == "run_data_erased")
        .any(|e| e.body["payload"]["erased"].to_string().contains("delegation_chain"));
    assert!(audited);
    let again = h
        .gateway
        .erase_run(&h.admission, "dpo", "subject request 12")
        .await
        .unwrap();
    assert!(!again["erased"].to_string().contains("delegation_chain"), "{again}");
}
