//! Settled shared-guarantee receipts are archived after their retention, so a resource
//! is not limited to 1,024 effects over its lifetime.

mod support;

use contextos_contract::canonical::sha256_canonical;
use contextos_gateway::EXPOSURE_RECEIPT_RETENTION_SECONDS;
use contextos_store::{DocKey, DocKind, DocumentStore};
use serde_json::{Value, json};
use support::*;

fn ledger_key() -> DocKey {
    let resource = sha256_canonical(&json!("ord_881")).unwrap();
    DocKey::new(
        TENANT,
        DocKind::SharedExposure,
        sha256_canonical(&json!(["refunds", resource])).unwrap(),
    )
}

async fn refund(h: &Harness, run: &str, amount: u64) -> Value {
    let admission = independent_run(h, run).await;
    let mut c = call(&format!("tc_{run}"), Some(&format!("refund_{run}")));
    c["run_id"] = json!(admission.run_id);
    c["principal_chain"][0]["id"] = json!("agt_independent");
    c["args"]["amount_minor"] = json!(amount);
    let out = h.gateway.dispatch(&admission, &c).await.unwrap();
    assert_eq!(out.result["status"], "completed", "{out:?}");
    h.store.get(&ledger_key()).await.unwrap().unwrap().body
}

#[tokio::test]
async fn settled_receipts_leave_the_ledger_after_their_retention() {
    let mut h = harness("allow", Behavior::Confirm).await;
    h.gateway.set_shared_guarantees(vec![shared_rule()]).unwrap();
    let first = refund(&h, "run_a", 100_000).await;
    let (receipt_a, _) = first["receipts"].as_object().unwrap().iter().next().unwrap();
    let receipt_a = receipt_a.clone();

    // The next reservation stamps the settled receipt; it is still fenced.
    let second = refund(&h, "run_b", 100_000).await;
    assert_eq!(second["receipts"][&receipt_a]["settled_seen_at"], NOW);

    // Once the retention has passed since then, the next reservation archives it.
    let key = ledger_key();
    let read = h.store.get(&key).await.unwrap().unwrap();
    let mut aged = read.body.clone();
    let seen = format!(
        "2026-10-20T{:02}:00:00.000000Z",
        10 - EXPOSURE_RECEIPT_RETENTION_SECONDS / 3600
    );
    aged["receipts"][&receipt_a]["settled_seen_at"] = json!(seen);
    h.store.compare_and_swap(&key, read.revision, &aged).await.unwrap();
    let third = refund(&h, "run_c", 100_000).await;
    assert!(third["receipts"].get(&receipt_a).is_none(), "{third}");
    assert_eq!(third["receipts"].as_object().unwrap().len(), 2);
    assert_eq!(
        (&third["archived_receipts"], &third["archived_committed"]),
        (&json!(1), &json!(100_000))
    );

    let digest = sha256_canonical(&json!("ord_881")).unwrap();
    let exposure = h
        .gateway
        .shared_exposure(TENANT, "refunds", &digest)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (&exposure["committed"], &exposure["available"]),
        (&json!(300_000), &json!(200_000))
    );
}
