//! Canonical resource identity: aliases of one business resource share one ledger.

mod support;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use async_trait::async_trait;
use contextos_contract::canonical::sha256_canonical;
use contextos_gateway::*;
use contextos_store::AppendLog;
use serde_json::{Value, json};
use support::*;

/// Maps any spelling of order 881 to `order:881`; `down` makes it unavailable.
#[derive(Default)]
struct Orders {
    down: AtomicBool,
}

#[async_trait]
impl ResourceIdentityProvider for Orders {
    async fn canonical(&self, _: &RunAdmission, guarantee_id: &str, resource: &str) -> Result<Value, PortError> {
        assert_eq!(guarantee_id, "refunds");
        if self.down.load(Ordering::SeqCst) {
            return Err(PortError::new("resource_identity", "unreachable"));
        }
        let digits: String = resource.chars().filter(char::is_ascii_digit).collect();
        Ok(json!({"canonical_id": format!("order:{digits}"), "evidence_ref": format!("orders:alias:{resource}")}))
    }
}

fn rule(canonicalizer: ResourceCanonicalizer) -> SharedGuarantee {
    let mut rule = shared_rule();
    rule.resource_canonicalizer = canonicalizer;
    rule
}

fn refund(admission: &RunAdmission, operation: &str, order: &str) -> Value {
    let mut v = call(operation, Some(operation));
    v["run_id"] = json!(admission.run_id);
    v["principal_chain"][0]["id"] = admission.actor["principal_id"].clone();
    v["args"]["amount_minor"] = json!(420_000);
    v["args"]["order_id"] = json!(order);
    v
}

/// Two runs refund 420,000 of a 500,000 limit, naming the order two ways: the second
/// is refused when both spellings are one resource.
async fn second_refund(canonicalizer: ResourceCanonicalizer, first: &str, second: &str) -> (Harness, Vec<String>) {
    let mut h = harness("allow", Behavior::Confirm).await;
    h.gateway.set_resource_identity(Arc::new(Orders::default()));
    h.gateway.set_shared_guarantees(vec![rule(canonicalizer)]).unwrap();
    let done = h
        .gateway
        .dispatch(&h.admission, &refund(&h.admission, "first", first))
        .await
        .unwrap();
    assert_eq!(done.result["status"], "completed");
    let other = independent_run(&h, "run_alias").await;
    let next = h
        .gateway
        .dispatch(&other, &refund(&other, "second", second))
        .await
        .unwrap();
    (h, next.report.reason_codes)
}

#[tokio::test]
async fn exact_identity_keeps_aliases_apart() {
    let (_, reasons) = second_refund(ResourceCanonicalizer::Exact, "ord_881", "ORD_881").await;
    assert!(reasons.is_empty(), "{reasons:?}");
}

#[tokio::test]
async fn casefolded_identity_joins_spellings_that_differ_in_case() {
    let (h, reasons) = second_refund(ResourceCanonicalizer::AsciiCasefold, "ord_881", "ORD_881").await;
    assert_eq!(reasons, ["shared_guarantee_exceeded"]);
    let digest = sha256_canonical(&json!("ord_881")).unwrap();
    let view = h
        .gateway
        .shared_exposure(TENANT, "refunds", &digest)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(view["committed"], 420_000);
}

#[tokio::test]
async fn provider_identity_joins_aliases_and_audits_the_mapping() {
    let (h, reasons) = second_refund(ResourceCanonicalizer::Provider, "ord_881", "ORD-881").await;
    assert_eq!(reasons, ["shared_guarantee_exceeded"]);
    let digest = sha256_canonical(&json!("order:881")).unwrap();
    let view = h
        .gateway
        .shared_exposure(TENANT, "refunds", &digest)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(view["committed"], 420_000);

    let entries = h.audit.log().range(TENANT, 1, 100).await.unwrap();
    let reserved = entries
        .iter()
        .find(|e| e.body["kind"] == "shared_guarantee_reserved")
        .map(|e| &e.body["payload"])
        .unwrap();
    assert_eq!(reserved["binding"]["resource_digest"], digest);
    assert_eq!(
        reserved["resource_identity"],
        json!({"canonicalizer": "provider", "extracted_digest": sha256_canonical(&json!("ord_881")).unwrap(),
            "evidence_ref": "orders:alias:ord_881"})
    );
}

#[tokio::test]
async fn an_unavailable_identity_provider_withholds_the_call() {
    let mut h = harness("allow", Behavior::Confirm).await;
    let orders = Arc::new(Orders::default());
    orders.down.store(true, Ordering::SeqCst);
    h.gateway.set_resource_identity(orders);
    h.gateway
        .set_shared_guarantees(vec![rule(ResourceCanonicalizer::Provider)])
        .unwrap();
    let refused = h
        .gateway
        .dispatch(&h.admission, &refund(&h.admission, "unmapped", "ord_881"))
        .await
        .unwrap();
    assert_eq!(refused.report.reason_codes, ["shared_guarantee_identity_unavailable"]);
    assert_eq!(h.adapter.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_provider_canonicalizer_needs_a_provider() {
    let mut h = harness("allow", Behavior::Confirm).await;
    let error = h
        .gateway
        .set_shared_guarantees(vec![rule(ResourceCanonicalizer::Provider)])
        .unwrap_err();
    assert!(error.to_string().contains("resource identity provider"), "{error}");
}
