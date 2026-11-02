//! Prior and outside exposure imported into a shared guarantee's ledger.

mod support;

use std::sync::atomic::Ordering;

use contextos_contract::canonical::sha256_canonical;
use contextos_gateway::*;
use contextos_store::AppendLog;
use serde_json::{Value, json};
use support::*;

fn row(id: &str, amount: u64) -> ImportRow {
    ImportRow {
        import_id: id.into(),
        resource: "ord_881".into(),
        amount,
        source: "legacy_backoffice".into(),
        as_of: "2026-10-01T00:00:00Z".into(),
        evidence_ref: format!("backoffice:refund:{id}"),
    }
}

fn refund(admission: &RunAdmission, operation: &str, amount: u64) -> Value {
    let mut v = call(operation, Some(operation));
    v["run_id"] = json!(admission.run_id);
    v["principal_chain"][0]["id"] = admission.actor["principal_id"].clone();
    v["args"]["amount_minor"] = json!(amount);
    v
}

async fn guarded() -> Harness {
    let mut h = harness("allow", Behavior::Confirm).await;
    h.gateway.set_shared_guarantees(vec![shared_rule()]).unwrap();
    h
}

#[tokio::test]
async fn prior_exposure_counts_against_the_limit_and_imports_once() {
    let h = guarded().await;
    let imported = h
        .gateway
        .import_shared_exposure(TENANT, "refunds", &row("legacy_1", 300_000), "svc_finance")
        .await
        .unwrap()
        .unwrap();
    let digest = sha256_canonical(&json!("ord_881")).unwrap();
    assert_eq!(
        imported,
        json!({"import_id": "legacy_1", "status": "imported", "resource_digest": digest, "over_limit": false})
    );
    let again = h
        .gateway
        .import_shared_exposure(TENANT, "refunds", &row("legacy_1", 300_000), "svc_finance")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(again["status"], "duplicate");
    let view = h
        .gateway
        .shared_exposure(TENANT, "refunds", &digest)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (view["committed"].as_u64(), view["available"].as_u64()),
        (Some(300_000), Some(200_000))
    );

    // Of a 500,000 limit, 300,000 was refunded before onboarding: 420,000 more is refused.
    let refused = h
        .gateway
        .dispatch(&h.admission, &refund(&h.admission, "too_much", 420_000))
        .await
        .unwrap();
    assert_eq!(refused.report.reason_codes, ["shared_guarantee_exceeded"]);
    assert_eq!(h.adapter.calls.load(Ordering::SeqCst), 0);

    let entries = h.audit.log().range(TENANT, 1, 100).await.unwrap();
    let audited: Vec<&Value> = entries
        .iter()
        .filter(|e| e.body["kind"] == "shared_guarantee_imported")
        .map(|e| &e.body["payload"])
        .collect();
    assert_eq!(audited.len(), 1, "a duplicate is not audited again");
    assert_eq!(audited[0]["evidence_ref"], "backoffice:refund:legacy_1");
    assert_eq!(audited[0]["imported_by"], "svc_finance");
}

#[tokio::test]
async fn a_late_import_past_the_limit_is_kept_and_refuses_new_effects() {
    let h = guarded().await;
    let done = h
        .gateway
        .dispatch(&h.admission, &refund(&h.admission, "first", 420_000))
        .await
        .unwrap();
    assert_eq!(done.result["status"], "completed");
    // The back office refunded the same order meanwhile.
    let late = h
        .gateway
        .import_shared_exposure(TENANT, "refunds", &row("backoffice_9", 200_000), "svc_finance")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(late["over_limit"], true);
    let digest = sha256_canonical(&json!("ord_881")).unwrap();
    let view = h
        .gateway
        .shared_exposure(TENANT, "refunds", &digest)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (view["committed"].as_u64(), view["available"].as_u64()),
        (Some(620_000), Some(0))
    );
    assert_eq!(view["over_limit"], true);
    let other = independent_run(&h, "run_after_import").await;
    let refused = h.gateway.dispatch(&other, &refund(&other, "second", 1)).await.unwrap();
    assert_eq!(refused.report.reason_codes, ["shared_guarantee_exceeded"]);
}

#[tokio::test]
async fn bad_rows_are_refused_without_audit() {
    let h = guarded().await;
    let import = |guarantee: &'static str, row: ImportRow| {
        let gateway = &h.gateway;
        async move {
            gateway
                .import_shared_exposure(TENANT, guarantee, &row, "svc_finance")
                .await
                .unwrap()
        }
    };
    assert_eq!(
        import("missing", row("legacy_1", 1)).await,
        Err("shared_guarantee_not_found")
    );
    for bad in [
        ImportRow {
            amount: 0,
            ..row("legacy_1", 1)
        },
        ImportRow {
            as_of: "yesterday".into(),
            ..row("legacy_1", 1)
        },
        ImportRow {
            resource: "ord 881".into(),
            ..row("legacy_1", 1)
        },
        ImportRow {
            evidence_ref: String::new(),
            ..row("legacy_1", 1)
        },
    ] {
        assert_eq!(import("refunds", bad).await, Err("shared_guarantee_import_invalid"));
    }
    assert!(import("refunds", row("legacy_1", 100)).await.is_ok());
    // The same id with other content is refused, not silently ignored.
    assert_eq!(
        import("refunds", row("legacy_1", 200)).await,
        Err("shared_guarantee_import_mismatch")
    );
    let entries = h.audit.log().range(TENANT, 1, 100).await.unwrap();
    assert_eq!(
        entries
            .iter()
            .filter(|e| e.body["kind"] == "shared_guarantee_imported")
            .count(),
        1
    );
}
