//! The inventory end to end: a runtime's verified chain and an owner's declaration
//! become `/api/inventory` rows, with shadow rows for what ran undeclared.

mod harness;

use harness::{call, runtime, tower};
use serde_json::{Value, json};

const AT: &str = "2026-10-21T10:00:00.000000Z";
const LATER: &str = "2026-10-21T10:05:00.000000Z";

fn traffic() -> Vec<(&'static str, Value, &'static str)> {
    vec![
        (
            "run_admitted",
            json!({"run_id": "r1", "trace_id": "trace_r1", "agent_id": "agt_support", "pack_ref": "ctxpack.support@5.2.0",
                "intent": "support.refund", "profiles": ["contextos.core"], "required_controls": [], "admitted_by": "svc",
                "release_refs": [{"artifact_type": "model_profile", "artifact_id": "claude-opus-5-5", "version": "1"},
                                 {"artifact_type": "model_profile", "artifact_id": "unlisted-model", "version": "2"}],
                "surfaced_capabilities": ["adp_payments.issue_refund"]}),
            AT,
        ),
        (
            "operation_claim",
            json!({"run_id": "r1", "operation_id": "op1", "attempt_id": "a1", "capability_id": "adp_payments.issue_refund"}),
            LATER,
        ),
        (
            "revocation_refusal",
            json!({"run_id": "r1", "capability_id": "crm.delete_customer", "reason_codes": ["capability_not_pinned"]}),
            LATER,
        ),
    ]
}

fn row<'a>(body: &'a Value, kind: &str, id: &str) -> &'a Value {
    body["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["kind"] == kind && i["id"] == id)
        .unwrap_or_else(|| panic!("no {kind} {id} in {body}"))
}

#[tokio::test]
async fn evidence_and_declarations_become_one_inventory() {
    let rt = runtime(&traffic()).await;
    let (base, _) = tower(&rt, "[governance]\nlifecycle_approval = false").await;
    let (status, _) = call(&base, "GET", "/api/inventory", "nobody", None).await;
    assert_eq!(status, 401);
    let (status, _) = call(&base, "GET", "/api/inventory?kind=planet", "viewer", None).await;
    assert_eq!(status, 422);
    let (status, _) = call(&base, "GET", "/api/inventory?format=xml", "viewer", None).await;
    assert_eq!(status, 422);

    let bad_tier = json!({"owner": "maya", "team": "support-ai", "purpose": "Refunds", "users_served": "customers",
        "lifecycle": "production", "risk_tier": "extreme"});
    let path = "/api/agents/tenant_acme_prod%2Fagt_support/declaration";
    let (status, _) = call(&base, "PUT", path, "owner", Some(bad_tier)).await;
    assert_eq!(status, 422);
    let declaration = json!({"owner": "maya", "team": "support-ai", "purpose": "Refunds", "users_served": "customers",
        "lifecycle": "production", "risk_tier": "high", "models": ["claude-opus-5-5"]});
    let (status, body) = call(&base, "PUT", path, "owner", Some(declaration)).await;
    assert_eq!(status, 200, "{body}");

    let (status, body) = call(&base, "GET", "/api/inventory", "viewer", None).await;
    assert_eq!(status, 200, "{body}");
    let agent = row(&body, "agent", "tenant_acme_prod/agt_support");
    assert_eq!(agent["declared"], true);
    assert_eq!(agent["risk_tier"], "high");
    assert_eq!(agent["lifecycle"], "production");
    assert_eq!(agent["environments"], json!(["production"]));
    assert_eq!(agent["owner_teams"], json!(["support-ai"]));
    let refund = row(&body, "capability", "adp_payments.issue_refund");
    assert_eq!(refund["declared"], true);
    assert_eq!(refund["last_seen"], LATER);
    assert_eq!(refund["risk_tier"], "high");
    assert_eq!(row(&body, "adapter", "adp_payments")["declared"], true);
    assert_eq!(row(&body, "model", "claude-opus-5-5@1")["declared"], true);
    assert_eq!(row(&body, "model", "unlisted-model@2")["declared"], false);
    assert_eq!(row(&body, "capability", "crm.delete_customer")["declared"], false);
    assert_eq!(
        row(&body, "owner", "support-ai")["agents"],
        json!(["tenant_acme_prod/agt_support"])
    );
    // The unlisted model, the unpinned capability and its adapter.
    assert_eq!(body["shadow"], 3, "{body}");

    let (_, shadow) = call(
        &base,
        "GET",
        "/api/inventory?shadow=true&kind=capability",
        "viewer",
        None,
    )
    .await;
    let ids: Vec<&str> = shadow["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, ["crm.delete_customer"]);

    let (status, csv) = call(&base, "GET", "/api/inventory?format=csv&kind=model", "viewer", None).await;
    assert_eq!(status, 200);
    let csv = csv.as_str().unwrap();
    assert!(csv.starts_with("kind,id,declared,"), "{csv}");
    assert!(csv.contains("model,unlisted-model@2,false,"), "{csv}");
    assert_eq!(csv.lines().count(), 3, "{csv}");
}
