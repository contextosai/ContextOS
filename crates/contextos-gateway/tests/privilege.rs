//! A capability that requires user roles runs only for a run acting for a user who
//! holds one, as their delegated credential says.

mod support;

use std::sync::atomic::Ordering;

use contextos_gateway::DelegationChain;
use contextos_store::AppendLog;
use serde_json::{Value, json};
use support::*;

async fn refusals(h: &Harness) -> Vec<Value> {
    h.audit
        .log()
        .range(TENANT, 1, 1000)
        .await
        .unwrap()
        .into_iter()
        .filter(|e| e.body["kind"] == "privilege_refusal")
        .map(|e| e.body["payload"].clone())
        .collect()
}

#[tokio::test]
async fn an_effect_needs_a_role_the_user_holds_not_only_the_agents_access() {
    let mut h = harness("allow", Behavior::Confirm).await;
    let mut refund = manifest();
    refund.required_user_roles = vec!["refund_approver".into(), "support_lead".into()];
    h.gateway.pin_capability(refund).unwrap();
    let chain = |roles: Option<Vec<&str>>| {
        Some(
            DelegationChain::new("u-alice", &["sa-support".into()])
                .with_roles(roles.map(|r| r.into_iter().map(str::to_owned).collect())),
        )
    };

    // No user, roles not read, roles that do not include one required: refused.
    for (case, delegation, reason) in [
        ("tc_none", None, "user_not_delegated"),
        ("tc_unknown", chain(None), "user_roles_unknown"),
        ("tc_missing", chain(Some(vec!["support_agent"])), "user_role_missing"),
    ] {
        h.admission.delegation_chain = delegation;
        let out = h.gateway.dispatch(&h.admission, &call(case, Some(case))).await.unwrap();
        assert_eq!(out.report.reason_codes, [reason], "{case}");
    }
    assert_eq!(h.adapter.calls.load(Ordering::SeqCst), 0, "nothing was sent");
    let audited = refusals(&h).await;
    assert_eq!(audited.len(), 3);
    assert_eq!(audited[2]["capability_id"], "adp_payments.issue_refund");
    assert!(
        !json!(audited).to_string().contains("u-alice"),
        "no user ids in the audit"
    );

    // A user holding one of the roles: the effect proceeds.
    h.admission.delegation_chain = chain(Some(vec!["support_agent", "support_lead"]));
    let out = h
        .gateway
        .dispatch(&h.admission, &call("tc_ok", Some("tc_ok")))
        .await
        .unwrap();
    assert_eq!(out.report.status, "completed", "{:?}", out.report.reason_codes);
}

#[test]
fn required_roles_are_bounded() {
    let mut m = manifest();
    m.required_user_roles = vec![String::new()];
    assert!(m.validate().is_err());
    m.required_user_roles = (0..33).map(|i| format!("r{i}")).collect();
    assert!(m.validate().is_err());
    m.required_user_roles = vec!["support_lead".into()];
    assert!(m.validate().is_ok());
    // A manifest without it serializes as before.
    assert!(
        serde_json::to_value(manifest())
            .unwrap()
            .get("required_user_roles")
            .is_none()
    );
}
