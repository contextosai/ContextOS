//! Decision plans over the support refund pack.

use contextos_contract::types::{ContextPack, RunContext};
use contextos_kernel::decision_plan::plan_decisions;
use serde_json::{Value, json};

fn load(path: &str) -> Value {
    let path = format!("{}/../../{path}", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn pack() -> ContextPack {
    serde_json::from_value(load("examples/support-refund/pack.json")).unwrap()
}

fn run_context(role: &str) -> RunContext {
    let mut run = load("examples/support-refund/requests/run.json")["run_context"].clone();
    run["user"]["role"] = json!(role);
    serde_json::from_value(run).unwrap()
}

#[test]
fn support_agent_refunds_depend_on_identity_and_amount() {
    let plan = serde_json::to_value(plan_decisions(&pack(), &run_context("support_agent"), "support.refund").unwrap())
        .unwrap();
    assert_eq!(plan["verdict"], "conditional");
    assert_eq!(plan["possible_verdicts"], json!(["deny", "require_approval", "allow"]));
    let identity = json!({"==": [{"var": "request.context.identity_verified"}, true]});
    // The role check is decided by the principal; only the amount remains.
    let amount = json!({">": [{"var": "request.context.refund_amount"}, 3000]});
    assert_eq!(plan["conditions"], json!([identity, amount]));
    let applies: Vec<(Value, Value, Value)> = plan["rules"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| (r["rule_id"].clone(), r["branch"].clone(), r["applies"].clone()))
        .collect();
    assert_eq!(
        applies,
        vec![
            (json!("R_REFUND_REQUIRES_IDV"), json!("then"), json!("when")),
            (json!("R_REFUND_REQUIRES_IDV"), json!("else"), json!("unless")),
            (json!("R_HIGH_VALUE_REQUIRES_APPROVAL"), json!("then"), json!("when")),
        ]
    );
    assert_eq!(plan["rules"][2]["approval_gate"], "GATE_FINANCE_APPROVAL");
    assert_eq!(plan["rules"][0]["obligations"], json!(["order_lookup"]));
}

#[test]
fn another_role_never_needs_finance_approval() {
    let plan = plan_decisions(&pack(), &run_context("supervisor"), "support.refund").unwrap();
    assert_eq!(plan.possible_verdicts, Some(vec!["deny".into(), "allow".into()]));
    assert!(plan.rules.iter().all(|r| r.rule_id != "R_HIGH_VALUE_REQUIRES_APPROVAL"));
}

#[test]
fn an_intent_no_rule_covers_is_denied() {
    // No business rule applies, so admission denies by default; the plan says so.
    let plan = plan_decisions(&pack(), &run_context("support_agent"), "data.lookup").unwrap();
    assert!(plan.rules.is_empty() && plan.conditions.is_empty());
    assert_eq!(plan.verdict, "deny");
    assert_eq!(plan.possible_verdicts, Some(vec!["deny".into()]));
}
