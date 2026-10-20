//! Parity with the reference run lifecycle, resume, operation ledger and budget ledger.

use contextos_contract::canonical::canonicalize;
use contextos_kernel::budget_ledger::{
    convert_legacy_cost_to_units, reserve_budget, reserve_child_budget, settle_budget, settle_child_budget,
};
use contextos_kernel::operation_ledger::{claim_operation, record_effect_observation};
use contextos_kernel::run_state::{transition_run, validate_resume};
use serde_json::Value;

mod common;

fn assert_same(group: &str, case: &Value, actual: &Value) {
    assert_eq!(
        canonicalize(actual).unwrap(),
        canonicalize(&case["expected"]).unwrap(),
        "{group} {}",
        case["name"]
    );
}

#[test]
fn durable_execution_matches_reference() {
    let v = common::load("durable.json.gz");
    let mut checked = 0;
    for case in v["runs"].as_array().unwrap() {
        if case["expected"].get("throws").is_some() {
            continue;
        }
        let i = &case["input"];
        let actual = transition_run(&i["state"], &i["event"], &i["evaluation_time"]);
        assert_same("run", case, &serde_json::to_value(actual).unwrap());
        checked += 1;
    }
    for case in v["ops"].as_array().unwrap() {
        if case["expected"].get("throws").is_some() {
            continue;
        }
        let i = &case["input"];
        let actual = if case["op"] == "claim" {
            claim_operation(
                &i["ledger"],
                &i["intent"],
                &i["expected_revision"],
                &i["executor_generation"],
            )
        } else {
            record_effect_observation(&i["ledger"], &i["observation"], &i["expected_revision"])
        };
        assert_same("op", case, &serde_json::to_value(actual).unwrap());
        checked += 1;
    }
    for case in v["resumes"].as_array().unwrap() {
        match (validate_resume(&case["input"]), case["expected"].get("throws")) {
            (Err(error), Some(message)) => assert_eq!(error.to_string(), message.as_str().unwrap(), "{}", case["name"]),
            (Ok(actual), None) => assert_same("resume", case, &serde_json::to_value(actual).unwrap()),
            (actual, expected) => panic!("resume {}: {actual:?} vs {expected:?}", case["name"]),
        }
        checked += 1;
    }
    for case in v["budgets"].as_array().unwrap() {
        if case["expected"].get("throws").is_some() {
            continue;
        }
        let i = &case["input"];
        let actual = match case["op"].as_str().unwrap() {
            "reserve" => reserve_budget(&i["ledger"], &i["request"]),
            "settle" => settle_budget(&i["ledger"], &i["request"]),
            "reserve_child" => reserve_child_budget(&i["ledger"], &i["request"]),
            _ => settle_child_budget(&i["ledger"], &i["request"]),
        };
        assert_same("budget", case, &serde_json::to_value(actual).unwrap());
        checked += 1;
    }
    for case in v["costs"].as_array().unwrap() {
        let actual = serde_json::to_value(convert_legacy_cost_to_units(&case["value"], &case["unit"])).unwrap();
        assert_eq!(actual, case["expected"], "cost {} {}", case["value"], case["unit"]);
    }
    assert!(checked > 1_800, "{checked}");
}
