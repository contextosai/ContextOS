//! Parity with the reference authority, policy-composition, approval, redemption and
//! authorization validators (`conformance/generator/authorization.gen.ts`).

use contextos_contract::canonical::canonicalize;
use contextos_kernel::authorization::{
    compose_policy_outcomes, digest_action_binding, evaluate_authorization, transition_approval_redemption,
    validate_approval_binding, validate_authority,
};
use serde::Serialize;
use serde_json::Value;

mod common;

fn check<T: Serialize>(group: &str, cases: &Value, run: impl Fn(&Value) -> T) -> usize {
    let mut checked = 0;
    for (index, case) in cases.as_array().unwrap().iter().enumerate() {
        let expected = &case["expected"];
        if expected.get("throws").is_some() {
            continue;
        }
        let actual = serde_json::to_value(run(&case["input"])).unwrap();
        let name = case
            .get("name")
            .and_then(Value::as_str)
            .map_or_else(|| index.to_string(), str::to_owned);
        assert_eq!(
            canonicalize(&actual).unwrap(),
            canonicalize(expected).unwrap(),
            "{group} {name}"
        );
        checked += 1;
    }
    checked
}

#[test]
fn authorization_family_matches_reference() {
    let vectors = common::load("authorization.json.gz");
    let mut total = 0;
    for case in vectors["digest"].as_array().unwrap() {
        let actual = digest_action_binding(&case["input"]);
        match case["expected"].get("throws") {
            Some(message) => assert_eq!(actual.unwrap_err().to_string(), message.as_str().unwrap()),
            None => assert_eq!(actual.unwrap(), case["expected"].as_str().unwrap()),
        }
        total += 1;
    }
    total += check("authority", &vectors["authority"], validate_authority);
    total += check("policy", &vectors["policy"], compose_policy_outcomes);
    total += check("approval", &vectors["approval"], validate_approval_binding);
    total += check("redemption", &vectors["redemption"], transition_approval_redemption);
    total += check("authorization", &vectors["authorization"], evaluate_authorization);
    assert!(total > 2_500, "{total}");
}
