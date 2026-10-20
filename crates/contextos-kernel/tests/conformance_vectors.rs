//! Parity with the reference conformance assessment.

use contextos_contract::canonical::canonicalize;
use contextos_kernel::conformance::assess_conformance_report;

mod common;

#[test]
fn conformance_assessment_matches_reference() {
    let v = common::load("conformance.json.gz");
    let mut checked = 0;
    for case in v["cases"].as_array().unwrap() {
        if case["expected"].get("throws").is_some() {
            continue;
        }
        let actual = serde_json::to_value(assess_conformance_report(&case["input"])).unwrap();
        assert_eq!(
            canonicalize(&actual).unwrap(),
            canonicalize(&case["expected"]).unwrap(),
            "{}",
            case["name"]
        );
        checked += 1;
    }
    assert!(checked > 300, "{checked}");
}
