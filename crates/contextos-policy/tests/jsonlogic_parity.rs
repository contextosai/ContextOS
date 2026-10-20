//! Parity with json-logic-js 2.0.5 over a seeded corpus
//! (`conformance/generator/jsonlogic.gen.ts`).

use contextos_contract::canonical::canonicalize;
use contextos_policy::{EvalErrorKind, JsVal, apply};
use serde_json::Value;

fn matches_expected(actual: &JsVal, expected: &Value) -> bool {
    match expected["t"].as_str().unwrap() {
        "undefined" => matches!(actual, JsVal::Undefined),
        "nan" => matches!(actual, JsVal::Num(n) if n.is_nan()),
        "inf" => matches!(actual, JsVal::Num(n) if *n == f64::INFINITY),
        "-inf" => matches!(actual, JsVal::Num(n) if *n == f64::NEG_INFINITY),
        "-0" => matches!(actual, JsVal::Num(n) if *n == 0.0 && n.is_sign_negative()),
        "value" => {
            if let JsVal::Num(n) = actual
                && n.to_bits() == (-0.0_f64).to_bits()
            {
                return false;
            }
            actual
                .to_json()
                .is_some_and(|json| canonicalize(&json).unwrap() == canonicalize(&expected["v"]).unwrap())
        }
        "json" => actual
            .to_json()
            .is_some_and(|json| canonicalize(&json).unwrap() == canonicalize(&expected["v"]).unwrap()),
        other => panic!("unexpected tag {other}"),
    }
}

#[test]
fn corpus_matches_reference() {
    let path = format!(
        "{}/../../conformance/vectors/jsonlogic.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let corpus: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let data = &corpus["data"];
    let (mut checked, mut stricter, mut failures) = (0, 0, Vec::new());
    for case in corpus["cases"].as_array().unwrap() {
        let (logic, expected) = (&case["logic"], &case["expected"]);
        let tag = expected["t"].as_str().unwrap();
        match apply(logic, data) {
            Err(error) if tag == "error" => {
                let _ = error;
                checked += 1;
            }
            Err(error)
                if matches!(
                    error.kind,
                    EvalErrorKind::UnsafeProperty(_) | EvalErrorKind::ReferenceComparison
                ) =>
            {
                // Deliberate, documented divergence: fail visibly where the reference
                // reads host prototype members or compares object identity.
                stricter += 1;
            }
            Err(error) => failures.push(format!("{logic} -> error {error:?}, expected {expected}")),
            Ok(actual) if tag != "error" && matches_expected(&actual, expected) => checked += 1,
            Ok(actual) => failures.push(format!("{logic} -> {actual:?}, expected {expected}")),
        }
    }
    assert!(
        failures.is_empty(),
        "{} mismatches:\n{}",
        failures.len(),
        failures[..failures.len().min(25)].join("\n")
    );
    assert!(checked > 5_500, "only {checked} cases checked");
    assert!(stricter < 200, "{stricter} stricter cases");
    eprintln!("checked {checked}, stricter {stricter}");
}
