//! Parity with the spec's TypeScript reference compiler and action-risk evaluator.

use contextos_contract::canonical::canonicalize;
use contextos_contract::types::{ContextPack, InvokeRequest, RunContext};
use contextos_kernel::{CompileDeps, CompileError, ContextPackCompiler, evaluate_action_risk_json};
use serde_json::Value;

mod common;
use common::load;

fn list(value: &Value) -> Vec<Value> {
    value.as_array().cloned().unwrap_or_default()
}

fn run(case: &Value) -> Result<Value, CompileError> {
    let pack: ContextPack = serde_json::from_value(case["pack"].clone()).unwrap();
    let request: InvokeRequest = serde_json::from_value(case["request"].clone()).unwrap();
    let run_context: RunContext = serde_json::from_value(case["run_context"].clone()).unwrap();
    let deps = CompileDeps {
        evidence: list(&case["deps"]["evidence"]),
        evidence_conflicts: list(&case["deps"]["evidence_conflicts"]),
        promoted_memory: list(&case["deps"]["promoted_memory"]),
    };
    let compiled = ContextPackCompiler::new(pack)?.compile(&request, &run_context, &deps)?;
    Ok(serde_json::to_value(compiled).unwrap())
}

#[test]
fn compiled_contexts_match_reference_byte_for_byte() {
    let vectors = load("compiler.json");
    let cases = vectors["cases"].as_array().unwrap();
    assert!(cases.len() >= 40);
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let actual = run(case).unwrap_or_else(|e| panic!("{name}: {e}"));
        let expected = &case["expected"];
        assert_eq!(
            actual["context_ledger"]["compiled_context_hash"], expected["context_ledger"]["compiled_context_hash"],
            "{name}: compiled_context_hash"
        );
        if canonicalize(&actual).unwrap() != canonicalize(expected).unwrap() {
            for key in [
                "compiled_prompt",
                "manifests",
                "runtime_controls",
                "budget_report",
                "context_ledger",
            ] {
                assert_eq!(
                    canonicalize(&actual[key]).unwrap(),
                    canonicalize(&expected[key]).unwrap(),
                    "{name}: {key} differs"
                );
            }
        }
    }
}

#[test]
fn compile_errors_match_reference() {
    let vectors = load("compiler.json");
    for case in vectors["error_cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let error = run(case).expect_err(name);
        let expected = &case["expected_error"];
        assert_eq!(error.to_string(), expected["message"].as_str().unwrap(), "{name}");
        if let CompileError::PolicyEval(detail) = &error {
            assert_eq!(serde_json::to_value(detail).unwrap(), expected["detail"], "{name}");
        } else {
            assert!(expected["detail"].is_null(), "{name}: expected structured detail");
        }
    }
}

#[test]
fn action_risk_evaluations_match_reference() {
    let vectors = load("action-risk.json");
    for case in vectors.as_array().unwrap() {
        let policy = (!case["policy"].is_null()).then_some(&case["policy"]);
        let actual = serde_json::to_value(evaluate_action_risk_json(&case["risk"], policy)).unwrap();
        assert_eq!(actual, case["expected"], "{}", case["risk"]);
    }
}

#[test]
fn standard_registry_matches_reference() {
    let vectors = load("negotiation.json.gz");
    let ours = serde_json::to_value(&*contextos_kernel::STANDARD_PROFILE_REGISTRY).unwrap();
    assert_eq!(
        canonicalize(&ours).unwrap(),
        canonicalize(&vectors["registry"]).unwrap()
    );
}

#[test]
fn negotiation_matches_reference() {
    let vectors = load("negotiation.json.gz");
    let mut checked = 0;
    for case in vectors["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        if case["expected"].get("throws").is_some() {
            continue;
        }
        let input = &case["input"];
        // A deleted top-level argument is JavaScript `undefined`, which a JSON API cannot receive.
        if ["contract", "support", "registry", "features"]
            .iter()
            .any(|k| input.get(*k).is_none())
        {
            continue;
        }
        let actual = contextos_kernel::negotiate_execution_contract(
            &input["contract"],
            &input["support"],
            &input["registry"],
            &input["features"],
        );
        let actual = serde_json::to_value(actual).unwrap();
        assert_eq!(
            canonicalize(&actual).unwrap(),
            canonicalize(&case["expected"]).unwrap(),
            "{name}"
        );
        checked += 1;
    }
    assert!(checked > 3_000, "{checked}");
}
