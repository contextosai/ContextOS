//! A stable, language-neutral facade over the pure ContextOS kernel.
//!
//! Every binding (Python, Node, WASM) exposes exactly one function,
//! `call(operation, input_json) -> output_json`, so all languages share one ABI and
//! one behavior. The kernel performs no I/O and reads no clock, so these calls are
//! safe to run in-process on the agent's hot path.
//!
//! Every response is an envelope: `{"ok": <result>}` or `{"error": {"code", "message"}}`.
//! Kernel *verdicts* (deny, rejected, insufficient evidence) are successful results;
//! `error` is reserved for unusable input.
//!
//! | Operation | Input | Output |
//! |---|---|---|
//! | `version` | `{}` | runtime and protocol versions |
//! | `canonicalize` | any JSON | RFC 8785 text and its digest |
//! | `validate` | `{schema, def?, instance}` | `{valid, violations}` |
//! | `compile` | `{pack, request, run_context, deps?}` | `CompiledContext` |
//! | `evaluate_action_risk` | `{risk, policy?}` | `ActionRiskEvaluation` |
//! | `negotiate` | `{contract, support, features, registry?}` | `ContractNegotiationResult` |
//! | `digest_action_binding` | `ActionBinding` | `{action_digest}` |
//! | `validate_authority` | `AuthorityValidationInput` | `AuthorityValidationResult` |
//! | `compose_policy` | `NormalizedPolicyOutcome[]` | `ComposedPolicyOutcome` |
//! | `evaluate_authorization` | `AuthorizationInput` | `AuthorizationOutcome` |
//! | `evaluate_boundary` | `{requirement, observation, evaluation_time}` | `BoundaryReadinessResult` |
//! | `evaluate_data_flow` | `{request, policy, evaluation_time}` | `DataFlowDecision` |
//! | `assess_conformance` | `ConformanceAssessmentInput` | `ConformanceAssessment` |
//! | `jsonlogic` | `{logic, data}` | result (`null` for `undefined`/non-finite) |

use contextos_contract::canonical::{canonicalize, sha256_text};
use contextos_contract::ingress::parse_strict;
#[cfg(feature = "schema")]
use contextos_contract::schema::{SchemaDoc, SchemaTarget, validate};
use contextos_contract::types::{ContextPack, InvokeRequest, RunContext};
use contextos_kernel::{
    CompileDeps, CompileError, ContextPackCompiler, STANDARD_PROFILE_REGISTRY, evaluate_action_risk_json,
    negotiate_execution_contract,
};
use contextos_kernel::{authorization, conformance, execution_boundary};
use serde_json::{Value, json};

/// Maximum accepted input size for one call.
pub const MAX_INPUT_BYTES: usize = 16 * 1024 * 1024;

fn error(code: &str, message: impl Into<String>) -> Value {
    json!({"error": {"code": code, "message": message.into()}})
}

fn ok(value: impl serde::Serialize) -> Value {
    json!({"ok": value})
}

fn compile(input: &Value) -> Value {
    #[cfg(feature = "schema")]
    if let Err(e) = validate(&SchemaTarget::document(SchemaDoc::ContextPack), &input["pack"]) {
        return error("pack_invalid", format!("{} schema violation(s)", e.violations.len()));
    }
    let parsed = (
        serde_json::from_value::<ContextPack>(input["pack"].clone()),
        serde_json::from_value::<InvokeRequest>(input["request"].clone()),
        serde_json::from_value::<RunContext>(input["run_context"].clone()),
    );
    let (Ok(pack), Ok(request), Ok(run_context)) = parsed else {
        return error(
            "input_invalid",
            "pack, request and run_context must be valid contract objects",
        );
    };
    let list = |key: &str| input["deps"][key].as_array().cloned().unwrap_or_default();
    let deps = CompileDeps {
        evidence: list("evidence"),
        evidence_conflicts: list("evidence_conflicts"),
        promoted_memory: list("promoted_memory"),
    };
    let compiler = match ContextPackCompiler::new(pack) {
        Ok(compiler) => compiler,
        Err(e) => return error("pack_invalid", e.to_string()),
    };
    match compiler.compile(&request, &run_context, &deps) {
        Ok(compiled) => ok(compiled),
        Err(CompileError::PolicyEval(detail)) => {
            json!({"error": {"code": "policy_eval_error", "message": detail.message, "detail": *detail}})
        }
        Err(CompileError::Invalid(message)) => error("compile_invalid", message),
    }
}

#[cfg(not(feature = "schema"))]
fn schema(_input: &Value) -> Value {
    error("unsupported", "schema validation is not included in this build")
}

#[cfg(feature = "schema")]
fn schema(input: &Value) -> Value {
    let name = input["schema"].as_str().unwrap_or_default();
    let Some(doc) = SchemaDoc::ALL
        .into_iter()
        .find(|d| d.file_name().split(".v").next() == Some(name))
    else {
        return error("schema_unknown", "unknown schema");
    };
    let target = match input["def"].as_str() {
        Some(def) if doc.document()["$defs"].get(def).is_none() => {
            return error("schema_unknown", "unknown schema definition");
        }
        Some(def) => SchemaTarget::def(doc, def),
        None => SchemaTarget::document(doc),
    };
    match validate(&target, &input["instance"]) {
        Ok(()) => ok(json!({"valid": true, "violations": []})),
        Err(e) => ok(json!({"valid": false, "violations": e.violations})),
    }
}

/// Runs one operation on parsed input.
pub fn call_value(operation: &str, input: &Value) -> Value {
    match operation {
        "version" => ok(json!({
            "runtime": env!("CARGO_PKG_VERSION"),
            "contract": ["contextos.execution_contract.v1", "context-pack.v2"],
            "registry": STANDARD_PROFILE_REGISTRY.registry_ref,
        })),
        "canonicalize" => match canonicalize(input) {
            Ok(text) => ok(json!({"digest": sha256_text(&text), "canonical": text})),
            Err(e) => error("input_invalid", e.to_string()),
        },
        "validate" => schema(input),
        "compile" => compile(input),
        "evaluate_action_risk" => {
            let policy = input.get("policy").filter(|p| !p.is_null());
            ok(evaluate_action_risk_json(&input["risk"], policy))
        }
        "negotiate" => {
            let registry = match input.get("registry").filter(|r| !r.is_null()) {
                Some(registry) => registry.clone(),
                None => serde_json::to_value(&*STANDARD_PROFILE_REGISTRY).unwrap_or(Value::Null),
            };
            ok(negotiate_execution_contract(
                &input["contract"],
                &input["support"],
                &registry,
                &input["features"],
            ))
        }
        "digest_action_binding" => match authorization::digest_action_binding(input) {
            Ok(digest) => ok(json!({"action_digest": digest})),
            Err(e) => error("binding_invalid", e.to_string()),
        },
        "validate_authority" => ok(authorization::validate_authority(input)),
        "compose_policy" => ok(authorization::compose_policy_outcomes(input)),
        "evaluate_authorization" => ok(authorization::evaluate_authorization(input)),
        "evaluate_boundary" => ok(execution_boundary::evaluate_boundary_readiness(
            &input["requirement"],
            input.get("observation").unwrap_or(&Value::Null),
            &input["evaluation_time"],
        )),
        "evaluate_data_flow" => ok(execution_boundary::evaluate_data_flow(
            &input["request"],
            &input["policy"],
            &input["evaluation_time"],
        )),
        "assess_conformance" => ok(conformance::assess_conformance_report(input)),
        "jsonlogic" => match contextos_policy_apply(&input["logic"], &input["data"]) {
            Ok(value) => ok(value),
            Err(message) => error("jsonlogic_error", message),
        },
        _ => error("operation_unknown", "unknown operation"),
    }
}

fn contextos_policy_apply(logic: &Value, data: &Value) -> Result<Value, String> {
    contextos_kernel::policy_apply(logic, data)
}

/// Runs one operation on JSON text and returns JSON text. Never panics on input.
pub fn call(operation: &str, input: &[u8]) -> String {
    let response = match parse_strict(input, MAX_INPUT_BYTES) {
        Ok(value) => std::panic::catch_unwind(|| call_value(operation, &value))
            .unwrap_or_else(|_| error("internal", "operation failed")),
        Err(e) => error("input_invalid", e.to_string()),
    };
    response.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(op: &str, input: &str) -> Value {
        serde_json::from_str(&call(op, input.as_bytes())).unwrap()
    }

    #[test]
    fn envelope_and_errors() {
        assert_eq!(
            run("canonicalize", r#"{"b":1,"a":2}"#)["ok"]["canonical"],
            r#"{"a":2,"b":1}"#
        );
        assert_eq!(
            run("canonicalize", r#"{"a":1,"a":2}"#)["error"]["code"],
            "input_invalid"
        );
        assert_eq!(run("nope", "{}")["error"]["code"], "operation_unknown");
        assert_eq!(run("jsonlogic", r#"{"logic":{"+":[1,2]},"data":null}"#)["ok"], 3);
        assert_eq!(
            run("jsonlogic", r#"{"logic":{"bad_op":[1]},"data":null}"#)["error"]["code"],
            "jsonlogic_error"
        );
        #[cfg(feature = "schema")]
        assert_eq!(
            run(
                "validate",
                r#"{"schema":"execution-contract","def":"ControlRef","instance":{"control_id":"a","control_version":"1"}}"#
            )["ok"]["valid"],
            true
        );
        assert_eq!(run("compose_policy", "[]")["ok"]["verdict"], "deny");
    }
}
