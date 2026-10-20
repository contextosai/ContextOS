//! Typed views must round-trip reference payloads without losing or inventing fields,
//! and those payloads must conform to the published schemas.

use contextos_contract::canonical::canonicalize;
use contextos_contract::schema::{SchemaDoc, SchemaTarget, validate};
use contextos_contract::types::{CompiledContext, ContextPack, InvokeRequest, RunContext};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

fn load(name: &str) -> Value {
    let path = format!("{}/../../conformance/vectors/{name}", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap()
}

fn round_trip<T: DeserializeOwned + Serialize>(value: &Value, doc: SchemaDoc, case: &str) {
    if let Err(error) = validate(&SchemaTarget::document(doc), value) {
        panic!("{case}: {doc:?} schema violations: {:#?}", error.violations);
    }
    let typed: T = serde_json::from_value(value.clone()).unwrap_or_else(|e| panic!("{case}: {doc:?}: {e}"));
    // Compare canonical forms: `1` and `1.0` are the same JSON number.
    let again = serde_json::to_value(&typed).unwrap();
    assert!(
        canonicalize(&again).unwrap() == canonicalize(value).unwrap(),
        "{case}: {doc:?} round trip changed the payload"
    );
}

#[test]
fn compiler_fixtures_round_trip_through_types() {
    let vectors = load("compiler.json");
    for case in vectors["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        round_trip::<ContextPack>(&case["pack"], SchemaDoc::ContextPack, name);
        round_trip::<InvokeRequest>(&case["request"], SchemaDoc::InvokeAgent, name);
        round_trip::<RunContext>(&case["run_context"], SchemaDoc::RunContext, name);
        round_trip::<CompiledContext>(&case["expected"], SchemaDoc::CompiledContext, name);
    }
}
