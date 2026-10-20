//! Property tests over every kernel entry point: arbitrary and mutated inputs must
//! never panic, must always produce a well-formed envelope, and must be
//! deterministic (the same input yields byte-identical output).

use std::io::Read;

use contextos_embed::call;
use proptest::prelude::*;
use serde_json::{Value, json};

const OPERATIONS: [&str; 14] = [
    "canonicalize",
    "validate",
    "compile",
    "evaluate_action_risk",
    "negotiate",
    "digest_action_binding",
    "validate_authority",
    "compose_policy",
    "evaluate_authorization",
    "evaluate_boundary",
    "evaluate_data_flow",
    "assess_conformance",
    "jsonlogic",
    "version",
];

/// Case count; raise with `CONTEXTOS_FUZZ_CASES` for long runs (CI nightly, local soak).
fn cases(default: u32) -> u32 {
    std::env::var("CONTEXTOS_FUZZ_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn arbitrary_json() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        any::<i64>().prop_map(Value::from),
        (-1e30f64..1e30).prop_map(|f| json!(f)),
        "[a-z_:.@#0-9]{0,12}".prop_map(Value::String),
        prop_oneof![
            Just("sha256:".to_owned() + &"a".repeat(64)),
            Just("2026-10-20T10:00:00Z".to_owned()),
            Just("verified".to_owned())
        ]
        .prop_map(Value::String),
    ];
    leaf.prop_recursive(5, 64, 6, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..6).prop_map(Value::Array),
            prop::collection::btree_map("[a-z_]{1,10}", inner, 0..6)
                .prop_map(|m| Value::Object(m.into_iter().collect())),
        ]
    })
}

fn envelope_ok(text: &str) -> bool {
    match serde_json::from_str::<Value>(text) {
        // A caught panic surfaces as `internal`; it is a failure, not a valid envelope.
        Ok(Value::Object(map)) => {
            map.len() == 1
                && (map.contains_key("ok") || map.contains_key("error"))
                && map.get("error").is_none_or(|e| e["code"] != "internal")
        }
        _ => false,
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: cases(256), .. ProptestConfig::default() })]

    #[test]
    fn arbitrary_inputs_never_panic_and_are_deterministic(op in prop::sample::select(OPERATIONS.to_vec()), input in arbitrary_json()) {
        let bytes = input.to_string();
        let first = call(op, bytes.as_bytes());
        prop_assert!(envelope_ok(&first), "{op}: {first}");
        prop_assert_eq!(first, call(op, bytes.as_bytes()));
    }

    #[test]
    fn arbitrary_bytes_are_rejected_cleanly(bytes in prop::collection::vec(any::<u8>(), 0..256)) {
        prop_assert!(envelope_ok(&call("compile", &bytes)));
    }

    #[test]
    fn canonical_form_is_a_fixed_point(input in arbitrary_json()) {
        let first: Value = serde_json::from_str(&call("canonicalize", input.to_string().as_bytes())).unwrap();
        let canonical = first["ok"]["canonical"].as_str().unwrap().to_owned();
        let second: Value = serde_json::from_str(&call("canonicalize", canonical.as_bytes())).unwrap();
        prop_assert_eq!(second["ok"]["canonical"].as_str().unwrap(), canonical);
    }
}

fn vectors(name: &str) -> Value {
    let path = format!("{}/../../conformance/vectors/{name}", env!("CARGO_MANIFEST_DIR"));
    let mut text = String::new();
    flate2::read::GzDecoder::new(std::fs::File::open(path).unwrap())
        .read_to_string(&mut text)
        .unwrap();
    serde_json::from_str(&text).unwrap()
}

/// Structure-aware mutation of valid inputs reaches deep validator paths that random
/// JSON rarely does.
fn mutate(value: &mut Value, choice: &[u8]) {
    let mut cursor = value;
    for (depth, byte) in choice.iter().enumerate() {
        let next = match cursor {
            Value::Object(map) if !map.is_empty() => {
                let key = map.keys().nth(*byte as usize % map.len()).cloned().unwrap();
                if depth + 1 == choice.len() || byte % 7 == 0 {
                    match byte % 5 {
                        0 => {
                            map.remove(&key);
                        }
                        1 => {
                            map.insert(key, Value::Null);
                        }
                        2 => {
                            map.insert(key, json!("x".repeat(300)));
                        }
                        3 => {
                            map.insert(key, json!(-1));
                        }
                        _ => {
                            map.insert(format!("{key}_extra"), json!(true));
                        }
                    }
                    return;
                }
                map.get_mut(&key).unwrap()
            }
            Value::Array(items) if !items.is_empty() => {
                let index = *byte as usize % items.len();
                if byte % 3 == 0 {
                    items.push(items[index].clone());
                    return;
                }
                &mut items[index]
            }
            _ => return,
        };
        cursor = next;
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: cases(384), .. ProptestConfig::default() })]

    #[test]
    fn mutated_reference_inputs_never_panic(case in 0usize..40, choice in prop::collection::vec(any::<u8>(), 1..8)) {
        static AUTH: std::sync::OnceLock<Value> = std::sync::OnceLock::new();
        let auth = AUTH.get_or_init(|| vectors("authorization.json.gz"));
        let groups = [("evaluate_authorization", "authorization"), ("validate_authority", "authority"), ("digest_action_binding", "digest")];
        let (op, group) = groups[case % groups.len()];
        let items = auth[group].as_array().unwrap();
        let mut input = items[case % items.len()]["input"].clone();
        mutate(&mut input, &choice);
        let bytes = input.to_string();
        let first = call(op, bytes.as_bytes());
        prop_assert!(envelope_ok(&first));
        prop_assert_eq!(first, call(op, bytes.as_bytes()));
    }
}
