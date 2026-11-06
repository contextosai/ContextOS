//! Every kernel entry point on arbitrary bytes: the first byte picks the operation, the
//! rest is its JSON input. `call` promises never to panic and always to answer JSON.
#![no_main]

use libfuzzer_sys::fuzz_target;

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

fuzz_target!(|data: &[u8]| {
    let Some((&pick, input)) = data.split_first() else {
        return;
    };
    let operation = OPERATIONS[usize::from(pick) % OPERATIONS.len()];
    let answer = contextos_embed::call(operation, input);
    let parsed: serde_json::Value = serde_json::from_str(&answer).expect("call answers JSON");
    assert!(
        parsed.get("ok").is_some() ^ parsed.get("error").is_some(),
        "not an envelope: {answer}"
    );
    assert_eq!(answer, contextos_embed::call(operation, input), "call is deterministic");
});
