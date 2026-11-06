//! Pack rules on arbitrary input: `rule\0data`, both JSON. Evaluation is bounded, so it
//! must end without panicking, whatever the rule.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let (rule, facts) = match data.iter().position(|b| *b == 0) {
        Some(at) => (&data[..at], &data[at + 1..]),
        None => (data, &b"{}"[..]),
    };
    let (Ok(rule), Ok(facts)) = (
        serde_json::from_slice::<serde_json::Value>(rule),
        serde_json::from_slice::<serde_json::Value>(facts),
    ) else {
        return;
    };
    let _ = contextos_policy::apply(&rule, &facts);
    let _ = contextos_policy::predicate(&rule, &facts);
    // Partial evaluation with every top-level fact unknown, as `/v1/plan` uses it.
    let unknown: Vec<&str> = facts
        .as_object()
        .map(|o| o.keys().map(String::as_str).collect())
        .unwrap_or_default();
    let _ = contextos_policy::partial_apply(&rule, &serde_json::json!({}), &unknown);
});
