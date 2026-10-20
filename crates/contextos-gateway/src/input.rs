//! Multi-round-trip input (MCP `input_required`).
//!
//! When a tool answers `input_required`, the attempt did not execute: the gateway
//! records it as a definitive `not_applied` fact and persists the input requests
//! against that attempt. A continuation is a new, fully re-authorized attempt of the
//! *same* operation: the tool call must bind to the same action digest, so answers
//! can never change the arguments, destination or amount that were authorized and
//! approved. Answers are accepted only when they:
//!
//! - answer the latest attempt's requests (a pending request is single-use: the new
//!   attempt supersedes it);
//! - answer exactly the requested keys, with supported request kinds (form
//!   elicitation) whose fields are flat primitives;
//! - match each requested schema (types, enums, required fields); and
//! - are bounded in size.
//!
//! Requests for credentials or other secrets (password-like fields or formats) are
//! refused outright: secrets never travel through an agent's tool flow. The
//! responder and a digest of the answers are audited; the answers themselves are not.

use contextos_contract::canonical::{canonicalize, sha256_canonical};
use serde_json::{Map, Value, json};

pub const MAX_INPUT_RESPONSE_BYTES: usize = 64 * 1024;

const SUPPORTED_METHODS: [&str; 1] = ["elicitation/create"];
const SENSITIVE: [&str; 10] = [
    "password",
    "passcode",
    "passphrase",
    "secret",
    "otp",
    "one_time",
    "pin",
    "cvv",
    "seed",
    "private_key",
];

/// Answers to a tool's input requests, supplied by an authenticated responder.
#[derive(Debug, Clone, PartialEq)]
pub struct Continuation {
    pub operation_id: String,
    /// Object keyed like the tool's `inputRequests`.
    pub input_responses: Value,
    pub responder_id: String,
    /// The answering executor's fenced generation, when ownership is enforced.
    pub executor_generation: Option<u64>,
}

/// The persisted state of an `input_required` result.
pub(crate) fn pending_record(operation_id: &str, attempt_id: &str, result: &Value, requested_at: &str) -> Value {
    json!({
        "operation_id": operation_id, "attempt_id": attempt_id, "requested_at": requested_at,
        "input_requests": result.get("inputRequests").cloned().unwrap_or(Value::Null),
        "request_state": result.get("requestState").cloned().unwrap_or(Value::Null),
    })
}

fn sensitive(name: &str, schema: &Value) -> bool {
    let name = name.to_ascii_lowercase();
    SENSITIVE.iter().any(|s| name.contains(s)) || schema["format"] == "password" || schema["writeOnly"] == true
}

fn primitive_matches(schema: &Value, value: &Value) -> bool {
    let typed = match schema["type"].as_str() {
        Some("string") => value.as_str().is_some_and(|s| {
            schema["maxLength"]
                .as_u64()
                .is_none_or(|m| s.chars().count() as u64 <= m)
                && schema["minLength"]
                    .as_u64()
                    .is_none_or(|m| s.chars().count() as u64 >= m)
        }),
        Some("boolean") => value.is_boolean(),
        Some("integer") => value.as_i64().is_some() || value.as_u64().is_some(),
        Some("number") => value.is_number(),
        _ => false,
    };
    typed && schema["enum"].as_array().is_none_or(|choices| choices.contains(value))
}

/// Checks one elicitation answer against its request.
fn answer_ok(request: &Value, response: &Value) -> Result<(), &'static str> {
    if !SUPPORTED_METHODS.contains(&request["method"].as_str().unwrap_or_default()) {
        return Err("input_request_unsupported");
    }
    let schema = &request["params"]["requestedSchema"];
    let Some(properties) = schema["properties"].as_object() else {
        return Err("input_request_unsupported");
    };
    if properties.iter().any(|(name, field)| sensitive(name, field)) {
        return Err("input_request_sensitive");
    }
    let Some(answer) = response.as_object() else {
        return Err("input_response_invalid");
    };
    match answer.get("action").and_then(Value::as_str) {
        Some("decline" | "cancel") => return Ok(()),
        Some("accept") => {}
        _ => return Err("input_response_invalid"),
    }
    let Some(content) = answer.get("content").and_then(Value::as_object) else {
        return Err("input_response_invalid");
    };
    let required = schema["required"].as_array().cloned().unwrap_or_default();
    let complete = required
        .iter()
        .all(|r| r.as_str().is_some_and(|k| content.contains_key(k)));
    let typed = content
        .iter()
        .all(|(k, v)| properties.get(k).is_some_and(|field| primitive_matches(field, v)));
    if complete && typed && answer.keys().all(|k| k == "action" || k == "content") {
        Ok(())
    } else {
        Err("input_response_invalid")
    }
}

/// Validates answers against the pending record for the operation's latest attempt.
/// Returns the adapter input (`inputResponses`, `requestState`) and the answers'
/// digest for audit.
pub(crate) fn validate_continuation(
    pending: Option<&Value>,
    latest_attempt_id: Option<&str>,
    continuation: &Continuation,
) -> Result<(Value, String), &'static str> {
    let Some(pending) = pending else {
        return Err("input_not_requested");
    };
    if latest_attempt_id != pending["attempt_id"].as_str() {
        return Err("input_not_requested");
    }
    let (Some(requests), Some(responses)) = (
        pending["input_requests"].as_object(),
        continuation.input_responses.as_object(),
    ) else {
        return Err("input_response_invalid");
    };
    let size = canonicalize(&continuation.input_responses).map_or(usize::MAX, |t| t.len());
    if size > MAX_INPUT_RESPONSE_BYTES || continuation.responder_id.is_empty() {
        return Err("input_response_invalid");
    }
    if requests.is_empty() || requests.len() != responses.len() || requests.keys().any(|k| !responses.contains_key(k)) {
        return Err("input_response_invalid");
    }
    for (key, request) in requests {
        answer_ok(request, &responses[key])?;
    }
    let mut input = Map::new();
    input.insert("inputResponses".into(), continuation.input_responses.clone());
    if !pending["request_state"].is_null() {
        input.insert("requestState".into(), pending["request_state"].clone());
    }
    let digest = sha256_canonical(&continuation.input_responses).unwrap_or_default();
    Ok((Value::Object(input), digest))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pending(schema: Value) -> Value {
        pending_record(
            "op_1",
            "attempt_1",
            &json!({"inputRequests": {"confirm": {"method": "elicitation/create",
                "params": {"message": "Confirm the refund reason", "requestedSchema": schema}}},
                "requestState": "opaque"}),
            "2026-10-20T10:00:00Z",
        )
    }

    fn reason_schema() -> Value {
        json!({"type": "object", "properties": {"reason": {"type": "string", "enum": ["damaged", "late"]},
            "notify": {"type": "boolean"}}, "required": ["reason"]})
    }

    fn answer(responses: Value) -> Continuation {
        Continuation {
            operation_id: "op_1".into(),
            input_responses: responses,
            responder_id: "user_9".into(),
            executor_generation: None,
        }
    }

    #[test]
    fn valid_answers_carry_request_state() {
        let ok = answer(json!({"confirm": {"action": "accept", "content": {"reason": "damaged", "notify": true}}}));
        let (input, digest) = validate_continuation(Some(&pending(reason_schema())), Some("attempt_1"), &ok).unwrap();
        assert_eq!(input["requestState"], "opaque");
        assert_eq!(input["inputResponses"]["confirm"]["content"]["reason"], "damaged");
        assert!(digest.starts_with("sha256:"));
        let declined = answer(json!({"confirm": {"action": "decline"}}));
        assert!(validate_continuation(Some(&pending(reason_schema())), Some("attempt_1"), &declined).is_ok());
    }

    #[test]
    fn answers_must_match_the_latest_request() {
        let p = pending(reason_schema());
        let check = |c: &Continuation, latest: &str| validate_continuation(Some(&p), Some(latest), c).unwrap_err();
        let good = answer(json!({"confirm": {"action": "accept", "content": {"reason": "late"}}}));
        assert_eq!(check(&good, "attempt_2"), "input_not_requested", "superseded request");
        assert_eq!(
            validate_continuation(None, Some("attempt_1"), &good).unwrap_err(),
            "input_not_requested"
        );
        for bad in [
            json!({"confirm": {"action": "accept", "content": {"reason": "other"}}}),
            json!({"confirm": {"action": "accept", "content": {"notify": true}}}),
            json!({"confirm": {"action": "accept", "content": {"reason": "late", "extra": 1}}}),
            json!({"confirm": {"action": "accept", "content": {"reason": "late"}, "amount_minor": 1}}),
            json!({"confirm": {"action": "maybe"}}),
            json!({"other": {"action": "decline"}}),
            json!({"confirm": {"action": "decline"}, "other": {"action": "decline"}}),
        ] {
            assert_eq!(
                check(&answer(bad.clone()), "attempt_1"),
                "input_response_invalid",
                "{bad}"
            );
        }
    }

    #[test]
    fn secrets_and_unsupported_requests_are_refused() {
        let secret = json!({"type": "object", "properties": {"card_pin": {"type": "string"}}});
        let c = answer(json!({"confirm": {"action": "accept", "content": {"card_pin": "1234"}}}));
        assert_eq!(
            validate_continuation(Some(&pending(secret)), Some("attempt_1"), &c).unwrap_err(),
            "input_request_sensitive"
        );
        let masked = json!({"type": "object", "properties": {"code": {"type": "string", "format": "password"}}});
        let c = answer(json!({"confirm": {"action": "decline"}}));
        assert_eq!(
            validate_continuation(Some(&pending(masked)), Some("attempt_1"), &c).unwrap_err(),
            "input_request_sensitive"
        );
        let mut sampling = pending(reason_schema());
        sampling["input_requests"]["confirm"]["method"] = json!("sampling/createMessage");
        assert_eq!(
            validate_continuation(Some(&sampling), Some("attempt_1"), &c).unwrap_err(),
            "input_request_unsupported"
        );
    }
}
