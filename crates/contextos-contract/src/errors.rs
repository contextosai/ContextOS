//! Structured, sanitized diagnostics.

use serde::{Deserialize, Serialize};

use crate::canonical::sha256_text;

/// Message returned for every policy-expression failure. The expression and the
/// evaluation context are never echoed back, so diagnostics cannot leak inputs.
pub const POLICY_ERROR_MESSAGE: &str = "An applicable policy predicate could not be evaluated.";

/// Identifiers longer than this are replaced by their digest in diagnostics.
pub const MAX_ERROR_ID_CHARS: usize = 256;

/// A failed enforcing predicate never produces a successful compiled context.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[error("{message}")]
pub struct ContextCompileError {
    pub code: String,
    pub stage: String,
    pub bundle_id: String,
    pub rule_id: String,
    pub expression_path: String,
    pub message: String,
}

impl ContextCompileError {
    pub fn policy_eval(bundle_id: &str, rule_id: &str) -> Self {
        Self {
            code: "policy_eval_error".into(),
            stage: "policy_resolution".into(),
            bundle_id: safe_error_id(bundle_id),
            rule_id: safe_error_id(rule_id),
            expression_path: "if".into(),
            message: POLICY_ERROR_MESSAGE.into(),
        }
    }
}

/// Bounds identifiers echoed in errors; JS `length` counts UTF-16 units.
pub fn safe_error_id(value: &str) -> String {
    if value.encode_utf16().count() <= MAX_ERROR_ID_CHARS {
        value.to_owned()
    } else {
        sha256_text(value)
    }
}
