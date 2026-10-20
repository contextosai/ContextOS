//! Small JSON helpers shared by the validators that operate on raw contract values.

use std::cmp::Ordering;
use std::collections::HashSet;

use contextos_contract::canonical::{canonicalize, utf16_cmp};
use contextos_contract::shape::{bounded_array, is_identifier};
use contextos_contract::validation::{compare_contract_times, is_within_contract_interval};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub(crate) const MAX_SAFE_INTEGER: i64 = (1 << 53) - 1;

pub(crate) fn s(value: &Value) -> &str {
    value.as_str().unwrap_or_default()
}

pub(crate) fn same(a: &Value, b: &Value) -> bool {
    contextos_contract::canonical::canonical_eq(a, b)
}

pub(crate) fn encoded(value: &Value) -> String {
    canonicalize(value).unwrap_or_default()
}

pub(crate) fn list(value: &Value, guard: impl Fn(&Value) -> bool) -> bool {
    bounded_array(value, 0, 128, guard)
}

/// Bounded list of unique identifiers.
pub(crate) fn unique_ids(value: &Value) -> bool {
    list(value, is_identifier)
        && value
            .as_array()
            .is_some_and(|a| a.iter().map(encoded).collect::<HashSet<_>>().len() == a.len())
}

pub(crate) fn sorted_strings(values: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut out: Vec<String> = values.into_iter().collect::<HashSet<_>>().into_iter().collect();
    out.sort_by(|a, b| utf16_cmp(a, b));
    out
}

/// JavaScript default `Array.prototype.sort()` over string values (UTF-16 order).
pub(crate) fn js_sorted(values: &Value) -> Value {
    let mut items: Vec<Value> = values.as_array().cloned().unwrap_or_default();
    items.sort_by(|a, b| utf16_cmp(s(a), s(b)));
    Value::Array(items)
}

pub(crate) fn within(time: &Value, start: &Value, end: &Value) -> bool {
    is_within_contract_interval(s(time), s(start), s(end))
}

pub(crate) fn cmp_times(a: &Value, b: &Value) -> Option<Ordering> {
    compare_contract_times(s(a), s(b))
}

pub(crate) fn verification_status(value: &Value) -> bool {
    matches!(value.as_str(), Some("verified" | "invalid" | "unavailable"))
}

/// Result of an intended state transition. The store applying it must enforce the
/// expected revision and executor fence atomically.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TransitionResult {
    pub status: String,
    pub state: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub obligations: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason_codes: Option<Vec<String>>,
}

impl TransitionResult {
    pub fn accepted(state: Value, obligations: Vec<String>) -> Self {
        Self {
            status: "accepted".into(),
            state,
            obligations: Some(obligations),
            reason_codes: None,
        }
    }

    pub fn rejected(state: Value, reason: &str) -> Self {
        Self {
            status: "rejected".into(),
            state,
            obligations: None,
            reason_codes: Some(vec![reason.into()]),
        }
    }

    pub fn is_accepted(&self) -> bool {
        self.status == "accepted"
    }
}
