//! Exact-shape checks over raw JSON, mirroring the reference validators.
//!
//! Execution-contract inputs are validated structurally *before* any field is
//! interpreted, so that every malformed input yields the same reason code as the
//! reference instead of a generic deserialization error.

use serde_json::{Map, Value};

use crate::canonical::is_sha256_digest;
use crate::validation::{is_contract_identifier, is_contract_timestamp};

/// The object's key set is exactly `keys`.
pub fn exact_keys<'a>(value: &'a Value, keys: &[&str]) -> Option<&'a Map<String, Value>> {
    let object = value.as_object()?;
    (object.len() == keys.len() && keys.iter().all(|k| object.contains_key(*k))).then_some(object)
}

/// Like [`exact_keys`], with `optional` keys allowed when present.
pub fn exact_keys_with_optional<'a>(
    value: &'a Value,
    keys: &[&str],
    optional: &[&str],
) -> Option<&'a Map<String, Value>> {
    let object = value.as_object()?;
    let present_optional = optional.iter().filter(|k| object.contains_key(**k)).count();
    (object.len() == keys.len() + present_optional && keys.iter().all(|k| object.contains_key(*k))).then_some(object)
}

pub fn is_identifier(value: &Value) -> bool {
    value.as_str().is_some_and(is_contract_identifier)
}

pub fn is_digest(value: &Value) -> bool {
    value.as_str().is_some_and(is_sha256_digest)
}

pub fn is_timestamp(value: &Value) -> bool {
    value.as_str().is_some_and(is_contract_timestamp)
}

/// JavaScript `Number.isSafeInteger(value) && value >= 0`.
pub fn is_safe_non_negative_integer(value: &Value) -> bool {
    as_safe_integer(value).is_some_and(|n| n >= 0)
}

/// JavaScript `Number.isSafeInteger(value)`, returning the integer.
pub fn as_safe_integer(value: &Value) -> Option<i64> {
    const MAX_SAFE: i64 = (1 << 53) - 1;
    let number = value.as_number()?;
    if let Some(i) = number.as_i64() {
        return (-MAX_SAFE..=MAX_SAFE).contains(&i).then_some(i);
    }
    let f = number.as_f64()?;
    #[allow(clippy::cast_possible_truncation)]
    let i = f as i64;
    #[allow(clippy::cast_precision_loss)]
    (f.fract() == 0.0 && (-MAX_SAFE..=MAX_SAFE).contains(&i) && i as f64 == f).then_some(i)
}

pub fn bounded_array(value: &Value, min: usize, max: usize, guard: impl Fn(&Value) -> bool) -> bool {
    value
        .as_array()
        .is_some_and(|items| items.len() >= min && items.len() <= max && items.iter().all(guard))
}

pub fn is_artifact_ref(value: &Value) -> bool {
    exact_keys(value, &["artifact_type", "artifact_id", "version", "sha256"]).is_some_and(|o| {
        is_identifier(&o["artifact_type"])
            && is_identifier(&o["artifact_id"])
            && is_identifier(&o["version"])
            && is_digest(&o["sha256"])
    })
}

pub fn is_control_ref(value: &Value) -> bool {
    exact_keys(value, &["control_id", "control_version"])
        .is_some_and(|o| is_identifier(&o["control_id"]) && is_identifier(&o["control_version"]))
}

pub fn is_profile_selection(value: &Value) -> bool {
    exact_keys(value, &["profile_id", "profile_version"])
        .is_some_and(|o| is_identifier(&o["profile_id"]) && is_identifier(&o["profile_version"]))
}

/// Bounded array (1..=128) of contract identifiers.
pub fn is_identifier_list(value: &Value) -> bool {
    bounded_array(value, 1, 128, is_identifier)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn exact_keys_rejects_missing_and_extra() {
        assert!(exact_keys(&json!({"a": 1, "b": 2}), &["a", "b"]).is_some());
        assert!(exact_keys(&json!({"a": 1}), &["a", "b"]).is_none());
        assert!(exact_keys(&json!({"a": 1, "b": 2, "c": 3}), &["a", "b"]).is_none());
        assert!(exact_keys(&json!([1, 2]), &["a", "b"]).is_none());
        assert!(exact_keys_with_optional(&json!({"a": 1, "o": 2}), &["a"], &["o"]).is_some());
        assert!(exact_keys_with_optional(&json!({"a": 1}), &["a"], &["o"]).is_some());
    }

    #[test]
    fn safe_integers_follow_javascript() {
        assert_eq!(as_safe_integer(&json!(3)), Some(3));
        assert_eq!(as_safe_integer(&json!(3.0)), Some(3));
        assert_eq!(as_safe_integer(&json!(1.5)), None);
        assert_eq!(as_safe_integer(&json!(9_007_199_254_740_992_u64)), None);
        assert!(!is_safe_non_negative_integer(&json!(-1)));
    }
}
