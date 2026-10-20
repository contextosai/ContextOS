//! Canonical JSON encodings and digests.
//!
//! Two encodings exist and must not be confused:
//!
//! * [`canonicalize`] — RFC 8785 JSON Canonicalization Scheme (JCS), bounded by the
//!   reference resource limits. Used by every execution-contract digest
//!   (action bindings, registry artifacts, grant and approval observations).
//! * [`legacy_stable_stringify`] — the compiler's original stable encoding, whose
//!   object keys are ordered by ICU root collation (JavaScript `localeCompare`).
//!   `compiled_context_hash` and other legacy compiler hashes keep this encoding so
//!   records produced by earlier runtimes stay verifiable.

use std::cmp::Ordering;
use std::fmt::Write as _;
use std::sync::LazyLock;

use icu_collator::options::CollatorOptions;
use icu_collator::{Collator, CollatorBorrowed};
use serde::Serialize;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

/// Maximum nesting depth accepted by [`canonicalize`].
pub const MAX_DEPTH: usize = 64;
/// Maximum number of JSON values visited by [`canonicalize`].
pub const MAX_VALUES: usize = 10_000;
/// Maximum UTF-8 output size of [`canonicalize`], and maximum UTF-16 length of any string.
pub const MAX_BYTES: usize = 1_048_576;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CanonicalError {
    #[error("Input is not a complete plain JSON value")]
    InvalidJson,
    #[error("Canonical JSON exceeds reference resource limits")]
    ResourceLimit,
}

/// RFC 8785 canonical encoding of a JSON value.
pub fn canonicalize(value: &Value) -> Result<String, CanonicalError> {
    let mut writer = JcsWriter {
        out: String::new(),
        values: 0,
    };
    writer.visit(value, 0)?;
    Ok(writer.out)
}

/// Canonicalizes any serializable value through its JSON form.
pub fn canonicalize_serialize<T: Serialize + ?Sized>(value: &T) -> Result<String, CanonicalError> {
    let json = serde_json::to_value(value).map_err(|_| CanonicalError::InvalidJson)?;
    canonicalize(&json)
}

/// `sha256:<hex>` over the RFC 8785 encoding of `value`.
pub fn sha256_canonical(value: &Value) -> Result<String, CanonicalError> {
    canonicalize(value).map(|text| sha256_text(&text))
}

/// `sha256:<hex>` over the RFC 8785 encoding of `{"domain": domain, "payload": payload}`.
///
/// Domain separation keeps digests of different artifact kinds from colliding even
/// when their payloads are identical.
pub fn domain_digest<T: Serialize + ?Sized>(domain: &str, payload: &T) -> Result<String, CanonicalError> {
    let payload = serde_json::to_value(payload).map_err(|_| CanonicalError::InvalidJson)?;
    let mut wrapper = Map::new();
    wrapper.insert("domain".into(), Value::String(domain.into()));
    wrapper.insert("payload".into(), payload);
    sha256_canonical(&Value::Object(wrapper))
}

/// `sha256:<hex>` of the UTF-8 bytes of `text`.
pub fn sha256_text(text: &str) -> String {
    let digest = Sha256::digest(text.as_bytes());
    format!("sha256:{}", hex::encode(digest))
}

/// Returns true for a `sha256:` digest string with 64 lowercase hex characters.
pub fn is_sha256_digest(value: &str) -> bool {
    value
        .strip_prefix("sha256:")
        .is_some_and(|hex| hex.len() == 64 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
}

struct JcsWriter {
    out: String,
    values: usize,
}

impl JcsWriter {
    fn emit(&mut self, text: &str) -> Result<(), CanonicalError> {
        if self.out.len() + text.len() > MAX_BYTES {
            return Err(CanonicalError::ResourceLimit);
        }
        self.out.push_str(text);
        Ok(())
    }

    fn visit(&mut self, value: &Value, depth: usize) -> Result<(), CanonicalError> {
        self.values += 1;
        if depth > MAX_DEPTH || self.values > MAX_VALUES {
            return Err(CanonicalError::ResourceLimit);
        }
        match value {
            Value::Null => self.emit("null"),
            Value::Bool(b) => self.emit(if *b { "true" } else { "false" }),
            Value::Number(n) => {
                let text = format_number(n)?;
                self.emit(&text)
            }
            Value::String(s) => {
                check_string(s)?;
                let text = quote(s);
                self.emit(&text)
            }
            Value::Array(items) => {
                if items.len() > MAX_VALUES - self.values {
                    return Err(CanonicalError::ResourceLimit);
                }
                self.emit("[")?;
                for (index, item) in items.iter().enumerate() {
                    if index > 0 {
                        self.emit(",")?;
                    }
                    self.visit(item, depth + 1)?;
                }
                self.emit("]")
            }
            Value::Object(map) => {
                if map.len() > MAX_VALUES - self.values {
                    return Err(CanonicalError::ResourceLimit);
                }
                let mut keys: Vec<&String> = map.keys().collect();
                keys.sort_by(|a, b| utf16_cmp(a, b));
                self.emit("{")?;
                for (index, key) in keys.into_iter().enumerate() {
                    if index > 0 {
                        self.emit(",")?;
                    }
                    check_string(key)?;
                    let quoted = quote(key);
                    self.emit(&quoted)?;
                    self.emit(":")?;
                    self.visit(&map[key], depth + 1)?;
                }
                self.emit("}")
            }
        }
    }
}

fn check_string(value: &str) -> Result<(), CanonicalError> {
    // Rust strings are always valid Unicode scalar sequences, so the lone-surrogate
    // check of the reference cannot fail here; only the size bound applies.
    if value.len() > MAX_BYTES && value.encode_utf16().count() > MAX_BYTES {
        return Err(CanonicalError::ResourceLimit);
    }
    Ok(())
}

/// Orders strings by UTF-16 code units, as RFC 8785 and JavaScript's default sort do.
pub fn utf16_cmp(a: &str, b: &str) -> Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
}

/// ECMAScript `Number.prototype.toString` formatting, as used by `JSON.stringify`.
fn format_number(number: &serde_json::Number) -> Result<String, CanonicalError> {
    #[allow(clippy::cast_precision_loss)]
    let value = if let Some(i) = number.as_i64() {
        i as f64
    } else if let Some(u) = number.as_u64() {
        u as f64
    } else {
        number.as_f64().ok_or(CanonicalError::InvalidJson)?
    };
    js_number(value).ok_or(CanonicalError::InvalidJson)
}

/// Formats a finite `f64` exactly like JavaScript; `None` for NaN and infinities.
pub fn js_number(value: f64) -> Option<String> {
    if !value.is_finite() {
        return None;
    }
    if value == 0.0 {
        return Some("0".to_owned());
    }
    let mut buffer = ryu_js::Buffer::new();
    Some(buffer.format_finite(value).to_owned())
}

/// `JSON.stringify` for a string value.
pub fn quote(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

static ROOT_COLLATOR: LazyLock<CollatorBorrowed<'static>> = LazyLock::new(|| {
    Collator::try_new(icu_collator::CollatorPreferences::default(), CollatorOptions::default())
        .expect("compiled root collation data is always available")
});

/// JavaScript `a.localeCompare(b)` under the root/en collation used by the reference.
pub fn locale_cmp(a: &str, b: &str) -> Ordering {
    ROOT_COLLATOR.compare(a, b)
}

/// The compiler's legacy stable encoding: `JSON.stringify` leaves, object keys ordered
/// by [`locale_cmp`]. Absent optional fields must be omitted by the caller's serde
/// attributes, exactly as `undefined` properties are dropped by the reference.
pub fn legacy_stable_stringify(value: &Value) -> String {
    let mut out = String::new();
    write_legacy(value, &mut out);
    out
}

fn write_legacy(value: &Value, out: &mut String) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => out.push_str(&format_number(n).unwrap_or_else(|_| "null".to_owned())),
        Value::String(s) => out.push_str(&quote(s)),
        Value::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_legacy(item, out);
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_by(|a, b| locale_cmp(a, b));
            out.push('{');
            for (index, key) in keys.into_iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                out.push_str(&quote(key));
                out.push(':');
                write_legacy(&map[key], out);
            }
            out.push('}');
        }
    }
}

/// `sha256:<hex>` over [`legacy_stable_stringify`] of a serializable value.
pub fn legacy_stable_sha256<T: Serialize + ?Sized>(value: &T) -> Result<String, CanonicalError> {
    let json = serde_json::to_value(value).map_err(|_| CanonicalError::InvalidJson)?;
    Ok(sha256_text(&legacy_stable_stringify(&json)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn rfc8785_orders_keys_by_utf16_code_units() {
        // U+1F600 (surrogate pair D83D DE00) sorts before U+FFFD in UTF-16 order
        // although it is the larger code point.
        let value = json!({"\u{fffd}": 1, "\u{1f600}": 2, "a": 3, "B": 4});
        assert_eq!(
            canonicalize(&value).unwrap(),
            "{\"B\":4,\"a\":3,\"\u{1f600}\":2,\"\u{fffd}\":1}"
        );
    }

    #[test]
    fn numbers_follow_ecmascript_formatting() {
        let cases = [
            (json!(0), "0"),
            (json!(-0.0), "0"),
            (json!(1.0), "1"),
            (json!(1e21), "1e+21"),
            (json!(1e-7), "1e-7"),
            (json!(123_456_789_012_345_680_000.0), "123456789012345680000"),
            (json!(0.1), "0.1"),
            (json!(-5), "-5"),
            (json!(9_007_199_254_740_993_u64), "9007199254740992"),
        ];
        for (value, expected) in cases {
            assert_eq!(canonicalize(&value).unwrap(), expected, "{value}");
        }
    }

    #[test]
    fn strings_escape_like_json_stringify() {
        let value = json!("a\"b\\c\u{8}\u{c}\n\r\t\u{1}\u{7f}\u{2028}é");
        assert_eq!(
            canonicalize(&value).unwrap(),
            "\"a\\\"b\\\\c\\b\\f\\n\\r\\t\\u0001\u{7f}\u{2028}é\""
        );
    }

    #[test]
    fn depth_limit_is_enforced() {
        let mut value = json!(0);
        for _ in 0..=MAX_DEPTH {
            value = json!([value]);
        }
        assert_eq!(canonicalize(&value), Err(CanonicalError::ResourceLimit));
    }

    #[test]
    fn value_count_limit_is_enforced() {
        let value = Value::Array(vec![json!(1); MAX_VALUES]);
        assert_eq!(canonicalize(&value), Err(CanonicalError::ResourceLimit));
        let value = Value::Array(vec![json!(1); MAX_VALUES - 1]);
        assert!(canonicalize(&value).is_ok());
    }

    #[test]
    fn legacy_encoding_uses_collation_order() {
        // localeCompare places "_" before letters and is case-insensitive at primary strength.
        let value = json!({"b": 1, "a_b": 2, "ab": 3, "A": 4, "a": 5});
        assert_eq!(
            legacy_stable_stringify(&value),
            "{\"a\":5,\"A\":4,\"a_b\":2,\"ab\":3,\"b\":1}"
        );
    }

    #[test]
    fn digest_format() {
        let digest = sha256_text("");
        assert_eq!(
            digest,
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert!(is_sha256_digest(&digest));
        assert!(!is_sha256_digest("sha256:E3B0"));
    }
}
