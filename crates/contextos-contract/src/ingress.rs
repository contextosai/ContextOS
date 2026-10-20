//! Strict JSON ingress.
//!
//! `serde_json` accepts duplicate object keys (the last one wins). Two components
//! that disagree on which duplicate wins can be made to approve one payload and
//! execute another, so every untrusted byte stream is parsed here: duplicate keys,
//! excessive nesting and oversized input are rejected before anything reads a field.

use std::fmt;

use serde::de::{self, DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};

/// Maximum accepted nesting depth for ingress JSON.
pub const MAX_INGRESS_DEPTH: usize = 64;
/// Default maximum accepted ingress body size.
pub const MAX_INGRESS_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IngressError {
    #[error("request body exceeds {0} bytes")]
    TooLarge(usize),
    #[error("invalid JSON: {0}")]
    Invalid(String),
}

/// Parses untrusted bytes into a JSON value, rejecting duplicate keys, nesting deeper
/// than [`MAX_INGRESS_DEPTH`] and bodies larger than `max_bytes`.
pub fn parse_strict(bytes: &[u8], max_bytes: usize) -> Result<Value, IngressError> {
    if bytes.len() > max_bytes {
        return Err(IngressError::TooLarge(max_bytes));
    }
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = StrictSeed { depth: 0 }
        .deserialize(&mut deserializer)
        .map_err(|e| IngressError::Invalid(e.to_string()))?;
    deserializer.end().map_err(|e| IngressError::Invalid(e.to_string()))?;
    Ok(value)
}

struct StrictSeed {
    depth: usize,
}

impl<'de> DeserializeSeed<'de> for StrictSeed {
    type Value = Value;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Value, D::Error> {
        if self.depth > MAX_INGRESS_DEPTH {
            return Err(de::Error::custom("nesting exceeds maximum depth"));
        }
        deserializer.deserialize_any(StrictVisitor { depth: self.depth })
    }
}

struct StrictVisitor {
    depth: usize,
}

impl<'de> Visitor<'de> for StrictVisitor {
    type Value = Value;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a JSON value")
    }

    fn visit_bool<E>(self, v: bool) -> Result<Value, E> {
        Ok(Value::Bool(v))
    }

    fn visit_i64<E>(self, v: i64) -> Result<Value, E> {
        Ok(Value::from(v))
    }

    fn visit_u64<E>(self, v: u64) -> Result<Value, E> {
        Ok(Value::from(v))
    }

    fn visit_f64<E: de::Error>(self, v: f64) -> Result<Value, E> {
        Number::from_f64(v)
            .map(Value::Number)
            .ok_or_else(|| E::custom("non-finite number"))
    }

    fn visit_str<E>(self, v: &str) -> Result<Value, E> {
        Ok(Value::String(v.to_owned()))
    }

    fn visit_string<E>(self, v: String) -> Result<Value, E> {
        Ok(Value::String(v))
    }

    fn visit_unit<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_none<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        let mut items = Vec::new();
        while let Some(item) = seq.next_element_seed(StrictSeed { depth: self.depth + 1 })? {
            items.push(item);
        }
        Ok(Value::Array(items))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut object = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if object.contains_key(&key) {
                return Err(de::Error::custom(format!("duplicate object key {key:?}")));
            }
            let value = map.next_value_seed(StrictSeed { depth: self.depth + 1 })?;
            object.insert(key, value);
        }
        Ok(Value::Object(object))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicate_keys_are_rejected_at_any_depth() {
        assert!(parse_strict(br#"{"a":1,"a":2}"#, 1024).is_err());
        assert!(parse_strict(br#"{"x":[{"amount":1,"amount":100000}]}"#, 1024).is_err());
        assert_eq!(parse_strict(br#"{"a":1,"b":{"a":2}}"#, 1024).unwrap()["b"]["a"], 2);
    }

    #[test]
    fn depth_size_and_trailing_bytes_are_bounded() {
        let deep = "[".repeat(MAX_INGRESS_DEPTH + 2) + &"]".repeat(MAX_INGRESS_DEPTH + 2);
        assert!(parse_strict(deep.as_bytes(), 1 << 20).is_err());
        assert_eq!(parse_strict(b"{}", 1), Err(IngressError::TooLarge(1)));
        assert!(parse_strict(b"{} {}", 1024).is_err());
    }
}
