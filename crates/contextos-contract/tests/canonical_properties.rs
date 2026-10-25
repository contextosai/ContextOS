//! Properties of canonical JSON (`docs/verification/PROPERTIES.md`). Every digest of
//! the execution contract rests on these: two parties that hold the same value must
//! produce the same bytes, and different values different bytes.

use contextos_contract::canonical::{canonicalize, js_number};
use proptest::prelude::*;
use std::fmt::Write as _;

use serde_json::{Map, Value, json};

/// Strings that stress escaping and key ordering: control characters, quotes,
/// characters on both sides of the surrogate range, and astral characters, whose
/// UTF-16 order differs from their UTF-8 order.
fn text() -> impl Strategy<Value = String> {
    prop::collection::vec(
        prop::sample::select(vec![
            'a',
            'B',
            'z',
            '"',
            '\\',
            '\n',
            '\u{1}',
            '\u{1f}',
            '\u{7f}',
            'é',
            '\u{2028}',
            '\u{e000}',
            '\u{ffff}',
            '\u{1f600}',
            '\u{10000}',
        ]),
        0..5,
    )
    .prop_map(|chars| chars.into_iter().collect())
}

/// JSON values without fractional numbers (their text is checked by CANON-3).
fn value() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        (-(1_i64 << 53) + 1..(1_i64 << 53)).prop_map(Value::from),
        text().prop_map(Value::String),
    ];
    leaf.prop_recursive(4, 48, 5, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..5).prop_map(Value::Array),
            prop::collection::vec((text(), inner), 0..5)
                .prop_map(|entries| Value::Object(entries.into_iter().collect())),
        ]
    })
}

/// An independent encoder written from RFC 8785 for these values: members sorted by
/// UTF-16 code units, strings escaped as ECMAScript `JSON.stringify` does.
fn oracle(value: &Value) -> String {
    match value {
        Value::Null => "null".into(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        Value::String(s) => string(s),
        Value::Array(items) => format!("[{}]", items.iter().map(oracle).collect::<Vec<_>>().join(",")),
        Value::Object(members) => {
            let mut keys: Vec<&String> = members.keys().collect();
            keys.sort_by_key(|k| k.encode_utf16().collect::<Vec<u16>>());
            let body: Vec<String> = keys
                .iter()
                .map(|k| format!("{}:{}", string(k), oracle(&members[*k])))
                .collect();
            format!("{{{}}}", body.join(","))
        }
    }
}

fn string(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' | '\\' => {
                out.push('\\');
                out.push(c);
            }
            '\u{8}' => out.push_str("\\b"),
            '\u{9}' => out.push_str("\\t"),
            '\u{a}' => out.push_str("\\n"),
            '\u{c}' => out.push_str("\\f"),
            '\u{d}' => out.push_str("\\r"),
            c if u32::from(c) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// `value` with every object's members inserted in reverse order.
fn reordered(value: &Value) -> Value {
    match value {
        Value::Array(items) => Value::Array(items.iter().map(reordered).collect()),
        Value::Object(members) => {
            let mut out = Map::new();
            for (k, v) in members.iter().rev() {
                out.insert(k.clone(), reordered(v));
            }
            Value::Object(out)
        }
        other => other.clone(),
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4096))]

    /// CANON-1: the encoding equals an independent RFC 8785 encoder, so member order
    /// is by UTF-16 code units and strings are escaped as the reference does.
    #[test]
    fn canonical_text_matches_an_independent_encoder(v in value()) {
        prop_assert_eq!(canonicalize(&v).unwrap(), oracle(&v));
    }

    /// CANON-2: the encoding is a fixed point (decoding and re-encoding it changes
    /// nothing), independent of member insertion order, and different values encode
    /// differently.
    #[test]
    fn canonical_text_is_stable_and_distinguishing(a in value(), b in value()) {
        let text = canonicalize(&a).unwrap();
        let decoded: Value = serde_json::from_str(&text).unwrap();
        prop_assert_eq!(&canonicalize(&decoded).unwrap(), &text);
        prop_assert_eq!(&canonicalize(&reordered(&a)).unwrap(), &text);
        if a != b {
            prop_assert_ne!(text, canonicalize(&b).unwrap());
        }
    }

    /// CANON-3: a number's text is ECMAScript's shortest round trip: it reads back as
    /// exactly the same double, integral doubles print as integers, and `-0` as `0`.
    #[test]
    fn numbers_read_back_exactly(x in any::<f64>().prop_filter("finite", |x| x.is_finite())) {
        let text = js_number(x).unwrap();
        let back: f64 = text.parse().unwrap();
        prop_assert_eq!(back.to_bits(), if x == 0.0 { 0.0_f64.to_bits() } else { x.to_bits() }, "{} -> {}", x, text);
        if x.fract() == 0.0 && x.abs() < 1e21 {
            prop_assert!(!text.contains('.') && !text.contains('e'), "{} -> {}", x, text);
        }
        prop_assert_eq!(canonicalize(&json!(x)).unwrap(), text);
    }
}
