//! JavaScript value semantics needed to evaluate JsonLogic exactly like the
//! `json-logic-js` reference: truthiness, `ToNumber`, `ToString`, `parseFloat`,
//! abstract equality and relational comparison.

use std::cmp::Ordering;
use std::rc::Rc;

use contextos_contract::canonical::js_number;
use serde_json::{Map, Value};

/// A JavaScript value restricted to what JSON data and JsonLogic operations produce.
#[derive(Debug, Clone)]
pub enum JsVal {
    Undefined,
    Null,
    Bool(bool),
    Num(f64),
    Str(Rc<str>),
    Arr(Rc<Vec<JsVal>>),
    Obj(Rc<Vec<(String, JsVal)>>),
}

impl JsVal {
    pub fn str(text: impl Into<Rc<str>>) -> Self {
        JsVal::Str(text.into())
    }

    pub fn from_json(value: &Value) -> Self {
        match value {
            Value::Null => JsVal::Null,
            Value::Bool(b) => JsVal::Bool(*b),
            Value::Number(n) => JsVal::Num(json_number(n)),
            Value::String(s) => JsVal::str(s.as_str()),
            Value::Array(items) => JsVal::Arr(Rc::new(items.iter().map(JsVal::from_json).collect())),
            Value::Object(map) => JsVal::Obj(Rc::new(
                map.iter().map(|(k, v)| (k.clone(), JsVal::from_json(v))).collect(),
            )),
        }
    }

    /// `JSON.stringify` semantics: non-finite numbers become `null`, `undefined`
    /// becomes `null` in arrays and is omitted from objects. Top-level `undefined`
    /// is `None`.
    pub fn to_json(&self) -> Option<Value> {
        Some(match self {
            JsVal::Undefined => return None,
            JsVal::Null => Value::Null,
            JsVal::Bool(b) => Value::Bool(*b),
            JsVal::Num(n) => {
                if n.is_finite() {
                    number_to_json(*n)
                } else {
                    Value::Null
                }
            }
            JsVal::Str(s) => Value::String(s.to_string()),
            JsVal::Arr(items) => Value::Array(items.iter().map(|v| v.to_json().unwrap_or(Value::Null)).collect()),
            JsVal::Obj(entries) => {
                let mut map = Map::new();
                for (key, value) in entries.iter() {
                    if let Some(json) = value.to_json() {
                        map.insert(key.clone(), json);
                    }
                }
                Value::Object(map)
            }
        })
    }

    pub fn is_nullish(&self) -> bool {
        matches!(self, JsVal::Undefined | JsVal::Null)
    }

    pub fn is_object_like(&self) -> bool {
        matches!(self, JsVal::Arr(_) | JsVal::Obj(_))
    }

    /// JavaScript `!!value`.
    pub fn js_truthy(&self) -> bool {
        match self {
            JsVal::Undefined | JsVal::Null => false,
            JsVal::Bool(b) => *b,
            JsVal::Num(n) => !(n.is_nan() || *n == 0.0),
            JsVal::Str(s) => !s.is_empty(),
            JsVal::Arr(_) | JsVal::Obj(_) => true,
        }
    }

    /// JsonLogic truthiness: like JavaScript, except an empty array is false.
    pub fn truthy(&self) -> bool {
        match self {
            JsVal::Arr(items) if items.is_empty() => false,
            other => other.js_truthy(),
        }
    }

    /// JavaScript `ToNumber`.
    pub fn to_number(&self) -> f64 {
        match self {
            JsVal::Undefined => f64::NAN,
            JsVal::Null => 0.0,
            JsVal::Bool(b) => f64::from(u8::from(*b)),
            JsVal::Num(n) => *n,
            JsVal::Str(s) => string_to_number(s),
            JsVal::Arr(_) | JsVal::Obj(_) => string_to_number(&self.to_js_string()),
        }
    }

    /// JavaScript `String(value)`.
    pub fn to_js_string(&self) -> String {
        match self {
            JsVal::Undefined => "undefined".into(),
            JsVal::Null => "null".into(),
            JsVal::Bool(b) => b.to_string(),
            JsVal::Num(n) => number_to_string(*n),
            JsVal::Str(s) => s.to_string(),
            JsVal::Arr(items) => {
                let mut out = String::new();
                for (index, item) in items.iter().enumerate() {
                    if index > 0 {
                        out.push(',');
                    }
                    if !item.is_nullish() {
                        out.push_str(&item.to_js_string());
                    }
                }
                out
            }
            JsVal::Obj(_) => "[object Object]".into(),
        }
    }

    /// `ToPrimitive` with the default hint: arrays and objects become strings.
    pub fn to_primitive(&self) -> JsVal {
        match self {
            JsVal::Arr(_) | JsVal::Obj(_) => JsVal::str(self.to_js_string()),
            other => other.clone(),
        }
    }

    /// UTF-16 length for strings and arrays (the JavaScript `length` property).
    pub fn length(&self) -> Option<usize> {
        match self {
            JsVal::Str(s) => Some(s.encode_utf16().count()),
            JsVal::Arr(items) => Some(items.len()),
            _ => None,
        }
    }
}

fn json_number(number: &serde_json::Number) -> f64 {
    #[allow(clippy::cast_precision_loss)]
    if let Some(i) = number.as_i64() {
        i as f64
    } else if let Some(u) = number.as_u64() {
        u as f64
    } else {
        number.as_f64().unwrap_or(f64::NAN)
    }
}

fn number_to_json(n: f64) -> Value {
    // Integral values within the safe range serialize as integers, like JSON.stringify.
    #[allow(clippy::cast_possible_truncation)]
    if n.fract() == 0.0 && n.abs() < 9_007_199_254_740_992.0 {
        return Value::from(n as i64);
    }
    serde_json::Number::from_f64(n).map_or(Value::Null, Value::Number)
}

/// JavaScript `Number.prototype.toString()`.
pub fn number_to_string(n: f64) -> String {
    if n.is_nan() {
        "NaN".into()
    } else if n.is_infinite() {
        if n > 0.0 { "Infinity".into() } else { "-Infinity".into() }
    } else {
        js_number(n).unwrap_or_default()
    }
}

/// JavaScript `StrWhiteSpaceChar` (WhiteSpace plus LineTerminator).
pub fn is_js_whitespace(c: char) -> bool {
    matches!(
        c,
        '\u{9}' | '\u{a}' | '\u{b}' | '\u{c}' | '\u{d}' | ' ' | '\u{a0}' | '\u{1680}' | '\u{2000}'
            ..='\u{200a}' | '\u{2028}' | '\u{2029}' | '\u{202f}' | '\u{205f}' | '\u{3000}' | '\u{feff}'
    )
}

/// Length in bytes of the longest prefix of `s` that is a `StrUnsignedDecimalLiteral`
/// without the `Infinity` form, or 0.
fn decimal_prefix_len(s: &str) -> usize {
    let b = s.as_bytes();
    let mut i = 0;
    let int_start = i;
    while i < b.len() && b[i].is_ascii_digit() {
        i += 1;
    }
    let int_digits = i - int_start;
    let mut frac_digits = 0;
    if i < b.len() && b[i] == b'.' {
        let mut j = i + 1;
        while j < b.len() && b[j].is_ascii_digit() {
            j += 1;
        }
        frac_digits = j - i - 1;
        if int_digits > 0 || frac_digits > 0 {
            i = j;
        }
    }
    if int_digits == 0 && frac_digits == 0 {
        return 0;
    }
    if i < b.len() && (b[i] == b'e' || b[i] == b'E') {
        let mut j = i + 1;
        if j < b.len() && (b[j] == b'+' || b[j] == b'-') {
            j += 1;
        }
        let exp_start = j;
        while j < b.len() && b[j].is_ascii_digit() {
            j += 1;
        }
        if j > exp_start {
            i = j;
        }
    }
    i
}

fn parse_decimal(text: &str) -> f64 {
    // Rust accepts the forms decimal_prefix_len admits ("1.", ".5", "1e5") with
    // correct rounding, matching ECMAScript.
    text.parse::<f64>().unwrap_or(f64::NAN)
}

/// JavaScript `StringToNumber` (used by `Number(s)` and implicit coercion).
pub fn string_to_number(s: &str) -> f64 {
    let t = s.trim_matches(is_js_whitespace);
    if t.is_empty() {
        return 0.0;
    }
    for (prefix, radix) in [("0x", 16), ("0X", 16), ("0o", 8), ("0O", 8), ("0b", 2), ("0B", 2)] {
        if let Some(digits) = t.strip_prefix(prefix) {
            if digits.is_empty() || !digits.chars().all(|c| c.is_digit(radix)) {
                return f64::NAN;
            }
            let mut value = 0.0_f64;
            for c in digits.chars() {
                value = value * f64::from(radix) + f64::from(c.to_digit(radix).unwrap_or(0));
            }
            return value;
        }
    }
    let (sign, body) = match t.as_bytes()[0] {
        b'+' => (1.0, &t[1..]),
        b'-' => (-1.0, &t[1..]),
        _ => (1.0, t),
    };
    if body == "Infinity" {
        return sign * f64::INFINITY;
    }
    let len = decimal_prefix_len(body);
    if len == 0 || len != body.len() {
        return f64::NAN;
    }
    sign * parse_decimal(body)
}

/// JavaScript `parseFloat(String(value))`.
pub fn parse_float(value: &JsVal) -> f64 {
    let text = value.to_js_string();
    let t = text.trim_start_matches(is_js_whitespace);
    let (sign, body) = match t.as_bytes().first() {
        Some(b'+') => (1.0, &t[1..]),
        Some(b'-') => (-1.0, &t[1..]),
        _ => (1.0, t),
    };
    if body.starts_with("Infinity") {
        return sign * f64::INFINITY;
    }
    let len = decimal_prefix_len(body);
    if len == 0 {
        return f64::NAN;
    }
    sign * parse_decimal(&body[..len])
}

/// JavaScript `ToIntegerOrInfinity`.
pub fn to_integer_or_infinity(n: f64) -> f64 {
    if n.is_nan() { 0.0 } else { n.trunc() }
}

/// Outcome of comparing two JavaScript values; `ReferenceIdentity` marks a comparison
/// between two arrays/objects, which JavaScript decides by object identity. Identity
/// is not part of JSON data, so evaluators must treat it as an error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Equality {
    Equal,
    NotEqual,
    ReferenceIdentity,
}

impl Equality {
    fn from_bool(equal: bool) -> Self {
        if equal { Equality::Equal } else { Equality::NotEqual }
    }
}

/// JavaScript `a === b`.
pub fn strict_equals(a: &JsVal, b: &JsVal) -> Equality {
    use JsVal::{Arr, Bool, Null, Num, Obj, Str, Undefined};
    match (a, b) {
        (Undefined, Undefined) | (Null, Null) => Equality::Equal,
        (Bool(x), Bool(y)) => Equality::from_bool(x == y),
        (Num(x), Num(y)) => Equality::from_bool(x == y),
        (Str(x), Str(y)) => Equality::from_bool(x == y),
        (Arr(_) | Obj(_), Arr(_) | Obj(_)) => Equality::ReferenceIdentity,
        _ => Equality::NotEqual,
    }
}

/// JavaScript `a == b` (IsLooselyEqual).
pub fn loose_equals(a: &JsVal, b: &JsVal) -> Equality {
    use JsVal::{Arr, Bool, Null, Num, Obj, Str, Undefined};
    match (a, b) {
        (Undefined | Null, Undefined | Null) => Equality::Equal,
        (Undefined | Null, _) | (_, Undefined | Null) => Equality::NotEqual,
        (Arr(_) | Obj(_), Arr(_) | Obj(_)) => Equality::ReferenceIdentity,
        (Num(_), Num(_)) | (Str(_), Str(_)) | (Bool(_), Bool(_)) => strict_equals(a, b),
        (Num(x), Str(s)) | (Str(s), Num(x)) => Equality::from_bool(*x == string_to_number(s)),
        (Bool(x), other) | (other, Bool(x)) => loose_equals(&JsVal::Num(f64::from(u8::from(*x))), other),
        (Arr(_) | Obj(_), other) | (other, Arr(_) | Obj(_)) => {
            let primitive = if a.is_object_like() {
                a.to_primitive()
            } else {
                b.to_primitive()
            };
            loose_equals(&primitive, other)
        }
    }
}

/// JavaScript abstract relational comparison `a < b`; `None` means undefined (NaN involved).
pub fn less_than(a: &JsVal, b: &JsVal) -> Option<bool> {
    let (pa, pb) = (a.to_primitive(), b.to_primitive());
    if let (JsVal::Str(x), JsVal::Str(y)) = (&pa, &pb) {
        return Some(x.encode_utf16().cmp(y.encode_utf16()) == Ordering::Less);
    }
    let (x, y) = (pa.to_number(), pb.to_number());
    if x.is_nan() || y.is_nan() {
        return None;
    }
    Some(x < y)
}

pub fn js_lt(a: &JsVal, b: &JsVal) -> bool {
    less_than(a, b).unwrap_or(false)
}

pub fn js_gt(a: &JsVal, b: &JsVal) -> bool {
    less_than(b, a).unwrap_or(false)
}

pub fn js_le(a: &JsVal, b: &JsVal) -> bool {
    // a <= b  is  !(b < a), false when undefined.
    less_than(b, a).is_some_and(|r| !r)
}

pub fn js_ge(a: &JsVal, b: &JsVal) -> bool {
    less_than(a, b).is_some_and(|r| !r)
}

/// JavaScript binary `+`.
pub fn js_plus(a: &JsVal, b: &JsVal) -> JsVal {
    let (pa, pb) = (a.to_primitive(), b.to_primitive());
    if matches!(pa, JsVal::Str(_)) || matches!(pb, JsVal::Str(_)) {
        let mut text = pa.to_js_string();
        text.push_str(&pb.to_js_string());
        JsVal::str(text)
    } else {
        JsVal::Num(pa.to_number() + pb.to_number())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn string_to_number_follows_ecmascript() {
        assert_eq!(string_to_number("  12 "), 12.0);
        assert_eq!(string_to_number(""), 0.0);
        assert_eq!(string_to_number("0x1F"), 31.0);
        assert!(string_to_number("-0x1F").is_nan());
        assert_eq!(string_to_number("1e3"), 1000.0);
        assert_eq!(string_to_number(".5"), 0.5);
        assert_eq!(string_to_number("5."), 5.0);
        assert!(string_to_number(".").is_nan());
        assert!(string_to_number("1e").is_nan());
        assert_eq!(string_to_number("-Infinity"), f64::NEG_INFINITY);
        assert!(string_to_number("infinity").is_nan());
        assert!(string_to_number("12abc").is_nan());
    }

    #[test]
    fn parse_float_takes_longest_prefix() {
        assert_eq!(parse_float(&JsVal::str("12abc")), 12.0);
        assert_eq!(parse_float(&JsVal::str("1e")), 1.0);
        assert_eq!(parse_float(&JsVal::str("0x10")), 0.0);
        assert!(parse_float(&JsVal::Null).is_nan());
        assert_eq!(parse_float(&JsVal::str(" -.5e1x")), -5.0);
        assert_eq!(parse_float(&JsVal::str("Infinityx")), f64::INFINITY);
    }

    #[test]
    fn loose_equality_coerces() {
        let eq = |a: JsVal, b: JsVal| loose_equals(&a, &b);
        assert_eq!(eq(JsVal::Num(1.0), JsVal::str("1")), Equality::Equal);
        assert_eq!(eq(JsVal::Bool(true), JsVal::str("1")), Equality::Equal);
        assert_eq!(eq(JsVal::Null, JsVal::Num(0.0)), Equality::NotEqual);
        assert_eq!(eq(JsVal::Null, JsVal::Undefined), Equality::Equal);
        let arr = JsVal::Arr(Rc::new(vec![JsVal::Num(1.0)]));
        assert_eq!(eq(arr.clone(), JsVal::Num(1.0)), Equality::Equal);
        assert_eq!(eq(arr.clone(), arr), Equality::ReferenceIdentity);
    }
}
