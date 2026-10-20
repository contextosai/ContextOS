//! JsonLogic evaluation with `json-logic-js` 2.0.5 semantics.
//!
//! Differences from the reference are deliberate and always fail visibly
//! (an [`EvalError`]), never silently:
//!
//! * Resource bounds: recursion depth, evaluation steps, string length and array size
//!   are capped, so an untrusted or buggy rule cannot exhaust a shared gateway.
//! * Prototype members (`constructor`, `__proto__`, `toString`, array/string methods)
//!   are not JSON data. The reference returns host functions for them; this evaluator
//!   reports [`EvalErrorKind::UnsafeProperty`].
//! * Comparing two arrays/objects is decided by object identity in JavaScript, which
//!   JSON data does not carry; this evaluator reports
//!   [`EvalErrorKind::ReferenceComparison`].
//! * `log` returns its argument without writing anywhere.

use std::rc::Rc;

use serde_json::Value;

use crate::value::{
    Equality, JsVal, is_js_whitespace, js_ge, js_gt, js_le, js_lt, js_plus, loose_equals, parse_float, strict_equals,
    to_integer_or_infinity,
};

/// Resource limits for one evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub max_depth: usize,
    pub max_steps: usize,
    pub max_string_utf16: usize,
    pub max_array_len: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_depth: 128,
            max_steps: 100_000,
            max_string_utf16: 1_048_576,
            max_array_len: 100_000,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvalErrorKind {
    UnrecognizedOperation(String),
    TypeError(&'static str),
    UnsafeProperty(String),
    ReferenceComparison,
    LimitExceeded(&'static str),
}

/// Evaluation failure. Callers surface it as a structured policy error and must not
/// treat it as a false predicate.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("jsonlogic evaluation failed: {kind:?}")]
pub struct EvalError {
    pub kind: EvalErrorKind,
}

impl EvalError {
    fn new(kind: EvalErrorKind) -> Self {
        Self { kind }
    }
}

type Result<T> = std::result::Result<T, EvalError>;

/// Evaluates `logic` against `data` with default limits.
pub fn apply(logic: &Value, data: &Value) -> Result<JsVal> {
    apply_with_limits(logic, data, Limits::default())
}

pub fn apply_with_limits(logic: &Value, data: &Value, limits: Limits) -> Result<JsVal> {
    let mut eval = Evaluator { limits, steps: 0 };
    let logic = JsVal::from_json(logic);
    eval.apply(&logic, &JsVal::from_json(data), 0)
}

/// Evaluates a predicate the way the ContextOS reference compiler does: JavaScript
/// `!!result`, so an empty array result counts as true.
pub fn predicate(logic: &Value, data: &Value) -> Result<bool> {
    apply(logic, data).map(|value| value.js_truthy())
}

struct Evaluator {
    limits: Limits,
    steps: usize,
}

fn logic_operator(logic: &JsVal) -> Option<(&str, &JsVal)> {
    match logic {
        JsVal::Obj(entries) if entries.len() == 1 => Some((entries[0].0.as_str(), &entries[0].1)),
        _ => None,
    }
}

const OPERATIONS: &[&str] = &[
    "==",
    "===",
    "!=",
    "!==",
    ">",
    ">=",
    "<",
    "<=",
    "!!",
    "!",
    "%",
    "log",
    "in",
    "cat",
    "substr",
    "+",
    "*",
    "-",
    "/",
    "min",
    "max",
    "merge",
    "var",
    "missing",
    "missing_some",
];

const OBJECT_PROTOTYPE: &[&str] = &[
    "constructor",
    "__proto__",
    "__defineGetter__",
    "__defineSetter__",
    "__lookupGetter__",
    "__lookupSetter__",
    "hasOwnProperty",
    "isPrototypeOf",
    "propertyIsEnumerable",
    "toLocaleString",
    "toString",
    "valueOf",
];

const ARRAY_PROTOTYPE: &[&str] = &[
    "at",
    "concat",
    "copyWithin",
    "entries",
    "every",
    "fill",
    "filter",
    "find",
    "findIndex",
    "findLast",
    "findLastIndex",
    "flat",
    "flatMap",
    "forEach",
    "includes",
    "indexOf",
    "join",
    "keys",
    "lastIndexOf",
    "map",
    "pop",
    "push",
    "reduce",
    "reduceRight",
    "reverse",
    "shift",
    "slice",
    "some",
    "sort",
    "splice",
    "toReversed",
    "toSorted",
    "toSpliced",
    "unshift",
    "values",
    "with",
];

const STRING_PROTOTYPE: &[&str] = &[
    "anchor",
    "at",
    "big",
    "blink",
    "bold",
    "charAt",
    "charCodeAt",
    "codePointAt",
    "concat",
    "endsWith",
    "fixed",
    "fontcolor",
    "fontsize",
    "includes",
    "indexOf",
    "isWellFormed",
    "italics",
    "lastIndexOf",
    "link",
    "localeCompare",
    "match",
    "matchAll",
    "normalize",
    "padEnd",
    "padStart",
    "repeat",
    "replace",
    "replaceAll",
    "search",
    "slice",
    "small",
    "split",
    "startsWith",
    "strike",
    "sub",
    "substr",
    "substring",
    "sup",
    "toLocaleLowerCase",
    "toLocaleUpperCase",
    "toLowerCase",
    "toUpperCase",
    "toWellFormed",
    "trim",
    "trimEnd",
    "trimLeft",
    "trimRight",
    "trimStart",
];

const NUMBER_PROTOTYPE: &[&str] = &["toExponential", "toFixed", "toPrecision"];

fn is_canonical_index(key: &str) -> Option<usize> {
    if key == "0" {
        return Some(0);
    }
    if key.is_empty() || key.starts_with('0') || !key.bytes().all(|b| b.is_ascii_digit()) || key.len() > 10 {
        return None;
    }
    key.parse::<u64>()
        .ok()
        .filter(|&n| n < u64::from(u32::MAX))
        .and_then(|n| usize::try_from(n).ok())
}

/// `data[key]` for JSON-derived data, refusing prototype members.
fn get_property(data: &JsVal, key: &str) -> Result<JsVal> {
    let unsafe_property = || Err(EvalError::new(EvalErrorKind::UnsafeProperty(key.to_owned())));
    match data {
        JsVal::Obj(entries) => {
            if let Some((_, value)) = entries.iter().rev().find(|(k, _)| k == key) {
                return Ok(value.clone());
            }
            if OBJECT_PROTOTYPE.contains(&key) {
                return unsafe_property();
            }
            Ok(JsVal::Undefined)
        }
        JsVal::Arr(items) => {
            if key == "length" {
                #[allow(clippy::cast_precision_loss)]
                return Ok(JsVal::Num(items.len() as f64));
            }
            if let Some(index) = is_canonical_index(key) {
                return Ok(items.get(index).cloned().unwrap_or(JsVal::Undefined));
            }
            if OBJECT_PROTOTYPE.contains(&key) || ARRAY_PROTOTYPE.contains(&key) {
                return unsafe_property();
            }
            Ok(JsVal::Undefined)
        }
        JsVal::Str(text) => {
            let units: Vec<u16> = text.encode_utf16().collect();
            if key == "length" {
                #[allow(clippy::cast_precision_loss)]
                return Ok(JsVal::Num(units.len() as f64));
            }
            if let Some(index) = is_canonical_index(key) {
                return Ok(units
                    .get(index)
                    .map_or(JsVal::Undefined, |unit| JsVal::str(String::from_utf16_lossy(&[*unit]))));
            }
            if OBJECT_PROTOTYPE.contains(&key) || STRING_PROTOTYPE.contains(&key) {
                return unsafe_property();
            }
            Ok(JsVal::Undefined)
        }
        JsVal::Num(_) | JsVal::Bool(_) => {
            if OBJECT_PROTOTYPE.contains(&key) || (matches!(data, JsVal::Num(_)) && NUMBER_PROTOTYPE.contains(&key)) {
                return unsafe_property();
            }
            Ok(JsVal::Undefined)
        }
        JsVal::Undefined | JsVal::Null => Err(EvalError::new(EvalErrorKind::TypeError("property of null"))),
    }
}

fn arg(values: &[JsVal], index: usize) -> &JsVal {
    values.get(index).unwrap_or(&JsVal::Undefined)
}

fn bool_val(b: bool) -> JsVal {
    JsVal::Bool(b)
}

impl Evaluator {
    fn step(&mut self, depth: usize) -> Result<()> {
        self.steps += 1;
        if self.steps > self.limits.max_steps {
            return Err(EvalError::new(EvalErrorKind::LimitExceeded("steps")));
        }
        if depth > self.limits.max_depth {
            return Err(EvalError::new(EvalErrorKind::LimitExceeded("depth")));
        }
        Ok(())
    }

    fn check_string(&self, text: &str) -> Result<()> {
        if text.len() > self.limits.max_string_utf16 && text.encode_utf16().count() > self.limits.max_string_utf16 {
            return Err(EvalError::new(EvalErrorKind::LimitExceeded("string")));
        }
        Ok(())
    }

    fn check_array(&self, len: usize) -> Result<()> {
        if len > self.limits.max_array_len {
            return Err(EvalError::new(EvalErrorKind::LimitExceeded("array")));
        }
        Ok(())
    }

    fn to_string_bounded(&self, value: &JsVal) -> Result<String> {
        if let JsVal::Arr(items) = value {
            self.check_array(items.len())?;
        }
        let text = value.to_js_string();
        self.check_string(&text)?;
        Ok(text)
    }

    fn apply(&mut self, logic: &JsVal, data: &JsVal, depth: usize) -> Result<JsVal> {
        self.step(depth)?;
        if let JsVal::Arr(items) = logic {
            let mut out = Vec::with_capacity(items.len());
            for item in items.iter() {
                out.push(self.apply(item, data, depth + 1)?);
            }
            return Ok(JsVal::Arr(Rc::new(out)));
        }
        let Some((op, raw_values)) = logic_operator(logic) else {
            return Ok(logic.clone());
        };
        let values: Vec<JsVal> = match raw_values {
            JsVal::Arr(items) => items.as_ref().clone(),
            other => vec![other.clone()],
        };
        let d = depth + 1;
        match op {
            "if" | "?:" => {
                let mut i = 0;
                while i + 1 < values.len() {
                    if self.apply(&values[i], data, d)?.truthy() {
                        return self.apply(&values[i + 1], data, d);
                    }
                    i += 2;
                }
                if values.len() == i + 1 {
                    return self.apply(&values[i], data, d);
                }
                Ok(JsVal::Null)
            }
            "and" | "or" => {
                let want = op == "or";
                let mut current = JsVal::Undefined;
                for value in &values {
                    current = self.apply(value, data, d)?;
                    if current.truthy() == want {
                        return Ok(current);
                    }
                }
                Ok(current)
            }
            "filter" | "map" | "all" | "none" | "some" => {
                let scoped = self.apply(arg(&values, 0), data, d)?;
                let scoped_logic = arg(&values, 1).clone();
                let JsVal::Arr(items) = scoped else {
                    return Ok(match op {
                        "filter" | "map" => JsVal::Arr(Rc::new(Vec::new())),
                        "none" => bool_val(true),
                        _ => bool_val(false),
                    });
                };
                match op {
                    "filter" => {
                        let mut out = Vec::new();
                        for item in items.iter() {
                            if self.apply(&scoped_logic, item, d)?.truthy() {
                                out.push(item.clone());
                            }
                        }
                        Ok(JsVal::Arr(Rc::new(out)))
                    }
                    "map" => {
                        let mut out = Vec::with_capacity(items.len());
                        for item in items.iter() {
                            out.push(self.apply(&scoped_logic, item, d)?);
                        }
                        Ok(JsVal::Arr(Rc::new(out)))
                    }
                    "all" => {
                        if items.is_empty() {
                            return Ok(bool_val(false));
                        }
                        for item in items.iter() {
                            if !self.apply(&scoped_logic, item, d)?.truthy() {
                                return Ok(bool_val(false));
                            }
                        }
                        Ok(bool_val(true))
                    }
                    "none" => {
                        for item in items.iter() {
                            if self.apply(&scoped_logic, item, d)?.truthy() {
                                return Ok(bool_val(false));
                            }
                        }
                        Ok(bool_val(true))
                    }
                    _ => {
                        for item in items.iter() {
                            if self.apply(&scoped_logic, item, d)?.truthy() {
                                return Ok(bool_val(true));
                            }
                        }
                        Ok(bool_val(false))
                    }
                }
            }
            "reduce" => {
                let scoped = self.apply(arg(&values, 0), data, d)?;
                let scoped_logic = arg(&values, 1).clone();
                let initial = match values.get(2) {
                    Some(JsVal::Undefined) | None => JsVal::Null,
                    Some(value) => self.apply(value, data, d)?,
                };
                let JsVal::Arr(items) = scoped else {
                    return Ok(initial);
                };
                let mut accumulator = initial;
                for item in items.iter() {
                    let scope = JsVal::Obj(Rc::new(vec![
                        ("current".to_owned(), item.clone()),
                        ("accumulator".to_owned(), accumulator),
                    ]));
                    accumulator = self.apply(&scoped_logic, &scope, d)?;
                }
                Ok(accumulator)
            }
            _ => {
                if !OPERATIONS.contains(&op) {
                    return Err(EvalError::new(EvalErrorKind::UnrecognizedOperation(op.to_owned())));
                }
                let mut evaluated = Vec::with_capacity(values.len());
                for value in &values {
                    evaluated.push(self.apply(value, data, d)?);
                }
                self.operation(op, &evaluated, data, d)
            }
        }
    }

    fn equality(result: Equality, negate: bool) -> Result<JsVal> {
        match result {
            Equality::ReferenceIdentity => Err(EvalError::new(EvalErrorKind::ReferenceComparison)),
            Equality::Equal => Ok(bool_val(!negate)),
            Equality::NotEqual => Ok(bool_val(negate)),
        }
    }

    #[allow(clippy::too_many_lines)]
    fn operation(&mut self, op: &str, values: &[JsVal], data: &JsVal, depth: usize) -> Result<JsVal> {
        let (a, b, c) = (arg(values, 0), arg(values, 1), arg(values, 2));
        match op {
            "==" => Self::equality(loose_equals(a, b), false),
            "!=" => Self::equality(loose_equals(a, b), true),
            "===" => Self::equality(strict_equals(a, b), false),
            "!==" => Self::equality(strict_equals(a, b), true),
            ">" => Ok(bool_val(js_gt(a, b))),
            ">=" => Ok(bool_val(js_ge(a, b))),
            "<" => Ok(bool_val(if matches!(c, JsVal::Undefined) {
                js_lt(a, b)
            } else {
                js_lt(a, b) && js_lt(b, c)
            })),
            "<=" => Ok(bool_val(if matches!(c, JsVal::Undefined) {
                js_le(a, b)
            } else {
                js_le(a, b) && js_le(b, c)
            })),
            "!!" => Ok(bool_val(a.truthy())),
            "!" => Ok(bool_val(!a.truthy())),
            "%" => Ok(JsVal::Num(a.to_number() % b.to_number())),
            "/" => Ok(JsVal::Num(a.to_number() / b.to_number())),
            "-" => Ok(JsVal::Num(if matches!(b, JsVal::Undefined) {
                -a.to_number()
            } else {
                a.to_number() - b.to_number()
            })),
            "log" => Ok(a.clone()),
            "in" => self.op_in(a, b),
            "cat" => {
                let mut out = String::new();
                for value in values {
                    if !value.is_nullish() {
                        out.push_str(&self.to_string_bounded(value)?);
                        self.check_string(&out)?;
                    }
                }
                Ok(JsVal::str(out))
            }
            "substr" => self.op_substr(a, b, c),
            "+" => {
                let mut acc = JsVal::Num(0.0);
                for value in values {
                    acc = JsVal::Num(parse_float(&acc) + parse_float(value));
                }
                Ok(acc)
            }
            "*" => {
                let Some((first, rest)) = values.split_first() else {
                    return Err(EvalError::new(EvalErrorKind::TypeError("reduce of empty array")));
                };
                let mut acc = first.clone();
                for value in rest {
                    acc = JsVal::Num(parse_float(&acc) * parse_float(value));
                }
                Ok(acc)
            }
            "min" | "max" => {
                let want_max = op == "max";
                let mut acc = if want_max { f64::NEG_INFINITY } else { f64::INFINITY };
                for value in values {
                    let n = value.to_number();
                    if n.is_nan() || acc.is_nan() {
                        acc = f64::NAN;
                        continue;
                    }
                    let take = if want_max {
                        n > acc || (n == 0.0 && acc == 0.0 && acc.is_sign_negative())
                    } else {
                        n < acc || (n == 0.0 && acc == 0.0 && n.is_sign_negative())
                    };
                    if take {
                        acc = n;
                    }
                }
                Ok(JsVal::Num(acc))
            }
            "merge" => {
                let mut out = Vec::new();
                for value in values {
                    match value {
                        JsVal::Arr(items) => out.extend(items.iter().cloned()),
                        other => out.push(other.clone()),
                    }
                    self.check_array(out.len())?;
                }
                Ok(JsVal::Arr(Rc::new(out)))
            }
            "var" => self.op_var(a, b, data),
            "missing" => self.op_missing(values, data, depth),
            "missing_some" => {
                let options = b.clone();
                let missing_logic = JsVal::Obj(Rc::new(vec![("missing".to_owned(), options.clone())]));
                let are_missing = self.apply(&missing_logic, data, depth)?;
                let missing_len = are_missing.length().unwrap_or(0);
                #[allow(clippy::cast_precision_loss)]
                let present = options.length().map_or(f64::NAN, |len| len as f64 - missing_len as f64);
                if js_ge(&JsVal::Num(present), a) {
                    Ok(JsVal::Arr(Rc::new(Vec::new())))
                } else {
                    Ok(are_missing)
                }
            }
            _ => Err(EvalError::new(EvalErrorKind::UnrecognizedOperation(op.to_owned()))),
        }
    }

    fn op_in(&self, a: &JsVal, b: &JsVal) -> Result<JsVal> {
        if !b.js_truthy() {
            return Ok(bool_val(false));
        }
        match b {
            JsVal::Str(haystack) => {
                let needle = self.to_string_bounded(a)?;
                let hay: Vec<u16> = haystack.encode_utf16().collect();
                let pin: Vec<u16> = needle.encode_utf16().collect();
                let found = pin.is_empty() || hay.windows(pin.len()).any(|window| window == pin.as_slice());
                Ok(bool_val(found))
            }
            JsVal::Arr(items) => {
                for item in items.iter() {
                    match strict_equals(a, item) {
                        Equality::Equal => return Ok(bool_val(true)),
                        Equality::ReferenceIdentity => {
                            return Err(EvalError::new(EvalErrorKind::ReferenceComparison));
                        }
                        Equality::NotEqual => {}
                    }
                }
                Ok(bool_val(false))
            }
            JsVal::Obj(entries) if entries.iter().any(|(k, _)| k == "indexOf") => {
                Err(EvalError::new(EvalErrorKind::TypeError("indexOf is not a function")))
            }
            _ => Ok(bool_val(false)),
        }
    }

    fn op_substr(&self, source: &JsVal, start: &JsVal, end: &JsVal) -> Result<JsVal> {
        let text = self.to_string_bounded(source)?;
        let units: Vec<u16> = text.encode_utf16().collect();
        if js_lt(end, &JsVal::Num(0.0)) {
            let temp = js_substr(&units, start, &JsVal::Undefined);
            #[allow(clippy::cast_precision_loss)]
            let length = js_plus(&JsVal::Num(temp.len() as f64), end);
            return Ok(JsVal::str(String::from_utf16_lossy(&js_substr(
                &temp,
                &JsVal::Num(0.0),
                &length,
            ))));
        }
        Ok(JsVal::str(String::from_utf16_lossy(&js_substr(&units, start, end))))
    }

    fn op_var(&self, a: &JsVal, b: &JsVal, data: &JsVal) -> Result<JsVal> {
        let not_found = if matches!(b, JsVal::Undefined) {
            JsVal::Null
        } else {
            b.clone()
        };
        if a.is_nullish() || matches!(a, JsVal::Str(s) if s.is_empty()) {
            return Ok(data.clone());
        }
        let path = self.to_string_bounded(a)?;
        let mut current = data.clone();
        for segment in path.split('.') {
            if current.is_nullish() {
                return Ok(not_found);
            }
            current = get_property(&current, segment)?;
            if matches!(current, JsVal::Undefined) {
                return Ok(not_found);
            }
        }
        Ok(current)
    }

    fn op_missing(&mut self, values: &[JsVal], data: &JsVal, depth: usize) -> Result<JsVal> {
        let keys: Vec<JsVal> = match values.first() {
            Some(JsVal::Arr(items)) => items.as_ref().clone(),
            _ => values.to_vec(),
        };
        let mut missing = Vec::new();
        for key in keys {
            // The reference re-applies `{"var": key}` as logic, so array and
            // one-key-object keys are evaluated rather than read literally.
            let var_logic = JsVal::Obj(Rc::new(vec![("var".to_owned(), key.clone())]));
            let value = self.apply(&var_logic, data, depth)?;
            if matches!(value, JsVal::Null) || matches!(&value, JsVal::Str(s) if s.is_empty()) {
                missing.push(key);
            }
        }
        Ok(JsVal::Arr(Rc::new(missing)))
    }
}

/// `String.prototype.substr` over UTF-16 code units.
fn js_substr(units: &[u16], start: &JsVal, length: &JsVal) -> Vec<u16> {
    #[allow(clippy::cast_precision_loss)]
    let size = units.len() as f64;
    let mut int_start = to_integer_or_infinity(start.to_number());
    if int_start == f64::NEG_INFINITY {
        int_start = 0.0;
    } else if int_start < 0.0 {
        int_start = (size + int_start).max(0.0);
    } else {
        int_start = int_start.min(size);
    }
    let int_length = if matches!(length, JsVal::Undefined) {
        size
    } else {
        to_integer_or_infinity(length.to_number())
    };
    let int_length = int_length.clamp(0.0, size);
    let int_end = (int_start + int_length).min(size);
    if int_start >= int_end {
        return Vec::new();
    }
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    units[int_start as usize..int_end as usize].to_vec()
}

/// Trims JavaScript whitespace; exposed for callers normalizing rule inputs.
pub fn js_trim(text: &str) -> &str {
    text.trim_matches(is_js_whitespace)
}

#[cfg(test)]
#[allow(clippy::needless_pass_by_value)]
mod tests {
    use super::*;
    use serde_json::json;

    fn eval(logic: Value, data: Value) -> Option<Value> {
        apply(&logic, &data).unwrap().to_json()
    }

    #[test]
    fn spec_examples() {
        assert_eq!(eval(json!({"==": [1, 1]}), json!(null)), Some(json!(true)));
        assert_eq!(eval(json!({"var": ["a"]}), json!({"a": 1})), Some(json!(1)));
        assert_eq!(eval(json!({"var": "a.b"}), json!({"a": {"b": "x"}})), Some(json!("x")));
        assert_eq!(eval(json!({"var": ["z", 26]}), json!({})), Some(json!(26)));
        assert_eq!(
            eval(json!({"var": 1}), json!(["apple", "banana"])),
            Some(json!("banana"))
        );
        assert_eq!(
            eval(json!({"missing": ["a", "b"]}), json!({"a": "x"})),
            Some(json!(["b"]))
        );
        assert_eq!(
            eval(json!({"missing_some": [1, ["a", "b"]]}), json!({"a": 1})),
            Some(json!([]))
        );
        assert_eq!(
            eval(json!({"if": [true, "yes", "no"]}), json!(null)),
            Some(json!("yes"))
        );
        assert_eq!(eval(json!({"<": [1, 2, 3]}), json!(null)), Some(json!(true)));
        assert_eq!(
            eval(json!({"in": ["Spring", "Springfield"]}), json!(null)),
            Some(json!(true))
        );
        assert_eq!(
            eval(json!({"cat": ["I love", " pie"]}), json!(null)),
            Some(json!("I love pie"))
        );
        assert_eq!(
            eval(json!({"substr": ["jsonlogic", -5]}), json!(null)),
            Some(json!("logic"))
        );
        assert_eq!(
            eval(json!({"substr": ["jsonlogic", 1, -1]}), json!(null)),
            Some(json!("sonlogi"))
        );
        assert_eq!(
            eval(json!({"merge": [[1, 2], 3, [[4]]]}), json!(null)),
            Some(json!([1, 2, 3, [4]]))
        );
        assert_eq!(
            eval(
                json!({"reduce": [[1, 2, 3], {"+": [{"var": "current"}, {"var": "accumulator"}]}, 0]}),
                json!(null)
            ),
            Some(json!(6))
        );
        assert_eq!(eval(json!({"and": []}), json!(null)), None);
        assert_eq!(eval(json!({"/": [1, 0]}), json!(null)), Some(json!(null)));
    }

    #[test]
    fn unknown_operation_fails_visibly() {
        let error = apply(&json!({"no_such_op": [1]}), &json!(null)).unwrap_err();
        assert_eq!(error.kind, EvalErrorKind::UnrecognizedOperation("no_such_op".into()));
    }

    #[test]
    fn prototype_members_are_refused() {
        for path in ["constructor", "a.__proto__", "s.toUpperCase", "list.map", "n.toFixed"] {
            let error = apply(&json!({"var": path}), &json!({"a": {}, "s": "x", "list": [], "n": 1})).unwrap_err();
            assert!(matches!(error.kind, EvalErrorKind::UnsafeProperty(_)), "{path}");
        }
        // Own keys that share a prototype name are ordinary data.
        assert_eq!(
            eval(json!({"var": "constructor"}), json!({"constructor": 7})),
            Some(json!(7))
        );
    }

    #[test]
    fn object_identity_comparison_fails_visibly() {
        let error = apply(&json!({"==": [{"var": "a"}, {"var": "a"}]}), &json!({"a": [1]})).unwrap_err();
        assert_eq!(error.kind, EvalErrorKind::ReferenceComparison);
    }

    #[test]
    fn limits_stop_runaway_rules() {
        let limits = Limits {
            max_steps: 50,
            ..Limits::default()
        };
        let big: Vec<i32> = (0..100).collect();
        let error = apply_with_limits(&json!({"map": [big, {"var": ""}]}), &json!(null), limits).unwrap_err();
        assert_eq!(error.kind, EvalErrorKind::LimitExceeded("steps"));

        let mut logic = json!(1);
        for _ in 0..200 {
            logic = json!({"!!": [logic]});
        }
        assert_eq!(
            apply(&logic, &json!(null)).unwrap_err().kind,
            EvalErrorKind::LimitExceeded("depth")
        );
    }

    #[test]
    fn predicate_uses_javascript_truthiness() {
        // The compiler applies `!!` to the result, so an empty array fires a rule.
        assert!(predicate(&json!({"merge": []}), &json!(null)).unwrap());
        assert!(!predicate(&json!({"!!": [[]]}), &json!(null)).unwrap());
    }
}
