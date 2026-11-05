//! Partial evaluation: evaluate what known data decides and keep the rest.
//!
//! Some data is known now (a principal) and some only later (a request). Given the
//! known part and the variable paths still unknown, [`partial_apply`] returns either
//! the value the logic takes whatever the unknown data turns out to be, or a residual
//! expression over the unknown paths.
//!
//! The residual is exact: evaluated against any complete data that agrees with the
//! known part, it yields the same value, or the same error, as the original logic.
//! It is only made smaller where that holds:
//!
//! * a subexpression that reads no unknown path is evaluated, and replaced by its
//!   value when that value is a JSON literal the evaluator reads back unchanged;
//! * `and` / `or` drop known operands before the first unknown one that cannot
//!   decide the result, and stop at a known operand that does; `if` drops branches
//!   whose known condition is false and takes the first whose known condition is true.
//!
//! Anything else, including the scoped logic of `map`, `filter`, `all`, `none`,
//! `some` and `reduce`, is kept as written. A variable path that cannot be read
//! statically (computed, or the whole data) counts as unknown.

use serde_json::{Map, Value};

use crate::jsonlogic::{EvalError, apply};
use crate::value::JsVal;

/// The result of partially evaluating logic.
#[derive(Debug, Clone)]
pub enum Partial {
    /// The logic takes this value for every completion of the data.
    Known(JsVal),
    /// The logic depends on unknown data; evaluate this residual once it is known.
    Residual(Value),
}

/// Evaluates `logic` against `known`, treating the variable paths in `unknown` (and
/// everything under them, as `a` covers `a.b`) as not yet known. An error is returned
/// only when the logic reads no unknown path and fails on the known data.
pub fn partial_apply(logic: &Value, known: &Value, unknown: &[&str]) -> Result<Partial, EvalError> {
    let eval = Evaluation { known, unknown };
    if !eval.reads_unknown(logic) {
        return apply(logic, known).map(Partial::Known);
    }
    Ok(eval.residual(logic))
}

struct Evaluation<'a> {
    known: &'a Value,
    unknown: &'a [&'a str],
}

fn operator(logic: &Value) -> Option<(&str, &Value)> {
    match logic {
        Value::Object(fields) if fields.len() == 1 => fields.iter().next().map(|(k, v)| (k.as_str(), v)),
        _ => None,
    }
}

/// An operator's operands: an array is the operand list, anything else one operand.
fn operands(raw: &Value) -> Vec<Value> {
    match raw {
        Value::Array(items) => items.clone(),
        other => vec![other.clone()],
    }
}

fn op(name: &str, args: Vec<Value>) -> Value {
    let mut fields = Map::new();
    fields.insert(name.to_owned(), Value::Array(args));
    Value::Object(fields)
}

/// The JSON literal that evaluates back to `value`, if there is one. Objects are
/// excluded (a one-key object is read as an operation); so are `undefined`, non-finite
/// numbers and `-0`, which JSON cannot carry.
fn literal(value: &JsVal) -> Option<Value> {
    match value {
        JsVal::Undefined | JsVal::Obj(_) => None,
        JsVal::Num(n) if !n.is_finite() || (*n == 0.0 && n.is_sign_negative()) => None,
        JsVal::Arr(items) => items.iter().map(literal).collect::<Option<Vec<_>>>().map(Value::Array),
        other => other.to_json(),
    }
}

impl Evaluation<'_> {
    fn path_unknown(&self, path: &Value) -> bool {
        let path = match path {
            Value::String(s) => s.clone(),
            Value::Number(n) => n.to_string(),
            // Null, "" and computed paths may read anything.
            _ => return true,
        };
        path.is_empty()
            || self
                .unknown
                .iter()
                .any(|u| path == *u || path.starts_with(&format!("{u}.")))
    }

    /// Whether evaluating `logic` may read an unknown path.
    fn reads_unknown(&self, logic: &Value) -> bool {
        if let Value::Array(items) = logic {
            return items.iter().any(|item| self.reads_unknown(item));
        }
        let Some((name, raw)) = operator(logic) else {
            return false;
        };
        let args = operands(raw);
        match name {
            "var" => {
                args.first().is_none_or(|path| self.path_unknown(path))
                    || args.iter().skip(1).any(|arg| self.reads_unknown(arg))
            }
            "missing" => {
                let keys = match args.first() {
                    Some(Value::Array(keys)) => keys.clone(),
                    _ => args,
                };
                keys.iter().any(|key| self.path_unknown(key))
            }
            "missing_some" => {
                self.reads_unknown(args.first().unwrap_or(&Value::Null))
                    || match args.get(1) {
                        Some(Value::Array(keys)) => keys.iter().any(|key| self.path_unknown(key)),
                        _ => true,
                    }
            }
            // Scoped logic reads the current item, not the data.
            "map" | "filter" | "all" | "none" | "some" => args.first().is_some_and(|a| self.reads_unknown(a)),
            "reduce" => {
                args.first().is_some_and(|a| self.reads_unknown(a))
                    || args.get(2).is_some_and(|a| self.reads_unknown(a))
            }
            _ => args.iter().any(|arg| self.reads_unknown(arg)),
        }
    }

    fn partial(&self, logic: &Value) -> Partial {
        if self.reads_unknown(logic) {
            return self.residual(logic);
        }
        match apply(logic, self.known) {
            Ok(value) => Partial::Known(value),
            // Kept as written: the failure belongs to whichever evaluation reaches it.
            Err(_) => Partial::Residual(logic.clone()),
        }
    }

    /// `logic` simplified where exact, as an expression.
    fn simplified(&self, logic: &Value) -> Value {
        match self.partial(logic) {
            Partial::Known(value) => literal(&value).unwrap_or_else(|| logic.clone()),
            Partial::Residual(residual) => residual,
        }
    }

    fn residual(&self, logic: &Value) -> Partial {
        if let Value::Array(items) = logic {
            return Partial::Residual(Value::Array(items.iter().map(|i| self.simplified(i)).collect()));
        }
        let Some((name, raw)) = operator(logic) else {
            return Partial::Known(JsVal::from_json(logic));
        };
        let args = operands(raw);
        match name {
            "and" | "or" => self.short_circuit(name, &args),
            "if" | "?:" => self.branches(name, &args),
            "var" | "missing" | "missing_some" => Partial::Residual(logic.clone()),
            "map" | "filter" | "all" | "none" | "some" | "reduce" => {
                let mut args = args;
                for index in [0, 2] {
                    if let Some(arg) = args.get(index).filter(|_| index == 0 || name == "reduce") {
                        args[index] = self.simplified(arg);
                    }
                }
                Partial::Residual(op(name, args))
            }
            _ => Partial::Residual(op(name, args.iter().map(|a| self.simplified(a)).collect())),
        }
    }

    fn short_circuit(&self, name: &str, args: &[Value]) -> Partial {
        let decides = name == "or";
        for (index, arg) in args.iter().enumerate() {
            match self.partial(arg) {
                Partial::Known(value) if value.truthy() == decides || index + 1 == args.len() => {
                    return Partial::Known(value);
                }
                Partial::Known(_) => {}
                Partial::Residual(first) => {
                    if index + 1 == args.len() {
                        return Partial::Residual(first);
                    }
                    let rest = args[index + 1..].iter().map(|a| self.simplified(a));
                    return Partial::Residual(op(name, std::iter::once(first).chain(rest).collect()));
                }
            }
        }
        // `and` / `or` of nothing.
        Partial::Known(JsVal::Undefined)
    }

    fn branches(&self, name: &str, args: &[Value]) -> Partial {
        let mut index = 0;
        while index + 1 < args.len() {
            match self.partial(&args[index]) {
                Partial::Known(value) if value.truthy() => return self.partial(&args[index + 1]),
                Partial::Known(_) => index += 2,
                Partial::Residual(condition) => {
                    let rest = args[index + 1..].iter().map(|a| self.simplified(a));
                    return Partial::Residual(op(name, std::iter::once(condition).chain(rest).collect()));
                }
            }
        }
        match args.get(index) {
            Some(otherwise) => self.partial(otherwise),
            None => Partial::Known(JsVal::Null),
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{Partial, partial_apply};
    use crate::JsVal;

    fn residual(logic: &serde_json::Value) -> serde_json::Value {
        let known = json!({"user": {"role": "support_agent"}, "intent": "support.refund"});
        match partial_apply(logic, &known, &["request"]).unwrap() {
            Partial::Residual(r) => r,
            Partial::Known(v) => panic!("expected a residual, got {v:?}"),
        }
    }

    #[test]
    fn known_operands_are_folded_and_short_circuited() {
        let amount = json!({">": [{"var": "request.context.refund_amount"}, 3000]});
        let logic = json!({"and": [{"==": [{"var": "user.role"}, "support_agent"]}, amount]});
        assert_eq!(residual(&logic), amount);

        let known = json!({"user": {"role": "manager"}});
        let decided = partial_apply(&logic, &known, &["request"]).unwrap();
        assert!(matches!(decided, Partial::Known(JsVal::Bool(false))));

        let or = json!({"or": [{"var": "request.x"}, {"var": "user.role"}]});
        assert_eq!(residual(&or), json!({"or": [{"var": "request.x"}, "support_agent"]}));
    }

    #[test]
    fn branches_drop_known_false_conditions() {
        let logic = json!({"if": [{"==": [{"var": "intent"}, "other"]}, 1, {"var": "request.a"}, 2, 3]});
        assert_eq!(residual(&logic), json!({"if": [{"var": "request.a"}, 2, 3]}));
        let taken = json!({"if": [{"var": "intent"}, {"var": "request.b"}, 3]});
        assert_eq!(residual(&taken), json!({"var": "request.b"}));
    }

    #[test]
    fn unreadable_paths_count_as_unknown() {
        for logic in [
            json!({"var": ""}),
            json!({"var": {"cat": ["us", "er"]}}),
            json!({"missing": ["request.a"]}),
        ] {
            assert_eq!(residual(&logic), logic);
        }
        let known = json!({"requests": 1});
        let read = partial_apply(&json!({"var": "requests"}), &known, &["request"]).unwrap();
        assert!(matches!(read, Partial::Known(JsVal::Num(n)) if n == 1.0));
    }

    #[test]
    fn a_known_failure_is_an_error() {
        let logic = json!({"nope": [1]});
        assert!(partial_apply(&logic, &json!({}), &["request"]).is_err());
    }
}
