//! A residual is exact: for any completion of the known data it evaluates to what the
//! original logic does, including failures.

use contextos_policy::{Partial, apply, partial_apply};
use proptest::prelude::*;
use serde_json::{Value, json};

fn leaf() -> impl Strategy<Value = Value> {
    prop_oneof![
        Just(json!({"var": "request.a"})),
        Just(json!({"var": "request.b"})),
        Just(json!({"var": ["request.c", 7]})),
        Just(json!({"var": "user.r"})),
        Just(json!({"var": "user.n"})),
        Just(json!({"var": "user"})),
        Just(json!({"missing": ["request.a", "user.r"]})),
        (-3i64..4).prop_map(Value::from),
        any::<bool>().prop_map(Value::from),
        prop_oneof![Just("x"), Just(""), Just("y")].prop_map(Value::from),
        Just(Value::Null),
        Just(json!([])),
    ]
}

fn logic() -> impl Strategy<Value = Value> {
    leaf().prop_recursive(4, 48, 3, |inner| {
        let ops = prop_oneof![
            Just("=="),
            Just("==="),
            Just("!="),
            Just(">"),
            Just("<"),
            Just("and"),
            Just("or"),
            Just("!"),
            Just("!!"),
            Just("if"),
            Just("in"),
            Just("+"),
            Just("cat"),
            Just("max"),
            Just("merge"),
            Just("some"),
            Just("map"),
        ];
        (ops, prop::collection::vec(inner, 0..4)).prop_map(|(op, args)| json!({ op: args }))
    })
}

fn scalar() -> impl Strategy<Value = Value> {
    prop_oneof![
        (-3i64..4).prop_map(Value::from),
        any::<bool>().prop_map(Value::from),
        prop_oneof![Just("x"), Just(""), Just("y")].prop_map(Value::from),
        Just(Value::Null),
        Just(json!([1, "x"])),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4096))]

    #[test]
    fn residual_agrees_with_the_original(
        logic in logic(),
        r in scalar(), n in scalar(),
        a in scalar(), b in scalar(), c in prop::option::of(scalar()),
    ) {
        let known = json!({"user": {"r": r, "n": n}});
        let mut full = known.clone();
        let mut request = json!({"a": a, "b": b});
        if let Some(c) = c {
            request["c"] = c;
        }
        full["request"] = request;
        let expected = format!("{:?}", apply(&logic, &full));
        let actual = match partial_apply(&logic, &known, &["request"]) {
            Ok(Partial::Known(value)) => format!("{:?}", Ok::<_, ()>(value)),
            Ok(Partial::Residual(residual)) => format!("{:?}", apply(&residual, &full)),
            Err(e) => format!("{:?}", Err::<(), _>(e)),
        };
        prop_assert_eq!(expected, actual, "logic {} residual {:?}", logic, partial_apply(&logic, &known, &["request"]));
    }
}
