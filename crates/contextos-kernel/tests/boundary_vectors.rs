//! Parity with the reference execution-boundary, data-flow and memory-lifecycle
//! validators, Node `path` normalization and WHATWG origin checks.

use contextos_contract::canonical::canonicalize;
use contextos_kernel::execution_boundary::{
    evaluate_boundary_readiness, evaluate_data_flow, network_origin_valid, validate_memory_lifecycle,
};
use contextos_kernel::pathspec::{posix_is_absolute, posix_normalize, win32_is_absolute, win32_normalize};
use serde::Serialize;
use serde_json::Value;

mod common;

fn check<T: Serialize>(group: &str, cases: &Value, run: impl Fn(&Value) -> T) -> usize {
    let mut checked = 0;
    for case in cases.as_array().unwrap() {
        if case["expected"].get("throws").is_some() {
            continue;
        }
        let actual = serde_json::to_value(run(&case["input"])).unwrap();
        assert_eq!(
            canonicalize(&actual).unwrap(),
            canonicalize(&case["expected"]).unwrap(),
            "{group} {}",
            case["name"]
        );
        checked += 1;
    }
    checked
}

#[test]
fn node_path_semantics_match() {
    let vectors = common::load("boundary.json.gz");
    for case in vectors["paths"].as_array().unwrap() {
        let p = case["p"].as_str().unwrap();
        assert_eq!(posix_is_absolute(p), case["posix_abs"], "posix abs {p:?}");
        assert_eq!(
            posix_normalize(p),
            case["posix_norm"].as_str().unwrap(),
            "posix norm {p:?}"
        );
        assert_eq!(win32_is_absolute(p), case["win_abs"], "win abs {p:?}");
        assert_eq!(win32_normalize(p), case["win_norm"].as_str().unwrap(), "win norm {p:?}");
    }
}

#[test]
fn origin_checks_match() {
    let vectors = common::load("boundary.json.gz");
    for case in vectors["origins"].as_array().unwrap() {
        let origin = case["origin"].as_str().unwrap();
        assert_eq!(network_origin_valid(origin), case["valid"], "{origin:?}");
    }
}

#[test]
fn boundary_dataflow_memory_match_reference() {
    let vectors = common::load("boundary.json.gz");
    let mut total = 0;
    total += check("boundary", &vectors["boundary"], |i| {
        evaluate_boundary_readiness(
            &i["requirement"],
            i.get("observation").unwrap_or(&Value::Null),
            &i["evaluation_time"],
        )
    });
    total += check("dataflow", &vectors["dataflow"], |i| {
        evaluate_data_flow(&i["request"], &i["policy"], &i["evaluation_time"])
    });
    total += check("memory", &vectors["memory"], |i| {
        validate_memory_lifecycle(&i["record"], &i["context"], &i["evaluation_time"])
    });
    assert!(total > 1_600, "{total}");
}
