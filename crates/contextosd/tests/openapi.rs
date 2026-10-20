//! The published OpenAPI document describes exactly the routes the server serves, and
//! every schema it references resolves.

use std::collections::BTreeSet;

use serde_json::Value;

fn root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn document() -> Value {
    serde_json::from_str(contextosd::app::OPENAPI).unwrap()
}

/// `(method, path)` for every route registered in the router.
fn served() -> BTreeSet<(String, String)> {
    let source = std::fs::read_to_string(root().join("crates/contextosd/src/app.rs")).unwrap();
    let compact: String = source.split_whitespace().collect();
    let mut routes = BTreeSet::new();
    for chunk in compact.split(".route(\"").skip(1) {
        let (path, rest) = chunk.split_once('"').unwrap();
        let method = rest.trim_start_matches(',').split('(').next().unwrap().to_owned();
        if path == "/v1/runs/{run_id}/{action}" {
            for action in ["complete", "fail", "cancel"] {
                routes.insert((method.clone(), format!("/v1/runs/{{run_id}}/{action}")));
            }
        } else {
            routes.insert((method, path.to_owned()));
        }
    }
    routes
}

#[test]
fn every_route_is_documented_and_nothing_else() {
    let doc = document();
    let documented: BTreeSet<(String, String)> = doc["paths"]
        .as_object()
        .unwrap()
        .iter()
        .flat_map(|(path, item)| item.as_object().unwrap().keys().map(move |m| (m.clone(), path.clone())))
        .collect();
    assert_eq!(documented, served());
}

fn refs<'a>(value: &'a Value, out: &mut Vec<&'a str>) {
    match value {
        Value::Object(map) => {
            if let Some(Value::String(r)) = map.get("$ref") {
                out.push(r);
            }
            map.values().for_each(|v| refs(v, out));
        }
        Value::Array(items) => items.iter().for_each(|v| refs(v, out)),
        _ => {}
    }
}

#[test]
fn every_reference_resolves() {
    let doc = document();
    let mut found = Vec::new();
    refs(&doc, &mut found);
    assert!(!found.is_empty());
    for r in found {
        let (base, fragment) = r.split_once('#').unwrap_or((r, ""));
        let target = if base.is_empty() {
            doc.clone()
        } else {
            let name = base
                .strip_prefix("https://contextosai.com/schemas/")
                .unwrap_or_else(|| panic!("{r}"));
            let schema: Value =
                serde_json::from_str(&std::fs::read_to_string(root().join("schemas").join(name)).unwrap()).unwrap();
            assert_eq!(schema["$id"], base, "{r}");
            schema
        };
        assert!(
            fragment.is_empty() || target.pointer(fragment).is_some(),
            "unresolved {r}"
        );
    }
}

#[test]
fn operations_are_identified_and_scoped() {
    let doc = document();
    let mut ids = BTreeSet::new();
    for (path, item) in doc["paths"].as_object().unwrap() {
        for (method, op) in item.as_object().unwrap() {
            let id = op["operationId"].as_str().unwrap_or_else(|| panic!("{method} {path}"));
            assert!(ids.insert(id.to_owned()), "duplicate operationId {id}");
            if path.starts_with("/v1/") && path != "/v1/openapi.json" {
                assert!(op["x-contextos-scope"].is_string(), "{method} {path} has no scope");
            }
        }
    }
}
