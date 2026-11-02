//! Reading identity claims from verified JWT payloads.
//!
//! Identity providers nest the claims ContextOS needs: Keycloak puts realm roles in
//! `realm_access.roles`, the acting client of a delegated token in `act.client_id`,
//! and organizations in `organization` as a string, a list of aliases or a map keyed
//! by alias. A claim is therefore named by a path:
//!
//! - a name the payload holds as a key, including namespaced names such as
//!   `https://example.com/tenant`, is that claim;
//! - otherwise `a.b.c` walks nested objects;
//! - `/a/b` is a JSON Pointer (RFC 6901), for keys that contain dots.

use serde_json::Value;

/// Resolves a claim path in a JWT payload.
#[must_use]
pub fn resolve<'a>(claims: &'a Value, path: &str) -> Option<&'a Value> {
    if path.starts_with('/') {
        return claims.pointer(path);
    }
    if let Some(value) = claims.get(path) {
        return Some(value);
    }
    if !path.contains('.') {
        return None;
    }
    path.split('.').try_fold(claims, |value, key| value.get(key))
}

/// The string values a claim carries: a string, the strings of an array, or the keys
/// of an object (Keycloak's `organization` map). Empty strings are dropped.
#[must_use]
pub fn strings(value: Option<&Value>) -> Vec<&str> {
    let values: Vec<&str> = match value {
        Some(Value::String(s)) => vec![s.as_str()],
        Some(Value::Array(items)) => items.iter().filter_map(Value::as_str).collect(),
        Some(Value::Object(map)) => map.keys().map(String::as_str).collect(),
        _ => Vec::new(),
    };
    values.into_iter().filter(|s| !s.is_empty()).collect()
}

/// A path is usable: non-empty, a JSON Pointer or dot path without empty segments.
#[must_use]
pub fn valid_path(path: &str) -> bool {
    if let Some(pointer) = path.strip_prefix('/') {
        return !pointer.is_empty();
    }
    !path.is_empty() && !path.starts_with('.') && !path.ends_with('.') && !path.contains("..")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn paths_name_flat_namespaced_nested_and_pointer_claims() {
        let claims = json!({
            "sub": "u1",
            "https://example.com/tenant": "acme",
            "realm_access": {"roles": ["support_manager", "offline_access"]},
            "resource_access": {"api.v2": {"roles": ["admit"]}},
            "act": {"sub": "sa-1", "client_id": "support-agent"},
        });
        assert_eq!(resolve(&claims, "sub"), Some(&json!("u1")));
        assert_eq!(resolve(&claims, "https://example.com/tenant"), Some(&json!("acme")));
        assert_eq!(resolve(&claims, "act.client_id"), Some(&json!("support-agent")));
        assert_eq!(
            strings(resolve(&claims, "realm_access.roles")),
            ["support_manager", "offline_access"]
        );
        assert_eq!(strings(resolve(&claims, "/resource_access/api.v2/roles")), ["admit"]);
        assert_eq!(
            resolve(&claims, "resource_access.api.v2.roles"),
            None,
            "dots in keys need a pointer"
        );
        assert_eq!(resolve(&claims, "missing"), None);
        assert_eq!(resolve(&claims, "act.missing"), None);
    }

    #[test]
    fn organization_claims_read_as_aliases_in_every_shape() {
        assert_eq!(strings(Some(&json!("acme"))), ["acme"]);
        assert_eq!(strings(Some(&json!(["acme", "", 3, "globex"]))), ["acme", "globex"]);
        assert_eq!(strings(Some(&json!({"acme": {"id": "42"}}))), ["acme"]);
        assert_eq!(strings(Some(&json!(7))), Vec::<&str>::new());
        assert_eq!(strings(None), Vec::<&str>::new());
    }

    #[test]
    fn paths_must_have_segments() {
        for good in [
            "sub",
            "act.client_id",
            "/resource_access/api.v2/roles",
            "https://x.example/t",
        ] {
            assert!(valid_path(good), "{good}");
        }
        for bad in ["", "/", ".a", "a.", "a..b"] {
            assert!(!valid_path(bad), "{bad}");
        }
    }
}
