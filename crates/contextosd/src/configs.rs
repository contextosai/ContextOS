//! Configuration review: the running configuration and dry-run validation of a
//! proposed one (`config` scope).
//!
//! The server never rewrites its own configuration: the file is code, reviewed and
//! deployed like code. What the server adds is the review input a pull request lacks:
//! a proposed file is checked by the same parser and checks the server starts with,
//! and diffed against the running configuration with every effective change classified
//! as tightening, loosening or neutral, so CI can require approval of any loosening.
//!
//! The file holds no secrets by design (keys are hashes, credentials are environment
//! variable names), so holders of `config` see it whole. `config` is a
//! deployment-administration scope: grant it only to the deployment's operators.

use std::collections::BTreeMap;

use contextos_contract::canonical::sha256_text;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::config::{Config, Mode};

/// Largest configuration text accepted for validation or proposal.
pub const MAX_TEXT_BYTES: usize = 256 * 1024;

/// The configuration this replica runs.
#[derive(Debug, Clone)]
pub struct Running {
    pub source: String,
    pub digest: String,
    pub effective: Value,
    pub findings: Vec<Finding>,
}

impl Running {
    pub fn of(config: &Config) -> Self {
        Self {
            source: config.source.clone(),
            digest: digest(&config.source),
            effective: effective(config),
            findings: findings(config),
        }
    }
}

/// `sha256:<hex>` of the exact configuration text.
pub fn digest(text: &str) -> String {
    sha256_text(text)
}

/// The configuration with every default and mode-dependent value resolved.
pub fn effective(config: &Config) -> Value {
    let mut value = serde_json::to_value(config).unwrap_or(Value::Null);
    let guards = &mut value["guards"];
    guards["required_release_refs"] = json!(config.required_release_refs());
    guards["require_user_role"] = json!(config.require_user_role());
    guards["completion_requires_scores"] = config.completion_score_floors().map_or(
        json!(false),
        |f| json!({"policy_floor": f.policy_floor, "safety_floor": f.safety_floor}),
    );
    guards["trust_supplied_memory"] =
        json!(config.server.mode == Mode::Development || config.guards.trust_supplied_memory);
    value
}

/// A posture observation about a configuration.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Finding {
    pub severity: &'static str,
    pub message: String,
}

fn finding(severity: &'static str, message: impl Into<String>) -> Finding {
    Finding {
        severity,
        message: message.into(),
    }
}

/// Settings that weaken a production deployment, by the production checklist.
pub fn findings(config: &Config) -> Vec<Finding> {
    let mut out = Vec::new();
    if config.server.mode == Mode::Development {
        out.push(finding(
            "warning",
            "development mode: loopback HTTP, trusted supplied memory and relaxed guards; never use with real tenants",
        ));
        return out;
    }
    if matches!(config.store, crate::config::StoreConfig::Memory) {
        out.push(finding(
            "critical",
            "in-memory store: state and audit are lost on restart",
        ));
    }
    if config.audit.kms.is_none() {
        out.push(finding(
            "warning",
            "the audit signing key is held in the process; sign with [audit.kms]",
        ));
    }
    if config.completion_score_floors().is_none() {
        out.push(finding(
            "warning",
            "completion_requires_scores is off: runs complete without independent scores",
        ));
    }
    if config.required_release_refs().is_empty() {
        out.push(finding(
            "warning",
            "required_release_refs = []: decisions do not record their model and evaluators",
        ));
    }
    if !config.require_user_role() {
        out.push(finding("warning", "require_user_role is off"));
    }
    if !config.guards.require_tool_schemas {
        out.push(finding(
            "notice",
            "require_tool_schemas is off: some tool results may not be shape-checked",
        ));
    }
    if !config.guards.require_task_authorization {
        out.push(finding(
            "notice",
            "require_task_authorization is off: effects are bounded by broker grants, not by what the principal asked",
        ));
    }
    if config.guards.trust_supplied_memory {
        out.push(finding(
            "warning",
            "trust_supplied_memory admits recalled memory nothing verified",
        ));
    }
    if !config.guards.refuse_repeated_effects {
        out.push(finding("warning", "the repeated-effect guard is off"));
    }
    if config.guards.identical_tool_calls == 0 {
        out.push(finding("warning", "the loop guard is off"));
    }
    if let Some(p) = &config.providers {
        if p.data_flow.is_none() {
            out.push(finding(
                "notice",
                "no data-flow provider: data permissions are not checked per effect",
            ));
        }
        if p.boundary.is_none() {
            out.push(finding("notice", "no execution-boundary controller"));
        }
    }
    if config.retention.run_content_days.is_none() {
        out.push(finding(
            "notice",
            "no retention: personal content is kept until an operator erases it",
        ));
    }
    out
}

/// One difference between two effective configurations.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct Change {
    pub path: String,
    pub from: Value,
    pub to: Value,
    /// `tightens`, `loosens` or `changes`.
    pub effect: &'static str,
    pub note: Option<&'static str>,
}

/// Identity of an element in a keyed array, so a reordered list is not a change.
fn element_key(path: &str, item: &Value) -> Option<String> {
    let field = match path {
        "api_keys" => {
            return Some(format!(
                "{}/{}",
                item["tenant_id"].as_str()?,
                item["principal_id"].as_str()?
            ));
        }
        "adapters" => "id",
        "guarantees" => "id",
        "oidc" => "issuer",
        "limits.tenants" => "tenant_id",
        "result_schemas" => "ref",
        "audit.retired_keys" => "kid",
        _ if path.starts_with("conformance.") => "principal_id",
        _ => return None,
    };
    item[field].as_str().map(str::to_owned)
}

/// Differences from `base` to `next`, leaf by leaf; keyed arrays element by element,
/// other arrays as sets.
pub fn diff(base: &Value, next: &Value) -> Vec<Change> {
    let mut out = Vec::new();
    walk("", base, next, &mut out);
    out
}

fn join(path: &str, key: &str) -> String {
    if path.is_empty() {
        key.to_owned()
    } else {
        format!("{path}.{key}")
    }
}

fn push(out: &mut Vec<Change>, path: String, from: &Value, to: &Value) {
    let (effect, note) = classify(&path, from, to);
    out.push(Change {
        path,
        from: from.clone(),
        to: to.clone(),
        effect,
        note,
    });
}

fn walk(path: &str, base: &Value, next: &Value, out: &mut Vec<Change>) {
    if base == next {
        return;
    }
    match (base, next) {
        (Value::Object(a), Value::Object(b)) => {
            let keys: std::collections::BTreeSet<&String> = a.keys().chain(b.keys()).collect();
            for key in keys {
                walk(
                    &join(path, key),
                    a.get(key).unwrap_or(&Value::Null),
                    b.get(key).unwrap_or(&Value::Null),
                    out,
                );
            }
        }
        (Value::Array(a), Value::Array(b)) => {
            let keyed = |items: &Vec<Value>| -> Option<BTreeMap<String, Value>> {
                items.iter().map(|i| Some((element_key(path, i)?, i.clone()))).collect()
            };
            if let (Some(ka), Some(kb)) = (keyed(a), keyed(b)) {
                let keys: std::collections::BTreeSet<&String> = ka.keys().chain(kb.keys()).collect();
                for key in keys {
                    walk(
                        &format!("{path}[{key}]"),
                        ka.get(key).unwrap_or(&Value::Null),
                        kb.get(key).unwrap_or(&Value::Null),
                        out,
                    );
                }
            } else {
                let added: Vec<Value> = b.iter().filter(|v| !a.contains(v)).cloned().collect();
                let removed: Vec<Value> = a.iter().filter(|v| !b.contains(v)).cloned().collect();
                if !added.is_empty() || !removed.is_empty() {
                    push(out, path.to_owned(), &json!(removed), &json!(added));
                }
            }
        }
        _ => push(out, path.to_owned(), base, next),
    }
}

fn number(v: &Value) -> Option<f64> {
    v.as_f64()
}

/// Whether a change weakens the deployment's governance or security (`loosens`),
/// strengthens it (`tightens`), or is neither by itself (`changes`). Arrays compared
/// as sets report removed items as `from` and added items as `to`.
fn classify(path: &str, from: &Value, to: &Value) -> (&'static str, Option<&'static str>) {
    let added = !to.is_null() && to.as_array().is_none_or(|a| !a.is_empty());
    let removed = !from.is_null() && from.as_array().is_none_or(|a| !a.is_empty());
    let more = || match (number(from), number(to)) {
        (Some(a), Some(b)) => Some(b > a),
        _ => None,
    };
    let flag = |loosen_when: bool| {
        if to.as_bool() == Some(loosen_when) {
            "loosens"
        } else {
            "tightens"
        }
    };
    let leaf = path.rsplit('.').next().unwrap_or(path);
    if path.starts_with("guarantees[") {
        let note = Some("shared exposure is durable; binding changes require an accounted migration");
        return if leaf == "limit" {
            (if more() == Some(false) { "tightens" } else { "loosens" }, note)
        } else if from.is_null() {
            ("tightens", note)
        } else {
            ("loosens", note)
        };
    }
    match path {
        "server.mode" => (
            if to == "development" { "loosens" } else { "tightens" },
            Some("development mode relaxes guards and allows loopback HTTP"),
        ),
        "guards.refuse_repeated_effects"
        | "guards.require_user_role"
        | "guards.require_tool_schemas"
        | "guards.require_task_authorization" => (flag(false), None),
        "guards.trust_supplied_memory" => (flag(true), Some("unverified recalled memory would be admitted")),
        "guards.identical_tool_calls" => match (from.as_u64(), to.as_u64()) {
            (_, Some(0)) => ("loosens", Some("disables the loop guard")),
            (Some(0), _) => ("tightens", None),
            _ => (if more() == Some(true) { "loosens" } else { "tightens" }, None),
        },
        "guards.model_call_min_tokens" => (if more() == Some(false) { "loosens" } else { "tightens" }, None),
        "guards.required_release_refs" => (
            if removed { "loosens" } else { "tightens" },
            Some("decisions record which model and evaluators produced them"),
        ),
        "guards.completion_requires_scores"
        | "guards.completion_requires_scores.policy_floor"
        | "guards.completion_requires_scores.safety_floor" => {
            if to == &json!(false) || to.is_null() || more() == Some(false) {
                (
                    "loosens",
                    Some("runs may complete with weaker or no independent scores"),
                )
            } else {
                ("tightens", None)
            }
        }
        "server.max_body_bytes" | "server.request_timeout_ms" => {
            (if more() == Some(true) { "loosens" } else { "tightens" }, None)
        }
        "retention.run_content_days" => {
            if to.is_null() || more() == Some(true) {
                ("loosens", Some("personal content is kept longer"))
            } else {
                ("tightens", None)
            }
        }
        "audit.kms" => (
            if to.is_null() { "loosens" } else { "tightens" },
            Some("where the audit signing key is held"),
        ),
        "audit.key_id" => (
            "changes",
            Some("a new signing key: list the old one in [[audit.retired_keys]]"),
        ),
        "store" | "store.kind" => ("changes", Some("a different store does not carry state or audit over")),
        _ if path.starts_with("api_keys") => {
            if leaf == "scopes" {
                (
                    if added { "loosens" } else { "tightens" },
                    Some("scopes granted to a principal"),
                )
            } else if from.is_null() {
                ("loosens", Some("a new credential"))
            } else if to.is_null() {
                ("tightens", Some("a credential removed"))
            } else {
                ("changes", Some("a credential replaced"))
            }
        }
        _ if path.starts_with("oidc") => {
            if from.is_null() || (leaf == "tenants" && added) {
                ("loosens", Some("an issuer may assert identities for more tenants"))
            } else if to.is_null() {
                ("tightens", None)
            } else {
                ("changes", None)
            }
        }
        _ if path.starts_with("conformance.") => (
            if from.is_null() { "loosens" } else { "changes" },
            Some("whose conformance reports and evidence this deployment trusts"),
        ),
        _ if path.starts_with("providers.") => {
            if to.is_null() && !from.is_null() {
                ("loosens", Some("a fact or governance service is no longer consulted"))
            } else if from.is_null() {
                ("tightens", None)
            } else {
                (
                    "changes",
                    Some("a fact service endpoint changed: review where decisions come from"),
                )
            }
        }
        _ if path.starts_with("adapters") => {
            if from.is_null() {
                ("loosens", Some("a new effect surface"))
            } else if to.is_null() {
                ("tightens", None)
            } else {
                ("changes", Some("an adapter changed: review where effects are sent"))
            }
        }
        "capabilities" | "packs" => (
            if added { "loosens" } else { "tightens" },
            Some("capabilities and packs pinned at startup"),
        ),
        _ if path.starts_with("limits") => match more() {
            Some(true) => ("loosens", Some("higher limits admit more load")),
            Some(false) => ("tightens", None),
            None => ("changes", None),
        },
        _ => ("changes", None),
    }
}

/// The result of validating a proposed configuration against the running one.
pub fn review(running: &Running, text: &str) -> Value {
    if text.len() > MAX_TEXT_BYTES {
        return json!({"valid": false, "errors": [format!("the configuration exceeds {MAX_TEXT_BYTES} bytes")]});
    }
    match Config::parse(text) {
        Err(e) => json!({"valid": false, "errors": [e.to_string()], "digest": digest(text)}),
        Ok(config) => {
            let effective = effective(&config);
            let changes = diff(&running.effective, &effective);
            let loosening: Vec<&str> = changes
                .iter()
                .filter(|c| c.effect == "loosens")
                .map(|c| c.path.as_str())
                .collect();
            json!({
                "valid": true,
                "errors": [],
                "digest": digest(text),
                "base_digest": running.digest,
                "identical": digest(text) == running.digest,
                "effective": effective,
                "changes": changes,
                "loosening": loosening,
                "findings": findings(&config),
                "notes": ["Files the configuration names (packs, capabilities, result schemas) and environment variables are checked when a server starts with it."],
            })
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidateBody {
    pub toml: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(extra: &str) -> Config {
        Config::parse(&format!(
            r#"
            [server]
            listen = "127.0.0.1:0"
            [store]
            kind = "memory"
            [audit]
            signing_seed_env = "SEED"
            key_id = "k"
            [support]
            implementation_id = "contextos-rs"
            implementation_version = "0.1.0"
            profiles = ["contextos.core"]
            controls = []
            {extra}
            "#
        ))
        .unwrap()
    }

    fn changes(base: &str, next: &str) -> Vec<Change> {
        diff(&effective(&config(base)), &effective(&config(next)))
    }

    #[test]
    fn identical_configurations_have_no_changes() {
        assert!(changes("", "").is_empty());
        // Spelling out a default is not a change of the effective configuration.
        assert!(changes("", "[guards]\nrefuse_repeated_effects = true").is_empty());
    }

    #[test]
    fn shared_guarantee_changes_surface_weakened_or_changed_protection() {
        let rule = "[[guarantees]]\nid='refunds'\ncapability_ids=['payments.refund']\nresource_pointer='/order'\namount_pointer='/amount'\nlimit=100\nunit='USD_minor'";
        assert!(changes(rule, "").iter().any(|c| c.effect == "loosens"));
        assert!(
            changes(rule, &rule.replace("limit=100", "limit=200"))
                .iter()
                .any(|c| c.effect == "loosens")
        );
        assert!(
            changes(rule, &rule.replace("/order", "/customer"))
                .iter()
                .any(|c| c.effect == "loosens")
        );
        assert!(
            changes(rule, &rule.replace("limit=100", "limit=50"))
                .iter()
                .any(|c| c.effect == "tightens")
        );
    }

    #[test]
    fn weakening_guards_loosens_and_strengthening_tightens() {
        let off = changes(
            "",
            "[guards]\nrefuse_repeated_effects = false\nidentical_tool_calls = 0\ntrust_supplied_memory = true",
        );
        let effects: Vec<(&str, &str)> = off.iter().map(|c| (c.path.as_str(), c.effect)).collect();
        assert!(effects.contains(&("guards.refuse_repeated_effects", "loosens")));
        assert!(effects.contains(&("guards.identical_tool_calls", "loosens")));
        assert!(effects.contains(&("guards.trust_supplied_memory", "loosens")));
        let on = changes(
            "",
            "[guards]\nrequire_tool_schemas = true\nidentical_tool_calls = 3\nrequire_task_authorization = true",
        );
        assert_eq!(on.len(), 3, "{on:?}");
        assert!(on.iter().all(|c| c.effect == "tightens"), "{on:?}");
        let scores = changes("", "[guards]\ncompletion_requires_scores = false");
        assert_eq!(scores[0].path, "guards.completion_requires_scores");
        assert_eq!(scores[0].effect, "loosens");
    }

    #[test]
    fn credentials_and_scopes_are_compared_by_principal() {
        let key = |scopes: &str| {
            format!(
                "[[api_keys]]\nkey_sha256 = \"sha256:{}\"\ntenant_id = \"t\"\nprincipal_id = \"ops\"\nscopes = [{scopes}]",
                "a".repeat(64)
            )
        };
        let added = changes("", &key("\"control\""));
        assert_eq!(added.len(), 1);
        assert_eq!(
            (added[0].path.as_str(), added[0].effect),
            ("api_keys[t/ops]", "loosens")
        );
        let widened = changes(&key("\"control\""), &key("\"control\", \"config\""));
        assert_eq!(
            (widened[0].path.as_str(), widened[0].effect),
            ("api_keys[t/ops].scopes", "loosens")
        );
        assert_eq!(widened[0].to, json!(["config"]));
        let narrowed = changes(&key("\"control\", \"config\""), &key("\"control\""));
        assert_eq!(narrowed[0].effect, "tightens");
    }

    #[test]
    fn the_review_names_loosenings_and_invalid_text() {
        let running = Running::of(&config(""));
        let bad = review(&running, "[server]\nlisten = 1");
        assert_eq!(bad["valid"], false);
        let text = config("[retention]\nrun_content_days = 30").source;
        let good = review(&running, &text);
        assert_eq!(good["valid"], true);
        assert_eq!(good["changes"][0]["effect"], "tightens");
        assert_eq!(good["identical"], false);
        assert_eq!(review(&running, &running.source)["identical"], true);
        let dev = review(
            &running,
            &config("")
                .source
                .replace("[server]", "[server]\nmode = \"development\""),
        );
        assert!(dev["loosening"].as_array().unwrap().contains(&json!("server.mode")));
    }

    #[test]
    fn production_refuses_the_published_administrator_keys() {
        for raw in [
            "dev-admin-0123456789abcdef0123456789abcd",
            "dev-review-0123456789abcdef0123456789abc",
        ] {
            let error = Config::parse(&config("").source.replace(
                "controls = []",
                &format!(
                    "controls = []\n[[api_keys]]\nkey_sha256 = \"{}\"\ntenant_id = \"t\"\nprincipal_id = \"p\"\nscopes = [\"config\"]",
                    crate::auth::hash_api_key(raw)
                ),
            ))
            .unwrap_err();
            assert!(error.to_string().contains("published example key"), "{error}");
        }
    }

    #[test]
    fn config_holders_do_not_run_agents() {
        let error = Config::parse(&config("").source.replace(
            "controls = []",
            &format!(
                "controls = []\n[[api_keys]]\nkey_sha256 = \"sha256:{}\"\ntenant_id = \"t\"\nprincipal_id = \"p\"\nscopes = [\"config\", \"dispatch\"]",
                "b".repeat(64)
            ),
        ))
        .unwrap_err();
        assert!(error.to_string().contains("cannot both hold config"), "{error}");
    }
}
