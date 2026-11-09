//! Environment guard: a gateway serves one environment, and refuses effects aimed at
//! another.
//!
//! Agents reach production through credentials they were never meant to use: a
//! staging task finds a production token, and one API call deletes a production
//! volume and its backups. Scoping credentials is the first defence; this is the
//! second, at the tool boundary. `[guards.environments]` names the environment this
//! gateway serves (`current`) and, per capability, how to tell a call's target
//! environment: a fixed `environment` (a capability bound to a production adapter), or
//! a `pointer` into the arguments whose string value is matched against `prefixes`
//! (`"prod-" = "production"`). A call whose target is another environment is refused
//! (`environment_mismatch`); a call whose target cannot be told is refused too
//! (`environment_unresolved`) unless the rule says `unmatched = "allow"`. In `observe`
//! mode both are audited and the call proceeds, to measure before enforcing.
//!
//! ```toml
//! [guards.environments]
//! current = "staging"
//! [[guards.environments.targets]]
//! capabilities = ["adp_infra.delete_volume", "adp_infra.replace_stack"]
//! pointer = "/volume_id"
//! prefixes = { "prod-" = "production", "stg-" = "staging" }
//! ```

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// At most this many target rules.
pub const MAX_RULES: usize = 64;

/// Whether a mismatch refuses the call or is only audited.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EnvironmentMode {
    #[default]
    Required,
    Observe,
}

/// What a pointer value that matches no prefix means.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Unmatched {
    /// Refused: the target environment cannot be told (fails closed).
    #[default]
    Refuse,
    /// Allowed: values outside the prefixes are not environment-scoped.
    Allow,
}

/// How to tell the target environment of some capabilities' calls.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TargetRule {
    pub capabilities: Vec<String>,
    /// Every call of these capabilities targets this environment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment: Option<String>,
    /// A JSON Pointer into the arguments whose string value names the target.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pointer: Option<String>,
    /// Value prefix to environment; the longest matching prefix wins.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub prefixes: BTreeMap<String, String>,
    #[serde(default)]
    pub unmatched: Unmatched,
}

/// `[guards.environments]`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentPolicy {
    /// The environment this gateway serves.
    pub current: String,
    #[serde(default)]
    pub mode: EnvironmentMode,
    #[serde(default)]
    pub targets: Vec<TargetRule>,
}

/// Why a call's target is not this gateway's environment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mismatch {
    /// `environment_mismatch` or `environment_unresolved`.
    pub reason: &'static str,
    /// The target's environment, when it could be told.
    pub target: Option<String>,
}

impl EnvironmentPolicy {
    /// Checks the policy is well formed.
    ///
    /// # Errors
    /// A message naming what is wrong.
    pub fn validate(&self) -> Result<(), String> {
        if self.current.trim().is_empty() {
            return Err("[guards.environments] current must name an environment".into());
        }
        if self.targets.len() > MAX_RULES {
            return Err(format!("[guards.environments] allows at most {MAX_RULES} target rules"));
        }
        let mut seen = BTreeSet::new();
        for (i, rule) in self.targets.iter().enumerate() {
            let at = format!("[guards.environments] targets[{i}]");
            if rule.capabilities.is_empty() {
                return Err(format!("{at} must list capabilities"));
            }
            if let Some(id) = rule.capabilities.iter().find(|c| !seen.insert(c.as_str())) {
                return Err(format!("{at}: capability {id} is in more than one rule"));
            }
            match (&rule.environment, &rule.pointer) {
                (Some(env), None) if !env.trim().is_empty() && rule.prefixes.is_empty() => {}
                (None, Some(pointer)) if pointer.starts_with('/') && !rule.prefixes.is_empty() => {
                    if rule
                        .prefixes
                        .iter()
                        .any(|(p, env)| p.is_empty() || env.trim().is_empty())
                    {
                        return Err(format!("{at}: prefixes and their environments must not be empty"));
                    }
                }
                _ => {
                    return Err(format!(
                        "{at} needs either environment, or a JSON Pointer with prefixes"
                    ));
                }
            }
        }
        Ok(())
    }

    /// Whether a mismatch refuses the call.
    #[must_use]
    pub fn enforced(&self) -> bool {
        self.mode == EnvironmentMode::Required
    }

    /// The call's mismatch with this gateway's environment, if any. Capabilities no
    /// rule names are not environment-scoped.
    #[must_use]
    pub fn check(&self, capability_id: &str, arguments: &Value) -> Option<Mismatch> {
        let rule = self
            .targets
            .iter()
            .find(|r| r.capabilities.iter().any(|c| c == capability_id))?;
        let target = match (&rule.environment, &rule.pointer) {
            (Some(env), _) => Some(env.clone()),
            (None, Some(pointer)) => arguments.pointer(pointer).and_then(Value::as_str).and_then(|value| {
                rule.prefixes
                    .iter()
                    .filter(|(prefix, _)| value.starts_with(prefix.as_str()))
                    .max_by_key(|(prefix, _)| prefix.len())
                    .map(|(_, env)| env.clone())
            }),
            (None, None) => None,
        };
        match target {
            Some(env) if env == self.current => None,
            Some(env) => Some(Mismatch {
                reason: "environment_mismatch",
                target: Some(env),
            }),
            None if rule.unmatched == Unmatched::Allow => None,
            None => Some(Mismatch {
                reason: "environment_unresolved",
                target: None,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn policy() -> EnvironmentPolicy {
        serde_json::from_value(json!({
            "current": "staging",
            "targets": [
                {"capabilities": ["infra.delete_volume"], "pointer": "/volume_id",
                 "prefixes": {"prod-": "production", "prod-eu-": "production-eu", "stg-": "staging"}},
                {"capabilities": ["payments.refund"], "environment": "production"},
                {"capabilities": ["infra.tag"], "pointer": "/id", "prefixes": {"prod-": "production"},
                 "unmatched": "allow"},
            ],
        }))
        .unwrap()
    }

    #[test]
    fn a_target_in_another_environment_is_refused() {
        let p = policy();
        p.validate().unwrap();
        assert_eq!(p.check("infra.delete_volume", &json!({"volume_id": "stg-db-1"})), None);
        let prod = p
            .check("infra.delete_volume", &json!({"volume_id": "prod-db-1"}))
            .unwrap();
        assert_eq!(
            (prod.reason, prod.target.as_deref()),
            ("environment_mismatch", Some("production"))
        );
        let eu = p
            .check("infra.delete_volume", &json!({"volume_id": "prod-eu-db"}))
            .unwrap();
        assert_eq!(eu.target.as_deref(), Some("production-eu"), "the longest prefix wins");
        assert_eq!(
            p.check("payments.refund", &json!({})).unwrap().target.as_deref(),
            Some("production")
        );
        assert_eq!(p.check("orders.lookup", &json!({})), None, "not environment-scoped");
    }

    #[test]
    fn an_unknown_target_fails_closed_unless_allowed() {
        let p = policy();
        for args in [json!({"volume_id": "db-1"}), json!({}), json!({"volume_id": 7})] {
            assert_eq!(
                p.check("infra.delete_volume", &args).unwrap().reason,
                "environment_unresolved"
            );
        }
        assert_eq!(p.check("infra.tag", &json!({"id": "db-1"})), None);
        assert!(p.check("infra.tag", &json!({"id": "prod-db-1"})).is_some());
    }

    #[test]
    fn malformed_policies_are_refused() {
        let mut p = policy();
        p.targets[1].pointer = Some("/x".into());
        assert!(p.validate().is_err(), "environment and pointer together");
        let mut p = policy();
        p.targets[0].prefixes.clear();
        assert!(p.validate().is_err(), "pointer without prefixes");
        let mut p = policy();
        p.targets[2].capabilities = vec!["infra.delete_volume".into()];
        assert!(p.validate().is_err(), "a capability in two rules");
        let mut p = policy();
        p.current = " ".into();
        assert!(p.validate().is_err());
    }
}
