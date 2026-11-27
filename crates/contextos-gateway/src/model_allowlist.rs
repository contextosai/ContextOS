//! Model allow-lists: which models runs may use, for every agent and per agent.
//!
//! `[guards.models]` lists the models allowed for every agent (`allowed`) and, per
//! agent, a narrower list (`agents`). An entry is a model id (any version) or
//! `id@version`. A run's pinned `model_profile` release refs are checked at admission
//! (`model_not_allowed`), and the model a metering gateway reports when it claims a
//! reservation is checked before the call goes out (`model_not_allowed`), so a routed
//! or fallen-back model outside the list is stopped where the call is made. An agent
//! with its own list may use only models on both lists.
//!
//! Agent risk tiers live in Tower's declarations; give each tier's agents the list that
//! tier allows.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Entries per list at most.
pub const MAX_ENTRIES: usize = 256;

/// `[guards.models]`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ModelPolicy {
    /// Models any agent may use.
    pub allowed: Vec<String>,
    /// Agent id to the models that agent may use (also on `allowed`).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub agents: BTreeMap<String, Vec<String>>,
}

fn matches(list: &[String], model: &str) -> bool {
    let id = model.split_once('@').map_or(model, |(id, _)| id);
    list.iter().any(|entry| entry == model || entry == id)
}

impl ModelPolicy {
    pub fn validate(&self) -> Result<(), String> {
        let bad = |l: &[String]| l.len() > MAX_ENTRIES || l.iter().any(|m| m.trim().is_empty() || m.len() > 256);
        if self.allowed.is_empty() || bad(&self.allowed) || self.agents.values().any(|l| l.is_empty() || bad(l)) {
            return Err(format!(
                "[guards.models] lists 1 to {MAX_ENTRIES} models in allowed and in each agent's list"
            ));
        }
        Ok(())
    }

    /// Whether `agent_id` may use `model` (`id@version`, or an id alone).
    #[must_use]
    pub fn allows(&self, agent_id: &str, model: &str) -> bool {
        matches(&self.allowed, model) && self.agents.get(agent_id).is_none_or(|own| matches(own, model))
    }

    /// Returns the configured allow-list label matching `model`, for bounded metric
    /// cardinality (threat T72). Never returns a caller-supplied string outside `allowed`.
    #[must_use]
    pub fn matched_label(&self, model: &str) -> Option<&str> {
        let id = model.split_once('@').map_or(model, |(id, _)| id);
        self.allowed
            .iter()
            .find(|entry| entry.as_str() == model || entry.as_str() == id)
            .map(String::as_str)
    }

    /// The pinned `model_profile` refs among `release_refs` this agent may not use.
    #[must_use]
    pub fn refused_profiles(&self, agent_id: &str, release_refs: &[Value]) -> Vec<String> {
        release_refs
            .iter()
            .filter(|r| r["artifact_type"] == "model_profile")
            .map(|r| {
                format!(
                    "{}@{}",
                    r["artifact_id"].as_str().unwrap_or("?"),
                    r["version"].as_str().unwrap_or("?")
                )
            })
            .filter(|m| !self.allows(agent_id, m))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn policy() -> ModelPolicy {
        serde_json::from_value(json!({"allowed": ["claude-sonnet-5-5", "claude-opus-5-5@2026-10"],
            "agents": {"agt_support": ["claude-sonnet-5-5"]}}))
        .unwrap()
    }

    #[test]
    fn ids_match_any_version_and_versions_match_exactly() {
        let p = policy();
        p.validate().unwrap();
        assert!(p.allows("agt_x", "claude-sonnet-5-5@2026-11"));
        assert!(p.allows("agt_x", "claude-opus-5-5@2026-10"));
        assert!(!p.allows("agt_x", "claude-opus-5-5@2026-11"));
        assert!(!p.allows("agt_x", "gpt-x"));
    }

    #[test]
    fn an_agents_own_list_narrows_never_widens() {
        let p = policy();
        assert!(p.allows("agt_support", "claude-sonnet-5-5"));
        assert!(
            !p.allows("agt_support", "claude-opus-5-5@2026-10"),
            "allowed globally, not for this agent"
        );
        let mut wide = policy();
        wide.agents.insert("agt_x".into(), vec!["gpt-x".into()]);
        assert!(!wide.allows("agt_x", "gpt-x"), "an agent list cannot add a model");
    }

    #[test]
    fn pinned_profiles_are_checked() {
        let refs = vec![
            json!({"artifact_type": "model_profile", "artifact_id": "claude-opus-5-5", "version": "2026-10"}),
            json!({"artifact_type": "evaluator_suite", "artifact_id": "x", "version": "1"}),
        ];
        assert_eq!(
            policy().refused_profiles("agt_support", &refs),
            ["claude-opus-5-5@2026-10"]
        );
        assert_eq!(policy().refused_profiles("agt_x", &refs), Vec::<String>::new());
        assert!(
            serde_json::from_value::<ModelPolicy>(json!({"allowed": []}))
                .unwrap()
                .validate()
                .is_err()
        );
    }
}
