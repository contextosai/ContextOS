//! Agent binding: the agent a run declares (`run_context.agent.agent_id`) must be one
//! the caller's credential is issued for, not just a name the caller chose.
//!
//! A credential names its agents in one of two ways: an OIDC issuer's `agent_claim`
//! (for example `sub` of a SPIFFE JWT-SVID, or `azp`), optionally mapped through the
//! issuer's `agents` table, or an API key's `agent_ids`. At admission the declared agent
//! is checked against them:
//!
//! - `required` refuses an unbound agent (`403 agent_not_bound`). The default for
//!   deployments that declare the `contextos.enterprise` profile.
//! - `observe` admits it, counts it (`contextos_agent_binding_mismatches_total`) and
//!   records `bound: false` in `run_admitted`, so operators can see what `required`
//!   would refuse before turning it on. The default otherwise.
//! - `off` checks nothing (development only; `--check-config` warns).
//!
//! Delegated runs are admitted by their parent's executor and inherit the parent's
//! binding; delegation already narrows what they may do. Their agent is the delegation
//! envelope's subject, which the parent names, so `run_admitted` records whether the
//! admitting credential names it too (`named_by_credential`) for whoever attributes
//! runs to agents.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::Config;
use crate::auth::Caller;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentBinding {
    Required,
    Observe,
    Off,
}

impl AgentBinding {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Required => "required",
            Self::Observe => "observe",
            Self::Off => "off",
        }
    }
}

/// `[guards] agent_binding`, or the default for the declared profiles.
#[must_use]
pub fn mode(config: &Config) -> AgentBinding {
    config.guards.agent_binding.unwrap_or_else(|| {
        if config.support.profiles.iter().any(|p| p == "contextos.enterprise") {
            AgentBinding::Required
        } else {
            AgentBinding::Observe
        }
    })
}

/// Startup check: with `required`, every credential that can admit runs names its
/// agents, so no run is refused for a configuration gap discovered in production.
pub fn check(config: &Config) -> Result<(), String> {
    for issuer in &config.oidc {
        if issuer.agents.values().any(Vec::is_empty) {
            return Err(format!(
                "oidc issuer {}: every agents entry needs agent ids",
                issuer.issuer
            ));
        }
        if !issuer.agents.is_empty() && issuer.agent_claim.is_none() {
            return Err(format!("oidc issuer {}: agents needs agent_claim", issuer.issuer));
        }
    }
    if config
        .api_keys
        .iter()
        .any(|k| k.agent_ids.as_ref().is_some_and(Vec::is_empty))
    {
        return Err("api key agent_ids, when set, must name at least one agent".into());
    }
    if mode(config) != AgentBinding::Required {
        return Ok(());
    }
    if let Some(issuer) = config.oidc.iter().find(|i| i.agent_claim.is_none()) {
        return Err(format!(
            "agent binding is required: oidc issuer {} needs agent_claim",
            issuer.issuer
        ));
    }
    if let Some(key) = config
        .api_keys
        .iter()
        .find(|k| k.agent_ids.is_none() && k.scopes.iter().any(|s| s == "admit"))
    {
        return Err(format!(
            "agent binding is required: the api key for {} can admit runs and needs agent_ids",
            key.principal_id
        ));
    }
    Ok(())
}

/// What admission decided about the declared agent.
#[derive(Debug, Clone, PartialEq)]
pub struct Verdict {
    /// Recorded in `run_admitted` as `agent_binding`.
    pub record: Value,
    /// The agent is not one the credential is issued for.
    pub unbound: bool,
    /// Admission must refuse (`required` and unbound).
    pub refuse: bool,
}

#[must_use]
pub fn evaluate(mode: AgentBinding, caller: &Caller, agent_id: &str, delegated: bool) -> Verdict {
    let named = caller
        .agents
        .as_ref()
        .is_some_and(|agents| agents.iter().any(|a| a == agent_id));
    if delegated {
        return Verdict {
            record: json!({"mode": mode.as_str(), "bound": "inherited", "named_by_credential": named}),
            unbound: false,
            refuse: false,
        };
    }
    if mode == AgentBinding::Off {
        return Verdict {
            record: json!({"mode": "off"}),
            unbound: false,
            refuse: false,
        };
    }
    Verdict {
        record: json!({"mode": mode.as_str(), "bound": named, "source": caller.agent_source}),
        unbound: !named,
        refuse: !named && mode == AgentBinding::Required,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn caller(agents: Option<Vec<&str>>) -> Caller {
        Caller {
            tenant_id: "t".into(),
            principal_id: "p".into(),
            scopes: vec!["admit".into()],
            agents: agents.map(|a| a.into_iter().map(str::to_owned).collect()),
            agent_source: Some("api_key".into()),
        }
    }

    #[test]
    fn only_required_refuses_and_only_an_issued_agent_is_bound() {
        let issued = caller(Some(vec!["agt_support"]));
        let unnamed = caller(None);
        for (mode, who, agent, refuse, unbound) in [
            (AgentBinding::Required, &issued, "agt_support", false, false),
            (AgentBinding::Required, &issued, "agt_other", true, true),
            (AgentBinding::Required, &unnamed, "agt_support", true, true),
            (AgentBinding::Observe, &issued, "agt_other", false, true),
            (AgentBinding::Observe, &unnamed, "agt_support", false, true),
            (AgentBinding::Off, &unnamed, "agt_support", false, false),
        ] {
            let verdict = evaluate(mode, who, agent, false);
            assert_eq!((verdict.refuse, verdict.unbound), (refuse, unbound), "{mode:?} {agent}");
        }
        let child = evaluate(AgentBinding::Required, &unnamed, "agt_child", true);
        assert!(!child.refuse);
        assert_eq!(child.record["bound"], "inherited");
        assert_eq!(child.record["named_by_credential"], false);
        let named = evaluate(AgentBinding::Required, &issued, "agt_support", true);
        assert_eq!(named.record["named_by_credential"], true);
    }
}
