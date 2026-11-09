//! Delegated tokens (RFC 8693): the caller is the actor (`act.sub`), acting for the user
//! the token is about (`sub`).
//!
//! When work passes through several agents, each token exchange wraps the previous
//! actor in the new one: `act: {sub: "agent-b", act: {sub: "assistant-a"}}` says agent-b
//! acts now, for assistant-a, which acted for the user. The whole chain is read, current
//! actor first, and recorded on the run (see [`contextos_gateway::delegation_chain`]),
//! so revoking any actor on it, the user, or the exact path stops the run.
//!
//! A chain longer than `max_chain`, one naming an actor twice, or one naming the user
//! as an actor is rejected: such a token describes a loop, not a delegation. A
//! malformed actor claim rejects the token rather than reading it as ordinary.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::auth::VerifiedUser;
use crate::oidc_claims::{resolve, strings};

/// Actors one token may chain at most, whatever `max_chain` says.
pub const MAX_CHAIN_LIMIT: usize = 16;

/// `[oidc.delegation]`: how a delegated token names its actor and user.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DelegationConfig {
    /// Claim path of the actor object (its `sub` is the caller).
    #[serde(default = "default_actor_claim")]
    pub actor_claim: String,
    /// Field of the actor object naming the agent, mapped through the issuer's
    /// `agents` table (Keycloak: `client_id`). Unset: the issuer's `agent_claim`.
    #[serde(default)]
    pub actor_agent_claim: Option<String>,
    /// Claim path listing the user's roles (Keycloak: `realm_access.roles`). Set, a
    /// run may declare only a role the user holds.
    #[serde(default)]
    pub user_roles_claim: Option<String>,
    /// Actors a token may chain, current one included (1 to 16). A token with a
    /// longer chain is rejected.
    #[serde(default = "default_max_chain")]
    pub max_chain: usize,
}

fn default_actor_claim() -> String {
    "act".into()
}

fn default_max_chain() -> usize {
    4
}

impl DelegationConfig {
    pub fn validate(&self) -> Result<(), String> {
        if !(1..=MAX_CHAIN_LIMIT).contains(&self.max_chain) {
            return Err(format!("delegation.max_chain must be 1 to {MAX_CHAIN_LIMIT}"));
        }
        Ok(())
    }
}

pub(crate) struct Delegated<'a> {
    pub actor: &'a str,
    pub agent_value: Option<&'a str>,
    pub agent_claim: Option<String>,
    pub user: VerifiedUser,
}

/// The actors of a delegated token, current first: each nested `act` (RFC 8693) is the
/// one before. `Err` for a malformed, too long or looping chain.
fn chain<'a>(actor: &'a Value, subject: &str, max: usize) -> Result<Vec<&'a str>, ()> {
    let mut actors: Vec<&str> = Vec::new();
    let mut next = Some(actor);
    while let Some(current) = next {
        let id = current["sub"].as_str().filter(|s| !s.is_empty()).ok_or(())?;
        if id == subject || actors.contains(&id) || actors.len() == max {
            return Err(());
        }
        actors.push(id);
        next = match current.get("act") {
            None | Some(Value::Null) => None,
            Some(nested @ Value::Object(_)) => Some(nested),
            Some(_) => return Err(()),
        };
    }
    Ok(actors)
}

/// The actor and user of a delegated token from `issuer`; `None` for an ordinary token.
pub(crate) fn delegated<'a>(
    issuer: &str,
    config: &DelegationConfig,
    claims: &'a Value,
    subject: &str,
) -> Result<Option<Delegated<'a>>, ()> {
    let Some(actor) = resolve(claims, &config.actor_claim) else {
        return Ok(None);
    };
    if !actor.is_object() {
        return Err(());
    }
    let actors = chain(actor, subject, config.max_chain)?;
    let roles = config
        .user_roles_claim
        .as_ref()
        .map(|path| strings(resolve(claims, path)).into_iter().map(str::to_owned).collect());
    Ok(Some(Delegated {
        actor: actors[0],
        agent_value: config
            .actor_agent_claim
            .as_ref()
            .and_then(|field| actor[field].as_str()),
        agent_claim: config
            .actor_agent_claim
            .as_ref()
            .map(|field| format!("{}.{field}", config.actor_claim)),
        user: VerifiedUser {
            user_id: subject.to_owned(),
            roles,
            source: format!("oidc:{issuer}#{}", config.actor_claim),
            actors: actors.into_iter().map(str::to_owned).collect(),
        },
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn nested_actors_are_read_current_first_and_loops_are_refused() {
        let token = json!({"sub": "u-alice",
            "act": {"sub": "agent-b", "act": {"sub": "assistant-a"}}});
        assert_eq!(chain(&token["act"], "u-alice", 4), Ok(vec!["agent-b", "assistant-a"]));
        assert_eq!(chain(&json!({"sub": "agent-b"}), "u-alice", 4), Ok(vec!["agent-b"]));
        // Too long, an actor twice, the user as an actor, a malformed hop.
        assert!(chain(&token["act"], "u-alice", 1).is_err());
        let looped = json!({"sub": "agent-b", "act": {"sub": "assistant-a", "act": {"sub": "agent-b"}}});
        assert!(chain(&looped, "u-alice", 8).is_err());
        assert!(chain(&json!({"sub": "agent-b", "act": {"sub": "u-alice"}}), "u-alice", 4).is_err());
        assert!(chain(&json!({"sub": "agent-b", "act": "assistant-a"}), "u-alice", 4).is_err());
        assert!(chain(&json!({"sub": ""}), "u-alice", 4).is_err());
    }

    #[test]
    fn the_chain_limit_is_bounded() {
        let mut config: DelegationConfig = serde_json::from_value(json!({})).unwrap();
        assert_eq!(config.max_chain, 4);
        assert!(config.validate().is_ok());
        config.max_chain = 0;
        assert!(config.validate().is_err());
        config.max_chain = MAX_CHAIN_LIMIT + 1;
        assert!(config.validate().is_err());
    }
}
