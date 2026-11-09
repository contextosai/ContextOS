//! Who a run acts for, and through whom: the chain of actors a delegated credential
//! names (RFC 8693 `act`, nested once per hop), recorded on the run at admission.
//!
//! A user signs in to an assistant, which hands work to an agent, which calls the
//! gateway: the token names the user (`sub`) and the actors, current one first. The run
//! keeps that chain so an operator can revoke the user (`user`), one exact path
//! (`delegation`, by the chain's digest) or any actor on it (`principal`), and every run
//! acting through it stops. A delegated child run inherits its parent's chain.
//!
//! The audit records only the depth and the digest, never the user id or actor names:
//! the chain is append-only, and the run's own record carries them.

use contextos_contract::canonical::sha256_canonical;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// The actors (current first) a run acts through for one user.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelegationChain {
    pub user_id: String,
    /// Current actor first, then each earlier one.
    pub actors: Vec<String>,
    /// `sha256:` over the user and the actors in order: the `delegation` revocation target.
    pub digest: String,
}

impl DelegationChain {
    #[must_use]
    pub fn new(user_id: &str, actors: &[String]) -> Self {
        let digest = sha256_canonical(&json!({"user": user_id, "actors": actors})).unwrap_or_default();
        Self {
            user_id: user_id.to_owned(),
            actors: actors.to_vec(),
            digest,
        }
    }

    /// What the audit records: the depth and digest, no identities.
    #[must_use]
    pub fn audit_record(&self) -> Value {
        json!({"depth": self.actors.len(), "chain_digest": self.digest})
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_digest_names_one_exact_path() {
        let a = DelegationChain::new("u-alice", &["agent-b".into(), "assistant-a".into()]);
        let reordered = DelegationChain::new("u-alice", &["assistant-a".into(), "agent-b".into()]);
        let other_user = DelegationChain::new("u-bob", &["agent-b".into(), "assistant-a".into()]);
        assert!(a.digest.starts_with("sha256:"));
        assert_ne!(a.digest, reordered.digest);
        assert_ne!(a.digest, other_user.digest);
        assert_eq!(a.digest, DelegationChain::new("u-alice", &a.actors).digest);
        let record = a.audit_record().to_string();
        assert!(!record.contains("u-alice") && !record.contains("agent-b"), "{record}");
    }
}
