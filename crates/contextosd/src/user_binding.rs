//! User binding: the user a run says it acts for (`run_context.user`) must be the
//! user the identity provider says the caller acts for, not just a name the caller
//! chose.
//!
//! A credential names a user only when it is a delegated token: an RFC 8693 token
//! whose actor claim (`act`) names the caller and whose `sub` names the user, as
//! Keycloak's token exchange delegation issues, from an issuer with
//! `[oidc.delegation]`. With `user_roles_claim` the issuer also says which roles the
//! user holds, so a run cannot claim a role (and the pack rules written for it) the
//! user does not have.
//!
//! - `required` refuses a run whose credential names no user, another user, or a user
//!   without the declared role (`403 user_not_bound`).
//! - `observe`, the default, admits it, counts it by reason
//!   (`contextos_user_binding_mismatches_total`) and records `bound: false` in
//!   `run_admitted`.
//! - `off` checks nothing.
//!
//! The audit records whether the run was bound and why not, never the user id: the
//! audit chain is append-only, and the run's own records carry the user.
//!
//! Delegated runs are admitted by their parent's executor and inherit the parent's
//! user binding.

use axum::http::StatusCode;
use contextos_contract::types::UserClaims;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::Config;
use crate::auth::Caller;
use crate::http::ApiError;
use crate::metrics::Metrics;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UserBinding {
    Required,
    Observe,
    Off,
}

impl UserBinding {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Required => "required",
            Self::Observe => "observe",
            Self::Off => "off",
        }
    }
}

/// `[guards] user_binding`, or `observe`. No profile turns `required` on: agents that
/// act for no user (batch jobs, pipelines) are legitimate.
#[must_use]
pub fn mode(config: &Config) -> UserBinding {
    config.guards.user_binding.unwrap_or(UserBinding::Observe)
}

/// Startup check: with `required`, every credential that can admit runs can name a
/// user, so no run is refused for a configuration gap discovered in production.
pub fn check(config: &Config) -> Result<(), String> {
    if mode(config) != UserBinding::Required {
        return Ok(());
    }
    if config.oidc.is_empty() {
        return Err("user binding is required: configure an [[oidc]] issuer with [oidc.delegation]".into());
    }
    if let Some(issuer) = config.oidc.iter().find(|i| i.delegation.is_none()) {
        return Err(format!(
            "user binding is required: oidc issuer {} needs [oidc.delegation]",
            issuer.issuer
        ));
    }
    if let Some(key) = config.api_keys.iter().find(|k| k.scopes.iter().any(|s| s == "admit")) {
        return Err(format!(
            "user binding is required: the api key for {} can admit runs but names no user",
            key.principal_id
        ));
    }
    Ok(())
}

/// What admission decided about the declared user.
#[derive(Debug, Clone, PartialEq)]
pub struct Verdict {
    /// Recorded in `run_admitted` as `user_binding`.
    pub record: Value,
    /// Why the run is not bound: `no_user`, `other_user`, `role_not_held`.
    pub unbound: Option<&'static str>,
    /// Admission must refuse (`required` and unbound).
    pub refuse: bool,
}

#[must_use]
pub fn evaluate(mode: UserBinding, caller: &Caller, user: &UserClaims, delegated: bool) -> Verdict {
    if delegated {
        return Verdict {
            record: json!({"mode": mode.as_str(), "bound": "inherited"}),
            unbound: None,
            refuse: false,
        };
    }
    if mode == UserBinding::Off {
        return Verdict {
            record: json!({"mode": "off"}),
            unbound: None,
            refuse: false,
        };
    }
    let reason = match &caller.user {
        None => Some("no_user"),
        Some(verified) if verified.user_id != user.user_id => Some("other_user"),
        Some(verified) => match (&verified.roles, &user.role) {
            (Some(roles), Some(role)) if !roles.contains(role) => Some("role_not_held"),
            _ => None,
        },
    };
    let mut record = json!({"mode": mode.as_str(), "bound": reason.is_none()});
    if let Some(reason) = reason {
        record["reason"] = json!(reason);
    }
    if let Some(verified) = &caller.user {
        record["source"] = json!(verified.source);
        record["roles_checked"] = json!(verified.roles.is_some());
    }
    Verdict {
        record,
        unbound: reason,
        refuse: reason.is_some() && mode == UserBinding::Required,
    }
}

/// Evaluates, counts and, under `required`, refuses; returns the audit record.
pub(crate) fn admit(
    mode: UserBinding,
    metrics: &Metrics,
    caller: &Caller,
    user: &UserClaims,
    delegated: bool,
) -> Result<Value, ApiError> {
    let verdict = evaluate(mode, caller, user, delegated);
    if let Some(reason) = verdict.unbound {
        metrics.user_binding_mismatch(reason);
    }
    if verdict.refuse {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "user_not_bound",
            "The run's user is not the user the caller's credential acts for.",
        )
        .with_detail(json!(verdict.unbound)));
    }
    Ok(verdict.record)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::VerifiedUser;

    fn caller(user: Option<(&str, Option<Vec<&str>>)>) -> Caller {
        Caller {
            tenant_id: "t".into(),
            principal_id: "sa-support".into(),
            scopes: vec!["admit".into()],
            agents: None,
            agent_source: None,
            user: user.map(|(id, roles)| VerifiedUser {
                user_id: id.into(),
                roles: roles.map(|r| r.into_iter().map(str::to_owned).collect()),
                source: "oidc:https://kc.example/realms/acme#act".into(),
            }),
        }
    }

    fn user(id: &str, role: Option<&str>) -> UserClaims {
        UserClaims {
            user_id: id.into(),
            delegation: None,
            role: role.map(str::to_owned),
            tenure_days: None,
        }
    }

    #[test]
    fn a_run_is_bound_to_the_delegating_user_and_their_roles() {
        let alice = caller(Some(("u-alice", None)));
        let alice_roles = caller(Some(("u-alice", Some(vec!["support_agent"]))));
        let service = caller(None);
        for (who, run_user, role, reason) in [
            (&alice, "u-alice", Some("support_manager"), None),
            (&alice, "u-bob", None, Some("other_user")),
            (&alice_roles, "u-alice", Some("support_agent"), None),
            (&alice_roles, "u-alice", None, None),
            (&alice_roles, "u-alice", Some("support_manager"), Some("role_not_held")),
            (&service, "u-alice", None, Some("no_user")),
        ] {
            let required = evaluate(UserBinding::Required, who, &user(run_user, role), false);
            assert_eq!(required.unbound, reason, "{run_user} {role:?}");
            assert_eq!(required.refuse, reason.is_some());
            assert_eq!(required.record["bound"], reason.is_none());
            let observed = evaluate(UserBinding::Observe, who, &user(run_user, role), false);
            assert_eq!(observed.unbound, reason);
            assert!(!observed.refuse);
        }
        let off = evaluate(UserBinding::Off, &service, &user("u-alice", None), false);
        assert_eq!((off.unbound, off.refuse), (None, false));
        let child = evaluate(UserBinding::Required, &service, &user("u-alice", None), true);
        assert!(!child.refuse);
        assert_eq!(child.record["bound"], "inherited");
    }

    #[test]
    fn the_record_never_holds_the_user_id() {
        let verdict = evaluate(
            UserBinding::Required,
            &caller(Some(("u-alice", None))),
            &user("u-bob", None),
            false,
        );
        assert!(!verdict.record.to_string().contains("u-alice"));
        assert!(!verdict.record.to_string().contains("u-bob"));
        assert_eq!(verdict.record["reason"], "other_user");
    }
}
