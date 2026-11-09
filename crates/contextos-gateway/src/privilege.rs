//! Privilege intersection: an effect needs the user's privilege, not only the agent's.
//!
//! An agent's credential often reaches far more than any one user may do. A capability
//! that declares `required_user_roles` runs only for a run acting for a user who holds
//! one of those roles, as the identity provider says in the user's delegated token
//! (`[oidc.delegation] user_roles_claim`). The roles are read at admission and kept on
//! the run with its delegation chain (see [`crate::delegation_chain`]); a delegated
//! child run inherits its parent's.
//!
//! Otherwise the call is refused before anything is reserved or sent, and audited as
//! `privilege_refusal` with the reason:
//!
//! | Reason | When |
//! |---|---|
//! | `user_not_delegated` | The run's credential named no user |
//! | `user_roles_unknown` | The issuer is not configured to read the user's roles |
//! | `user_role_missing` | The user holds none of the roles |

use crate::admission::RunAdmission;
use crate::manifest::CapabilityManifest;

/// Roles one capability may require at most.
pub const MAX_REQUIRED_ROLES: usize = 32;

/// Why the run may not apply this capability's effects, if it may not.
#[must_use]
pub fn refusal(manifest: &CapabilityManifest, admission: &RunAdmission) -> Option<&'static str> {
    if manifest.required_user_roles.is_empty() {
        return None;
    }
    let Some(chain) = &admission.delegation_chain else {
        return Some("user_not_delegated");
    };
    let Some(held) = &chain.user_roles else {
        return Some("user_roles_unknown");
    };
    (!manifest.required_user_roles.iter().any(|r| held.contains(r))).then_some("user_role_missing")
}

/// Whether a manifest's role list is well formed.
pub(crate) fn valid(roles: &[String]) -> bool {
    roles.len() <= MAX_REQUIRED_ROLES && roles.iter().all(|r| !r.is_empty() && r.len() <= 128)
}
