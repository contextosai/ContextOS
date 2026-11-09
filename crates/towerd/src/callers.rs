//! Who is calling Tower: a person or service holding a configured key, or, with
//! `[sso]`, a person signed in with the organization's identity provider.

use std::sync::Arc;

use sha2::{Digest, Sha256};

use crate::config::ApiKey;

#[derive(Debug, Clone)]
pub struct Caller {
    pub principal_id: String,
    pub roles: Vec<String>,
    pub teams: Vec<String>,
}

impl Caller {
    pub fn has(&self, role: &str) -> bool {
        self.roles.iter().any(|r| r == role || r == "admin") || (role == "viewer" && !self.roles.is_empty())
    }
}

#[derive(Clone, Default)]
pub struct Callers {
    keys: Vec<([u8; 32], Caller)>,
    /// ID tokens from the organization's identity provider, besides keys.
    sso: Option<Arc<crate::sso::Sso>>,
}

impl std::fmt::Debug for Callers {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Callers")
            .field("keys", &self.keys.len())
            .field("sso", &self.sso.is_some())
            .finish()
    }
}

impl Callers {
    pub fn new(keys: &[ApiKey], sso: Option<Arc<crate::sso::Sso>>) -> Self {
        let keys = keys
            .iter()
            .filter_map(|k| {
                let digest: [u8; 32] = hex::decode(k.key_sha256.strip_prefix("sha256:")?)
                    .ok()?
                    .try_into()
                    .ok()?;
                Some((
                    digest,
                    Caller {
                        principal_id: k.principal_id.clone(),
                        roles: k.roles.clone(),
                        teams: k.teams.clone(),
                    },
                ))
            })
            .collect();
        Self { keys, sso }
    }

    pub(crate) fn authenticate(&self, header: Option<&str>) -> Option<Caller> {
        let token = header?.strip_prefix("Bearer ")?.trim();
        // A JWT (three dot-separated parts) is an ID token for single sign-on.
        if let Some(sso) = &self.sso
            && token.len() <= 16 * 1024
            && token.split('.').count() == 3
        {
            return sso.authenticate(token);
        }
        if token.is_empty() || token.len() > 512 {
            return None;
        }
        let digest: [u8; 32] = Sha256::digest(token.as_bytes()).into();
        let mut found = None;
        for (candidate, caller) in &self.keys {
            // Every key is compared, so timing does not reveal which matched.
            if candidate
                .iter()
                .zip(digest.iter())
                .fold(0u8, |acc, (a, b)| acc | (a ^ b))
                == 0
            {
                found = Some(caller.clone());
            }
        }
        found
    }
}
