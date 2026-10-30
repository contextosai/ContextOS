//! Caller authentication.
//!
//! Callers present either an API key or an OIDC-issued JWT as a bearer token. API
//! keys are configured as SHA-256 hashes and compared in constant time; JWTs are
//! verified against each issuer's published keys (see [`crate::oidc`]). Every
//! authenticated caller is bound to exactly one tenant; handlers reject any request
//! whose tenant differs.

use std::sync::Arc;

use sha2::{Digest, Sha256};

use crate::config::ApiKey;
use crate::oidc::{OidcIssuer, authenticate_jwt};

const MAX_API_KEY_BYTES: usize = 512;
const MAX_JWT_BYTES: usize = 8 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Caller {
    pub tenant_id: String,
    pub principal_id: String,
    pub scopes: Vec<String>,
    /// The agent ids this credential is issued for, if it names any (see
    /// [`crate::agent_binding`]).
    pub agents: Option<Vec<String>>,
    /// Where `agents` came from: `api_key`, or `oidc:<issuer>#<claim>`.
    pub agent_source: Option<String>,
}

impl Caller {
    pub fn has(&self, scope: &str) -> bool {
        self.scopes.iter().any(|s| s == scope)
    }
}

#[derive(Debug, Clone)]
pub struct Authenticator {
    keys: Vec<([u8; 32], Caller)>,
    issuers: Vec<Arc<OidcIssuer>>,
}

fn constant_time_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.iter().zip(b.iter()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

impl Authenticator {
    pub fn new(keys: &[ApiKey]) -> Self {
        let keys = keys
            .iter()
            .filter_map(|k| {
                let bytes = hex::decode(k.key_sha256.strip_prefix("sha256:")?).ok()?;
                let digest: [u8; 32] = bytes.try_into().ok()?;
                Some((
                    digest,
                    Caller {
                        tenant_id: k.tenant_id.clone(),
                        principal_id: k.principal_id.clone(),
                        scopes: k.scopes.clone(),
                        agents: k.agent_ids.clone(),
                        agent_source: k.agent_ids.as_ref().map(|_| "api_key".to_owned()),
                    },
                ))
            })
            .collect();
        Self {
            keys,
            issuers: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_issuers(mut self, issuers: Vec<Arc<OidcIssuer>>) -> Self {
        self.issuers = issuers;
        self
    }

    pub fn issuers(&self) -> &[Arc<OidcIssuer>] {
        &self.issuers
    }

    /// Whether every OIDC issuer has a key set loaded.
    pub fn ready(&self) -> bool {
        self.issuers.iter().all(|i| i.ready())
    }

    /// Authenticates an `Authorization: Bearer <token>` header value.
    pub fn authenticate(&self, header: Option<&str>) -> Option<Caller> {
        let token = header?.strip_prefix("Bearer ")?.trim();
        if !self.issuers.is_empty() && token.bytes().filter(|b| *b == b'.').count() == 2 {
            return (token.len() <= MAX_JWT_BYTES).then(|| authenticate_jwt(&self.issuers, token))?;
        }
        if token.is_empty() || token.len() > MAX_API_KEY_BYTES {
            return None;
        }
        let digest: [u8; 32] = Sha256::digest(token.as_bytes()).into();
        // Scan every key so timing does not reveal which entry matched.
        let mut found = None;
        for (candidate, caller) in &self.keys {
            if constant_time_eq(candidate, &digest) {
                found = Some(caller.clone());
            }
        }
        found
    }
}

/// `sha256:<hex>` for configuring a raw key.
pub fn hash_api_key(raw: &str) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(raw.as_bytes())))
}
