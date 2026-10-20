//! Caller authentication.
//!
//! API keys are configured as SHA-256 hashes and compared in constant time. Every
//! authenticated caller is bound to exactly one tenant; handlers reject any request
//! whose tenant differs. Production deployments typically front this with mTLS or
//! an OIDC-validating proxy; the tenant binding still applies.

use sha2::{Digest, Sha256};

use crate::config::ApiKey;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Caller {
    pub tenant_id: String,
    pub principal_id: String,
    pub scopes: Vec<String>,
}

impl Caller {
    pub fn has(&self, scope: &str) -> bool {
        self.scopes.iter().any(|s| s == scope)
    }
}

#[derive(Debug, Clone)]
pub struct Authenticator {
    keys: Vec<([u8; 32], Caller)>,
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
                    },
                ))
            })
            .collect();
        Self { keys }
    }

    /// Authenticates an `Authorization: Bearer <key>` header value.
    pub fn authenticate(&self, header: Option<&str>) -> Option<Caller> {
        let token = header?.strip_prefix("Bearer ")?.trim();
        if token.is_empty() || token.len() > 512 {
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
