//! OIDC / JWT caller authentication.
//!
//! Each configured issuer publishes its signing keys as a JWKS document. Keys are
//! fetched in the background, so verifying a token never waits on the network; an
//! unknown `kid` is rejected and triggers a rate-limited refresh, which handles key
//! rotation without letting callers drive fetch storms.
//!
//! A token is accepted only if it carries a `kid` the issuer published, is signed with
//! an asymmetric algorithm the issuer is configured for (and the key is declared for),
//! names the issuer and this audience, is within `nbf`/`exp`, and asserts a tenant the
//! issuer is configured to speak for. Symmetric (`HS*`) and `none` are never accepted.

use std::collections::HashMap;
use std::str::FromStr;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use jsonwebtoken::jwk::{AlgorithmParameters, JwkSet, PublicKeyUse};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use serde_json::Value;

use crate::auth::Caller;

/// Scopes a token may grant; anything else in the scope claim is ignored.
pub const KNOWN_SCOPES: [&str; 4] = ["compile", "admit", "dispatch", "audit:read"];

const MAX_JWKS_BYTES: usize = 1024 * 1024;
const MIN_REFRESH_INTERVAL: Duration = Duration::from_secs(30);
const RETRY_INTERVAL: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OidcConfig {
    /// Exact `iss` value.
    pub issuer: String,
    /// Required `aud` value.
    pub audience: String,
    /// HTTPS URL of the issuer's JWKS (HTTP is allowed only in development mode).
    pub jwks_url: String,
    /// Tenants this issuer may assert. A token naming any other tenant is rejected.
    pub tenants: Vec<String>,
    #[serde(default = "default_tenant_claim")]
    pub tenant_claim: String,
    /// Space-separated string or array of scopes.
    #[serde(default = "default_scope_claim")]
    pub scope_claim: String,
    #[serde(default = "default_algorithms")]
    pub algorithms: Vec<String>,
    #[serde(default = "default_leeway")]
    pub leeway_seconds: u64,
    #[serde(default = "default_refresh")]
    pub refresh_seconds: u64,
}

fn default_tenant_claim() -> String {
    "tenant_id".into()
}

fn default_scope_claim() -> String {
    "scope".into()
}

fn default_algorithms() -> Vec<String> {
    vec!["RS256".into(), "ES256".into()]
}

fn default_leeway() -> u64 {
    60
}

fn default_refresh() -> u64 {
    300
}

impl OidcConfig {
    pub(crate) fn check(&self, development: bool) -> Result<(), String> {
        let who = &self.issuer;
        if self.issuer.is_empty() || self.audience.is_empty() {
            return Err("oidc issuers need an issuer and audience".into());
        }
        if self.tenants.is_empty() || self.tenants.iter().any(String::is_empty) {
            return Err(format!("oidc issuer {who} must list the tenants it may assert"));
        }
        let url = url::Url::parse(&self.jwks_url).map_err(|_| format!("oidc issuer {who}: invalid jwks_url"))?;
        if url.scheme() != "https" && !(development && url.scheme() == "http") {
            return Err(format!("oidc issuer {who}: jwks_url must use https"));
        }
        if self.algorithms.is_empty() {
            return Err(format!("oidc issuer {who} needs at least one algorithm"));
        }
        for name in &self.algorithms {
            match Algorithm::from_str(name) {
                Ok(Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512) => {
                    return Err(format!("oidc issuer {who}: symmetric algorithm {name} is not allowed"));
                }
                Ok(_) => {}
                Err(_) => return Err(format!("oidc issuer {who}: unknown algorithm {name}")),
            }
        }
        if self.leeway_seconds > 300 {
            return Err(format!("oidc issuer {who}: leeway_seconds must be at most 300"));
        }
        if self.refresh_seconds < 30 {
            return Err(format!("oidc issuer {who}: refresh_seconds must be at least 30"));
        }
        Ok(())
    }
}

struct VerificationKey {
    key: DecodingKey,
    /// The algorithm the key is declared for, when the JWKS states one.
    algorithm: Option<Algorithm>,
}

#[derive(Default)]
struct KeyCache {
    keys: Option<Arc<HashMap<String, VerificationKey>>>,
    fetched_at: Option<Instant>,
}

pub struct OidcIssuer {
    config: OidcConfig,
    algorithms: Vec<Algorithm>,
    cache: RwLock<KeyCache>,
    refresh: tokio::sync::Notify,
    client: reqwest::Client,
}

impl std::fmt::Debug for OidcIssuer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OidcIssuer")
            .field("issuer", &self.config.issuer)
            .finish_non_exhaustive()
    }
}

impl OidcIssuer {
    pub fn new(config: OidcConfig, development: bool) -> Result<Self, String> {
        config.check(development)?;
        let algorithms = config
            .algorithms
            .iter()
            .filter_map(|a| Algorithm::from_str(a).ok())
            .collect();
        let client = reqwest::Client::builder()
            .https_only(!development)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(5))
            .build()
            .map_err(|e| e.to_string())?;
        Ok(Self {
            config,
            algorithms,
            cache: RwLock::default(),
            refresh: tokio::sync::Notify::new(),
            client,
        })
    }

    pub fn issuer(&self) -> &str {
        &self.config.issuer
    }

    /// Whether a key set has been loaded.
    pub fn ready(&self) -> bool {
        self.cache.read().is_ok_and(|c| c.keys.is_some())
    }

    /// Replaces the key set from a JWKS document. Symmetric, encryption-only and
    /// unidentified keys are dropped.
    pub fn install(&self, jwks: &JwkSet) {
        let keys: HashMap<String, VerificationKey> = jwks
            .keys
            .iter()
            .filter(|jwk| !matches!(jwk.algorithm, AlgorithmParameters::OctetKey(_)))
            .filter(|jwk| !matches!(jwk.common.public_key_use, Some(PublicKeyUse::Encryption)))
            .filter_map(|jwk| {
                let kid = jwk.common.key_id.clone()?;
                let key = DecodingKey::from_jwk(jwk).ok()?;
                let algorithm = match jwk.common.key_algorithm {
                    // A key declared for an algorithm we cannot name is unusable.
                    Some(declared) => Some(Algorithm::from_str(&format!("{declared:?}")).ok()?),
                    None => None,
                };
                Some((kid, VerificationKey { key, algorithm }))
            })
            .collect();
        if let Ok(mut cache) = self.cache.write() {
            cache.keys = Some(Arc::new(keys));
            cache.fetched_at = Some(Instant::now());
        }
    }

    /// Fetches and installs the JWKS once.
    pub async fn refresh_once(&self) -> Result<(), String> {
        let response = self
            .client
            .get(&self.config.jwks_url)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        if !response.status().is_success() {
            return Err(format!("jwks status {}", response.status()));
        }
        if response.content_length().is_some_and(|n| n > MAX_JWKS_BYTES as u64) {
            return Err("jwks too large".into());
        }
        let bytes = response.bytes().await.map_err(|e| e.to_string())?;
        if bytes.len() > MAX_JWKS_BYTES {
            return Err("jwks too large".into());
        }
        let jwks: JwkSet = serde_json::from_slice(&bytes).map_err(|e| format!("invalid jwks: {e}"))?;
        self.install(&jwks);
        Ok(())
    }

    /// Keeps the key set fresh: periodically, and soon after an unknown `kid` (at most
    /// once per [`MIN_REFRESH_INTERVAL`]).
    pub async fn run_refresh(self: Arc<Self>) {
        let period = Duration::from_secs(self.config.refresh_seconds);
        loop {
            let wait = match self.refresh_once().await {
                Ok(()) => period,
                Err(error) => {
                    tracing::warn!(issuer = %self.config.issuer, %error, "jwks refresh failed");
                    RETRY_INTERVAL
                }
            };
            tokio::select! {
                () = tokio::time::sleep(wait) => {}
                () = self.refresh.notified() => tokio::time::sleep(MIN_REFRESH_INTERVAL).await,
            }
        }
    }

    /// Verifies a token signed by this issuer. `None` if it is not this issuer's key.
    fn verify(&self, token: &str, kid: &str, algorithm: Algorithm) -> Option<Result<Caller, ()>> {
        let keys = self.cache.read().ok()?.keys.clone()?;
        let Some(key) = keys.get(kid) else {
            self.refresh.notify_one();
            return None;
        };
        Some(self.verify_with(token, key, algorithm))
    }

    fn verify_with(&self, token: &str, key: &VerificationKey, algorithm: Algorithm) -> Result<Caller, ()> {
        if !self.algorithms.contains(&algorithm) || key.algorithm.is_some_and(|declared| declared != algorithm) {
            return Err(());
        }
        let mut validation = Validation::new(algorithm);
        validation.set_issuer(&[&self.config.issuer]);
        validation.set_audience(&[&self.config.audience]);
        validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
        validation.validate_nbf = true;
        validation.leeway = self.config.leeway_seconds;
        let claims = jsonwebtoken::decode::<Value>(token, &key.key, &validation)
            .map_err(|_| ())?
            .claims;
        let principal_id = claims["sub"].as_str().filter(|s| !s.is_empty()).ok_or(())?;
        let tenant_id = claims[&self.config.tenant_claim].as_str().ok_or(())?;
        if !self.config.tenants.iter().any(|t| t == tenant_id) {
            return Err(());
        }
        let granted: Vec<&str> = match &claims[&self.config.scope_claim] {
            Value::String(s) => s.split_ascii_whitespace().collect(),
            Value::Array(items) => items.iter().filter_map(Value::as_str).collect(),
            _ => Vec::new(),
        };
        let scopes = KNOWN_SCOPES
            .iter()
            .filter(|s| granted.contains(s))
            .map(|s| (*s).to_owned())
            .collect();
        Ok(Caller {
            tenant_id: tenant_id.to_owned(),
            principal_id: principal_id.to_owned(),
            scopes,
        })
    }
}

/// Verifies a compact JWS against the configured issuers.
pub fn authenticate_jwt(issuers: &[Arc<OidcIssuer>], token: &str) -> Option<Caller> {
    let header = jsonwebtoken::decode_header(token).ok()?;
    let kid = header.kid.as_deref()?;
    issuers
        .iter()
        .find_map(|issuer| issuer.verify(token, kid, header.alg)?.ok())
}
