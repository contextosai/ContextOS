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
//!
//! Without `jwks_url`, the key set's location comes from the issuer's OpenID Provider
//! Metadata (`<issuer>/.well-known/openid-configuration`), whose `issuer` must equal the
//! configured one. Claims are named by path (see [`crate::oidc_claims`]), so nested
//! claims such as Keycloak's `organization` map or `realm_access.roles` can be read.
//!
//! With `[oidc.delegation]`, a token carrying an RFC 8693 actor claim (`act`) is a
//! delegated token: the caller is the actor (`act.sub`), acting for the user the token
//! is about (`sub`). Keycloak issues these from token exchange delegation; see
//! [`crate::user_binding`] for how admission uses the user.

use std::collections::HashMap;
use std::str::FromStr;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use jsonwebtoken::jwk::{AlgorithmParameters, JwkSet, PublicKeyUse};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::auth::{Caller, VerifiedUser};
use crate::oidc_claims::{resolve, strings, valid_path};

/// Scopes a token may grant; anything else in the scope claim is ignored.
pub const KNOWN_SCOPES: [&str; 13] = [
    "compile",
    "admit",
    "dispatch",
    "reconcile",
    "audit:read",
    "evaluate",
    "control",
    "meter",
    "config",
    "authorize",
    "attest",
    "exposure:import",
    "outcome:report",
];

const MAX_JWKS_BYTES: usize = 1024 * 1024;
const MIN_REFRESH_INTERVAL: Duration = Duration::from_secs(30);
const RETRY_INTERVAL: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OidcConfig {
    /// Exact `iss` value.
    pub issuer: String,
    /// Required `aud` value.
    pub audience: String,
    /// HTTPS URL of the issuer's JWKS (HTTP is allowed only in development mode).
    /// Unset: discovered from the issuer's OpenID Provider Metadata.
    #[serde(default)]
    pub jwks_url: Option<String>,
    /// Tenants this issuer may assert. A token naming any other tenant is rejected.
    pub tenants: Vec<String>,
    /// Claim path naming the tenant: a string, an array or an object keyed by name
    /// (Keycloak's `organization`). It must name exactly one of `tenants`.
    #[serde(default = "default_tenant_claim")]
    pub tenant_claim: String,
    /// Maps `tenant_claim` values (for example Keycloak organization aliases) to
    /// tenant ids. Empty: the claim value itself is the tenant id.
    #[serde(default)]
    pub tenant_map: std::collections::BTreeMap<String, String>,
    /// Space-separated string or array of scopes.
    #[serde(default = "default_scope_claim")]
    pub scope_claim: String,
    /// Claim naming the agent the token is issued for (for example `sub` of a SPIFFE
    /// JWT-SVID, or `azp`), checked against the run's declared agent at admission.
    #[serde(default)]
    pub agent_claim: Option<String>,
    /// Maps an `agent_claim` value to the agent ids it may run as. Empty: the claim
    /// value itself is the agent id.
    #[serde(default)]
    pub agents: std::collections::BTreeMap<String, Vec<String>>,
    #[serde(default = "default_algorithms")]
    pub algorithms: Vec<String>,
    #[serde(default = "default_leeway")]
    pub leeway_seconds: u64,
    #[serde(default = "default_refresh")]
    pub refresh_seconds: u64,
    /// Accept RFC 8693 delegated tokens: the caller is the actor, acting for a user.
    #[serde(default)]
    pub delegation: Option<DelegationConfig>,
}

/// `[oidc.delegation]`: how a delegated token names its actor and user.
#[derive(Debug, Clone, Deserialize, Serialize)]
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
}

fn default_actor_claim() -> String {
    "act".into()
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
    /// Validates the issuer as startup does.
    pub fn check(&self, development: bool) -> Result<(), String> {
        let who = &self.issuer;
        if self.issuer.is_empty() || self.audience.is_empty() {
            return Err("oidc issuers need an issuer and audience".into());
        }
        if self.tenants.is_empty() || self.tenants.iter().any(String::is_empty) {
            return Err(format!("oidc issuer {who} must list the tenants it may assert"));
        }
        let checked = match &self.jwks_url {
            Some(jwks_url) => check_url(jwks_url, development).map_err(|e| format!("jwks_url {e}")),
            None => check_url(&self.issuer, development).map_err(|e| format!("discovery needs an issuer URL that {e}")),
        };
        checked.map_err(|e| format!("oidc issuer {who}: {e}"))?;
        let mut paths = vec![&self.tenant_claim, &self.scope_claim];
        paths.extend(&self.agent_claim);
        if let Some(delegation) = &self.delegation {
            paths.push(&delegation.actor_claim);
            paths.extend(&delegation.actor_agent_claim);
            paths.extend(&delegation.user_roles_claim);
            if delegation.actor_agent_claim.is_some() && self.agent_claim.is_none() {
                return Err(format!(
                    "oidc issuer {who}: delegation.actor_agent_claim needs agent_claim"
                ));
            }
        }
        if let Some(path) = paths.into_iter().find(|p| !valid_path(p)) {
            return Err(format!("oidc issuer {who}: invalid claim path {path:?}"));
        }
        if let Some((value, tenant)) = self.tenant_map.iter().find(|(_, t)| !self.tenants.contains(t)) {
            return Err(format!(
                "oidc issuer {who}: tenant_map {value} names {tenant}, which is not in tenants"
            ));
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

fn check_url(url: &str, development: bool) -> Result<(), String> {
    let parsed = url::Url::parse(url).map_err(|_| "must be a valid URL".to_owned())?;
    if parsed.scheme() == "https" || (development && parsed.scheme() == "http") {
        Ok(())
    } else {
        Err("must use https".into())
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
    development: bool,
    /// The JWKS URL: configured, or discovered and kept until a fetch from it fails.
    jwks_url: RwLock<Option<String>>,
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
        let client = contextos_adapters::tls::builder()
            .https_only(!development)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(5))
            .build()
            .map_err(|e| e.to_string())?;
        Ok(Self {
            jwks_url: RwLock::new(config.jwks_url.clone()),
            config,
            algorithms,
            cache: RwLock::default(),
            refresh: tokio::sync::Notify::new(),
            client,
            development,
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

    /// Fetches and installs the JWKS once (discovering its URL first if needed).
    pub async fn refresh_once(&self) -> Result<(), String> {
        let known = self.jwks_url.read().map_err(|e| e.to_string())?.clone();
        let url = if let Some(url) = known {
            url
        } else {
            let url = self.discover().await?;
            *self.jwks_url.write().map_err(|e| e.to_string())? = Some(url.clone());
            url
        };
        let result = self
            .fetch_json(&url, "jwks")
            .await
            .and_then(|bytes| serde_json::from_slice::<JwkSet>(&bytes).map_err(|e| format!("invalid jwks: {e}")));
        match result {
            Ok(jwks) => {
                self.install(&jwks);
                Ok(())
            }
            Err(error) => {
                if self.config.jwks_url.is_none() {
                    // Rediscover next time: the provider may have moved its keys.
                    *self.jwks_url.write().map_err(|e| e.to_string())? = None;
                }
                Err(error)
            }
        }
    }

    /// Reads `jwks_uri` from the issuer's OpenID Provider Metadata.
    async fn discover(&self) -> Result<String, String> {
        let url = format!(
            "{}/.well-known/openid-configuration",
            self.config.issuer.trim_end_matches('/')
        );
        let bytes = self.fetch_json(&url, "discovery").await?;
        let metadata: Value = serde_json::from_slice(&bytes).map_err(|e| format!("invalid discovery document: {e}"))?;
        if metadata["issuer"].as_str() != Some(self.config.issuer.as_str()) {
            return Err("discovery document names a different issuer".into());
        }
        let jwks_uri = metadata["jwks_uri"]
            .as_str()
            .ok_or("discovery document has no jwks_uri")?;
        check_url(jwks_uri, self.development).map_err(|e| format!("discovered jwks_uri {e}"))?;
        Ok(jwks_uri.to_owned())
    }

    async fn fetch_json(&self, url: &str, what: &str) -> Result<bytes::Bytes, String> {
        let response = self.client.get(url).send().await.map_err(|e| e.to_string())?;
        if !response.status().is_success() {
            return Err(format!("{what} status {}", response.status()));
        }
        if response.content_length().is_some_and(|n| n > MAX_JWKS_BYTES as u64) {
            return Err(format!("{what} too large"));
        }
        let bytes = response.bytes().await.map_err(|e| e.to_string())?;
        if bytes.len() > MAX_JWKS_BYTES {
            return Err(format!("{what} too large"));
        }
        Ok(bytes)
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
        let subject = claims["sub"].as_str().filter(|s| !s.is_empty()).ok_or(())?;
        let tenant_id = self.tenant(&claims)?;
        let granted = strings(resolve(&claims, &self.config.scope_claim));
        let granted: Vec<&str> = granted.iter().flat_map(|s| s.split_ascii_whitespace()).collect();
        let scopes = KNOWN_SCOPES
            .iter()
            .filter(|s| granted.contains(s))
            .map(|s| (*s).to_owned())
            .collect();
        let delegation = self.delegation(&claims, subject)?;
        let principal_id = delegation.as_ref().map_or(subject, |d| d.actor).to_owned();
        let (agent_value, agent_source) = match (&delegation, &self.config.agent_claim) {
            (Some(d), Some(_)) if d.agent_claim.is_some() => (d.agent_value, d.agent_claim.clone()),
            (_, Some(claim)) => (resolve(&claims, claim).and_then(Value::as_str), Some(claim.clone())),
            (_, None) => (None, None),
        };
        let agents = agent_source
            .as_ref()
            .map(|_| match agent_value.filter(|v| !v.is_empty()) {
                Some(v) if self.config.agents.is_empty() => vec![v.to_owned()],
                Some(v) => self.config.agents.get(v).cloned().unwrap_or_default(),
                None => Vec::new(),
            });
        Ok(Caller {
            tenant_id,
            principal_id,
            scopes,
            agents,
            agent_source: agent_source.map(|claim| format!("oidc:{}#{claim}", self.config.issuer)),
            user: delegation.map(|d| d.user),
        })
    }

    /// The one configured tenant the token names, after `tenant_map`.
    fn tenant(&self, claims: &Value) -> Result<String, ()> {
        let mut named: Vec<&str> = strings(resolve(claims, &self.config.tenant_claim))
            .into_iter()
            .filter_map(|value| {
                if self.config.tenant_map.is_empty() {
                    Some(value)
                } else {
                    self.config.tenant_map.get(value).map(String::as_str)
                }
            })
            .filter(|tenant| self.config.tenants.iter().any(|t| t == tenant))
            .collect();
        named.sort_unstable();
        named.dedup();
        match named.as_slice() {
            [tenant] => Ok((*tenant).to_owned()),
            _ => Err(()),
        }
    }

    /// The actor and user of a delegated token; `None` for an ordinary token. A
    /// malformed actor claim rejects the token rather than reading it as ordinary.
    fn delegation<'a>(&self, claims: &'a Value, subject: &str) -> Result<Option<Delegated<'a>>, ()> {
        let Some(config) = &self.config.delegation else {
            return Ok(None);
        };
        let Some(actor) = resolve(claims, &config.actor_claim) else {
            return Ok(None);
        };
        let actor_id = actor["sub"].as_str().filter(|s| !s.is_empty()).ok_or(())?;
        if actor_id == subject {
            return Err(());
        }
        let roles = config
            .user_roles_claim
            .as_ref()
            .map(|path| strings(resolve(claims, path)).into_iter().map(str::to_owned).collect());
        let source = format!("oidc:{}#{}", self.config.issuer, config.actor_claim);
        Ok(Some(Delegated {
            actor: actor_id,
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
                source,
            },
        }))
    }
}

struct Delegated<'a> {
    actor: &'a str,
    agent_value: Option<&'a str>,
    agent_claim: Option<String>,
    user: VerifiedUser,
}

/// Verifies a compact JWS against the configured issuers.
pub fn authenticate_jwt(issuers: &[Arc<OidcIssuer>], token: &str) -> Option<Caller> {
    let header = jsonwebtoken::decode_header(token).ok()?;
    let kid = header.kid.as_deref()?;
    issuers
        .iter()
        .find_map(|issuer| issuer.verify(token, kid, header.alg)?.ok())
}
