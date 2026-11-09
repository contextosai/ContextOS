//! Single sign-on for Tower: people sign in with the organization's identity provider
//! instead of holding API keys.
//!
//! With `[sso]`, Tower accepts an OpenID Connect ID token as a bearer token besides its
//! API keys. A token is accepted only if it is signed with an asymmetric algorithm the
//! configuration allows, by a key the issuer publishes (`kid`), names the issuer and
//! this client as audience, and is within `nbf`/`exp` (with `leeway_seconds`). The
//! caller is the `principal_claim` (default `email`, else `sub`); roles and teams come
//! from the token's groups (`groups_claim`) through `[[sso.groups]]`. A person in no
//! mapped group is refused: signing in grants nothing by itself.
//!
//! Keys are fetched in the background from `jwks_url`, or from the issuer's OpenID
//! Provider Metadata, which also gives the UI its authorization and token endpoints
//! for the authorization-code flow with PKCE (`GET /api/sso`). Verifying a token never
//! waits on the network; an unknown `kid` triggers a rate-limited refresh.

use std::collections::BTreeSet;
use std::str::FromStr;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::api::Caller;
use crate::config::ROLES;

/// Largest document read from the identity provider (metadata, key set, token response).
pub(crate) const MAX_DOCUMENT_BYTES: usize = 1024 * 1024;
const MIN_REFRESH: Duration = Duration::from_secs(30);

/// `[sso]`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SsoConfig {
    /// Exact `iss` value; its `/.well-known/openid-configuration` is read unless
    /// `jwks_url` is set.
    pub issuer: String,
    /// The OAuth client id Tower's UI signs in as; the ID token's `aud`.
    pub client_id: String,
    /// Where the identity provider sends the browser back: Tower's UI root as
    /// registered with the client (for example `https://tower.example.com/tower/`).
    pub redirect_uri: String,
    /// Environment variable holding the client secret, for a confidential client.
    /// Unset: a public client, protected by PKCE.
    #[serde(default)]
    pub client_secret_env: Option<String>,
    /// The issuer's JWKS. Unset: from the issuer's metadata.
    #[serde(default)]
    pub jwks_url: Option<String>,
    /// Claim naming the person.
    #[serde(default = "default_principal_claim")]
    pub principal_claim: String,
    /// Claim (dotted path) listing the person's groups.
    #[serde(default = "default_groups_claim")]
    pub groups_claim: String,
    #[serde(default = "default_algorithms")]
    pub algorithms: Vec<String>,
    #[serde(default = "default_leeway")]
    pub leeway_seconds: u64,
    #[serde(default = "default_refresh")]
    pub refresh_seconds: u64,
    /// Scopes the UI asks for.
    #[serde(default = "default_scopes")]
    pub scopes: Vec<String>,
    /// Identity-provider groups and the Tower roles and teams they grant.
    pub groups: Vec<GroupMapping>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupMapping {
    pub group: String,
    #[serde(default)]
    pub roles: Vec<String>,
    #[serde(default)]
    pub teams: Vec<String>,
}

fn default_principal_claim() -> String {
    "email".into()
}
fn default_groups_claim() -> String {
    "groups".into()
}
fn default_algorithms() -> Vec<String> {
    vec!["RS256".into(), "ES256".into()]
}
fn default_leeway() -> u64 {
    60
}
fn default_refresh() -> u64 {
    600
}
fn default_scopes() -> Vec<String> {
    vec!["openid".into(), "profile".into(), "email".into()]
}

impl SsoConfig {
    pub fn validate(&self, development: bool) -> Result<(), String> {
        let https = |url: &str| url.starts_with("https://") || (development && url.starts_with("http://"));
        if !https(&self.issuer) || self.jwks_url.as_deref().is_some_and(|u| !https(u)) {
            return Err("[sso] issuer and jwks_url must be HTTPS (HTTP only with server.development)".into());
        }
        if self.client_id.is_empty() {
            return Err("[sso] client_id is required".into());
        }
        if !https(&self.redirect_uri) {
            return Err("[sso] redirect_uri must be HTTPS (HTTP only with server.development)".into());
        }
        if self.algorithms.is_empty()
            || self
                .algorithms
                .iter()
                .any(|a| Algorithm::from_str(a).map_or(true, |a| a.family() == jsonwebtoken::AlgorithmFamily::Hmac))
        {
            return Err("[sso] algorithms must be asymmetric (RS*, PS*, ES*, EdDSA)".into());
        }
        if self.groups.is_empty() {
            return Err("[sso] needs at least one [[sso.groups]] mapping".into());
        }
        for g in &self.groups {
            if g.group.is_empty() || g.roles.is_empty() {
                return Err("[[sso.groups]] needs a group and at least one role".into());
            }
            if let Some(role) = g.roles.iter().find(|r| !ROLES.contains(&r.as_str())) {
                return Err(format!("[[sso.groups]] {}: unknown role {role}", g.group));
            }
        }
        Ok(())
    }
}

#[derive(Default)]
struct State {
    keys: Option<JwkSet>,
    /// From the issuer's metadata, for the UI.
    authorization_endpoint: Option<String>,
    token_endpoint: Option<String>,
    jwks_url: Option<String>,
    last_fetch: Option<Instant>,
}

/// Verifies ID tokens for one issuer.
pub struct Sso {
    config: SsoConfig,
    state: RwLock<State>,
    refresh_wanted: std::sync::atomic::AtomicBool,
    /// Code exchanges in flight at most: the exchange route is unauthenticated.
    pub exchanges: tokio::sync::Semaphore,
}

impl std::fmt::Debug for Sso {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sso")
            .field("issuer", &self.config.issuer)
            .finish_non_exhaustive()
    }
}

fn path<'a>(claims: &'a Value, dotted: &str) -> &'a Value {
    dotted.split('.').fold(claims, |v, k| &v[k])
}

/// Holds the endpoints an issuer's metadata names to the issuer's own transport:
/// HTTPS, unless the issuer itself is plain HTTP (allowed only in development).
fn discovered_endpoints_secure(issuer: &str, metadata: &Value) -> Result<(), String> {
    let secure =
        |url: &str| url.starts_with("https://") || (issuer.starts_with("http://") && url.starts_with("http://"));
    for field in ["authorization_endpoint", "token_endpoint", "jwks_uri"] {
        if metadata[field].as_str().is_some_and(|u| !secure(u)) {
            return Err(format!("{issuer}: metadata {field} is not HTTPS"));
        }
    }
    Ok(())
}

impl Sso {
    #[must_use]
    pub fn new(config: SsoConfig) -> Arc<Self> {
        Arc::new(Self {
            state: RwLock::new(State {
                jwks_url: config.jwks_url.clone(),
                ..State::default()
            }),
            config,
            refresh_wanted: std::sync::atomic::AtomicBool::new(true),
            exchanges: tokio::sync::Semaphore::new(4),
        })
    }

    /// Installs a key set directly (tests, or keys pinned in configuration).
    pub fn set_keys(&self, keys: JwkSet) {
        if let Ok(mut s) = self.state.write() {
            s.keys = Some(keys);
            s.last_fetch = Some(Instant::now());
        }
    }

    /// What the UI needs to start a sign-in, or `None` before the metadata is known.
    #[must_use]
    pub fn public_settings(&self) -> Value {
        let s = self.state.read().ok();
        json!({"issuer": self.config.issuer, "client_id": self.config.client_id,
            "scopes": self.config.scopes, "redirect_uri": self.config.redirect_uri,
            "authorization_endpoint": s.as_ref().and_then(|s| s.authorization_endpoint.clone())})
    }

    #[must_use]
    pub fn config(&self) -> &SsoConfig {
        &self.config
    }

    #[must_use]
    pub fn token_endpoint(&self) -> Option<String> {
        self.state.read().ok().and_then(|s| s.token_endpoint.clone())
    }

    /// The caller an ID token names, if it verifies and maps to at least one role.
    pub fn authenticate(&self, token: &str) -> Option<Caller> {
        self.verify(token, None)
    }

    /// As [`Self::authenticate`], and the token must carry `nonce` when given (a token
    /// fresh from the sign-in this browser started).
    pub fn verify(&self, token: &str, nonce: Option<&str>) -> Option<Caller> {
        let header = jsonwebtoken::decode_header(token).ok()?;
        let kid = header.kid.as_deref()?;
        let allowed = self
            .config
            .algorithms
            .iter()
            .any(|a| Algorithm::from_str(a).ok() == Some(header.alg));
        if !allowed {
            return None;
        }
        let key = {
            let state = self.state.read().ok()?;
            let jwk = state.keys.as_ref().and_then(|k| k.find(kid)).cloned();
            if jwk.is_none() {
                self.refresh_wanted.store(true, std::sync::atomic::Ordering::Relaxed);
            }
            DecodingKey::from_jwk(&jwk?).ok()?
        };
        let mut validation = Validation::new(header.alg);
        validation.set_issuer(&[&self.config.issuer]);
        validation.set_audience(&[&self.config.client_id]);
        validation.leeway = self.config.leeway_seconds;
        validation.validate_nbf = true;
        validation.set_required_spec_claims(&["exp", "iss", "aud"]);
        let claims = jsonwebtoken::decode::<Value>(token, &key, &validation).ok()?.claims;
        if nonce.is_some_and(|n| claims["nonce"].as_str() != Some(n)) {
            return None;
        }
        let principal = path(&claims, &self.config.principal_claim)
            .as_str()
            .or_else(|| claims["sub"].as_str())
            .filter(|p| !p.is_empty() && p.len() <= 256)?;
        let held: BTreeSet<&str> = match path(&claims, &self.config.groups_claim) {
            Value::Array(items) => items.iter().filter_map(Value::as_str).collect(),
            Value::String(one) => [one.as_str()].into(),
            _ => BTreeSet::new(),
        };
        let mut roles = BTreeSet::new();
        let mut teams = BTreeSet::new();
        for mapping in self.config.groups.iter().filter(|g| held.contains(g.group.as_str())) {
            roles.extend(mapping.roles.iter().cloned());
            teams.extend(mapping.teams.iter().cloned());
        }
        if roles.is_empty() {
            return None;
        }
        Some(Caller {
            principal_id: principal.to_owned(),
            roles: roles.into_iter().collect(),
            teams: teams.into_iter().collect(),
        })
    }

    async fn fetch(client: &reqwest::Client, url: &str) -> Result<Value, String> {
        let response = client
            .get(url)
            .send()
            .await
            .and_then(reqwest::Response::error_for_status)
            .map_err(|e| format!("{url}: {e}"))?;
        let bytes = response.bytes().await.map_err(|e| format!("{url}: {e}"))?;
        if bytes.len() > MAX_DOCUMENT_BYTES {
            return Err(format!("{url}: larger than {MAX_DOCUMENT_BYTES} bytes"));
        }
        serde_json::from_slice(&bytes).map_err(|e| format!("{url}: {e}"))
    }

    /// Fetches the metadata (if needed) and the key set once.
    pub async fn refresh(&self, client: &reqwest::Client) -> Result<(), String> {
        let issuer = self.config.issuer.trim_end_matches('/');
        let metadata = Self::fetch(client, &format!("{issuer}/.well-known/openid-configuration")).await;
        let mut jwks_url = self.config.jwks_url.clone();
        match &metadata {
            Ok(m) => {
                if m["issuer"].as_str() != Some(self.config.issuer.as_str()) {
                    return Err(format!("{issuer}: metadata names another issuer"));
                }
                discovered_endpoints_secure(&self.config.issuer, m)?;
                if let Ok(mut s) = self.state.write() {
                    s.authorization_endpoint = m["authorization_endpoint"].as_str().map(str::to_owned);
                    s.token_endpoint = m["token_endpoint"].as_str().map(str::to_owned);
                }
                jwks_url = jwks_url.or_else(|| m["jwks_uri"].as_str().map(str::to_owned));
            }
            Err(e) if jwks_url.is_none() => return Err(e.clone()),
            Err(_) => {}
        }
        let url = jwks_url.ok_or("no jwks_uri in the issuer's metadata")?;
        let keys: JwkSet =
            serde_json::from_value(Self::fetch(client, &url).await?).map_err(|e| format!("{url}: {e}"))?;
        if let Ok(mut s) = self.state.write() {
            s.keys = Some(keys);
            s.jwks_url = Some(url);
            s.last_fetch = Some(Instant::now());
        }
        Ok(())
    }

    /// Keeps the keys fresh: every `refresh_seconds`, and soon after an unknown `kid`
    /// (at most every 30 seconds).
    pub async fn run(self: Arc<Self>) {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap_or_default();
        let every = Duration::from_secs(self.config.refresh_seconds.max(60));
        loop {
            let last = self.state.read().ok().and_then(|s| s.last_fetch);
            let due = last.is_none_or(|t| {
                t.elapsed() >= every
                    || (self.refresh_wanted.load(std::sync::atomic::Ordering::Relaxed) && t.elapsed() >= MIN_REFRESH)
            });
            if due {
                self.refresh_wanted.store(false, std::sync::atomic::Ordering::Relaxed);
                if let Err(error) = self.refresh(&client).await {
                    tracing::warn!(%error, "sso: could not refresh the issuer's keys");
                }
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovered_endpoints_are_held_to_the_issuers_transport() {
        let https = "https://login.example.com";
        let good = json!({"jwks_uri": "https://login.example.com/keys",
            "token_endpoint": "https://login.example.com/token"});
        assert!(discovered_endpoints_secure(https, &good).is_ok());
        for field in ["authorization_endpoint", "token_endpoint", "jwks_uri"] {
            let mut bad = good.clone();
            bad[field] = json!("http://login.example.com/x");
            assert!(discovered_endpoints_secure(https, &bad).is_err(), "{field}");
        }
        let development = json!({"jwks_uri": "http://127.0.0.1:9/keys"});
        assert!(discovered_endpoints_secure("http://127.0.0.1:9", &development).is_ok());
    }
}
