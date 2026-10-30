//! A credential broker that obtains provider tokens with the OAuth 2.0 client
//! credentials grant (RFC 6749 §4.4), for providers such as MCP servers that require
//! OAuth.
//!
//! The token endpoint is pinned like any adapter endpoint (HTTPS, no redirects, a
//! size-limited response). The client authenticates with HTTP Basic, and the request
//! names the provider as the RFC 8707 `resource`, so the token is audience-bound to it.
//! Tokens are cached and refreshed before they expire. One fetch runs at a time, so a
//! burst of calls does not stampede the authorization server. A token that cannot be
//! obtained fails the call before anything is sent. Tokens are never logged.

use std::time::{Duration, Instant};

use async_trait::async_trait;
use contextos_contract::ingress::parse_strict;
use contextos_gateway::{AdapterCall, CapabilityManifest, PortError};
use tokio::sync::Mutex;
use url::Url;

use crate::transport::{Credential, CredentialBroker, Exchange, TransportPolicy, client, pinned_endpoint, send};

const MAX_TOKEN_RESPONSE: usize = 64 * 1024;
/// When a token response omits `expires_in`.
const DEFAULT_LIFETIME: Duration = Duration::from_secs(300);

pub struct OAuthClientCredentials {
    token_url: Url,
    client_id: String,
    client_secret: String,
    scope: Option<String>,
    resource: String,
    refresh_before: Duration,
    client: reqwest::Client,
    timeout: Duration,
    /// The current token and when to replace it.
    cached: Mutex<Option<(Credential, Instant)>>,
}

impl std::fmt::Debug for OAuthClientCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OAuthClientCredentials")
            .field("token_url", &self.token_url.as_str())
            .field("client_id", &self.client_id)
            .field("resource", &self.resource)
            .finish_non_exhaustive()
    }
}

fn port(message: impl Into<String>) -> PortError {
    PortError::new("credentials", message)
}

impl OAuthClientCredentials {
    /// `resource` is the provider's URL (RFC 8707); `refresh_before` is how long
    /// before expiry a cached token is replaced.
    pub fn new(
        token_url: &str,
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        scope: Option<String>,
        resource: impl Into<String>,
        refresh_before: Duration,
        policy: &TransportPolicy,
    ) -> Result<Self, crate::EndpointError> {
        Ok(Self {
            token_url: pinned_endpoint(token_url, policy)?,
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            scope,
            resource: resource.into(),
            refresh_before,
            client: client(policy),
            timeout: policy.connect_timeout.max(Duration::from_secs(5)),
            cached: Mutex::new(None),
        })
    }

    async fn fetch(&self) -> Result<(Credential, Instant), PortError> {
        let mut form = vec![
            ("grant_type", "client_credentials"),
            ("resource", self.resource.as_str()),
        ];
        if let Some(scope) = &self.scope {
            form.push(("scope", scope));
        }
        let body = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(form)
            .finish();
        let request = self
            .client
            .post(self.token_url.clone())
            .basic_auth(&self.client_id, Some(&self.client_secret))
            .header(reqwest::header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(reqwest::header::ACCEPT, "application/json")
            .body(body);
        let Exchange::Response { status, body, .. } = send(request, self.timeout, MAX_TOKEN_RESPONSE).await else {
            return Err(port("token endpoint unreachable"));
        };
        if !(200..300).contains(&status) {
            return Err(port(format!("token endpoint answered {status}")));
        }
        let token = parse_strict(&body, MAX_TOKEN_RESPONSE).map_err(|_| port("token response is not JSON"))?;
        let access = token["access_token"]
            .as_str()
            .filter(|t| !t.is_empty())
            .ok_or_else(|| port("token response has no access_token"))?;
        if !token["token_type"]
            .as_str()
            .is_some_and(|t| t.eq_ignore_ascii_case("bearer"))
        {
            return Err(port("token response is not a bearer token"));
        }
        let lifetime = token["expires_in"]
            .as_u64()
            .map_or(DEFAULT_LIFETIME, Duration::from_secs);
        // Refreshed `refresh_before` ahead of expiry, or halfway for short-lived tokens.
        let refresh_at = Instant::now() + lifetime.saturating_sub(self.refresh_before.min(lifetime / 2));
        Ok((Credential::bearer(access), refresh_at))
    }
}

#[async_trait]
impl CredentialBroker for OAuthClientCredentials {
    async fn credential(&self, _: &CapabilityManifest, _: &AdapterCall) -> Result<Option<Credential>, PortError> {
        let mut cached = self.cached.lock().await;
        if let Some((credential, refresh_at)) = cached.as_ref()
            && Instant::now() < *refresh_at
        {
            return Ok(Some(credential.clone()));
        }
        let fresh = self.fetch().await?;
        let credential = fresh.0.clone();
        *cached = Some(fresh);
        Ok(Some(credential))
    }
}
