//! Shared HTTP transport discipline for adapters.
//!
//! - The endpoint is pinned at construction: HTTPS only (plain HTTP is accepted only
//!   for an explicitly allowed loopback test endpoint).
//! - Redirects are never followed; a redirect cannot move an effect to another origin.
//! - Responses are read up to a hard size limit.
//! - Credentials come from a broker per call and are never logged or echoed.
//! - Failures are classified by *what is known about the effect*: a request that
//!   never connected was not dispatched; anything after the request may have
//!   been sent is unknown, never "failed".

use std::time::Duration;

use async_trait::async_trait;
use contextos_gateway::{AdapterCall, CapabilityManifest, PortError};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use sha2::{Digest, Sha256};
use url::Url;

/// A short-lived, capability-scoped credential. Its value is never printed.
#[derive(Clone)]
pub struct Credential(String);

impl Credential {
    pub fn bearer(token: impl Into<String>) -> Self {
        Self(token.into())
    }

    pub(crate) fn header(&self) -> Option<HeaderValue> {
        let mut value = HeaderValue::from_str(&format!("Bearer {}", self.0)).ok()?;
        value.set_sensitive(true);
        Some(value)
    }
}

impl std::fmt::Debug for Credential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Credential(<redacted>)")
    }
}

/// Issues credentials bound to actor, capability, destination and lifetime. Tokens
/// presented by callers are never passed through to providers.
#[async_trait]
pub trait CredentialBroker: Send + Sync {
    async fn credential(
        &self,
        manifest: &CapabilityManifest,
        call: &AdapterCall,
    ) -> Result<Option<Credential>, PortError>;

    /// A credential for reading the provider's tool definitions (discovery, no effect).
    /// `None` by default: discovery is sent without one.
    async fn discovery_credential(&self) -> Result<Option<Credential>, PortError> {
        Ok(None)
    }
}

/// A broker for providers that need no credential.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoCredentials;

#[async_trait]
impl CredentialBroker for NoCredentials {
    async fn credential(&self, _: &CapabilityManifest, _: &AdapterCall) -> Result<Option<Credential>, PortError> {
        Ok(None)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EndpointError {
    #[error("endpoint is not a valid URL")]
    Invalid,
    #[error("endpoint must use https")]
    Insecure,
    #[error("endpoint must not carry credentials, a query or a fragment")]
    Unsafe,
}

/// Transport limits for one adapter.
#[derive(Debug, Clone)]
pub struct TransportPolicy {
    pub max_response_bytes: usize,
    pub connect_timeout: Duration,
    /// Permit `http://` only when the host is a loopback address (local testing).
    pub allow_loopback_http: bool,
}

impl Default for TransportPolicy {
    fn default() -> Self {
        Self {
            max_response_bytes: 4 * 1024 * 1024,
            connect_timeout: Duration::from_secs(5),
            allow_loopback_http: false,
        }
    }
}

pub fn pinned_endpoint(endpoint: &str, policy: &TransportPolicy) -> Result<Url, EndpointError> {
    let url = Url::parse(endpoint).map_err(|_| EndpointError::Invalid)?;
    if !url.username().is_empty() || url.password().is_some() || url.query().is_some() || url.fragment().is_some() {
        return Err(EndpointError::Unsafe);
    }
    let loopback = match url.host() {
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        Some(url::Host::Domain(d)) => d == "localhost",
        None => false,
    };
    match url.scheme() {
        "https" => Ok(url),
        "http" if policy.allow_loopback_http && loopback => Ok(url),
        _ => Err(EndpointError::Insecure),
    }
}

pub fn client(policy: &TransportPolicy) -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(policy.connect_timeout)
        .https_only(!policy.allow_loopback_http)
        .user_agent(concat!("contextos-gateway/", env!("CARGO_PKG_VERSION")))
        .build()
        .expect("static client configuration is valid")
}

/// W3C `traceparent` for one attempt: the run's trace id and a span id derived from
/// the attempt id.
pub(crate) fn traceparent(call: &AdapterCall) -> Option<String> {
    let trace = call.trace_id.to_ascii_lowercase();
    if trace.len() != 32 || !trace.bytes().all(|b| b.is_ascii_hexdigit()) || trace.bytes().all(|b| b == b'0') {
        return None;
    }
    let span = hex::encode(&Sha256::digest(call.attempt_id.as_bytes())[..8]);
    Some(format!("00-{trace}-{span}-01"))
}

pub(crate) fn governance_headers(call: &AdapterCall, credential: Option<&Credential>) -> HeaderMap {
    let mut headers = HeaderMap::new();
    let mut put = |name: &'static str, value: &str| {
        if let Ok(value) = HeaderValue::from_str(value) {
            headers.insert(HeaderName::from_static(name), value);
        }
    };
    if let Some(tp) = traceparent(call) {
        put("traceparent", &tp);
    }
    if let Some(key) = &call.idempotency_key {
        put("idempotency-key", key);
    }
    put("x-contextos-operation-id", &call.operation_id);
    put("x-contextos-attempt-id", &call.attempt_id);
    put("x-contextos-action-digest", &call.action_digest);
    if let Some(generation) = call.executor_generation {
        put("x-contextos-executor-generation", &generation.to_string());
    }
    if let Some(value) = credential.and_then(Credential::header) {
        headers.insert(reqwest::header::AUTHORIZATION, value);
    }
    headers
}

/// What reached (or did not reach) the provider.
#[derive(Debug)]
pub(crate) enum Exchange {
    /// The request never left: connection refused, DNS failure, TLS failure.
    NotSent,
    /// The request may have been delivered but no complete response was read.
    Lost,
    /// A complete response within limits.
    Response {
        status: u16,
        content_type: String,
        body: Vec<u8>,
    },
}

pub(crate) async fn send(request: reqwest::RequestBuilder, timeout: Duration, max_bytes: usize) -> Exchange {
    let response = match request.timeout(timeout).send().await {
        Ok(response) => response,
        Err(error) if error.is_connect() || error.is_builder() => return Exchange::NotSent,
        Err(_) => return Exchange::Lost,
    };
    let status = response.status().as_u16();
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_ascii_lowercase();
    let mut response = response;
    let mut body = Vec::new();
    loop {
        match response.chunk().await {
            Ok(Some(chunk)) => {
                if body.len() + chunk.len() > max_bytes {
                    return Exchange::Lost;
                }
                body.extend_from_slice(&chunk);
            }
            Ok(None) => break,
            Err(_) => return Exchange::Lost,
        }
    }
    Exchange::Response {
        status,
        content_type,
        body,
    }
}
