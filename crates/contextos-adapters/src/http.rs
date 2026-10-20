//! HTTP/JSON (OpenAPI-style) adapter.
//!
//! `POST {endpoint}/{protocol_tool}` with the arguments as a JSON body, the provider
//! idempotency key in `Idempotency-Key`, W3C trace context and governance correlation
//! headers. Status codes map to effect knowledge:
//!
//! | Response | Outcome |
//! |---|---|
//! | 2xx | confirmed (definitive) |
//! | 400, 401, 403, 404, 405, 413, 415, 422 | not applied (definitive; rejected before execution) |
//! | anything else (3xx, 408, 409, 429, 5xx), lost or oversized response | unknown |
//! | connection never established | not dispatched (definitive) |

use std::time::Duration;

use async_trait::async_trait;
use contextos_contract::ingress::parse_strict;
use contextos_gateway::{Adapter, AdapterCall, AdapterResponse, CapabilityManifest, EffectOutcome};
use serde_json::{Map, Value};
use url::Url;

use crate::transport::{
    CredentialBroker, EndpointError, Exchange, TransportPolicy, client, governance_headers, pinned_endpoint, send,
};

const REJECTED_BEFORE_EXECUTION: [u16; 8] = [400, 401, 403, 404, 405, 413, 415, 422];

pub struct HttpAdapter {
    endpoint: Url,
    policy: TransportPolicy,
    client: reqwest::Client,
    credentials: std::sync::Arc<dyn CredentialBroker>,
}

impl std::fmt::Debug for HttpAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpAdapter")
            .field("endpoint", &self.endpoint.as_str())
            .finish_non_exhaustive()
    }
}

impl HttpAdapter {
    pub fn new(
        endpoint: &str,
        policy: TransportPolicy,
        credentials: std::sync::Arc<dyn CredentialBroker>,
    ) -> Result<Self, EndpointError> {
        let mut endpoint = pinned_endpoint(endpoint, &policy)?;
        if !endpoint.path().ends_with('/') {
            let path = format!("{}/", endpoint.path());
            endpoint.set_path(&path);
        }
        Ok(Self {
            client: client(&policy),
            endpoint,
            policy,
            credentials,
        })
    }
}

pub(crate) fn object(value: Value) -> Map<String, Value> {
    match value {
        Value::Object(map) => map,
        other => {
            let mut map = Map::new();
            map.insert("value".into(), other);
            map
        }
    }
}

#[async_trait]
impl Adapter for HttpAdapter {
    async fn invoke(&self, manifest: &CapabilityManifest, call: &AdapterCall) -> AdapterResponse {
        // Tool names are path segments only; they cannot address another origin or path.
        if manifest.protocol_tool.is_empty()
            || !manifest
                .protocol_tool
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        {
            return not_dispatched();
        }
        let Ok(url) = self.endpoint.join(&manifest.protocol_tool) else {
            return not_dispatched();
        };
        let Ok(credential) = self.credentials.credential(manifest, call).await else {
            return not_dispatched();
        };
        let request = self
            .client
            .post(url)
            .headers(governance_headers(call, credential.as_ref()))
            .json(&call.arguments);
        match send(
            request,
            Duration::from_millis(manifest.timeout_ms),
            self.policy.max_response_bytes,
        )
        .await
        {
            Exchange::NotSent => not_dispatched(),
            Exchange::Lost => AdapterResponse::unknown(),
            Exchange::Response { status, body, .. } => {
                let output = if body.is_empty() {
                    Map::new()
                } else {
                    match parse_strict(&body, self.policy.max_response_bytes) {
                        Ok(value) => object(value),
                        Err(_) if (200..300).contains(&status) => return AdapterResponse::unknown(),
                        Err(_) => Map::new(),
                    }
                };
                let external_ref = output.get("id").and_then(Value::as_str).map(str::to_owned);
                match status {
                    200..=299 => AdapterResponse {
                        outcome: EffectOutcome::Confirmed,
                        definitive: true,
                        output,
                        external_ref,
                        cost_units: None,
                    },
                    s if REJECTED_BEFORE_EXECUTION.contains(&s) => AdapterResponse {
                        outcome: EffectOutcome::NotApplied,
                        definitive: true,
                        output,
                        external_ref: None,
                        cost_units: None,
                    },
                    _ => AdapterResponse {
                        output,
                        ..AdapterResponse::unknown()
                    },
                }
            }
        }
    }
}

pub(crate) fn not_dispatched() -> AdapterResponse {
    AdapterResponse {
        outcome: EffectOutcome::NotDispatched,
        definitive: true,
        output: Map::new(),
        external_ref: None,
        cost_units: None,
    }
}
