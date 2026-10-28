//! HTTP/JSON (OpenAPI-style) adapter.
//!
//! `POST {endpoint}/{protocol_tool}` with the arguments as a JSON body, the provider
//! idempotency key in `Idempotency-Key`, W3C trace context and governance correlation
//! headers. Status codes map to effect knowledge:
//!
//! | Response | Outcome |
//! |---|---|
//! | effectful capability without `recovery.completion` | not dispatched (definitive): the call is never sent |
//! | 2xx except 202, 206, 207, effectful | the body's state at `state_pointer`: listed confirmed / partial / not applied (definitive), otherwise unknown |
//! | 2xx except 202, 206, 207, read-only | confirmed (definitive) |
//! | 202, 206, 207 (accepted, partial or multi-status) | unknown; a response `id` becomes the external reference |
//! | 4xx listed in the manifest's `recovery.not_applied_statuses` | not applied (definitive) |
//! | 400, 401, 403, 404, 405, 413, 415, 422 from a read-only capability | not applied (definitive) |
//! | any other 4xx, 3xx, 5xx, lost or oversized response | unknown |
//! | connection never established | not dispatched (definitive) |
//!
//! Reconciliation queries an accepted job only when the pinned manifest declares the
//! provider's completion contract (`recovery.completion`): `GET
//! {endpoint}/{status_tool}/{external_ref}`, mapping the reported state to the listed
//! outcome. An unlisted state, a missing job (404) or a failed lookup stays unknown.
//!
//! Acceptance is not completion (RFC 9110 §15.3.3): a 202 says the provider queued the
//! work, not that the effect's postcondition holds, so the outcome stays unknown until
//! reconciliation establishes it.
//!
//! A client error is not proof of absence either. HTTP gives a 4xx no guarantee that the
//! handler made no change before it failed, and a definitive "not applied" releases
//! shared exposure and permits a retry. An effectful capability is therefore settled as
//! not applied only by the statuses its reviewed manifest declares the provider returns
//! before any effect; a read-only capability has no effect to apply.

use std::time::Duration;

use async_trait::async_trait;
use contextos_contract::ingress::parse_strict;
use contextos_contract::types::ActionEffect;
use contextos_gateway::{Adapter, AdapterCall, AdapterResponse, CapabilityManifest, EffectOutcome, is_path_segment};
use serde_json::{Map, Value};
use url::Url;

use crate::transport::{
    CredentialBroker, EndpointError, Exchange, TransportPolicy, client, governance_headers, pinned_endpoint, send,
};

const REJECTED_BEFORE_EXECUTION: [u16; 8] = [400, 401, 403, 404, 405, 413, 415, 422];
/// Successful statuses that do not establish the effect: accepted, partial content and
/// multi-status.
const UNFINISHED: [u16; 3] = [202, 206, 207];

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
        if !is_path_segment(&manifest.protocol_tool) {
            return not_dispatched();
        }
        // A success status alone cannot confirm an effect; without the provider's
        // reported-state contract an effectful call is not sent (contextosd refuses
        // such a configuration at startup).
        if manifest.action_risk.effect != ActionEffect::None && manifest.recovery.completion.is_none() {
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
                    s if UNFINISHED.contains(&s) => AdapterResponse {
                        output,
                        external_ref,
                        ..AdapterResponse::unknown()
                    },
                    200..=299 => success(manifest, output, external_ref),
                    s if rejected_before_execution(manifest, s) => AdapterResponse {
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

    /// Looks up an accepted job when the manifest declares how; otherwise only an
    /// operator can reconcile.
    async fn query(
        &self,
        manifest: &CapabilityManifest,
        call: &AdapterCall,
        external_ref: &str,
    ) -> Option<AdapterResponse> {
        let check = manifest.recovery.completion.as_ref()?;
        Some(self.completion(manifest, call, check, external_ref).await)
    }
}

impl HttpAdapter {
    /// `GET {endpoint}/{status_tool}/{external_ref}` under the declared completion contract.
    async fn completion(
        &self,
        manifest: &CapabilityManifest,
        call: &AdapterCall,
        check: &contextos_gateway::CompletionCheck,
        external_ref: &str,
    ) -> AdapterResponse {
        if !is_path_segment(&check.status_tool) {
            return AdapterResponse::unknown();
        }
        let Ok(mut url) = self.endpoint.join(&format!("{}/", check.status_tool)) else {
            return AdapterResponse::unknown();
        };
        // The reference is percent-encoded as one segment: it cannot add path or query.
        if let Ok(mut segments) = url.path_segments_mut() {
            segments.pop_if_empty().push(external_ref);
        } else {
            return AdapterResponse::unknown();
        }
        let Ok(credential) = self.credentials.credential(manifest, call).await else {
            return AdapterResponse::unknown();
        };
        let request = self
            .client
            .get(url)
            .headers(governance_headers(call, credential.as_ref()));
        let Exchange::Response { status: 200, body, .. } = send(
            request,
            Duration::from_millis(manifest.timeout_ms),
            self.policy.max_response_bytes,
        )
        .await
        else {
            return AdapterResponse::unknown();
        };
        let Ok(value) = parse_strict(&body, self.policy.max_response_bytes) else {
            return AdapterResponse::unknown();
        };
        let outcome = value
            .pointer(&check.state_pointer)
            .and_then(Value::as_str)
            .and_then(|state| check.outcome(state));
        let output = object(value);
        match outcome {
            Some(outcome) => AdapterResponse {
                outcome,
                definitive: true,
                output,
                external_ref: Some(external_ref.to_owned()),
                cost_units: None,
            },
            None => AdapterResponse {
                output,
                external_ref: Some(external_ref.to_owned()),
                ..AdapterResponse::unknown()
            },
        }
    }
}

/// A finished 2xx. Under the provider contract (`recovery.completion`, required for
/// effectful capabilities) the reported state decides, as it does for a status lookup:
/// a `200` whose body says `pending` or `failed` is not a confirmed effect. An unlisted
/// or missing state stays unknown, keeping the provider's `id` so reconciliation can
/// look the effect up. A read-only capability without a contract has no effect to
/// confirm, and its success status stands.
fn success(manifest: &CapabilityManifest, output: Map<String, Value>, external_ref: Option<String>) -> AdapterResponse {
    let outcome = match &manifest.recovery.completion {
        None => Some(EffectOutcome::Confirmed),
        Some(check) => pointer(&output, &check.state_pointer)
            .and_then(Value::as_str)
            .and_then(|state| check.outcome(state)),
    };
    match outcome {
        Some(outcome) => AdapterResponse {
            outcome,
            definitive: true,
            output,
            external_ref,
            cost_units: None,
        },
        None => AdapterResponse {
            output,
            external_ref,
            ..AdapterResponse::unknown()
        },
    }
}

/// RFC 6901 lookup in an object, without copying it into a `Value`.
fn pointer<'a>(object: &'a Map<String, Value>, pointer: &str) -> Option<&'a Value> {
    let rest = pointer.strip_prefix('/')?;
    let (head, tail) = rest.split_once('/').map_or((rest, None), |(h, t)| (h, Some(t)));
    let value = object.get(&head.replace("~1", "/").replace("~0", "~"))?;
    match tail {
        None => Some(value),
        Some(tail) => value.pointer(&format!("/{tail}")),
    }
}

/// Whether `status` establishes that the effect was not applied: a status the
/// manifest declares for this provider, or a request rejection when there is no effect.
pub(crate) fn rejected_before_execution(manifest: &CapabilityManifest, status: u16) -> bool {
    manifest.recovery.not_applied_statuses.contains(&status)
        || (manifest.action_risk.effect == ActionEffect::None && REJECTED_BEFORE_EXECUTION.contains(&status))
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
