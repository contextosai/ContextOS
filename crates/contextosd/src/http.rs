//! HTTP plumbing shared by every route: the API error type, caller authorization,
//! body parsing and schema checks, and the unauthenticated probe, key and metrics
//! endpoints.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use contextos_contract::ingress::parse_strict;
use contextos_contract::schema::{SchemaTarget, validate};
use contextos_store::{DocKey, DocKind, DocumentStore};
use serde_json::{Value, json};

use crate::app::AppState;
use crate::auth::Caller;

/// API error. Messages are fixed strings; inputs are never echoed back.
#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    code: &'static str,
    message: String,
    detail: Option<Value>,
    retry_after_seconds: Option<u64>,
    /// `WWW-Authenticate` value; a `401` without one sends `Bearer`.
    challenge: Option<String>,
}

impl ApiError {
    pub fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
            detail: None,
            retry_after_seconds: None,
            challenge: None,
        }
    }

    pub(crate) fn retry_after(mut self, wait: std::time::Duration) -> Self {
        // Whole seconds, rounded up, at least one.
        self.retry_after_seconds = Some((wait.as_secs() + u64::from(wait.subsec_nanos() > 0)).max(1));
        self
    }

    pub(crate) fn with_challenge(mut self, challenge: String) -> Self {
        self.challenge = Some(challenge);
        self
    }

    pub(crate) fn with_detail(mut self, detail: Value) -> Self {
        self.detail = Some(detail);
        self
    }

    pub(crate) fn unauthorized() -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            "unauthenticated",
            "A valid credential is required.",
        )
    }

    pub(crate) fn forbidden() -> Self {
        Self::new(
            StatusCode::FORBIDDEN,
            "forbidden",
            "The caller is not permitted to perform this request.",
        )
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let mut body = json!({"error": {"code": self.code, "message": self.message}});
        if let Some(detail) = self.detail {
            body["error"]["detail"] = detail;
        }
        let mut response = (self.status, axum::Json(body)).into_response();
        if let Some(seconds) = self.retry_after_seconds {
            response
                .headers_mut()
                .insert(header::RETRY_AFTER, header::HeaderValue::from(seconds));
        }
        let challenge = match self.challenge {
            Some(challenge) => header::HeaderValue::from_str(&challenge).ok(),
            None => (self.status == StatusCode::UNAUTHORIZED).then(|| header::HeaderValue::from_static("Bearer")),
        };
        if let Some(challenge) = challenge {
            response.headers_mut().insert(header::WWW_AUTHENTICATE, challenge);
        }
        response
    }
}

pub(crate) type ApiResult = Result<Response, ApiError>;

pub(crate) fn authorize<S, L>(
    state: &AppState<S, L>,
    headers: &HeaderMap,
    scope: Option<&str>,
) -> Result<Caller, ApiError> {
    authorize_resource(state, headers, scope, "")
}

/// As [`authorize`], naming `resource_path`'s protected resource metadata in the
/// challenge of a refusal (see [`crate::protected_resource`]).
pub(crate) fn authorize_resource<S, L>(
    state: &AppState<S, L>,
    headers: &HeaderMap,
    scope: Option<&str>,
    resource_path: &str,
) -> Result<Caller, ApiError> {
    let public_url = state.public_url.as_deref();
    let header = headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok());
    let caller = state.auth.authenticate(header).ok_or_else(|| {
        ApiError::unauthorized().with_challenge(crate::protected_resource::challenge(public_url, resource_path, None))
    })?;
    if let Some(scope) = scope
        && !caller.has(scope)
    {
        return Err(
            ApiError::forbidden().with_challenge(crate::protected_resource::challenge(
                public_url,
                resource_path,
                Some(scope),
            )),
        );
    }
    state.limits.take(&caller.tenant_id).map_err(|wait| {
        ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            "The tenant's request rate limit is exceeded.",
        )
        .retry_after(wait)
    })?;
    Ok(caller)
}

pub(crate) fn parse_body<S, L>(state: &AppState<S, L>, body: &Bytes) -> Result<Value, ApiError> {
    parse_strict(body, state.max_body_bytes).map_err(|e| {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_json",
            "The request body is not acceptable JSON.",
        )
        .with_detail(json!(e.to_string()))
    })
}

pub(crate) fn schema_check(target: &SchemaTarget, value: &Value, code: &'static str) -> Result<(), ApiError> {
    validate(target, value).map_err(|e| {
        ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            code,
            "The payload does not conform to the published schema.",
        )
        .with_detail(serde_json::to_value(&e.violations).unwrap_or(Value::Null))
    })
}

pub(crate) fn same_tenant(caller: &Caller, tenant: &Value) -> Result<(), ApiError> {
    if tenant.as_str() == Some(caller.tenant_id.as_str()) {
        Ok(())
    } else {
        Err(ApiError::forbidden())
    }
}

/// The OpenAPI 3.1 description of this API (`openapi/contextosd.v1.json`).
pub const OPENAPI: &str = include_str!("../../../openapi/contextosd.v1.json");

pub(crate) async fn openapi() -> Response {
    ([(header::CONTENT_TYPE, "application/json")], OPENAPI).into_response()
}

/// The audit chain's public signing keys, so anyone can verify exported entries
/// (`ctx audit-verify`) without trusting this server.
pub(crate) async fn audit_keys<S, L>(State(state): State<Arc<AppState<S, L>>>) -> Response {
    let keys: Vec<Value> = state
        .audit_keys
        .public_keys()
        .into_iter()
        .map(|(kid, key, retired_at)| match retired_at {
            Some(retired_at) => json!({"kid": kid, "alg": "ed25519", "public_key": key, "retired_at": retired_at}),
            None => json!({"kid": kid, "alg": "ed25519", "public_key": key}),
        })
        .collect();
    axum::Json(json!({"keys": keys})).into_response()
}

pub(crate) async fn healthz() -> &'static str {
    "ok"
}

pub(crate) fn request_span<B>(request: &axum::http::Request<B>) -> tracing::Span {
    let route = request
        .extensions()
        .get::<axum::extract::MatchedPath>()
        .map_or("unmatched", axum::extract::MatchedPath::as_str);
    let span = tracing::info_span!("http.request", method = %request.method(), route, otel.kind = "server");
    crate::telemetry::link_parent(&span, request.headers());
    span
}

pub(crate) async fn readyz<S: DocumentStore, L>(State(state): State<Arc<AppState<S, L>>>) -> Response {
    if !state.auth.ready() {
        return (StatusCode::SERVICE_UNAVAILABLE, "identity keys not loaded").into_response();
    }
    let probe = DocKey::new("__contextos", DocKind::ProfileRegistry, "__readiness");
    match state.store.get(&probe).await {
        Ok(_) => (StatusCode::OK, "ready").into_response(),
        Err(_) => (StatusCode::SERVICE_UNAVAILABLE, "store unavailable").into_response(),
    }
}

pub(crate) async fn metrics<S, L>(State(state): State<Arc<AppState<S, L>>>) -> Response {
    (
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        format!(
            "{}# HELP contextos_replicas Live replicas sharing tenant limits.\n# TYPE contextos_replicas gauge\ncontextos_replicas {}\n",
            state.metrics.render(),
            state.limits.replicas()
        ),
    )
        .into_response()
}
