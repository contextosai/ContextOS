//! HTTP API.
//!
//! | Route | Scope | Purpose |
//! |---|---|---|
//! | `GET /healthz` | – | liveness |
//! | `GET /readyz` | – | store reachable |
//! | `GET /metrics` | – | Prometheus metrics |
//! | `POST /v1/compile` | `compile` | compile a pinned Context Pack for a request |
//! | `POST /v1/contracts/negotiate` | `admit` | negotiate an execution contract against this deployment |
//! | `POST /v1/schemas/{doc}/validate` | – (authenticated) | validate a payload against a published schema |
//! | `GET /v1/audit/verify` | `audit:read` | verify the caller tenant's audit chain |
//!
//! Every body is parsed with strict ingress (duplicate keys rejected). Every request is
//! bound to the caller's tenant; a mismatched tenant is refused without detail.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use axum::Router;
use axum::body::Bytes;
use axum::extract::{MatchedPath, Path, Query, Request, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use contextos_audit::{AuditWriter, KeyRing, verify_tenant_chain};
use contextos_contract::ingress::parse_strict;
use contextos_contract::schema::{SchemaDoc, SchemaTarget, validate};
use contextos_contract::types::{ContextPack, InvokeRequest, RunContext};
use contextos_kernel::{
    CompileDeps, CompileError, ContextPackCompiler, STANDARD_PROFILE_REGISTRY, negotiate_execution_contract,
};
use contextos_store::{AppendLog, DocKey, DocKind, DocumentStore};
use serde_json::{Value, json};

use crate::auth::{Authenticator, Caller};
use crate::metrics::Metrics;

/// A loaded, validated Context Pack.
#[derive(Debug)]
pub struct LoadedPack {
    pub tenant_id: String,
    pub compiler: ContextPackCompiler,
}

pub struct AppState<S, L> {
    pub store: Arc<S>,
    pub audit: Arc<AuditWriter<L>>,
    pub audit_keys: KeyRing,
    pub auth: Authenticator,
    pub metrics: Arc<Metrics>,
    pub packs: HashMap<String, LoadedPack>,
    /// `RuntimeSupportDeclaration` for this deployment.
    pub support: Value,
    pub max_body_bytes: usize,
}

impl<S, L> std::fmt::Debug for AppState<S, L> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppState")
            .field("packs", &self.packs.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

/// API error. Messages are fixed strings; inputs are never echoed back.
#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    code: &'static str,
    message: String,
    detail: Option<Value>,
}

impl ApiError {
    pub fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
            detail: None,
        }
    }

    fn with_detail(mut self, detail: Value) -> Self {
        self.detail = Some(detail);
        self
    }

    fn unauthorized() -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            "unauthenticated",
            "A valid credential is required.",
        )
    }

    fn forbidden() -> Self {
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
        if self.status == StatusCode::UNAUTHORIZED {
            response
                .headers_mut()
                .insert(header::WWW_AUTHENTICATE, "Bearer".parse().expect("static header"));
        }
        response
    }
}

type ApiResult = Result<Response, ApiError>;

fn authorize<S, L>(state: &AppState<S, L>, headers: &HeaderMap, scope: Option<&str>) -> Result<Caller, ApiError> {
    let header = headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok());
    let caller = state.auth.authenticate(header).ok_or_else(ApiError::unauthorized)?;
    match scope {
        Some(scope) if !caller.has(scope) => Err(ApiError::forbidden()),
        _ => Ok(caller),
    }
}

fn parse_body<S, L>(state: &AppState<S, L>, body: &Bytes) -> Result<Value, ApiError> {
    parse_strict(body, state.max_body_bytes).map_err(|e| {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_json",
            "The request body is not acceptable JSON.",
        )
        .with_detail(json!(e.to_string()))
    })
}

fn schema_check(target: &SchemaTarget, value: &Value, code: &'static str) -> Result<(), ApiError> {
    validate(target, value).map_err(|e| {
        ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            code,
            "The payload does not conform to the published schema.",
        )
        .with_detail(serde_json::to_value(&e.violations).unwrap_or(Value::Null))
    })
}

fn same_tenant(caller: &Caller, tenant: &Value) -> Result<(), ApiError> {
    if tenant.as_str() == Some(caller.tenant_id.as_str()) {
        Ok(())
    } else {
        Err(ApiError::forbidden())
    }
}

async fn healthz() -> &'static str {
    "ok"
}

async fn readyz<S: DocumentStore, L>(State(state): State<Arc<AppState<S, L>>>) -> Response {
    let probe = DocKey::new("__contextos", DocKind::ProfileRegistry, "__readiness");
    match state.store.get(&probe).await {
        Ok(_) => (StatusCode::OK, "ready").into_response(),
        Err(_) => (StatusCode::SERVICE_UNAVAILABLE, "store unavailable").into_response(),
    }
}

async fn metrics<S, L>(State(state): State<Arc<AppState<S, L>>>) -> Response {
    (
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        state.metrics.render(),
    )
        .into_response()
}

async fn compile<S, L>(State(state): State<Arc<AppState<S, L>>>, headers: HeaderMap, body: Bytes) -> ApiResult {
    let caller = authorize(&state, &headers, Some("compile"))?;
    let input = parse_body(&state, &body)?;
    schema_check(
        &SchemaTarget::document(SchemaDoc::InvokeAgent),
        &input["request"],
        "request_invalid",
    )?;
    schema_check(
        &SchemaTarget::document(SchemaDoc::RunContext),
        &input["run_context"],
        "run_context_invalid",
    )?;
    same_tenant(&caller, &input["request"]["tenant_id"])?;
    same_tenant(&caller, &input["run_context"]["tenant_id"])?;
    let pack_ref = input["pack_ref"].as_str().unwrap_or_default();
    let pack = state
        .packs
        .get(pack_ref)
        .filter(|p| p.tenant_id == caller.tenant_id)
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::NOT_FOUND,
                "pack_not_found",
                "No such Context Pack for this tenant.",
            )
        })?;
    let request: InvokeRequest = serde_json::from_value(input["request"].clone()).map_err(|_| {
        ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "request_invalid",
            "The request is invalid.",
        )
    })?;
    let run_context: RunContext = serde_json::from_value(input["run_context"].clone()).map_err(|_| {
        ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "run_context_invalid",
            "The run context is invalid.",
        )
    })?;
    let list = |key: &str| input["deps"][key].as_array().cloned().unwrap_or_default();
    let deps = CompileDeps {
        evidence: list("evidence"),
        evidence_conflicts: list("evidence_conflicts"),
        promoted_memory: list("promoted_memory"),
    };
    match pack.compiler.compile(&request, &run_context, &deps) {
        Ok(compiled) => Ok(axum::Json(compiled).into_response()),
        Err(CompileError::PolicyEval(detail)) => Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "policy_eval_error",
            "An applicable policy predicate could not be evaluated.",
        )
        .with_detail(serde_json::to_value(&*detail).unwrap_or(Value::Null))),
        Err(CompileError::Invalid(message)) => Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "compile_invalid",
            message,
        )),
    }
}

async fn negotiate<S, L>(State(state): State<Arc<AppState<S, L>>>, headers: HeaderMap, body: Bytes) -> ApiResult {
    let caller = authorize(&state, &headers, Some("admit"))?;
    let input = parse_body(&state, &body)?;
    same_tenant(&caller, &input["contract"]["tenant_id"])?;
    let registry = serde_json::to_value(&*STANDARD_PROFILE_REGISTRY).unwrap_or(Value::Null);
    let result = negotiate_execution_contract(&input["contract"], &state.support, &registry, &input["features"]);
    Ok(axum::Json(result).into_response())
}

#[derive(serde::Deserialize)]
struct ValidateQuery {
    def: Option<String>,
}

fn schema_doc(name: &str) -> Option<SchemaDoc> {
    SchemaDoc::ALL
        .into_iter()
        .find(|doc| doc.file_name().split(".v").next() == Some(name))
}

async fn validate_schema<S, L>(
    State(state): State<Arc<AppState<S, L>>>,
    Path(doc): Path<String>,
    Query(query): Query<ValidateQuery>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult {
    authorize(&state, &headers, None)?;
    let doc =
        schema_doc(&doc).ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "schema_not_found", "Unknown schema."))?;
    let target = match query.def {
        Some(def) => {
            let known = doc.document()["$defs"].get(&def).is_some();
            if !known {
                return Err(ApiError::new(
                    StatusCode::NOT_FOUND,
                    "schema_not_found",
                    "Unknown schema definition.",
                ));
            }
            SchemaTarget::def(doc, &def)
        }
        None => SchemaTarget::document(doc),
    };
    let instance = parse_body(&state, &body)?;
    Ok(match validate(&target, &instance) {
        Ok(()) => axum::Json(json!({"valid": true, "violations": []})).into_response(),
        Err(e) => axum::Json(json!({"valid": false, "violations": e.violations})).into_response(),
    })
}

async fn audit_verify<S, L: AppendLog>(State(state): State<Arc<AppState<S, L>>>, headers: HeaderMap) -> ApiResult {
    let caller = authorize(&state, &headers, Some("audit:read"))?;
    match verify_tenant_chain(state.audit.log(), &caller.tenant_id, &state.audit_keys).await {
        Ok(entries) => Ok(axum::Json(json!({"verified": true, "entries": entries})).into_response()),
        Err(e) => Ok((
            StatusCode::CONFLICT,
            axum::Json(json!({"verified": false, "error": e.to_string()})),
        )
            .into_response()),
    }
}

async fn observe<S, L>(State(state): State<Arc<AppState<S, L>>>, request: Request, next: Next) -> Response {
    let route = request
        .extensions()
        .get::<MatchedPath>()
        .map_or_else(|| "unmatched".to_owned(), |p| p.as_str().to_owned());
    let started = Instant::now();
    let response = next.run(request).await;
    state
        .metrics
        .observe(&route, response.status().as_u16(), started.elapsed());
    response
}

/// Builds the router with security middleware: body limit, timeout, panic isolation
/// and per-route metrics.
pub fn router<S, L>(state: Arc<AppState<S, L>>, request_timeout: std::time::Duration) -> Router
where
    S: DocumentStore + 'static,
    L: AppendLog + 'static,
{
    let max_body = state.max_body_bytes;
    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz::<S, L>))
        .route("/metrics", get(metrics::<S, L>))
        .route("/v1/compile", post(compile::<S, L>))
        .route("/v1/contracts/negotiate", post(negotiate::<S, L>))
        .route("/v1/schemas/{doc}/validate", post(validate_schema::<S, L>))
        .route("/v1/audit/verify", get(audit_verify::<S, L>))
        .layer(middleware::from_fn_with_state(state.clone(), observe::<S, L>))
        .layer(tower_http::limit::RequestBodyLimitLayer::new(max_body))
        .layer(tower_http::timeout::TimeoutLayer::with_status_code(
            StatusCode::GATEWAY_TIMEOUT,
            request_timeout,
        ))
        .layer(tower_http::catch_panic::CatchPanicLayer::new())
        .with_state(state)
}

/// Loads and validates a Context Pack file.
pub fn load_pack(text: &str) -> Result<(String, LoadedPack), String> {
    let value = parse_strict(text.as_bytes(), 16 * 1024 * 1024).map_err(|e| e.to_string())?;
    validate(&SchemaTarget::document(SchemaDoc::ContextPack), &value).map_err(|e| {
        format!(
            "pack does not conform to context-pack.v2: {} violation(s)",
            e.violations.len()
        )
    })?;
    let pack: ContextPack = serde_json::from_value(value).map_err(|e| e.to_string())?;
    let pack_ref = pack.pack_meta.pack_ref();
    let tenant_id = pack.pack_meta.tenant.tenant_id.clone();
    let compiler = ContextPackCompiler::new(pack).map_err(|e| e.to_string())?;
    Ok((pack_ref, LoadedPack { tenant_id, compiler }))
}
