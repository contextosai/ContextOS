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
//! | `POST /v1/runs` | `admit` | compile, negotiate and admit a run (pins policy, opens ledgers) |
//! | `POST /v1/runs/{run_id}/tool-calls` | `dispatch` | govern and dispatch one tool call |
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
use contextos_contract::validation::is_contract_timestamp;
use contextos_gateway::{AdmissionError, AdmissionRequest, BudgetLimits, Gateway, RunAdmission, admit_run};
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
    /// Governed dispatch; `None` when no fact providers are configured.
    pub gateway: Option<Arc<Gateway<S, L>>>,
    pub trust_domain: String,
    pub gateway_principal_id: String,
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

fn dispatch_gateway<S, L>(state: &AppState<S, L>) -> Result<&Arc<Gateway<S, L>>, ApiError> {
    state.gateway.as_ref().ok_or_else(|| {
        ApiError::new(
            StatusCode::NOT_IMPLEMENTED,
            "dispatch_disabled",
            "Governed dispatch is not configured on this deployment.",
        )
    })
}

async fn admit<S, L>(State(state): State<Arc<AppState<S, L>>>, headers: HeaderMap, body: Bytes) -> ApiResult
where
    S: DocumentStore + 'static,
    L: AppendLog + 'static,
{
    let caller = authorize(&state, &headers, Some("admit"))?;
    let gateway = dispatch_gateway(&state)?;
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
    for tenant in [
        &input["request"]["tenant_id"],
        &input["run_context"]["tenant_id"],
        &input["contract"]["tenant_id"],
    ] {
        same_tenant(&caller, tenant)?;
    }
    let run_context_value = &input["run_context"];
    if input["contract"]["run_id"] != run_context_value["run_id"]
        || input["contract"]["trace_id"] != run_context_value["trace_id"]
    {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "contract_unbound",
            "The contract is not bound to this run.",
        ));
    }
    let deadline = input["deadline"]
        .as_str()
        .filter(|d| is_contract_timestamp(d))
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "deadline_invalid",
                "A contract timestamp deadline is required.",
            )
        })?;
    let limits: BudgetLimits = serde_json::from_value(input["limits"].clone()).map_err(|_| {
        ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "limits_invalid",
            "Budget limits are required.",
        )
    })?;
    let pack = state
        .packs
        .get(input["pack_ref"].as_str().unwrap_or_default())
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
    let run_context: RunContext = serde_json::from_value(run_context_value.clone()).map_err(|_| {
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
    let compiled = pack
        .compiler
        .compile(&request, &run_context, &deps)
        .map_err(|e| match e {
            CompileError::PolicyEval(detail) => ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "policy_eval_error",
                "An applicable policy predicate could not be evaluated.",
            )
            .with_detail(serde_json::to_value(&*detail).unwrap_or(Value::Null)),
            CompileError::Invalid(message) => {
                ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, "compile_invalid", message)
            }
        })?;
    let features = crate::runtime::derive_features(
        gateway,
        &compiled,
        pack.compiler.pack().pack_meta.data_classification,
        &input["features"],
    )
    .map_err(|message| ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, "features_invalid", message))?;
    let principal = |id: &str, kind: &str| json!({"principal_id": id, "principal_type": kind, "trust_domain": state.trust_domain, "tenant_id": caller.tenant_id});
    let admission = admit_run(
        state.store.as_ref(),
        AdmissionRequest {
            contract: &input["contract"],
            support: &state.support,
            registry: &STANDARD_PROFILE_REGISTRY,
            features,
            compiled: &compiled,
            compiler: &pack.compiler,
            request: &request,
            run_context: &run_context,
            actor: principal(&run_context.agent.agent_id, "agent"),
            gateway_observer: principal(&state.gateway_principal_id, "workload"),
            deadline: deadline.to_owned(),
            executor_generation: 1,
            limits,
        },
    )
    .await
    .map_err(|e| match e {
        AdmissionError::ContractRejected(reasons) => ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "contract_rejected",
            "The execution contract cannot be admitted.",
        )
        .with_detail(json!(reasons)),
        AdmissionError::Store(e) if e.is_conflict() => ApiError::new(
            StatusCode::CONFLICT,
            "run_exists",
            "This run has already been admitted.",
        ),
        AdmissionError::Budget(code) => ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, "limits_invalid", code),
        other => ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "admission_failed", other.to_string()),
    })?;
    let stored = serde_json::to_value(&admission).unwrap_or(Value::Null);
    state
        .store
        .create(
            &DocKey::new(&caller.tenant_id, DocKind::RunAdmission, &admission.run_id),
            &stored,
        )
        .await
        .map_err(|_| {
            ApiError::new(
                StatusCode::CONFLICT,
                "run_exists",
                "This run has already been admitted.",
            )
        })?;
    Ok((
        StatusCode::CREATED,
        axum::Json(json!({
            "run_id": admission.run_id,
            "compiled_context_hash": compiled.context_ledger.compiled_context_hash,
            "required_controls": admission.required_controls,
            "policy_refs": admission.policy_refs,
            "policy_outcomes": admission.policy_outcomes,
            "features": features,
            "compiled": compiled,
        })),
    )
        .into_response())
}

async fn tool_call<S, L>(
    State(state): State<Arc<AppState<S, L>>>,
    Path(run_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult
where
    S: DocumentStore + 'static,
    L: AppendLog + 'static,
{
    let caller = authorize(&state, &headers, Some("dispatch"))?;
    let gateway = dispatch_gateway(&state)?;
    let envelope = parse_body(&state, &body)?;
    // The admission is looked up under the caller's tenant, so another tenant's run
    // is indistinguishable from a missing one.
    let stored = state
        .store
        .get(&DocKey::new(&caller.tenant_id, DocKind::RunAdmission, &run_id))
        .await
        .map_err(|_| {
            ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "store_unavailable",
                "The store is unavailable.",
            )
        })?
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "run_not_found", "No such run."))?;
    let admission: RunAdmission = serde_json::from_value(stored.body).map_err(|_| {
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "admission_corrupt",
            "The stored admission is unreadable.",
        )
    })?;
    let outcome = gateway.dispatch(&admission, &envelope).await.map_err(|_| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "dispatch_unavailable",
            "Governed dispatch is temporarily unavailable.",
        )
    })?;
    state.metrics.dispatch_outcome(outcome.report.status.as_str());
    Ok(axum::Json(json!({"result": outcome.result, "report": outcome.report})).into_response())
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
        .route("/v1/runs", post(admit::<S, L>))
        .route("/v1/runs/{run_id}/tool-calls", post(tool_call::<S, L>))
        .layer(middleware::from_fn_with_state(state.clone(), observe::<S, L>))
        .layer(tower_http::set_header::SetResponseHeaderLayer::overriding(
            header::X_CONTENT_TYPE_OPTIONS,
            header::HeaderValue::from_static("nosniff"),
        ))
        .layer(tower_http::set_header::SetResponseHeaderLayer::overriding(
            header::CACHE_CONTROL,
            header::HeaderValue::from_static("no-store"),
        ))
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
