//! HTTP API.
//!
//! | Route | Scope | Purpose |
//! |---|---|---|
//! | `GET /healthz` | – | liveness |
//! | `GET /readyz` | – | store reachable and OIDC keys loaded |
//! | `GET /metrics` | – | Prometheus metrics |
//! | `GET /v1/openapi.json` | – | this API as OpenAPI 3.1 (`openapi/contextosd.v1.json`) |
//! | `POST /v1/compile` | `compile` | compile a pinned Context Pack for a request |
//! | `POST /v1/contracts/negotiate` | `admit` | negotiate an execution contract against this deployment |
//! | `POST /v1/schemas/{doc}/validate` | – (authenticated) | validate a payload against a published schema |
//! | `GET /v1/audit/verify` | `audit:read` | verify the caller tenant's audit chain |
//! | `GET /v1/revocations` | `control` | the tenant's revoked targets (kill switch) |
//! | `POST /v1/revocations` | `control` | revoke a `tenant`, `pack`, `agent`, `adapter` or `capability`: refused at the next dispatch and admission |
//! | `POST /v1/revocations/restore` | `control` | restore a revoked target |
//! | `GET /v1/audit/entries?from=&limit=` | `audit:read` | page the signed audit chain out |
//! | `POST /v1/runs/{run_id}/decisions` | `dispatch` | record a DecisionRecord (lineage verified, evidence gate enforced) and its replay packet |
//! | `POST /v1/runs/{run_id}/decisions/{record_id}/scores` | `evaluate` (without `admit`/`dispatch`) | an independent evaluator's score of a decision, signed into the audit chain |
//! | `GET /v1/runs/{run_id}/replay-case` | `audit:read` | the run's admission inputs as a release-gate case (`ctx gate`) |
//! | `GET /v1/runs/{run_id}/evidence` | `audit:read` | the run's evidence bundle |
//! | `POST /v1/runs` | `admit` | compile, negotiate and admit a run (pins policy, opens ledgers) |
//! | `POST /v1/runs` with `delegation` | `admit` | admit a delegated child run (narrowed lane, sub-budget reserved from the parent) |
//! | `POST /v1/runs/{run_id}/mcp` | `dispatch` | MCP server for the run: `tools/list` of surfaced capabilities, governed `tools/call` |
//! | `POST /v1/runs/{run_id}/memory` | `dispatch` | govern a memory lifecycle operation against trusted memory policy |
//! | `GET /v1/memory/{record_id}` | `audit:read` | a memory's current governed lifecycle state |
//! | `GET /v1/runs/{run_id}` | `dispatch` | lifecycle status and current executor generation |
//! | `POST /v1/runs/{run_id}/takeover` | `dispatch` | move the run to a new executor; the old generation goes stale |
//! | `POST /v1/runs/{run_id}/complete` | `dispatch` | complete the run (no unresolved effect, open child or work in flight) |
//! | `POST /v1/runs/{run_id}/fail` | `dispatch` | mark the run failed |
//! | `POST /v1/runs/{run_id}/cancel` | `admit` | cancel the run and its children; stops dispatch, settles children |
//! | `POST /v1/runs/{run_id}/close` | `admit` | close a delegated child (`accept`/`reject`) and settle its usage into the parent |
//! | `POST /v1/runs/{run_id}/tool-calls` | `dispatch` | govern and dispatch one tool call |
//! | `POST /v1/runs/{run_id}/operations/{operation_id}/input` | `dispatch` | answer a tool's `input_required` and continue the same operation |
//! | `POST /v1/runs/{run_id}/operations/{operation_id}/reconcile` | `reconcile` | resolve an unknown effect by provider query or evidenced operator assertion |
//!
//! Effectful routes (tool calls, input, reconcile, close, complete, fail) require the
//! `ContextOS-Executor-Generation` header returned by admission or takeover.
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
use contextos_audit::{AuditWriter, DecisionError, KeyRing, verify_tenant_chain};
use contextos_contract::ingress::parse_strict;
use contextos_contract::schema::{SchemaDoc, SchemaTarget, validate};
use contextos_contract::types::{ContextPack, InvokeRequest, RunContext};
use contextos_contract::validation::is_contract_timestamp;
use contextos_gateway::{
    AdmissionError, AdmissionRequest, BudgetLimits, CloseDecision, Continuation, DecisionRefusal, DecisionReport,
    EffectOutcome, Gateway, Ownership, REVOCATION_KINDS, Resolution, RevocationError, RunAdmission, ScoreRefusal,
    ScoreReport, admit_run,
};
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
    pub limits: Arc<crate::limits::Limiter>,
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
    retry_after_seconds: Option<u64>,
}

impl ApiError {
    pub fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
            detail: None,
            retry_after_seconds: None,
        }
    }

    fn retry_after(mut self, wait: std::time::Duration) -> Self {
        // Whole seconds, rounded up, at least one.
        self.retry_after_seconds = Some((wait.as_secs() + u64::from(wait.subsec_nanos() > 0)).max(1));
        self
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
        if let Some(seconds) = self.retry_after_seconds {
            response
                .headers_mut()
                .insert(header::RETRY_AFTER, header::HeaderValue::from(seconds));
        }
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
    if let Some(scope) = scope
        && !caller.has(scope)
    {
        return Err(ApiError::forbidden());
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

/// The OpenAPI 3.1 description of this API (`openapi/contextosd.v1.json`).
pub const OPENAPI: &str = include_str!("../../../openapi/contextosd.v1.json");

async fn openapi() -> Response {
    ([(header::CONTENT_TYPE, "application/json")], OPENAPI).into_response()
}

async fn healthz() -> &'static str {
    "ok"
}

fn request_span<B>(request: &axum::http::Request<B>) -> tracing::Span {
    let route = request
        .extensions()
        .get::<axum::extract::MatchedPath>()
        .map_or("unmatched", axum::extract::MatchedPath::as_str);
    let span = tracing::info_span!("http.request", method = %request.method(), route, otel.kind = "server");
    crate::telemetry::link_parent(&span, request.headers());
    span
}

async fn readyz<S: DocumentStore, L>(State(state): State<Arc<AppState<S, L>>>) -> Response {
    if !state.auth.ready() {
        return (StatusCode::SERVICE_UNAVAILABLE, "identity keys not loaded").into_response();
    }
    let probe = DocKey::new("__contextos", DocKind::ProfileRegistry, "__readiness");
    match state.store.get(&probe).await {
        Ok(_) => (StatusCode::OK, "ready").into_response(),
        Err(_) => (StatusCode::SERVICE_UNAVAILABLE, "store unavailable").into_response(),
    }
}

async fn metrics<S, L>(State(state): State<Arc<AppState<S, L>>>) -> Response {
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
    // A delegated child takes its deadline and budget from the envelope.
    let delegation = input.get("delegation").filter(|d| !d.is_null());
    let parent = match delegation {
        Some(envelope) => {
            let parent =
                load_admission(&state, &caller, envelope["parent_run_id"].as_str().unwrap_or_default()).await?;
            // Delegating spends the parent's budget: only the parent's current executor may.
            require_owner(gateway, &parent, &headers).await?;
            Some(parent)
        }
        None => None,
    };
    let deadline = input["deadline"]
        .as_str()
        .filter(|d| is_contract_timestamp(d))
        .or(parent.as_ref().map(|_| "1970-01-01T00:00:00Z"))
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "deadline_invalid",
                "A contract timestamp deadline is required.",
            )
        })?;
    let limits_input = match &parent {
        Some(_) => json!({"tokens": 0, "tool_calls": 0, "replans": 0, "cost_cents": 0}),
        None => input["limits"].clone(),
    };
    let limits: BudgetLimits = serde_json::from_value(limits_input).map_err(|_| {
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
    // Kill switch: no new runs of a revoked tenant, pack or agent.
    match gateway
        .admission_revoked(
            &caller.tenant_id,
            &compiled.context_ledger.pack_ref,
            &run_context.agent.agent_id,
        )
        .await
    {
        Ok(None) => {}
        Ok(Some(reason)) => {
            return Err(ApiError::new(
                StatusCode::FORBIDDEN,
                "revoked",
                "This run has been revoked by an operator.",
            )
            .with_detail(json!([reason])));
        }
        Err(_) => {
            return Err(ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "store_unavailable",
                "The store is unavailable.",
            ));
        }
    }
    let features = crate::runtime::derive_features(
        gateway,
        &compiled,
        pack.compiler.pack().pack_meta.data_classification,
        &input["features"],
    )
    .map_err(|message| ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, "features_invalid", message))?;
    let principal = |id: &str, kind: &str| json!({"principal_id": id, "principal_type": kind, "trust_domain": state.trust_domain, "tenant_id": caller.tenant_id});
    let admission_request = AdmissionRequest {
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
        admitted_at: gateway.now(),
        admitted_by: caller.principal_id.clone(),
        executor_generation: 1,
        limits,
    };
    let admitted = match (&parent, delegation) {
        (Some(parent), Some(envelope)) => gateway.delegate(parent, envelope, admission_request).await,
        _ => admit_run(state.store.as_ref(), admission_request).await,
    };
    let admission = admitted.map_err(|e| match e {
        AdmissionError::Delegation(reasons) => ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "delegation_rejected",
            "The delegation exceeds the parent run or is not bound to it.",
        )
        .with_detail(json!(reasons)),
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
        other => {
            // Store and audit errors can name internals; log them, return a code.
            tracing::error!(error = ?other, "admission failed");
            ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "admission_unavailable",
                "Admission is temporarily unavailable.",
            )
        }
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
    gateway
        .remember_replay_case(&admission, &input["request"], &input["run_context"], &input["deps"])
        .await
        .map_err(|_| {
            ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "store_unavailable",
                "The store is unavailable.",
            )
        })?;
    gateway.remember_compiled(&admission, &compiled).await.map_err(|_| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "store_unavailable",
            "The store is unavailable.",
        )
    })?;
    let generation = match gateway.open_run(&admission).await {
        Ok(Ownership::Current(generation)) => generation,
        Ok(Ownership::Refused(reason)) => {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                reason,
                "The run could not be started.",
            ));
        }
        Err(_) => {
            return Err(ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "store_unavailable",
                "The store is unavailable.",
            ));
        }
    };
    Ok((
        StatusCode::CREATED,
        axum::Json(json!({
            "run_id": admission.run_id,
            "executor_generation": generation,
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
    let _dispatch_slot = state.limits.dispatch_permit(&caller.tenant_id).ok_or_else(|| {
        ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "dispatch_concurrency_limited",
            "The tenant has the maximum number of governed effects in progress.",
        )
        .retry_after(std::time::Duration::from_secs(1))
    })?;
    let gateway = dispatch_gateway(&state)?;
    let envelope = parse_body(&state, &body)?;
    let admission = load_admission(&state, &caller, &run_id).await?;
    let generation = executor_generation(&headers)?;
    let outcome = gateway
        .dispatch_as(&admission, &envelope, generation)
        .await
        .map_err(|_| {
            ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "dispatch_unavailable",
                "Governed dispatch is temporarily unavailable.",
            )
        })?;
    state.metrics.dispatch_outcome(outcome.report.status.as_str());
    Ok(axum::Json(json!({"result": outcome.result, "report": outcome.report})).into_response())
}

/// The fencing token an executor presents with effectful requests.
pub const EXECUTOR_GENERATION_HEADER: &str = "contextos-executor-generation";

fn executor_generation(headers: &HeaderMap) -> Result<u64, ApiError> {
    headers
        .get(EXECUTOR_GENERATION_HEADER)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse().ok())
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::PRECONDITION_REQUIRED,
                "executor_generation_required",
                "Effectful requests must carry the executor generation returned at admission or takeover.",
            )
        })
}

/// Refuses a request from an executor that no longer owns the run.
async fn require_owner<S: DocumentStore + 'static, L: AppendLog + 'static>(
    gateway: &Gateway<S, L>,
    admission: &RunAdmission,
    headers: &HeaderMap,
) -> Result<u64, ApiError> {
    let generation = executor_generation(headers)?;
    match gateway.check_owner(admission, generation).await {
        Ok(Ownership::Current(g)) => Ok(g),
        Ok(Ownership::Refused(reason)) => Err(ApiError::new(
            StatusCode::CONFLICT,
            reason,
            "The executor does not own this run; take it over or use the current generation.",
        )),
        Err(_) => Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "store_unavailable",
            "The store is unavailable.",
        )),
    }
}

/// The admission is looked up under the caller's tenant, so another tenant's run is
/// indistinguishable from a missing one.
async fn load_admission<S: DocumentStore, L>(
    state: &AppState<S, L>,
    caller: &Caller,
    run_id: &str,
) -> Result<RunAdmission, ApiError> {
    let stored = state
        .store
        .get(&DocKey::new(&caller.tenant_id, DocKind::RunAdmission, run_id))
        .await
        .map_err(|_| {
            ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "store_unavailable",
                "The store is unavailable.",
            )
        })?
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "run_not_found", "No such run."))?;
    serde_json::from_value(stored.body).map_err(|_| {
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "admission_corrupt",
            "The stored admission is unreadable.",
        )
    })
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields, tag = "source", rename_all = "snake_case")]
enum ReconcileBody {
    /// Ask the provider about the attempt (for example an MCP task).
    Provider,
    /// Assert a definitive outcome with evidence; the caller is recorded as the source.
    Operator { outcome: String, evidence_ref: Value },
}

async fn reconcile<S, L>(
    State(state): State<Arc<AppState<S, L>>>,
    Path((run_id, operation_id)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult
where
    S: DocumentStore + 'static,
    L: AppendLog + 'static,
{
    let caller = authorize(&state, &headers, Some("reconcile"))?;
    let _dispatch_slot = state.limits.dispatch_permit(&caller.tenant_id).ok_or_else(|| {
        ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "dispatch_concurrency_limited",
            "The tenant has the maximum number of governed effects in progress.",
        )
        .retry_after(std::time::Duration::from_secs(1))
    })?;
    let gateway = dispatch_gateway(&state)?;
    let request: ReconcileBody = serde_json::from_value(parse_body(&state, &body)?).map_err(|_| {
        ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "request_invalid",
            "The reconcile request is invalid.",
        )
    })?;
    let resolution = match request {
        ReconcileBody::Provider => Resolution::Query,
        ReconcileBody::Operator { outcome, evidence_ref } => Resolution::Assert {
            outcome: match outcome.as_str() {
                "confirmed" => EffectOutcome::Confirmed,
                "not_applied" => EffectOutcome::NotApplied,
                "partial" => EffectOutcome::Partial,
                _ => {
                    return Err(ApiError::new(
                        StatusCode::UNPROCESSABLE_ENTITY,
                        "request_invalid",
                        "outcome must be confirmed, not_applied or partial.",
                    ));
                }
            },
            evidence_ref,
            principal_id: caller.principal_id.clone(),
        },
    };
    let admission = load_admission(&state, &caller, &run_id).await?;
    require_owner(gateway, &admission, &headers).await?;
    let outcome = gateway
        .reconcile(&admission, &operation_id, resolution)
        .await
        .map_err(|_| {
            ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "reconcile_unavailable",
                "Reconciliation is temporarily unavailable.",
            )
        })?;
    Ok(axum::Json(outcome).into_response())
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct InputBody {
    tool_call: Value,
    input_responses: Value,
}

async fn provide_input<S, L>(
    State(state): State<Arc<AppState<S, L>>>,
    Path((run_id, operation_id)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult
where
    S: DocumentStore + 'static,
    L: AppendLog + 'static,
{
    let caller = authorize(&state, &headers, Some("dispatch"))?;
    let _dispatch_slot = state.limits.dispatch_permit(&caller.tenant_id).ok_or_else(|| {
        ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "dispatch_concurrency_limited",
            "The tenant has the maximum number of governed effects in progress.",
        )
        .retry_after(std::time::Duration::from_secs(1))
    })?;
    let gateway = dispatch_gateway(&state)?;
    let request: InputBody = serde_json::from_value(parse_body(&state, &body)?).map_err(|_| {
        ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "request_invalid",
            "Expected tool_call and input_responses.",
        )
    })?;
    let admission = load_admission(&state, &caller, &run_id).await?;
    let continuation = Continuation {
        operation_id,
        input_responses: request.input_responses,
        responder_id: caller.principal_id.clone(),
        executor_generation: Some(executor_generation(&headers)?),
    };
    let outcome = gateway
        .continue_with_input(&admission, &request.tool_call, &continuation)
        .await
        .map_err(|_| {
            ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "dispatch_unavailable",
                "Governed dispatch is temporarily unavailable.",
            )
        })?;
    state.metrics.dispatch_outcome(outcome.report.status.as_str());
    Ok(axum::Json(json!({"result": outcome.result, "report": outcome.report})).into_response())
}

/// Sheds load beyond the global in-flight cap. Probes and metrics are exempt so an
/// overloaded instance still reports its state.
async fn shed<S, L>(State(state): State<Arc<AppState<S, L>>>, request: Request, next: Next) -> Response {
    if matches!(request.uri().path(), "/healthz" | "/readyz" | "/metrics") {
        return next.run(request).await;
    }
    let Some(_slot) = state.limits.admit_request() else {
        return ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "overloaded",
            "The server is at capacity; retry shortly.",
        )
        .retry_after(std::time::Duration::from_secs(1))
        .into_response();
    };
    next.run(request).await
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct CloseBody {
    decision: CloseDecision,
}

/// Closes a delegated child run and settles its usage into the parent.
async fn close_child<S, L>(
    State(state): State<Arc<AppState<S, L>>>,
    Path(run_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult
where
    S: DocumentStore + 'static,
    L: AppendLog + 'static,
{
    let caller = authorize(&state, &headers, Some("admit"))?;
    let gateway = dispatch_gateway(&state)?;
    let request: CloseBody = serde_json::from_value(parse_body(&state, &body)?).map_err(|_| {
        ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "request_invalid",
            "Expected decision: accept or reject.",
        )
    })?;
    let child = load_admission(&state, &caller, &run_id).await?;
    let Some(lineage) = &child.lineage else {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "not_delegated",
            "Only delegated runs are closed.",
        ));
    };
    let parent = load_admission(&state, &caller, &lineage.parent_run_id).await?;
    // The parent's executor closes its children.
    require_owner(gateway, &parent, &headers).await?;
    let outcome = gateway
        .close_delegation(&parent, &child, request.decision, &caller.principal_id)
        .await
        .map_err(|_| {
            ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "close_unavailable",
                "Closing is temporarily unavailable.",
            )
        })?;
    let status = if outcome.status == "closed" {
        StatusCode::OK
    } else {
        StatusCode::CONFLICT
    };
    Ok((status, axum::Json(outcome)).into_response())
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct TakeoverBody {
    /// The generation the new executor last observed (`GET /v1/runs/{run_id}`).
    expected_generation: u64,
}

/// Moves a run to a new executor; the previous executor's generation goes stale.
async fn take_over<S, L>(
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
    let request: TakeoverBody = serde_json::from_value(parse_body(&state, &body)?).map_err(|_| {
        ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "request_invalid",
            "Expected expected_generation.",
        )
    })?;
    let admission = load_admission(&state, &caller, &run_id).await?;
    match gateway.take_over(&admission, request.expected_generation).await {
        Ok(Ownership::Current(generation)) => {
            Ok(axum::Json(json!({"run_id": run_id, "executor_generation": generation})).into_response())
        }
        Ok(Ownership::Refused(reason)) => Err(ApiError::new(
            StatusCode::CONFLICT,
            reason,
            "The run could not be taken over at that generation.",
        )),
        Err(_) => Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "store_unavailable",
            "The store is unavailable.",
        )),
    }
}

/// The run's lifecycle status and current executor generation.
async fn run_status<S, L>(
    State(state): State<Arc<AppState<S, L>>>,
    Path(run_id): Path<String>,
    headers: HeaderMap,
) -> ApiResult
where
    S: DocumentStore + 'static,
    L: AppendLog + 'static,
{
    let caller = authorize(&state, &headers, Some("dispatch"))?;
    let gateway = dispatch_gateway(&state)?;
    let admission = load_admission(&state, &caller, &run_id).await?;
    let run = gateway
        .run_state(&admission)
        .await
        .map_err(|_| {
            ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "store_unavailable",
                "The store is unavailable.",
            )
        })?
        .unwrap_or(Value::Null);
    Ok(axum::Json(
        json!({"run_id": run_id, "status": run["status"], "executor_generation": run["executor_generation"],
        "deadline": admission.deadline, "parent_run_id": admission.lineage.as_ref().map(|l| l.parent_run_id.clone())}),
    )
    .into_response())
}

/// `complete`, `fail` (fenced by the executor generation) or `cancel` (administrative).
async fn lifecycle<S, L>(
    State(state): State<Arc<AppState<S, L>>>,
    Path((run_id, action)): Path<(String, String)>,
    headers: HeaderMap,
) -> ApiResult
where
    S: DocumentStore + 'static,
    L: AppendLog + 'static,
{
    let scope = if action == "cancel" { "admit" } else { "dispatch" };
    let caller = authorize(&state, &headers, Some(scope))?;
    let gateway = dispatch_gateway(&state)?;
    let admission = load_admission(&state, &caller, &run_id).await?;
    let unavailable = |_| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "store_unavailable",
            "The store is unavailable.",
        )
    };
    let outcome = match action.as_str() {
        "complete" => gateway
            .complete_run(&admission, executor_generation(&headers)?)
            .await
            .map_err(unavailable)?,
        "fail" => gateway
            .fail_run(&admission, executor_generation(&headers)?)
            .await
            .map_err(unavailable)?,
        "cancel" => gateway
            .cancel_run(&admission, &caller.principal_id)
            .await
            .map_err(unavailable)?,
        _ => return Err(ApiError::new(StatusCode::NOT_FOUND, "not_found", "No such run action.")),
    };
    let status = if outcome.reason_codes.is_empty() {
        StatusCode::OK
    } else {
        StatusCode::CONFLICT
    };
    Ok((status, axum::Json(outcome)).into_response())
}

/// Records a DecisionRecord for the run, verified against the run's own records.
async fn record_decision<S, L>(
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
    let report: DecisionReport = serde_json::from_value(parse_body(&state, &body)?).map_err(|e| {
        ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "request_invalid",
            format!("Invalid decision report: {e}"),
        )
    })?;
    let admission = load_admission(&state, &caller, &run_id).await?;
    require_owner(gateway, &admission, &headers).await?;
    match gateway.record_decision(&admission, report, &caller.principal_id).await {
        Ok(recorded) => Ok((StatusCode::CREATED, axum::Json(recorded)).into_response()),
        Err(refusal) => Err(match refusal {
            DecisionRefusal::Decision(DecisionError::EvidenceGateOpen(key)) => ApiError::new(
                StatusCode::CONFLICT,
                "evidence_gate_open",
                "The decision cannot be committed while its evidence gate is open.",
            )
            .with_detail(json!({"decision_key": key})),
            DecisionRefusal::Decision(DecisionError::OutcomeNotAllowed(outcome)) => ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "outcome_not_allowed",
                "The outcome is not an allowed outcome of the decision.",
            )
            .with_detail(json!({"outcome": outcome})),
            DecisionRefusal::UnknownToolCall(id) => ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "lineage_unverified",
                "A reported tool call is not a governed effect of this run.",
            )
            .with_detail(json!({"tool_call_id": id})),
            DecisionRefusal::TooLarge => ApiError::new(
                StatusCode::PAYLOAD_TOO_LARGE,
                "decision_too_large",
                "The decision cites too many tool calls or its details are too large.",
            ),
            DecisionRefusal::CompiledContextMissing | DecisionRefusal::TooManyDecisions => {
                ApiError::new(StatusCode::CONFLICT, "decision_unavailable", refusal.to_string())
            }
            DecisionRefusal::Decision(other) => {
                ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, "decision_invalid", other.to_string())
            }
            DecisionRefusal::Gateway(_) => ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "store_unavailable",
                "The store is unavailable.",
            ),
        }),
    }
}

/// Records an evaluator's score of one of the run's decisions. Separation of duties:
/// a principal that may run or admit agents cannot also score them.
async fn score_decision<S, L>(
    State(state): State<Arc<AppState<S, L>>>,
    Path((run_id, record_id)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult
where
    S: DocumentStore + 'static,
    L: AppendLog + 'static,
{
    let caller = authorize(&state, &headers, Some("evaluate"))?;
    if caller.has("dispatch") || caller.has("admit") {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "evaluator_not_independent",
            "An evaluator cannot also run or admit agents.",
        ));
    }
    let gateway = dispatch_gateway(&state)?;
    let report: ScoreReport = serde_json::from_value(parse_body(&state, &body)?).map_err(|e| {
        ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "request_invalid",
            format!("Invalid score: {e}"),
        )
    })?;
    let admission = load_admission(&state, &caller, &run_id).await?;
    match gateway
        .score_decision(&admission, &record_id, &caller.principal_id, &report)
        .await
    {
        Ok(score) => Ok((StatusCode::CREATED, axum::Json(score)).into_response()),
        Err(refusal) => Err(match refusal {
            ScoreRefusal::Invalid => {
                ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, "score_invalid", refusal.to_string())
            }
            ScoreRefusal::UnknownDecision => {
                ApiError::new(StatusCode::NOT_FOUND, "decision_not_found", refusal.to_string())
            }
            ScoreRefusal::SelfScoring => {
                ApiError::new(StatusCode::FORBIDDEN, "evaluator_not_independent", refusal.to_string())
            }
            ScoreRefusal::AlreadyScored | ScoreRefusal::TooManyScores => {
                ApiError::new(StatusCode::CONFLICT, "score_exists", refusal.to_string())
            }
            ScoreRefusal::Gateway(_) => ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "store_unavailable",
                "The store is unavailable.",
            ),
        }),
    }
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RevocationBody {
    kind: String,
    target: String,
    reason: String,
}

/// The tenant's revoked targets.
async fn list_revocations<S, L>(State(state): State<Arc<AppState<S, L>>>, headers: HeaderMap) -> ApiResult
where
    S: DocumentStore + 'static,
    L: AppendLog + 'static,
{
    let caller = authorize(&state, &headers, Some("control"))?;
    let gateway = dispatch_gateway(&state)?;
    let revoked = gateway.revocations(&caller.tenant_id).await.map_err(|_| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "store_unavailable",
            "The store is unavailable.",
        )
    })?;
    Ok(axum::Json(revoked).into_response())
}

async fn change_revocation<S, L>(state: &AppState<S, L>, headers: &HeaderMap, body: &Bytes, revoke: bool) -> ApiResult
where
    S: DocumentStore + 'static,
    L: AppendLog + 'static,
{
    let caller = authorize(state, headers, Some("control"))?;
    let gateway = dispatch_gateway(state)?;
    let change: RevocationBody = serde_json::from_value(parse_body(state, body)?).map_err(|e| {
        ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "request_invalid",
            format!("Invalid revocation: {e}"),
        )
    })?;
    match gateway
        .set_revocation(
            &caller.tenant_id,
            &change.kind,
            &change.target,
            &change.reason,
            &caller.principal_id,
            revoke,
        )
        .await
    {
        Ok(revoked) => Ok(axum::Json(revoked).into_response()),
        Err(RevocationError::Invalid) => Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "revocation_invalid",
            format!("kind must be one of {REVOCATION_KINDS:?}; target and reason are required"),
        )),
        Err(RevocationError::TooMany) => Err(ApiError::new(
            StatusCode::CONFLICT,
            "revocations_full",
            "The tenant has the maximum number of revocations.",
        )),
        Err(RevocationError::Gateway(_)) => Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "store_unavailable",
            "The store is unavailable.",
        )),
    }
}

/// Revokes a target (kill switch); effective for the next dispatch and admission.
async fn revoke<S, L>(State(state): State<Arc<AppState<S, L>>>, headers: HeaderMap, body: Bytes) -> ApiResult
where
    S: DocumentStore + 'static,
    L: AppendLog + 'static,
{
    change_revocation(&state, &headers, &body, true).await
}

/// Restores a revoked target.
async fn restore<S, L>(State(state): State<Arc<AppState<S, L>>>, headers: HeaderMap, body: Bytes) -> ApiResult
where
    S: DocumentStore + 'static,
    L: AppendLog + 'static,
{
    change_revocation(&state, &headers, &body, false).await
}

/// The run's evidence bundle: admission, lifecycle, budget ledger with its archive
/// chain, and DecisionRecords with replay packets.
async fn run_evidence<S, L>(
    State(state): State<Arc<AppState<S, L>>>,
    Path(run_id): Path<String>,
    headers: HeaderMap,
) -> ApiResult
where
    S: DocumentStore + 'static,
    L: AppendLog + 'static,
{
    let caller = authorize(&state, &headers, Some("audit:read"))?;
    let gateway = dispatch_gateway(&state)?;
    let admission = load_admission(&state, &caller, &run_id).await?;
    let evidence = gateway.run_evidence(&admission).await.map_err(|_| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "store_unavailable",
            "The store is unavailable.",
        )
    })?;
    Ok(axum::Json(evidence).into_response())
}

#[derive(serde::Deserialize)]
struct EntriesQuery {
    #[serde(default = "first_sequence")]
    from: u64,
    #[serde(default = "page_size")]
    limit: usize,
}

fn first_sequence() -> u64 {
    1
}

fn page_size() -> usize {
    500
}

/// Pages the caller tenant's signed audit chain out (for SIEM export and offline
/// verification with `verify_chain`).
async fn audit_entries<S, L: AppendLog>(
    State(state): State<Arc<AppState<S, L>>>,
    headers: HeaderMap,
    axum::extract::Query(query): axum::extract::Query<EntriesQuery>,
) -> ApiResult {
    let caller = authorize(&state, &headers, Some("audit:read"))?;
    let limit = query.limit.clamp(1, 1000);
    let rows = state
        .audit
        .log()
        .range(&caller.tenant_id, query.from.max(1), limit)
        .await
        .map_err(|_| {
            ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "store_unavailable",
                "The store is unavailable.",
            )
        })?;
    let next = rows.last().map(|r| r.sequence + 1).filter(|_| rows.len() == limit);
    let entries: Vec<Value> = rows.into_iter().map(|r| r.body).collect();
    Ok(axum::Json(json!({"entries": entries, "next": next})).into_response())
}

/// MCP gateway mode for one run (see [`crate::mcp`]).
async fn mcp_endpoint<S, L>(
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
    let Ok(request) = parse_body(&state, &body) else {
        return Ok(crate::mcp::parse_error());
    };
    let admission = load_admission(&state, &caller, &run_id).await?;
    let _dispatch_slot = state.limits.dispatch_permit(&caller.tenant_id).ok_or_else(|| {
        ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "dispatch_concurrency_limited",
            "The tenant has the maximum number of governed effects in progress.",
        )
        .retry_after(std::time::Duration::from_secs(1))
    })?;
    let mut response = crate::mcp::handle(gateway, &admission, &caller.principal_id, &headers, &request).await;
    response.headers_mut().insert(
        "mcp-protocol-version",
        header::HeaderValue::from_static(crate::mcp::PROTOCOL_VERSION),
    );
    Ok(response)
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct MemoryBody {
    record: Value,
}

/// Governs a memory lifecycle operation (propose, promote, correct, delete).
async fn govern_memory<S, L>(
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
    let request: MemoryBody = serde_json::from_value(parse_body(&state, &body)?).map_err(|_| {
        ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "request_invalid",
            "Expected a record.",
        )
    })?;
    let admission = load_admission(&state, &caller, &run_id).await?;
    require_owner(gateway, &admission, &headers).await?;
    let decision = gateway.govern_memory(&admission, &request.record).await.map_err(|_| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "store_unavailable",
            "The store is unavailable.",
        )
    })?;
    let status = if decision.allowed {
        StatusCode::OK
    } else {
        StatusCode::UNPROCESSABLE_ENTITY
    };
    Ok((status, axum::Json(decision)).into_response())
}

/// A memory's current governed lifecycle state.
async fn memory_state<S, L>(
    State(state): State<Arc<AppState<S, L>>>,
    Path(record_id): Path<String>,
    headers: HeaderMap,
) -> ApiResult
where
    S: DocumentStore + 'static,
    L: AppendLog + 'static,
{
    let caller = authorize(&state, &headers, Some("audit:read"))?;
    let gateway = dispatch_gateway(&state)?;
    let found = gateway
        .memory_state(&caller.tenant_id, &record_id)
        .await
        .map_err(|_| {
            ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "store_unavailable",
                "The store is unavailable.",
            )
        })?
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "memory_not_found", "No such memory."))?;
    Ok(axum::Json(found).into_response())
}

/// The inputs the run was admitted with, as a release-gate replay case (`ctx gate`).
async fn replay_case<S, L>(
    State(state): State<Arc<AppState<S, L>>>,
    Path(run_id): Path<String>,
    headers: HeaderMap,
) -> ApiResult
where
    S: DocumentStore + 'static,
    L: AppendLog + 'static,
{
    let caller = authorize(&state, &headers, Some("audit:read"))?;
    let gateway = dispatch_gateway(&state)?;
    let admission = load_admission(&state, &caller, &run_id).await?;
    let case = gateway
        .replay_case(&admission)
        .await
        .map_err(|_| {
            ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "store_unavailable",
                "The store is unavailable.",
            )
        })?
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::NOT_FOUND,
                "replay_case_not_found",
                "No replay case for this run.",
            )
        })?;
    Ok(axum::Json(case).into_response())
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
        .route("/v1/openapi.json", get(openapi))
        .route("/v1/compile", post(compile::<S, L>))
        .route("/v1/contracts/negotiate", post(negotiate::<S, L>))
        .route("/v1/schemas/{doc}/validate", post(validate_schema::<S, L>))
        .route("/v1/audit/verify", get(audit_verify::<S, L>))
        .route("/v1/audit/entries", get(audit_entries::<S, L>))
        .route("/v1/revocations", get(list_revocations::<S, L>).post(revoke::<S, L>))
        .route("/v1/revocations/restore", post(restore::<S, L>))
        .route("/v1/runs", post(admit::<S, L>))
        .route("/v1/runs/{run_id}/tool-calls", post(tool_call::<S, L>))
        .route("/v1/runs/{run_id}", get(run_status::<S, L>))
        .route("/v1/runs/{run_id}/takeover", post(take_over::<S, L>))
        .route("/v1/runs/{run_id}/close", post(close_child::<S, L>))
        .route("/v1/runs/{run_id}/memory", post(govern_memory::<S, L>))
        .route("/v1/memory/{record_id}", get(memory_state::<S, L>))
        .route("/v1/runs/{run_id}/mcp", post(mcp_endpoint::<S, L>))
        .route("/v1/runs/{run_id}/decisions", post(record_decision::<S, L>))
        .route("/v1/runs/{run_id}/evidence", get(run_evidence::<S, L>))
        .route(
            "/v1/runs/{run_id}/decisions/{record_id}/scores",
            post(score_decision::<S, L>),
        )
        .route("/v1/runs/{run_id}/replay-case", get(replay_case::<S, L>))
        .route("/v1/runs/{run_id}/{action}", post(lifecycle::<S, L>))
        .route(
            "/v1/runs/{run_id}/operations/{operation_id}/input",
            post(provide_input::<S, L>),
        )
        .route(
            "/v1/runs/{run_id}/operations/{operation_id}/reconcile",
            post(reconcile::<S, L>),
        )
        .layer(middleware::from_fn_with_state(state.clone(), shed::<S, L>))
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
        .layer(tower_http::trace::TraceLayer::new_for_http().make_span_with(request_span))
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
