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
//! | `POST /v1/runs/{run_id}/checkpoint` | `dispatch` | save the orchestrator's checkpoint (current executor; optimistic on revision) |
//! | `GET /v1/runs/{run_id}/checkpoint` | `dispatch` | the latest checkpoint, for the executor that takes over |
//! | `POST /v1/runs/{run_id}/usage/reserve` | `dispatch` | reserve budget for a model call or a replan |
//! | `POST /v1/runs/{run_id}/usage/settle` | `meter` or `dispatch` | settle it: measured by a meter, or the whole reservation if self-reported |
//! | `POST /v1/runs/{run_id}/erase` | `control` | erase a finished run's personal content (replay case, compiled context), leaving audited tombstones |
//! | `GET /v1/rollouts` | `control` | the tenant's staged rollouts |
//! | `POST /v1/rollouts` | `control` | route a percentage of a baseline pack's new runs to a candidate pack (optionally shadow-diffing the rest) |
//! | `POST /v1/rollouts/clear` | `control` | return all of a baseline's new runs to it |
//! | `POST /v1/runs/{run_id}/feedback` | `evaluate` (independent) | file an operator correction or override, with the run's replay case as obligation |
//! | `GET /v1/escalations` | `audit:read` | the tenant's open policy escalations, oldest first |
//! | `POST /v1/escalations/{escalation_id}/resolve` | `control` | record how a human resolved an escalation (`handled`/`dismissed`); grants nothing |
//! | `GET /v1/feedback` | `audit:read` | the tenant's open feedback (the replay corpus a change must pass) |
//! | `POST /v1/feedback/{feedback_id}/close` | `control` | close feedback as fixed/still_failing/invalid/superseded, with evidence |
//! | `POST /v1/conformance/assess` | `audit:read` | assess a conformance report for this deployment against configured trust anchors; audited |
//! | `GET /v1/audit/keys` | – | the audit signing public keys, for independent verification (`ctx audit-verify`) |
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
    AdmissionError, AdmissionRequest, BudgetLimits, CheckpointRefusal, CloseDecision, Continuation, DecisionRefusal,
    DecisionReport, EffectOutcome, ErasureError, Gateway, MAX_CHECKPOINT_BYTES, Ownership, REVOCATION_KINDS,
    Resolution, RevocationError, RunAdmission, ScoreRefusal, ScoreReport, UsageKind, UsageRefusal, admit_run,
    is_erased,
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
    /// Conformance trust anchors.
    pub conformance: crate::config::ConformanceConfig,
    /// Concurrent shadow diffs at most; beyond it a diff is skipped, never queued.
    pub shadow_slots: Arc<tokio::sync::Semaphore>,
    /// `[guards] required_release_refs` (resolved for the mode).
    pub required_release_refs: Vec<String>,
    /// `[guards] require_user_role` (resolved for the mode).
    pub require_user_role: bool,
    /// Whether recalled memory without a memory-governance service is admitted.
    pub trust_supplied_memory: bool,
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

/// The audit chain's public signing keys, so anyone can verify exported entries
/// (`ctx audit-verify`) without trusting this server.
async fn audit_keys<S, L>(State(state): State<Arc<AppState<S, L>>>) -> Response {
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
    check_recalled_memory(
        &state,
        gateway,
        &caller.tenant_id,
        &input["run_context"],
        &input["deps"]["promoted_memory"],
    )
    .await?;
    if state.require_user_role
        // A role is a visible identifier (invisible or whitespace characters are not one).
        && run_context_value["user"]["role"]
            .as_str()
            .is_none_or(|r| {
                r.is_empty() || !r.chars().all(|c| c.is_ascii_alphanumeric() || "_.:-".contains(c))
            })
    {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "user_role_missing",
            "The run's user claims must state a role.",
        ));
    }
    // The deployment may require the executing model profile (and evaluators) to be
    // pinned, so every decision records what produced it.
    let pinned = input["contract"]["release_refs"].as_array();
    let unpinned: Vec<&String> = state
        .required_release_refs
        .iter()
        .filter(|t| !pinned.is_some_and(|refs| refs.iter().any(|r| r["artifact_type"] == t.as_str())))
        .collect();
    if !unpinned.is_empty() {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "release_ref_missing",
            "The execution contract must pin these release artifacts in release_refs.",
        )
        .with_detail(json!({"artifact_types": unpinned})));
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
    // Staged rollout: a run asking for a baseline may be admitted on its candidate.
    let requested = input["pack_ref"].as_str().unwrap_or_default();
    let rollouts = state
        .store
        .get(&crate::rollout::key(&caller.tenant_id))
        .await
        .map_err(|_| {
            ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "store_unavailable",
                "The store is unavailable.",
            )
        })?
        .map(|r| r.body);
    let routing_id = parent.as_ref().map_or_else(
        || run_context_value["run_id"].as_str().unwrap_or_default(),
        |p| p.run_id.as_str(),
    );
    let (selected, rollout) = crate::rollout::route(rollouts.as_ref(), requested, &caller.tenant_id, routing_id);
    let rollout = rollout.cloned();
    let selected = selected.to_owned();
    // A delegated lane runs on its parent's pack: a child cannot move to another pack
    // (for example one that is not revoked, or not yet rolled out).
    if let Some(parent) = parent.as_ref().filter(|p| !p.pack_ref.is_empty())
        && selected != parent.pack_ref
    {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "delegation_pack_mismatch",
            "A delegated run must use its parent's Context Pack.",
        )
        .with_detail(json!({"parent_pack_ref": parent.pack_ref})));
    }
    let pack = state
        .packs
        .get(&selected)
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
    let compiled = tracing::info_span!("contextos.compile", pack_id = %pack.compiler.pack().pack_meta.pack_id)
        .in_scope(|| pack.compiler.compile(&request, &run_context, &deps))
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
    // Kill switch: no new runs of a revoked tenant, pack, principal or agent, and no
    // delegation from a run that is itself revoked.
    match gateway
        .admission_revoked(
            &caller.tenant_id,
            &compiled.context_ledger.pack_ref,
            &caller.principal_id,
            &run_context.agent.agent_id,
            parent.as_ref(),
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
    if let Some(r) = rollout
        .as_ref()
        .filter(|r| r["shadow"] == true && selected == requested)
    {
        shadow_diff(&state, r, &admission.run_id, &input);
    }
    state.metrics.admission(&selected);
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
            "pack_ref": selected,
            "rollout": rollout.as_ref().map(|r| json!({"baseline": r["baseline"], "candidate": r["candidate"],
                "percent": r["percent"], "on_candidate": selected != requested})),
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
    let capability = outcome.result["capability_id"].as_str().unwrap_or_default();
    let capability = if gateway.manifest(capability).is_some() {
        capability
    } else {
        "unpinned"
    };
    state
        .metrics
        .dispatch_outcome(capability, &outcome.report.status, &outcome.report.reason_codes);
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
    let capability = outcome.result["capability_id"].as_str().unwrap_or_default();
    let capability = if gateway.manifest(capability).is_some() {
        capability
    } else {
        "unpinned"
    };
    state
        .metrics
        .dispatch_outcome(capability, &outcome.report.status, &outcome.report.reason_codes);
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
        Ok(recorded) => {
            state.metrics.decision(
                serde_json::to_value(recorded.record.status)
                    .ok()
                    .as_ref()
                    .and_then(Value::as_str)
                    .unwrap_or("unknown"),
            );
            Ok((StatusCode::CREATED, axum::Json(recorded)).into_response())
        }
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
struct AssessmentScope {
    workflow_id: Value,
    release_refs: Value,
    environment_ref: Value,
    required_utility_case_ids: Value,
}

/// What the caller of an assessment supplies; trust anchors, the support declaration,
/// the registry, the implementation identity and the evaluation time are the server's.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct AssessmentBody {
    contract: Value,
    features: Value,
    report: Value,
    report_verification: Value,
    evidence_observations: Value,
    scope: AssessmentScope,
    /// The report's evaluator's signature over the report, contract and features.
    report_signature: Value,
    /// The named observer's signature over `report_verification`.
    verification_signature: Value,
    /// One signature per evidence observation, by the observer it names.
    evidence_signatures: Vec<Value>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
enum UsageKindBody {
    ModelCall,
    Replan,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ReserveUsage {
    kind: UsageKindBody,
    #[serde(default)]
    tokens: u64,
    #[serde(default)]
    cost_cents: u64,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SettleUsage {
    reservation_id: String,
    #[serde(default)]
    tokens: u64,
    #[serde(default)]
    cost_cents: u64,
}

fn usage_error(refusal: UsageRefusal) -> ApiError {
    match refusal {
        UsageRefusal::Budget(reasons) => ApiError::new(
            StatusCode::CONFLICT,
            "budget_exhausted",
            "The run's budget cannot fit this.",
        )
        .with_detail(json!(reasons)),
        UsageRefusal::Revoked(reason) => ApiError::new(
            StatusCode::FORBIDDEN,
            "revoked",
            "This run has been revoked by an operator.",
        )
        .with_detail(json!([reason])),
        UsageRefusal::Invalid => ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "usage_invalid",
            "The usage values are out of range.",
        ),
        UsageRefusal::UnknownReservation => ApiError::new(
            StatusCode::NOT_FOUND,
            "reservation_not_found",
            "No open usage reservation with this id in this run.",
        ),
        UsageRefusal::Gateway(_) => ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "store_unavailable",
            "The store is unavailable.",
        ),
    }
}

/// Reserves budget for a model call or a replan (the run's current executor).
async fn reserve_usage<S, L>(
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
    let request: ReserveUsage = serde_json::from_value(parse_body(&state, &body)?).map_err(|e| {
        ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "request_invalid",
            format!("Invalid reservation: {e}"),
        )
    })?;
    let admission = load_admission(&state, &caller, &run_id).await?;
    require_owner(gateway, &admission, &headers).await?;
    let kind = match request.kind {
        UsageKindBody::ModelCall => UsageKind::ModelCall,
        UsageKindBody::Replan => UsageKind::Replan,
    };
    let reservation_id = gateway
        .reserve_usage(&admission, kind, request.tokens, request.cost_cents)
        .await
        .map_err(usage_error)?;
    Ok((
        StatusCode::CREATED,
        axum::Json(json!({"reservation_id": reservation_id})),
    )
        .into_response())
}

/// Settles a usage reservation: verified when reported by a metering principal,
/// otherwise the whole reservation is charged.
async fn settle_usage<S, L>(
    State(state): State<Arc<AppState<S, L>>>,
    Path(run_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult
where
    S: DocumentStore + 'static,
    L: AppendLog + 'static,
{
    let caller = authorize(&state, &headers, None)?;
    let metered = caller.has("meter") && !caller.has("dispatch") && !caller.has("admit");
    if !metered && !caller.has("dispatch") {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "scope_missing",
            "This requires the meter or dispatch scope.",
        ));
    }
    let gateway = dispatch_gateway(&state)?;
    let request: SettleUsage = serde_json::from_value(parse_body(&state, &body)?).map_err(|e| {
        ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "request_invalid",
            format!("Invalid settlement: {e}"),
        )
    })?;
    let admission = load_admission(&state, &caller, &run_id).await?;
    if !metered {
        require_owner(gateway, &admission, &headers).await?;
    } else if caller.principal_id == admission.admitted_by {
        // The run's own admitter cannot verify its usage, whatever token it presents.
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "meter_not_independent",
            "The principal that admitted the run cannot meter it.",
        ));
    }
    let measured = metered.then_some((request.tokens, request.cost_cents));
    let settled = gateway
        .settle_usage(&admission, &request.reservation_id, measured, &caller.principal_id)
        .await
        .map_err(usage_error)?;
    Ok(axum::Json(settled).into_response())
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckpointBody {
    expected_revision: u64,
    state: Value,
}

/// Saves the orchestrator's checkpoint (the run's current executor only).
async fn save_checkpoint<S, L>(
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
    let request: CheckpointBody = serde_json::from_value(parse_body(&state, &body)?).map_err(|e| {
        ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "request_invalid",
            format!("Invalid checkpoint: {e}"),
        )
    })?;
    let admission = load_admission(&state, &caller, &run_id).await?;
    let generation = require_owner(gateway, &admission, &headers).await?;
    match gateway
        .save_checkpoint(&admission, generation, request.expected_revision, request.state)
        .await
    {
        Ok(record) => Ok((StatusCode::CREATED, axum::Json(record)).into_response()),
        Err(CheckpointRefusal::Invalid) => Err(ApiError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "checkpoint_too_large",
            format!("A checkpoint's state is at most {MAX_CHECKPOINT_BYTES} bytes of plain JSON."),
        )),
        Err(CheckpointRefusal::RevisionConflict { current, .. }) => Err(ApiError::new(
            StatusCode::CONFLICT,
            "checkpoint_conflict",
            "The checkpoint changed since the revision you read.",
        )
        .with_detail(json!({"current_revision": current}))),
        Err(CheckpointRefusal::Closed) => Err(ApiError::new(
            StatusCode::GONE,
            "checkpoint_closed",
            "The run is past its deadline or its content was erased.",
        )),
        Err(CheckpointRefusal::Gateway(_)) => Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "store_unavailable",
            "The store is unavailable.",
        )),
    }
}

/// The run's latest orchestrator checkpoint.
async fn latest_checkpoint<S, L>(
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
    // Only the run's current executor reads its working state.
    require_owner(gateway, &admission, &headers).await?;
    let checkpoint = gateway
        .latest_checkpoint(&admission)
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
                "checkpoint_not_found",
                "This run has no checkpoint.",
            )
        })?;
    if is_erased(&checkpoint) {
        return Err(ApiError::new(
            StatusCode::GONE,
            "checkpoint_erased",
            "This run's content was erased.",
        ));
    }
    Ok(axum::Json(checkpoint).into_response())
}

fn feedback_error(error: crate::feedback::FeedbackError) -> ApiError {
    use crate::feedback::FeedbackError;
    match error {
        FeedbackError::Invalid(why) => ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, "feedback_invalid", why),
        FeedbackError::Full => ApiError::new(StatusCode::CONFLICT, "feedback_full", "Too many open feedback records."),
        FeedbackError::NotFound => {
            ApiError::new(StatusCode::NOT_FOUND, "feedback_not_found", "No such feedback record.")
        }
        FeedbackError::Closed => ApiError::new(
            StatusCode::CONFLICT,
            "feedback_closed",
            "The feedback record is already closed.",
        ),
        FeedbackError::Store(_) => ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "store_unavailable",
            "The store is unavailable.",
        ),
    }
}

/// Files an operator correction or override against a run, with its replay case as
/// the replay obligation (independent reviewers only).
async fn file_feedback<S, L>(
    State(state): State<Arc<AppState<S, L>>>,
    Path(run_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult
where
    S: DocumentStore + 'static,
    L: AppendLog + 'static,
{
    let caller = authorize(&state, &headers, Some("evaluate"))?;
    let gateway = dispatch_gateway(&state)?;
    let request: crate::feedback::FeedbackBody = serde_json::from_value(parse_body(&state, &body)?).map_err(|e| {
        ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "request_invalid",
            format!("Invalid feedback: {e}"),
        )
    })?;
    request.check().map_err(feedback_error)?;
    let admission = load_admission(&state, &caller, &run_id).await?;
    if caller.has("dispatch") || caller.has("admit") || caller.principal_id == admission.admitted_by {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "reviewer_not_independent",
            "Feedback comes from a reviewer independent of the run.",
        ));
    }
    let unavailable = |_| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "store_unavailable",
            "The store is unavailable.",
        )
    };
    if let Some(record_id) = &request.decision_record_id {
        let issued = state
            .store
            .get(&DocKey::new(
                &admission.tenant_id,
                DocKind::DecisionLog,
                &admission.run_id,
            ))
            .await
            .map_err(unavailable)?
            .is_some_and(|d| {
                d.body["record_ids"]
                    .as_array()
                    .is_some_and(|ids| ids.iter().any(|i| i == record_id))
            });
        if !issued {
            return Err(ApiError::new(
                StatusCode::NOT_FOUND,
                "decision_not_found",
                "No such decision in this run.",
            ));
        }
    }
    let now = gateway.now();
    // Random, so concurrent filings never share an id.
    let id = gateway.new_id("fb");
    let summary_digest = contextos_contract::canonical::sha256_text(&request.summary);
    let record = json!({"feedback_id": id, "tenant_id": admission.tenant_id, "run_id": run_id, "trace_id": admission.trace_id,
        "decision_record_id": request.decision_record_id, "kind": request.kind, "target_surface": request.target_surface,
        "summary": request.summary, "expected_outcome": request.expected_outcome, "reporter": caller.principal_id,
        "filed_at": now, "status": "open",
        "replay_obligation": {"case": run_id, "replay_case": format!("/v1/runs/{run_id}/replay-case")}});
    // Audited by digest: the summary itself stays out of the chain.
    state
        .audit
        .append(
            &admission.tenant_id,
            "feedback_filed",
            json!({"feedback_id": id, "run_id": run_id,
            "kind": record["kind"], "target_surface": record["target_surface"], "summary_digest": summary_digest,
            "reporter": caller.principal_id}),
            &now,
        )
        .await
        .map_err(|_| {
            ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "audit_unavailable",
                "The audit log is unavailable.",
            )
        })?;
    // Indexed before the record exists so the bound holds; an id left without a record
    // (a failed create) is dropped by the next list or close that meets it.
    crate::feedback::index_open(state.store.as_ref(), &admission.tenant_id, &id)
        .await
        .map_err(feedback_error)?;
    let store_down = || {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "store_unavailable",
            "The store is unavailable.",
        )
    };
    // Known to the run's erasure before it exists; filed after an erasure, its text is
    // redacted at once.
    let record_key = crate::feedback::record_key(&admission.tenant_id, &id);
    gateway
        .note_run_feedback(&admission, &record_key.id)
        .await
        .map_err(|_| store_down())?;
    state
        .store
        .create(&record_key, &record)
        .await
        .map_err(|_| store_down())?;
    let replay = state
        .store
        .get(&DocKey::new(
            &admission.tenant_id,
            DocKind::ReplayCase,
            &admission.run_id,
        ))
        .await
        .map_err(|_| store_down())?;
    if replay.is_some_and(|r| contextos_gateway::is_erased(&r.body)) {
        gateway
            .erase_run(
                &admission,
                &caller.principal_id,
                "feedback filed after the run was erased",
            )
            .await
            .map_err(|_| store_down())?;
        let redacted = state.store.get(&record_key).await.map_err(|_| store_down())?;
        return Ok((StatusCode::CREATED, axum::Json(redacted.map_or(record, |r| r.body))).into_response());
    }
    Ok((StatusCode::CREATED, axum::Json(record)).into_response())
}

#[derive(serde::Deserialize)]
struct FeedbackQuery {
    #[serde(default)]
    limit: Option<usize>,
}

/// The tenant's open feedback, oldest first: the replay corpus a change must pass.
async fn list_feedback<S, L>(
    State(state): State<Arc<AppState<S, L>>>,
    Query(query): Query<FeedbackQuery>,
    headers: HeaderMap,
) -> ApiResult
where
    S: DocumentStore + 'static,
    L: AppendLog + 'static,
{
    let caller = authorize(&state, &headers, Some("audit:read"))?;
    let ids = crate::feedback::open_ids(state.store.as_ref(), &caller.tenant_id)
        .await
        .map_err(feedback_error)?;
    let unavailable = |_| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "store_unavailable",
            "The store is unavailable.",
        )
    };
    let wanted = query.limit.unwrap_or(500).clamp(1, 1000);
    let mut fetched = Vec::new();
    for id in ids.iter().take(wanted) {
        fetched.push(
            state
                .store
                .get(&crate::feedback::record_key(&caller.tenant_id, id))
                .await
                .map_err(unavailable)?,
        );
    }
    let mut records = Vec::new();
    let mut stale = Vec::new();
    for (id, record) in ids.iter().zip(fetched) {
        // Only open records are the replay corpus; anything else is a leftover of an
        // interrupted file or close, dropped from the index here.
        match record {
            Some(r) if r.body["status"] == "open" => records.push(r.body),
            _ => stale.push(id.clone()),
        }
    }
    for id in &stale {
        let _ = crate::feedback::index_close(state.store.as_ref(), &caller.tenant_id, id).await;
    }
    Ok(axum::Json(json!({"open": ids.len() - stale.len(), "feedback": records})).into_response())
}

/// Closes feedback with evidence (operators only).
async fn close_feedback<S, L>(
    State(state): State<Arc<AppState<S, L>>>,
    Path(feedback_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult
where
    S: DocumentStore + 'static,
    L: AppendLog + 'static,
{
    use crate::feedback::{CloseBody, FeedbackError};
    let caller = authorize(&state, &headers, Some("control"))?;
    let gateway = dispatch_gateway(&state)?;
    let request: CloseBody = serde_json::from_value(parse_body(&state, &body)?).map_err(|e| {
        ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "request_invalid",
            format!("Invalid closure: {e}"),
        )
    })?;
    request.check().map_err(feedback_error)?;
    let key = crate::feedback::record_key(&caller.tenant_id, &feedback_id);
    let unavailable = |_| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "store_unavailable",
            "The store is unavailable.",
        )
    };
    let current = state.store.get(&key).await.map_err(unavailable)?;
    // Whatever is not an open record leaves the open index (an interrupted file or
    // close must not hold a slot forever).
    let Some(current) = current.filter(|c| c.body["status"] == "open") else {
        let _ = crate::feedback::index_close(state.store.as_ref(), &caller.tenant_id, &feedback_id).await;
        let exists = state.store.get(&key).await.map_err(unavailable)?.is_some();
        return Err(feedback_error(if exists {
            FeedbackError::Closed
        } else {
            FeedbackError::NotFound
        }));
    };
    let now = gateway.now();
    let mut closed = current.body.clone();
    closed["status"] = json!(request.status);
    closed["closed_at"] = json!(now);
    closed["closed_by"] = json!(caller.principal_id);
    closed["evidence_ref"] = json!(request.evidence_ref);
    // The closure takes effect first, so the chain never records one that lost a race;
    // if it cannot be audited, it is put back.
    match state.store.compare_and_swap(&key, current.revision, &closed).await {
        Ok(_) => {}
        Err(e) if e.is_conflict() => return Err(feedback_error(FeedbackError::Closed)),
        Err(_) => {
            return Err(ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "store_unavailable",
                "The store is unavailable.",
            ));
        }
    }
    let audited = state
        .audit
        .append(
            &caller.tenant_id,
            "feedback_closed",
            json!({"feedback_id": feedback_id, "status": request.status,
            "evidence_ref": request.evidence_ref, "closed_by": caller.principal_id}),
            &now,
        )
        .await;
    if audited.is_err() {
        if let Ok(Some(now_closed)) = state.store.get(&key).await {
            let _ = state
                .store
                .compare_and_swap(&key, now_closed.revision, &current.body)
                .await;
        }
        return Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "audit_unavailable",
            "The audit log is unavailable.",
        ));
    }
    crate::feedback::index_close(state.store.as_ref(), &caller.tenant_id, &feedback_id)
        .await
        .map_err(feedback_error)?;
    Ok(axum::Json(closed).into_response())
}

/// The tenant's staged rollouts.
async fn list_rollouts<S, L>(State(state): State<Arc<AppState<S, L>>>, headers: HeaderMap) -> ApiResult
where
    S: DocumentStore + 'static,
    L: AppendLog + 'static,
{
    let caller = authorize(&state, &headers, Some("control"))?;
    let current = state
        .store
        .get(&crate::rollout::key(&caller.tenant_id))
        .await
        .map_err(|_| {
            ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "store_unavailable",
                "The store is unavailable.",
            )
        })?;
    Ok(axum::Json(current.map_or_else(|| json!({"rollouts": []}), |r| r.body)).into_response())
}

/// Sets a staged rollout from a baseline pack to a candidate pack; audited first.
async fn set_rollout<S, L>(State(state): State<Arc<AppState<S, L>>>, headers: HeaderMap, body: Bytes) -> ApiResult
where
    S: DocumentStore + 'static,
    L: AppendLog + 'static,
{
    let caller = authorize(&state, &headers, Some("control"))?;
    let change: crate::rollout::RolloutChange = serde_json::from_value(parse_body(&state, &body)?).map_err(|e| {
        ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "request_invalid",
            format!("Invalid rollout: {e}"),
        )
    })?;
    let ours = |r: &str| state.packs.get(r).is_some_and(|p| p.tenant_id == caller.tenant_id);
    if change.baseline == change.candidate
        || !ours(&change.baseline)
        || !ours(&change.candidate)
        || change.percent > 100
        || change.reason.trim().is_empty()
        || change.reason.len() > 1024
    {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "rollout_invalid",
            "Baseline and candidate must be different packs of this tenant, percent 0 to 100, with a reason.",
        ));
    }
    // Live traffic only after the release gate passes on replayed cases.
    let gate = if change.percent > 0 {
        Some(rollout_gate(&state, &caller.tenant_id, &change).await?)
    } else {
        None
    };
    let now = dispatch_gateway(&state)?.now();
    let rollout = json!({"baseline": change.baseline, "candidate": change.candidate, "percent": change.percent,
        "shadow": change.shadow, "reason": change.reason, "by": caller.principal_id, "at": now, "gate": gate});
    state
        .audit
        .append(&caller.tenant_id, "rollout_set", rollout.clone(), &now)
        .await
        .map_err(|_| {
            ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "audit_unavailable",
                "The audit log is unavailable.",
            )
        })?;
    rollout_result(
        crate::rollout::change(state.store.as_ref(), &caller.tenant_id, &change.baseline, Some(rollout)).await,
    )
}

/// Recalled memory is trusted context, so it must be what the memory governance
/// promoted: each item names a stored record (`memory_ref` = record id) that is promoted
/// or corrected, not deleted or past its retention, readable by the run's user or agent,
/// and whose pinned content digest is the recalled content's. Without a memory-governance service, recalled memory is
/// admitted only where the deployment trusts its caller to supply it.
async fn check_recalled_memory<S, L>(
    state: &Arc<AppState<S, L>>,
    gateway: &Gateway<S, L>,
    tenant_id: &str,
    run_context: &Value,
    recalled: &Value,
) -> Result<(), ApiError>
where
    S: DocumentStore + 'static,
    L: AppendLog + 'static,
{
    let items = recalled.as_array().map(Vec::as_slice).unwrap_or_default();
    if items.is_empty() {
        return Ok(());
    }
    let refused = |detail: Value| {
        ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "memory_unverified",
            "Recalled memory must be promoted, current and unchanged.",
        )
        .with_detail(detail)
    };
    if !gateway.governs_memory() {
        return if state.trust_supplied_memory {
            Ok(())
        } else {
            Err(refused(
                json!({"reason": "no memory governance verifies recalled memory"}),
            ))
        };
    }
    let now = gateway.now();
    // One run may not recall two promoted values for the same memory key.
    let mut values: std::collections::HashMap<String, Value> = std::collections::HashMap::new();
    for item in items {
        let memory_ref = item["memory_ref"].as_str().unwrap_or_default();
        let content = item["content"].as_str();
        let stored = match (memory_ref.is_empty(), content) {
            (false, Some(_)) => gateway.memory_state(tenant_id, memory_ref).await.map_err(|_| {
                ApiError::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "store_unavailable",
                    "The store is unavailable.",
                )
            })?,
            _ => None,
        };
        let record = stored.as_ref().map(|s| &s["record"]);
        // Readership is rechecked at recall: the run reads on behalf of its user, by its agent.
        let principals = [&run_context["user"]["user_id"], &run_context["agent"]["agent_id"]];
        let current = record.is_some_and(|r| {
            matches!(r["operation"].as_str(), Some("promote" | "correct"))
                && r["readers"]
                    .as_array()
                    .is_some_and(|readers| principals.iter().any(|p| p.as_str().is_some() && readers.contains(p)))
                && r["retention_expires_at"].as_str().is_some_and(|until| {
                    contextos_contract::validation::compare_contract_times(until, &now)
                        == Some(std::cmp::Ordering::Greater)
                })
                && content.is_some_and(|c| {
                    r["memory_ref"]["sha256"] == contextos_contract::canonical::sha256_text(c).as_str()
                })
        });
        if !current {
            return Err(refused(json!({"memory_ref": memory_ref})));
        }
        // Keyed case-insensitively; a memory without a key cannot be checked, so it is refused.
        let Some(key) = record
            .and_then(|r| r["memory_ref"]["artifact_id"].as_str())
            .map(str::to_lowercase)
        else {
            return Err(refused(json!({"memory_ref": memory_ref, "reason": "no memory key"})));
        };
        if let Some(record) = record
            && let Some(previous) = values.insert(key.clone(), record["memory_ref"]["sha256"].clone())
            && previous != record["memory_ref"]["sha256"]
        {
            return Err(ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "memory_conflict",
                "Recalled memory holds conflicting values for the same key; resolve them first.",
            )
            .with_detail(json!({"memory_key": key})));
        }
    }
    Ok(())
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ResolveEscalation {
    resolution: String,
    reason: String,
}

/// The tenant's open policy escalations, oldest first.
async fn list_escalations<S, L>(
    State(state): State<Arc<AppState<S, L>>>,
    Query(query): Query<FeedbackQuery>,
    headers: HeaderMap,
) -> ApiResult
where
    S: DocumentStore + 'static,
    L: AppendLog + 'static,
{
    let caller = authorize(&state, &headers, Some("audit:read"))?;
    let gateway = dispatch_gateway(&state)?;
    let open = gateway
        .open_escalations(&caller.tenant_id, query.limit.unwrap_or(500).clamp(1, 1000))
        .await
        .map_err(|_| {
            ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "store_unavailable",
                "The store is unavailable.",
            )
        })?;
    Ok(axum::Json(json!({"open": open.len(), "escalations": open})).into_response())
}

/// Records how a human resolved an escalation (operators only).
async fn resolve_escalation<S, L>(
    State(state): State<Arc<AppState<S, L>>>,
    Path(escalation_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult
where
    S: DocumentStore + 'static,
    L: AppendLog + 'static,
{
    use contextos_gateway::EscalationError;
    let caller = authorize(&state, &headers, Some("control"))?;
    let gateway = dispatch_gateway(&state)?;
    let request: ResolveEscalation = serde_json::from_value(parse_body(&state, &body)?).map_err(|e| {
        ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "request_invalid",
            format!("Invalid resolution: {e}"),
        )
    })?;
    match gateway
        .resolve_escalation(
            &caller.tenant_id,
            &escalation_id,
            &caller.principal_id,
            &request.resolution,
            &request.reason,
        )
        .await
    {
        Ok(resolved) => Ok(axum::Json(resolved).into_response()),
        Err(EscalationError::Invalid) => Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "escalation_invalid",
            "Resolution must be handled or dismissed, with a reason.",
        )),
        Err(EscalationError::NotFound) => Err(ApiError::new(
            StatusCode::NOT_FOUND,
            "escalation_not_found",
            "No such escalation.",
        )),
        Err(EscalationError::Resolved) => Err(ApiError::new(
            StatusCode::CONFLICT,
            "escalation_resolved",
            "The escalation is already resolved.",
        )),
        Err(EscalationError::Gateway(_)) => Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "store_unavailable",
            "The store or audit log is unavailable.",
        )),
    }
}

/// Runs the release gate for a rollout: the named runs' replay cases plus every open
/// feedback record's, baseline against candidate. Refuses unless it passes.
async fn rollout_gate<S, L>(
    state: &Arc<AppState<S, L>>,
    tenant_id: &str,
    change: &crate::rollout::RolloutChange,
) -> Result<Value, ApiError>
where
    S: DocumentStore + 'static,
    L: AppendLog + 'static,
{
    let unavailable = |_| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "store_unavailable",
            "The store is unavailable.",
        )
    };
    if change.gate_runs.len() > crate::rollout::MAX_GATE_RUNS {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "rollout_invalid",
            "Too many gate runs.",
        ));
    }
    let mut runs: Vec<String> = change.gate_runs.clone();
    let mut obligations = Vec::new();
    for id in crate::feedback::open_ids(state.store.as_ref(), tenant_id)
        .await
        .map_err(feedback_error)?
        .iter()
        .take(crate::feedback::MAX_OPEN)
    {
        if let Some(record) = state
            .store
            .get(&crate::feedback::record_key(tenant_id, id))
            .await
            .map_err(unavailable)?
            .filter(|r| r.body["status"] == "open")
            && let Some(case) = record.body["replay_obligation"]["case"].as_str()
        {
            obligations.push(case.to_owned());
            runs.push(case.to_owned());
        }
    }
    runs.sort();
    runs.dedup();
    if runs.is_empty() {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "gate_cases_required",
            "Name gate_runs whose replay cases the candidate must pass before it takes live traffic.",
        ));
    }
    // An open correction must be fixed (or its feedback closed with evidence), never
    // waived: acknowledgements may not name feedback cases.
    let ack = &change.acknowledge;
    let waived_feedback: Vec<&String> = obligations
        .iter()
        .filter(|case| ack.policy_loosening.contains(case) || ack.compile_expansion.contains(case))
        .collect();
    if !waived_feedback.is_empty() {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "feedback_not_waivable",
            "Open feedback cases cannot be acknowledged; fix them or close the feedback with evidence.",
        )
        .with_detail(json!({"cases": waived_feedback})));
    }
    let mut cases = Vec::with_capacity(runs.len());
    let mut unavailable_cases = Vec::new();
    let mut unrelated = Vec::new();
    for run in &runs {
        let stored = state
            .store
            .get(&DocKey::new(tenant_id, DocKind::ReplayCase, run))
            .await
            .map_err(unavailable)?
            .filter(|d| !contextos_gateway::is_erased(&d.body));
        match stored.and_then(|d| serde_json::from_value::<contextos_kernel::release_gate::ReplayCase>(d.body).ok()) {
            // Named gate runs must be runs of the baseline (feedback cases are whatever
            // runs the corrections were filed against).
            Some(case) if !obligations.contains(run) && !case.request.context_pack_refs.contains(&change.baseline) => {
                unrelated.push(run.clone());
            }
            Some(case) => cases.push(case),
            None => unavailable_cases.push(run.clone()),
        }
    }
    if !unrelated.is_empty() {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "gate_case_unrelated",
            "Gate runs must be runs of the baseline pack.",
        )
        .with_detail(json!({"runs": unrelated})));
    }
    if !unavailable_cases.is_empty() {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "gate_cases_unavailable",
            "Some replay cases are missing or erased; close feedback whose case was erased.",
        )
        .with_detail(json!({"runs": unavailable_cases})));
    }
    let (baseline, candidate) = (
        state.packs[&change.baseline].compiler.pack().clone(),
        state.packs[&change.candidate].compiler.pack().clone(),
    );
    let acknowledged = change.acknowledge.clone();
    let report = tokio::task::spawn_blocking(move || {
        contextos_kernel::release_gate::evaluate_release_gate(&baseline, &candidate, &cases, &acknowledged)
    })
    .await
    .map_err(|_| {
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "gate_failed",
            "The release gate failed.",
        )
    })?
    .map_err(|e| ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, "gate_invalid", e))?;
    let report = serde_json::to_value(&report).unwrap_or(Value::Null);
    if report["verdict"] != "pass" {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "release_gate_failed",
            "The candidate fails the release gate on replayed cases.",
        )
        .with_detail(report));
    }
    // Global acknowledgements (capabilities, evidence gates) may not waive a feedback case either.
    let waived_in_feedback: Vec<&Value> = report["cases"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|c| {
            c["name"].as_str().is_some_and(|n| obligations.iter().any(|o| o == n))
                && c["changes"].as_array().is_some_and(|chs| {
                    chs.iter()
                        .any(|ch| ch["acknowledged"] == true && ch["effect"] != "neutral")
                })
        })
        .map(|c| &c["name"])
        .collect();
    if !waived_in_feedback.is_empty() {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "feedback_not_waivable",
            "Open feedback cases cannot be acknowledged; fix them or close the feedback with evidence.",
        )
        .with_detail(json!({"cases": waived_in_feedback})));
    }
    // What was waived is part of the record, not only a digest of a report kept nowhere.
    let waived: Vec<Value> = report["cases"]
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|c| {
            c["changes"].as_array().into_iter().flatten().filter(|ch| ch["acknowledged"] == true && ch["effect"] != "neutral").map(
                move |ch| json!({"case": c["name"], "kind": ch["kind"], "effect": ch["effect"], "detail": ch["detail"]}),
            )
        })
        .collect();
    Ok(
        json!({"verdict": "pass", "cases": runs, "feedback_cases": obligations, "waived": waived,
        "report_digest": contextos_contract::canonical::sha256_canonical(&report).unwrap_or_default()}),
    )
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ClearRollout {
    baseline: String,
    reason: String,
}

/// Clears a rollout: all of the baseline's new runs return to it.
async fn clear_rollout<S, L>(State(state): State<Arc<AppState<S, L>>>, headers: HeaderMap, body: Bytes) -> ApiResult
where
    S: DocumentStore + 'static,
    L: AppendLog + 'static,
{
    let caller = authorize(&state, &headers, Some("control"))?;
    let clear: ClearRollout = serde_json::from_value(parse_body(&state, &body)?).map_err(|e| {
        ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "request_invalid",
            format!("Invalid request: {e}"),
        )
    })?;
    if clear.reason.trim().is_empty() || clear.reason.len() > 1024 {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "request_invalid",
            "A reason is required.",
        ));
    }
    let now = dispatch_gateway(&state)?.now();
    state
        .audit
        .append(
            &caller.tenant_id,
            "rollout_cleared",
            json!({"baseline": clear.baseline, "reason": clear.reason, "by": caller.principal_id}),
            &now,
        )
        .await
        .map_err(|_| {
            ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "audit_unavailable",
                "The audit log is unavailable.",
            )
        })?;
    rollout_result(crate::rollout::change(state.store.as_ref(), &caller.tenant_id, &clear.baseline, None).await)
}

fn rollout_result(result: Result<Value, crate::rollout::RolloutError>) -> ApiResult {
    match result {
        Ok(rollouts) => Ok(axum::Json(rollouts).into_response()),
        Err(crate::rollout::RolloutError::TooMany) => Err(ApiError::new(
            StatusCode::CONFLICT,
            "rollouts_full",
            "The tenant has the maximum number of rollouts.",
        )),
        Err(crate::rollout::RolloutError::Store(_)) => Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "store_unavailable",
            "The store is unavailable.",
        )),
    }
}

/// Shadow stage: compiles a baseline run's case under the candidate too, off the
/// request path, and audits the governance difference (`shadow_diff`).
fn shadow_diff<S, L>(state: &Arc<AppState<S, L>>, rollout: &Value, run_id: &str, input: &Value)
where
    S: DocumentStore + 'static,
    L: AppendLog + 'static,
{
    use contextos_kernel::release_gate::{Acknowledgements, ReplayCase, evaluate_release_gate};
    let pack = |key: &Value| {
        state
            .packs
            .get(key.as_str().unwrap_or_default())
            .map(|p| p.compiler.pack().clone())
    };
    let (Some(baseline), Some(candidate)) = (pack(&rollout["baseline"]), pack(&rollout["candidate"])) else {
        return;
    };
    let Ok(case) = serde_json::from_value::<ReplayCase>(json!({"name": run_id, "request": input["request"],
        "run_context": input["run_context"], "deps": if input["deps"].is_null() { json!({}) } else { input["deps"].clone() }}))
    else {
        return;
    };
    // Bounded: shadow work never competes with request handling for more than a few
    // blocking threads, and is dropped (not queued) when they are busy.
    let Ok(slot) = state.shadow_slots.clone().try_acquire_owned() else {
        tracing::debug!("shadow diff skipped: all slots busy");
        return;
    };
    let (state, rollout, run_id) = (state.clone(), rollout.clone(), run_id.to_owned());
    tokio::spawn(async move {
        let compared = tokio::task::spawn_blocking(move || {
            let _slot = slot;
            evaluate_release_gate(&baseline, &candidate, &[case], &Acknowledgements::default())
        })
        .await;
        let Ok(Ok(report)) = compared else {
            return;
        };
        let tenant = state
            .packs
            .get(rollout["baseline"].as_str().unwrap_or_default())
            .map(|p| p.tenant_id.clone());
        let now = state.gateway.as_ref().map(|g| g.now()).unwrap_or_default();
        if let Some(tenant) = tenant {
            let entry = json!({"run_id": run_id, "baseline": rollout["baseline"], "candidate": rollout["candidate"],
                "verdict": report.verdict, "changes": report.cases[0].changes});
            if let Err(error) = state.audit.append(&tenant, "shadow_diff", entry, &now).await {
                tracing::warn!(%error, "shadow diff not recorded");
            }
        }
    });
}

/// Assesses a conformance report for this deployment and audits the outcome.
async fn assess_conformance<S, L>(
    State(state): State<Arc<AppState<S, L>>>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult
where
    S: DocumentStore + 'static,
    L: AppendLog + 'static,
{
    use crate::attest::{OBSERVATION_DOMAIN, REPORT_DOMAIN, TrustedSigner, VERIFICATION_DOMAIN, verify};
    let caller = authorize(&state, &headers, Some("audit:read"))?;
    let body: AssessmentBody = serde_json::from_value(parse_body(&state, &body)?).map_err(|e| {
        ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "request_invalid",
            format!("Invalid assessment: {e}"),
        )
    })?;
    let tenant_only = |signers: &[TrustedSigner]| -> Vec<TrustedSigner> {
        signers
            .iter()
            .filter(|s| s.principal["tenant_id"] == caller.tenant_id.as_str())
            .cloned()
            .collect()
    };
    let assessors = tenant_only(&state.conformance.trusted_assessors);
    let observers = tenant_only(&state.conformance.trusted_evidence_observers);
    if assessors.is_empty() || observers.is_empty() {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "conformance_not_configured",
            "No trusted assessors or evidence observers are configured for this tenant.",
        ));
    }
    // Every attestation must be signed by the trusted principal it names; nothing the
    // caller asserts about verification is taken on its word.
    let attested_report = json!({"report": body.report, "contract": body.contract, "features": body.features});
    let observations = body.evidence_observations.as_array().map_or(&[][..], Vec::as_slice);
    let mut unverified = Vec::new();
    if !verify(
        &assessors,
        &body.report["evaluator"],
        REPORT_DOMAIN,
        &attested_report,
        &body.report_signature,
    ) {
        unverified.push("report".to_owned());
    }
    if !verify(
        &observers,
        &body.report_verification["observer"],
        VERIFICATION_DOMAIN,
        &body.report_verification,
        &body.verification_signature,
    ) {
        unverified.push("report_verification".to_owned());
    }
    if observations.len() != body.evidence_signatures.len() {
        unverified.push("evidence_signatures".to_owned());
    }
    for (i, (observation, signature)) in observations.iter().zip(&body.evidence_signatures).enumerate() {
        if !verify(
            &observers,
            &observation["observer"],
            OBSERVATION_DOMAIN,
            observation,
            signature,
        ) {
            unverified.push(format!("evidence_observations/{i}"));
        }
    }
    if !unverified.is_empty() {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "attestation_unverified",
            "An attestation is not signed by the trusted principal it names.",
        )
        .with_detail(json!(unverified)));
    }
    let assessors: Vec<Value> = assessors.into_iter().map(|s| s.principal).collect();
    let observers: Vec<Value> = observers.into_iter().map(|s| s.principal).collect();
    let now = state.gateway.as_ref().map_or_else(
        || {
            let micros = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| i64::try_from(d.as_micros()).unwrap_or(i64::MAX));
            contextos_contract::validation::format_unix_micros(micros)
        },
        |g| g.now(),
    );
    let input = json!({
        "contract": body.contract, "features": body.features, "report": body.report,
        "report_verification": body.report_verification, "evidence_observations": body.evidence_observations,
        "support": state.support, "registry": serde_json::to_value(&*STANDARD_PROFILE_REGISTRY).unwrap_or(Value::Null),
        "evaluation_time": now,
        "scope": {"workflow_id": body.scope.workflow_id, "release_refs": body.scope.release_refs,
            "environment_ref": body.scope.environment_ref, "required_utility_case_ids": body.scope.required_utility_case_ids,
            "implementation_id": state.support["implementation_id"], "implementation_version": state.support["implementation_version"]},
        "trusted_assessors": assessors, "trusted_evidence_observers": observers,
    });
    let assessment = contextos_kernel::conformance::assess_conformance_report(&input);
    state
        .audit
        .append(
            &caller.tenant_id,
            "conformance_assessed",
            json!({"report_id": assessment.report_id, "workflow_id": assessment.workflow_id,
                "outcome": assessment.outcome, "reasons": assessment.reasons, "assessed_for": caller.principal_id}),
            &now,
        )
        .await
        .map_err(|_| {
            ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "audit_unavailable",
                "The audit log is unavailable.",
            )
        })?;
    Ok(axum::Json(assessment).into_response())
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ErasureBody {
    reason: String,
}

/// Erases a finished run's personal content (replay case and compiled context),
/// leaving audited tombstones.
async fn erase_run<S, L>(
    State(state): State<Arc<AppState<S, L>>>,
    Path(run_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult
where
    S: DocumentStore + 'static,
    L: AppendLog + 'static,
{
    let caller = authorize(&state, &headers, Some("control"))?;
    let gateway = dispatch_gateway(&state)?;
    let request: ErasureBody = serde_json::from_value(parse_body(&state, &body)?).map_err(|e| {
        ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "request_invalid",
            format!("Invalid erasure: {e}"),
        )
    })?;
    let admission = load_admission(&state, &caller, &run_id).await?;
    match gateway
        .erase_run(&admission, &caller.principal_id, &request.reason)
        .await
    {
        Ok(record) => Ok(axum::Json(record).into_response()),
        Err(ErasureError::RunActive) => Err(ApiError::new(
            StatusCode::CONFLICT,
            "run_active",
            "Only a finished run can be erased.",
        )),
        Err(ErasureError::Invalid) => Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "request_invalid",
            "A reason is required.",
        )),
        Err(ErasureError::Gateway(_)) => Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "store_unavailable",
            "The store is unavailable.",
        )),
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
    if is_erased(&case) {
        return Err(ApiError::new(
            StatusCode::GONE,
            "replay_case_erased",
            "This run's content was erased.",
        ));
    }
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
        .route("/v1/audit/keys", get(audit_keys::<S, L>))
        .route("/v1/revocations", get(list_revocations::<S, L>).post(revoke::<S, L>))
        .route("/v1/revocations/restore", post(restore::<S, L>))
        .route("/v1/conformance/assess", post(assess_conformance::<S, L>))
        .route("/v1/runs/{run_id}/feedback", post(file_feedback::<S, L>))
        .route("/v1/feedback", get(list_feedback::<S, L>))
        .route("/v1/escalations", get(list_escalations::<S, L>))
        .route(
            "/v1/escalations/{escalation_id}/resolve",
            post(resolve_escalation::<S, L>),
        )
        .route("/v1/feedback/{feedback_id}/close", post(close_feedback::<S, L>))
        .route("/v1/rollouts", get(list_rollouts::<S, L>).post(set_rollout::<S, L>))
        .route("/v1/rollouts/clear", post(clear_rollout::<S, L>))
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
        .route("/v1/runs/{run_id}/erase", post(erase_run::<S, L>))
        .route("/v1/runs/{run_id}/usage/reserve", post(reserve_usage::<S, L>))
        .route(
            "/v1/runs/{run_id}/checkpoint",
            get(latest_checkpoint::<S, L>).post(save_checkpoint::<S, L>),
        )
        .route("/v1/runs/{run_id}/usage/settle", post(settle_usage::<S, L>))
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
