//! Runtime wiring for governed dispatch: system clock, identifiers and gateway setup.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use contextos_contract::execution::WorkflowFeatureSet;
use contextos_contract::types::{ActionEffect, ActionInteraction, CompiledContext, DataClassification};
use contextos_contract::validation::format_unix_micros;
use contextos_gateway::{Adapter, CapabilityManifest, Clock, Gateway, IdSource, Ports};
use contextos_store::{AppendLog, DocumentStore};
use serde_json::Value;

/// Wall clock with microsecond contract timestamps.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> String {
        let micros = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| i64::try_from(d.as_micros()).unwrap_or(i64::MAX));
        format_unix_micros(micros)
    }
}

/// Time-ordered UUIDv7 identifiers.
#[derive(Debug, Clone, Copy, Default)]
pub struct UuidIds;

impl IdSource for UuidIds {
    fn new_id(&self, prefix: &str) -> String {
        format!("{prefix}_{}", uuid::Uuid::now_v7().simple())
    }
}

/// Everything needed to enable governed dispatch.
pub struct DispatchSetup {
    pub ports: Ports,
    pub adapters: Vec<(String, Arc<dyn Adapter>)>,
    pub manifests: Vec<CapabilityManifest>,
    /// Replaced versions (`retired_capabilities`), read for recovery only.
    pub retired: Vec<CapabilityManifest>,
    pub trust_domain: String,
    pub gateway_principal_id: String,
    /// Loop guard limit (`[guards] identical_tool_calls`); `None` disables it.
    pub loop_limit: Option<u64>,
    /// `[guards] refuse_repeated_effects`.
    pub refuse_repeated_effects: bool,
    /// `[guards] model_call_min_tokens`.
    pub model_call_floor: u64,
    /// Registered result schemas for delegations (`[[result_schemas]]`), by reference.
    pub result_schemas: Vec<(String, serde_json::Value)>,
    /// `[guards] completion_requires_scores` as (policy, safety) floors.
    pub completion_floor: Option<(f64, f64)>,
    /// Production: every delegation names a registered result schema.
    pub require_result_schemas: bool,
    pub guarantees: Vec<contextos_gateway::SharedGuarantee>,
    /// `[guards.approval_step_up]`.
    pub approval_step_up: Option<contextos_gateway::step_up::StepUpPolicy>,
    /// `[providers.result_screening]`.
    pub result_screening: Option<Arc<dyn contextos_gateway::result_screening::ResultScreeningProvider>>,
}

impl std::fmt::Debug for DispatchSetup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DispatchSetup")
            .field("trust_domain", &self.trust_domain)
            .finish_non_exhaustive()
    }
}

pub(crate) fn build_gateway<S, L>(
    store: Arc<S>,
    audit: Arc<contextos_audit::AuditWriter<L>>,
    setup: DispatchSetup,
) -> Result<Gateway<S, L>, contextos_gateway::GatewayError>
where
    S: DocumentStore + 'static,
    L: AppendLog + 'static,
{
    let mut gateway = Gateway::new(store, audit, setup.ports);
    for (id, adapter) in setup.adapters {
        gateway.register_adapter(id, adapter);
    }
    for manifest in setup.manifests {
        gateway.pin_capability(manifest)?;
    }
    for manifest in setup.retired {
        gateway.retire_capability(manifest)?;
    }
    for (schema_ref, schema) in &setup.result_schemas {
        gateway
            .register_result_schema(schema_ref, schema)
            .map_err(|e| contextos_gateway::manifest::ManifestError::OutputSchema(schema_ref.clone(), e))?;
    }
    gateway.set_loop_limit(setup.loop_limit);
    gateway.set_refuse_repeated_effects(setup.refuse_repeated_effects);
    gateway.set_model_call_floor(setup.model_call_floor);
    gateway.set_completion_floor(setup.completion_floor);
    gateway.require_result_schemas(setup.require_result_schemas);
    gateway.set_shared_guarantees(setup.guarantees)?;
    gateway.set_approval_step_up(setup.approval_step_up);
    if let Some(screening) = setup.result_screening {
        gateway.set_result_screening(screening);
    }
    Ok(gateway)
}

/// Workflow features derived from what the run can actually do. Callers may add
/// features (`requested`), never remove derived ones.
pub fn derive_features<S, L>(
    gateway: &Gateway<S, L>,
    compiled: &CompiledContext,
    pack_classification: DataClassification,
    requested: &Value,
) -> Result<WorkflowFeatureSet, &'static str>
where
    S: DocumentStore + 'static,
    L: AppendLog + 'static,
{
    let mut features = WorkflowFeatureSet {
        sensitive_data: pack_classification >= DataClassification::Confidential,
        ..Default::default()
    };
    for tool in &compiled.manifests.tool_manifest {
        for capability in &tool.capabilities {
            let Some(manifest) = gateway.manifest(&format!("{}.{capability}", tool.adapter_id)) else {
                continue;
            };
            let risk = &manifest.action_risk;
            features.external_network = true;
            features.external_effects |= risk.effect != ActionEffect::None;
            features.arbitrary_code |= risk.interaction == ActionInteraction::Computer;
            features.delegation |= risk.interaction == ActionInteraction::AgentToAgent;
            features.sensitive_data |= risk.data_scope >= DataClassification::Confidential;
        }
    }
    if !requested.is_null() {
        let object = requested.as_object().ok_or("features must be an object of booleans")?;
        let mut merged = serde_json::to_value(features).map_err(|_| "features")?;
        for (key, value) in object {
            let flag = value.as_bool().ok_or("features must be an object of booleans")?;
            let slot = merged.get_mut(key).ok_or("unknown workflow feature")?;
            *slot = Value::Bool(slot.as_bool().unwrap_or(false) || flag);
        }
        features = serde_json::from_value(merged).map_err(|_| "features")?;
    }
    Ok(features)
}

/// A broker that hands adapters one credential from the environment. Deployments with
/// a real broker (per-call, capability-scoped tokens) implement `CredentialBroker`.
#[derive(Debug, Clone)]
struct EnvCredential(contextos_adapters::Credential);

#[async_trait::async_trait]
impl contextos_adapters::CredentialBroker for EnvCredential {
    async fn credential(
        &self,
        _: &CapabilityManifest,
        _: &contextos_gateway::AdapterCall,
    ) -> Result<Option<contextos_adapters::Credential>, contextos_gateway::PortError> {
        Ok(Some(self.0.clone()))
    }

    async fn discovery_credential(
        &self,
    ) -> Result<Option<contextos_adapters::Credential>, contextos_gateway::PortError> {
        Ok(Some(self.0.clone()))
    }
}

/// The adapter's OAuth client-credentials broker, with the secret from the environment.
pub fn oauth_broker(
    adapter: &crate::config::AdapterConfig,
    oauth: &crate::config::OAuthClientConfig,
    policy: &contextos_adapters::TransportPolicy,
) -> Result<contextos_adapters::OAuthClientCredentials, String> {
    if adapter.token_env.is_some() {
        return Err(format!("{}: set token_env or oauth, not both", adapter.id));
    }
    let secret =
        std::env::var(&oauth.client_secret_env).map_err(|_| format!("{} is not set", oauth.client_secret_env))?;
    contextos_adapters::OAuthClientCredentials::new(
        &oauth.token_url,
        &oauth.client_id,
        secret,
        oauth.scope.clone(),
        oauth.resource.clone().unwrap_or_else(|| adapter.endpoint.clone()),
        std::time::Duration::from_secs(oauth.refresh_before_seconds),
        policy,
    )
    .map_err(|e| format!("{}: oauth token_url: {e}", adapter.id))
}

fn env_credential(var: Option<&String>) -> Result<Option<contextos_adapters::Credential>, String> {
    var.map(|var| {
        std::env::var(var)
            .map(contextos_adapters::Credential::bearer)
            .map_err(|_| format!("{var} is not set"))
    })
    .transpose()
}

/// Builds dispatch wiring from configuration; `None` when no providers are configured.
pub fn dispatch_setup_from_config(config: &crate::Config) -> Result<Option<DispatchSetup>, String> {
    use contextos_adapters::{
        HttpAdapter, McpAdapter, NoCredentials, RemoteApprovals, RemoteAuthority, RemoteConstraints, RemoteFacts,
        RemoteIdempotency, ResultProjection, TransportPolicy,
    };
    let Some(providers) = &config.providers else {
        if !config.guarantees.is_empty() {
            return Err("shared guarantees require configured dispatch providers".into());
        }
        return Ok(None);
    };
    let identity = config
        .identity
        .as_ref()
        .ok_or("dispatch requires an [identity] section")?;
    let policy = TransportPolicy {
        allow_loopback_http: config.server.mode == crate::config::Mode::Development,
        ..TransportPolicy::default()
    };
    let remote = |p: &crate::config::RemoteProvider| -> Result<Arc<RemoteFacts>, String> {
        let credential = env_credential(p.token_env.as_ref())?;
        let timeout = std::time::Duration::from_millis(p.timeout_ms);
        RemoteFacts::new(&p.url, credential, policy.clone(), timeout)
            .map(Arc::new)
            .map_err(|e| format!("{}: {e}", p.url))
    };
    let ports = Ports {
        clock: Arc::new(SystemClock),
        ids: Arc::new(UuidIds),
        authority: Arc::new(RemoteAuthority(remote(&providers.authority)?)),
        policy: Arc::new(contextos_gateway::PinnedPolicy),
        constraints: Arc::new(RemoteConstraints(remote(&providers.constraints)?)),
        approvals: Arc::new(RemoteApprovals(remote(&providers.approvals)?)),
        idempotency: match &providers.idempotency {
            Some(p) => Some(Arc::new(RemoteIdempotency(remote(p)?))),
            None => None,
        },
        data_flow: match &providers.data_flow {
            Some(p) => Some(Arc::new(contextos_adapters::remote::RemoteDataFlow(remote(p)?))),
            None => None,
        },
        boundary: match &providers.boundary {
            Some(p) => Some(Arc::new(contextos_adapters::remote::RemoteBoundary(remote(p)?))),
            None => None,
        },
        memory: match &providers.memory {
            Some(p) => Some(Arc::new(contextos_adapters::remote::RemoteMemoryPolicy(remote(p)?))),
            None => None,
        },
    };
    let mut adapters: Vec<(String, Arc<dyn Adapter>)> = Vec::new();
    for adapter in &config.adapters {
        let broker: Arc<dyn contextos_adapters::CredentialBroker> = match &adapter.oauth {
            Some(oauth) => Arc::new(oauth_broker(adapter, oauth, &policy)?),
            None => match env_credential(adapter.token_env.as_ref())? {
                Some(credential) => Arc::new(EnvCredential(credential)),
                None => Arc::new(NoCredentials),
            },
        };
        let projection = match adapter.result_projection {
            None | Some(crate::config::ResultProjectionConfig::Flat) => ResultProjection::Flat,
            Some(crate::config::ResultProjectionConfig::McpResultV1) => ResultProjection::McpResultV1,
        };
        if adapter.kind != crate::config::AdapterKind::Mcp && adapter.result_projection.is_some() {
            return Err(format!(
                "{}: result_projection applies only to mcp adapters",
                adapter.id
            ));
        }
        let built: Arc<dyn Adapter> = match adapter.kind {
            crate::config::AdapterKind::Mcp => Arc::new(
                McpAdapter::new(&adapter.endpoint, policy.clone(), broker, "contextosd")
                    .map_err(|e| format!("{}: {e}", adapter.id))?
                    .with_projection(projection),
            ),
            crate::config::AdapterKind::Http => Arc::new(
                HttpAdapter::new(&adapter.endpoint, policy.clone(), broker)
                    .map_err(|e| format!("{}: {e}", adapter.id))?,
            ),
        };
        adapters.push((adapter.id.clone(), built));
    }
    let mut result_schemas = Vec::new();
    for schema in &config.result_schemas {
        let path = &schema.path;
        let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let value = contextos_contract::ingress::parse_strict(text.as_bytes(), 1 << 20)
            .map_err(|e| format!("{}: {e}", path.display()))?;
        contextos_contract::schema::ArgumentSchema::compile(&value).map_err(|e| format!("{}: {e}", path.display()))?;
        result_schemas.push((schema.schema_ref.clone(), value));
    }
    let mut manifests = Vec::new();
    for path in &config.capabilities {
        let manifest = read_manifest(path)?;
        // Read-only tools included: what they return is where injected content arrives.
        if config.guards.require_tool_schemas && (manifest.input_schema.is_none() || manifest.output_schema.is_none()) {
            return Err(format!(
                "{}: [guards] require_tool_schemas: {} needs input_schema and output_schema",
                path.display(),
                manifest.capability_id
            ));
        }
        // Only an MCP server lists its tools, so a pin elsewhere could never be checked
        // and would refuse every call.
        if !config
            .adapters
            .iter()
            .any(|a| a.id == manifest.adapter_id && a.kind == crate::config::AdapterKind::Mcp)
            && (manifest.upstream_tool_digest.is_some() || manifest.upstream_description_digest.is_some())
        {
            return Err(format!(
                "{}: {} pins an upstream tool, but adapter {} is not an MCP adapter, whose tools \
                 could be listed and checked",
                path.display(),
                manifest.capability_id,
                manifest.adapter_id
            ));
        }
        // An HTTP success status is not proof of the effect: the provider's reported
        // state is, so an effectful HTTP capability must declare how to read it.
        let http = config
            .adapters
            .iter()
            .any(|a| a.id == manifest.adapter_id && a.kind == crate::config::AdapterKind::Http);
        let effectful = manifest.action_risk.effect != contextos_contract::types::ActionEffect::None;
        if http
            && effectful
            && manifest
                .recovery
                .completion
                .as_ref()
                .is_none_or(|c| c.status_tool.is_empty())
        {
            return Err(format!(
                "{}: {} is effectful on HTTP adapter {} and needs recovery.completion: the provider's \
                 reported-state contract that decides its 2xx responses, with a status_tool",
                path.display(),
                manifest.capability_id,
                manifest.adapter_id
            ));
        }
        // Nor is an MCP result without `isError`: a tool can finish reporting a pending
        // or failed job. Its reported state decides once the contract is declared.
        let mcp = config
            .adapters
            .iter()
            .any(|a| a.id == manifest.adapter_id && a.kind == crate::config::AdapterKind::Mcp);
        if mcp && effectful && manifest.recovery.completion.is_none() && config.require_completion_contracts() {
            return Err(format!(
                "{}: [guards] require_completion_contracts: {} is effectful on MCP adapter {} and needs \
                 recovery.completion (state_pointer into structuredContent and the states that settle it)",
                path.display(),
                manifest.capability_id,
                manifest.adapter_id
            ));
        }
        // An upstream MCP server can change what a tool does under the same name; the
        // enterprise profile requires each effectful one to be pinned to its review.
        if mcp
            && effectful
            && manifest.upstream_tool_digest.is_none()
            && config.support.profiles.iter().any(|p| p == "contextos.enterprise")
        {
            return Err(format!(
                "{}: {} is effectful on MCP adapter {} and needs upstream_tool_digest under the enterprise \
                 profile (print it with `contextosd --pin-mcp-tools <config>`)",
                path.display(),
                manifest.capability_id,
                manifest.adapter_id
            ));
        }
        manifests.push(manifest);
    }
    // Startup guards are for what is dispatched; a retired version only recovers.
    let retired = config
        .retired_capabilities
        .iter()
        .map(|path| read_manifest(path))
        .collect::<Result<_, _>>()?;
    Ok(Some(DispatchSetup {
        ports,
        adapters,
        manifests,
        retired,
        trust_domain: identity.trust_domain.clone(),
        gateway_principal_id: identity.gateway_principal_id.clone(),
        loop_limit: Some(config.guards.identical_tool_calls).filter(|n| *n > 0),
        refuse_repeated_effects: config.guards.refuse_repeated_effects,
        model_call_floor: config.guards.model_call_min_tokens,
        result_schemas,
        completion_floor: config
            .completion_score_floors()
            .map(|f| (f.policy_floor, f.safety_floor)),
        require_result_schemas: config.server.mode == crate::config::Mode::Production,
        guarantees: config.guarantees.clone(),
        approval_step_up: config.guards.approval_step_up.clone(),
        result_screening: match &providers.result_screening {
            Some(p) => Some(Arc::new(contextos_adapters::remote::RemoteResultScreening(remote(p)?))),
            None => None,
        },
    }))
}

fn read_manifest(path: &std::path::Path) -> Result<CapabilityManifest, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let value = contextos_contract::ingress::parse_strict(text.as_bytes(), 1 << 20)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    let manifest: CapabilityManifest = serde_json::from_value(value).map_err(|e| format!("{}: {e}", path.display()))?;
    manifest.validate().map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(manifest)
}

/// Effectful capabilities whose actions carry no amount, or name no resource: a task
/// scope's `amount_ceiling` or `resource_ids`, and a task's `amount_total`, pass them
/// whatever they move. Declare `amount` and `resource_pointers` for money-moving tools.
pub fn unbounded_capabilities(setup: &DispatchSetup) -> Vec<String> {
    let mut notes = Vec::new();
    for m in &setup.manifests {
        if m.action_risk.effect == contextos_contract::types::ActionEffect::None {
            continue;
        }
        let missing: Vec<&str> = [
            ("amount", m.amount.is_none()),
            ("resource_pointers", m.resource_pointers.is_empty()),
        ]
        .into_iter()
        .filter_map(|(name, absent)| absent.then_some(name))
        .collect();
        if !missing.is_empty() {
            notes.push(format!(
                "{} is effectful and declares no {}: task amount and resource limits do not bound it",
                m.capability_id,
                missing.join(" or ")
            ));
        }
    }
    notes
}
