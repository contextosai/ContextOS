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
    pub trust_domain: String,
    pub gateway_principal_id: String,
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
        RemoteIdempotency, TransportPolicy,
    };
    let Some(providers) = &config.providers else {
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
    };
    let mut adapters: Vec<(String, Arc<dyn Adapter>)> = Vec::new();
    for adapter in &config.adapters {
        let broker: Arc<dyn contextos_adapters::CredentialBroker> = match env_credential(adapter.token_env.as_ref())? {
            Some(credential) => Arc::new(EnvCredential(credential)),
            None => Arc::new(NoCredentials),
        };
        let built: Arc<dyn Adapter> = match adapter.kind {
            crate::config::AdapterKind::Mcp => Arc::new(
                McpAdapter::new(&adapter.endpoint, policy.clone(), broker, "contextosd")
                    .map_err(|e| format!("{}: {e}", adapter.id))?,
            ),
            crate::config::AdapterKind::Http => Arc::new(
                HttpAdapter::new(&adapter.endpoint, policy.clone(), broker)
                    .map_err(|e| format!("{}: {e}", adapter.id))?,
            ),
        };
        adapters.push((adapter.id.clone(), built));
    }
    let mut manifests = Vec::new();
    for path in &config.capabilities {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let value = contextos_contract::ingress::parse_strict(text.as_bytes(), 1 << 20)
            .map_err(|e| format!("{}: {e}", path.display()))?;
        let manifest: CapabilityManifest =
            serde_json::from_value(value).map_err(|e| format!("{}: {e}", path.display()))?;
        manifest.validate().map_err(|e| format!("{}: {e}", path.display()))?;
        manifests.push(manifest);
    }
    Ok(Some(DispatchSetup {
        ports,
        adapters,
        manifests,
        trust_domain: identity.trust_domain.clone(),
        gateway_principal_id: identity.gateway_principal_id.clone(),
    }))
}
