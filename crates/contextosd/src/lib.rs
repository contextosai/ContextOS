//! `contextosd`: the ContextOS runtime server.

pub mod app;
pub mod auth;
pub mod config;
pub mod limits;
pub mod mcp;
pub mod membership;
pub mod metrics;
pub mod oidc;
pub mod retention;
pub mod runtime;
pub mod telemetry;

use std::collections::HashMap;
use std::sync::Arc;

use contextos_audit::{AuditSigner, AuditWriter, KeyRing};
use contextos_kernel::STANDARD_PROFILE_REGISTRY;
use serde_json::{Value, json};

pub use app::{AppState, LoadedPack, load_pack, router};
pub use config::{Config, ConfigError};

/// Reads a 32-byte hex seed from the named environment variable.
pub fn signer_from_env(var: &str, key_id: &str) -> Result<AuditSigner, String> {
    let hex_seed = std::env::var(var).map_err(|_| format!("{var} is not set"))?;
    let bytes = hex::decode(hex_seed.trim()).map_err(|_| format!("{var} must be hex"))?;
    let seed: [u8; 32] = bytes.try_into().map_err(|_| format!("{var} must hold 32 bytes"))?;
    Ok(AuditSigner::from_seed(key_id, seed))
}

/// The deployment's `RuntimeSupportDeclaration`.
pub fn support_declaration(config: &Config) -> Value {
    let profiles: Vec<Value> = config
        .support
        .profiles
        .iter()
        .map(|p| json!({"profile_id": p, "profile_version": "1"}))
        .collect();
    let controls: Vec<Value> = config
        .support
        .controls
        .iter()
        .map(|c| json!({"control_id": c, "control_version": "1"}))
        .collect();
    json!({
        "implementation_id": config.support.implementation_id,
        "implementation_version": config.support.implementation_version,
        "supported_profiles": profiles,
        "supported_controls": controls,
    })
}

/// Assembles server state for any store backend.
#[allow(clippy::implicit_hasher)]
pub fn build_state<S, L>(
    config: &Config,
    store: Arc<S>,
    log: L,
    signer: AuditSigner,
    packs: HashMap<String, LoadedPack>,
    dispatch: Option<runtime::DispatchSetup>,
) -> Result<Arc<AppState<S, L>>, String>
where
    S: contextos_store::DocumentStore + 'static,
    L: contextos_store::AppendLog + 'static,
{
    let mut keys = KeyRing::new();
    keys.insert(signer.kid(), signer.verifying_key());
    let _ = &*STANDARD_PROFILE_REGISTRY;
    let audit = Arc::new(AuditWriter::new(log, signer));
    let (trust_domain, gateway_principal_id) = dispatch
        .as_ref()
        .map(|d| (d.trust_domain.clone(), d.gateway_principal_id.clone()))
        .unwrap_or_default();
    let gateway = match dispatch {
        Some(setup) => Some(Arc::new(
            runtime::build_gateway(store.clone(), audit.clone(), setup).map_err(|e| e.to_string())?,
        )),
        None => None,
    };
    let development = config.server.mode == config::Mode::Development;
    let issuers = config
        .oidc
        .iter()
        .map(|c| oidc::OidcIssuer::new(c.clone(), development).map(Arc::new))
        .collect::<Result<Vec<_>, _>>()?;
    let limits = Arc::new(limits::Limiter::new(config.limits.clone()));
    if let Ok(runtime) = tokio::runtime::Handle::try_current() {
        for issuer in &issuers {
            runtime.spawn(issuer.clone().run_refresh());
        }
        let leader = Arc::new(std::sync::atomic::AtomicBool::new(false));
        runtime.spawn(membership::run(
            store.clone(),
            limits.clone(),
            leader.clone(),
            std::time::Duration::from_millis(config.limits.heartbeat_ms),
        ));
        if let Some(gateway) = &gateway {
            runtime.spawn(retention::run(
                store.clone(),
                gateway.clone(),
                leader,
                config.retention.clone(),
            ));
        }
    }
    Ok(Arc::new(AppState {
        store,
        audit,
        audit_keys: keys,
        auth: auth::Authenticator::new(&config.api_keys).with_issuers(issuers),
        metrics: Arc::default(),
        packs,
        support: support_declaration(config),
        max_body_bytes: config.server.max_body_bytes,
        gateway,
        trust_domain,
        gateway_principal_id,
        limits,
        conformance: config.conformance.clone(),
    }))
}
