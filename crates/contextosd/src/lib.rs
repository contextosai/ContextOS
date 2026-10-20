//! `contextosd`: the ContextOS runtime server.

pub mod app;
pub mod auth;
pub mod config;
pub mod metrics;

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
pub fn build_state<S, L: contextos_store::AppendLog>(
    config: &Config,
    store: Arc<S>,
    log: L,
    signer: AuditSigner,
    packs: HashMap<String, LoadedPack>,
) -> Arc<AppState<S, L>> {
    let mut keys = KeyRing::new();
    keys.insert(signer.kid(), signer.verifying_key());
    let _ = &*STANDARD_PROFILE_REGISTRY;
    Arc::new(AppState {
        store,
        audit: Arc::new(AuditWriter::new(log, signer)),
        audit_keys: keys,
        auth: auth::Authenticator::new(&config.api_keys),
        metrics: Arc::default(),
        packs,
        support: support_declaration(config),
        max_body_bytes: config.server.max_body_bytes,
    })
}
