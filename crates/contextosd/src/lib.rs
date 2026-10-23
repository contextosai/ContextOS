//! `contextosd`: the ContextOS runtime server.

pub mod app;
pub mod attest;
pub mod auth;
pub mod config;
pub mod configs;
pub mod feedback;
pub mod kms;
pub mod limits;
pub mod mcp;
pub mod membership;
pub mod metrics;
pub mod oidc;
pub mod retention;
pub mod rollout;
pub mod runtime;
pub mod telemetry;

use std::collections::HashMap;
use std::sync::Arc;

use contextos_audit::{AuditSigner, AuditWriter, KeyRing};
use contextos_kernel::STANDARD_PROFILE_REGISTRY;
use serde_json::{Value, json};

pub use app::{AppState, LoadedPack, load_pack, router};
pub use config::{Config, ConfigError};

/// The configured audit signer: a KMS-held key, or a seed from the environment.
pub async fn audit_signer(config: &Config) -> Result<AuditSigner, String> {
    match &config.audit.kms {
        Some(kms) => {
            let development = config.server.mode == config::Mode::Development;
            kms::vault_transit_signer(kms, &config.audit.key_id, development).await
        }
        None => signer_from_env(&config.audit.signing_seed_env, &config.audit.key_id),
    }
}

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

/// What this deployment enforces, for operators (`GET /v1/deployment`): mode, support,
/// resolved guards, which fact services and adapters are wired, and how audit is
/// signed. Names only: no endpoint, credential or environment variable is included.
pub fn deployment_summary(config: &Config) -> Value {
    let providers = config.providers.as_ref().map(|p| {
        json!({
            "authority": true,
            "constraints": true,
            "approvals": true,
            "idempotency": p.idempotency.is_some(),
            "data_flow": p.data_flow.is_some(),
            "boundary": p.boundary.is_some(),
            "memory": p.memory.is_some(),
        })
    });
    let adapters: Vec<Value> = config
        .adapters
        .iter()
        .map(|a| {
            let kind = match a.kind {
                config::AdapterKind::Mcp => "mcp",
                config::AdapterKind::Http => "http",
            };
            json!({"id": a.id, "kind": kind})
        })
        .collect();
    let floors = config
        .completion_score_floors()
        .map(|f| json!({"policy_floor": f.policy_floor, "safety_floor": f.safety_floor}));
    json!({
        "mode": match config.server.mode {
            config::Mode::Production => "production",
            config::Mode::Development => "development",
        },
        "support": support_declaration(config),
        "store": match config.store {
            config::StoreConfig::Memory => "memory",
            config::StoreConfig::Postgres { .. } => "postgres",
        },
        "dispatch": config.providers.is_some(),
        "guarantees": config.guarantees,
        "providers": providers,
        "adapters": adapters,
        "guards": {
            "identical_tool_calls": config.guards.identical_tool_calls,
            "refuse_repeated_effects": config.guards.refuse_repeated_effects,
            "model_call_min_tokens": config.guards.model_call_min_tokens,
            "required_release_refs": config.required_release_refs(),
            "require_user_role": config.require_user_role(),
            "trust_supplied_memory": config.server.mode == config::Mode::Development || config.guards.trust_supplied_memory,
            "require_tool_schemas": config.guards.require_tool_schemas,
            "completion_requires_scores": floors,
            "require_task_authorization": config.guards.require_task_authorization,
        },
        "audit": {
            "key_id": config.audit.key_id,
            "signer": if config.audit.kms.is_some() { "kms" } else { "local" },
            "retired_key_ids": config.audit.retired_keys.iter().map(|k| k.kid.clone()).collect::<Vec<_>>(),
        },
        "authentication": {"api_keys": !config.api_keys.is_empty(), "oidc_issuers": config.oidc.len()},
        "retention": {"run_content_days": config.retention.run_content_days},
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
    if !config.guarantees.is_empty() && dispatch.is_none() {
        return Err("shared guarantees require an active dispatch gateway".into());
    }
    let mut keys = KeyRing::new();
    keys.insert(signer.kid(), signer.verifying_key());
    for retired in &config.audit.retired_keys {
        if let Some(key) = retired.verifying_key() {
            keys.insert_retired(&retired.kid, key, &retired.retired_at);
        }
    }
    let _ = &*STANDARD_PROFILE_REGISTRY;
    let audit = Arc::new(
        AuditWriter::new(log, signer).with_retired_kids(config.audit.retired_keys.iter().map(|k| k.kid.clone())),
    );
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
        deployment: deployment_summary(config),
        running: Arc::new(configs::Running::of(config)),
        max_body_bytes: config.server.max_body_bytes,
        gateway,
        trust_domain,
        gateway_principal_id,
        limits,
        conformance: config.conformance.clone(),
        shadow_slots: Arc::new(tokio::sync::Semaphore::new(4)),
        required_release_refs: config.required_release_refs(),
        require_user_role: config.require_user_role(),
        require_task_authorization: config.guards.require_task_authorization,
        trust_supplied_memory: development || config.guards.trust_supplied_memory,
    }))
}
