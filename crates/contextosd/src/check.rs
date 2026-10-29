//! `contextosd --check-config <path>`: the validation startup performs before serving,
//! run on its own. It reads the configuration, packs and pinned manifests and checks
//! that the signing key source and store settings are present, then binds the listen
//! address once to confirm it is free. It does not contact a key service, connect to
//! the store or start background work, so a passing check does not prove those reachable.

use std::path::Path;

use crate::config::{Mode, StoreConfig};
use crate::{Config, guarantees_need_dispatch, load_packs, runtime, signer_from_env};

/// One line per passing check, or the first failure.
pub fn check_config(path: &Path) -> Result<Vec<String>, String> {
    let config = Config::load(path).map_err(|e| e.to_string())?;
    let mut report = vec![format!(
        "configuration parsed ({} mode)",
        match config.server.mode {
            Mode::Production => "production",
            Mode::Development => "development",
        }
    )];

    let packs = load_packs(&config)?;
    report.push(format!("{} context pack(s) valid", packs.len()));

    let dispatch = runtime::dispatch_setup_from_config(&config)?;
    guarantees_need_dispatch(&config, dispatch.is_some())?;
    report.push(match &dispatch {
        Some(_) => format!(
            "dispatch gateway and manifests valid; {} shared guarantee(s)",
            config.guarantees.len()
        ),
        None => "no dispatch gateway configured".into(),
    });

    report.push(if let Some(kms) = &config.audit.kms {
        if std::env::var_os(&kms.token_env).is_none() {
            return Err(format!("{} (the KMS token) is not set", kms.token_env));
        }
        format!("audit signing via {} at {} (not contacted)", kms.kind, kms.url)
    } else {
        signer_from_env(&config.audit.signing_seed_env, &config.audit.key_id)?;
        format!("audit signing seed in {}", config.audit.signing_seed_env)
    });

    report.push(match &config.store {
        StoreConfig::Memory => "in-memory store (state is lost on restart)".into(),
        StoreConfig::Postgres { url_env, .. } => {
            if std::env::var_os(url_env).is_none() {
                return Err(format!("{url_env} (the PostgreSQL URL) is not set"));
            }
            format!("PostgreSQL URL in {url_env} (not connected)")
        }
    });

    let listen = config.server.listen;
    std::net::TcpListener::bind(listen).map_err(|e| format!("cannot listen on {listen}: {e}"))?;
    report.push(format!("{listen} is free"));
    Ok(report)
}
