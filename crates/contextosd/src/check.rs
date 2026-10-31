//! `contextosd --check-config <path>`: the validation startup performs before serving,
//! run on its own. It reads the configuration, packs and pinned manifests and checks
//! that the signing key source and store settings are present, then binds the listen
//! address once to confirm it is free. It does not contact a key service, connect to
//! the store or start background work, so a passing check does not prove those reachable.

use std::path::Path;

use crate::config::{Mode, StoreConfig};
use crate::{Config, guarantees_need_dispatch, load_packs, runtime, signer_from_env};

/// Every environment variable the configuration names, with what it holds.
fn named_env(config: &Config) -> Vec<(&str, String)> {
    let mut vars = Vec::new();
    if let Some(providers) = &config.providers {
        let optional = [
            &providers.idempotency,
            &providers.data_flow,
            &providers.boundary,
            &providers.memory,
            &providers.result_screening,
        ];
        let named = [
            ("authority", Some(&providers.authority)),
            ("constraints", Some(&providers.constraints)),
            ("approvals", Some(&providers.approvals)),
        ]
        .into_iter()
        .chain(
            ["idempotency", "data_flow", "boundary", "memory", "result_screening"]
                .into_iter()
                .zip(optional.into_iter().map(Option::as_ref)),
        );
        for (name, provider) in named {
            if let Some(var) = provider.and_then(|p| p.token_env.as_deref()) {
                vars.push((var, format!("the {name} service token")));
            }
        }
    }
    for adapter in &config.adapters {
        if let Some(var) = adapter.token_env.as_deref() {
            vars.push((var, format!("adapter {}'s provider token", adapter.id)));
        }
        if let Some(oauth) = &adapter.oauth {
            vars.push((
                oauth.client_secret_env.as_str(),
                format!("adapter {}'s OAuth client secret", adapter.id),
            ));
        }
    }
    for hook in &config.notifications {
        vars.push((
            hook.secret_env.as_str(),
            format!("webhook {}'s signing secret", hook.id),
        ));
    }
    match &config.audit.kms {
        Some(kms) => vars.push((kms.token_env.as_str(), "the KMS token".into())),
        None => vars.push((
            config.audit.signing_seed_env.as_str(),
            "the audit signing seed: 64 hex characters".into(),
        )),
    }
    if let StoreConfig::Postgres { url_env, .. } = &config.store {
        vars.push((url_env.as_str(), "the PostgreSQL URL".into()));
    }
    vars
}

/// One line per passing check (`warning: ` for a check that passes with a caveat), or
/// the first failure. Missing environment variables are reported together.
pub fn check_config(path: &Path) -> Result<Vec<String>, String> {
    let config = Config::load(path).map_err(|e| e.to_string())?;
    let missing: Vec<String> = named_env(&config)
        .into_iter()
        .filter(|(var, _)| std::env::var_os(var).is_none())
        .map(|(var, what)| format!("  {var} ({what})"))
        .collect();
    if !missing.is_empty() {
        return Err(format!("environment variables not set:\n{}", missing.join("\n")));
    }
    let mut report = vec![format!(
        "configuration parsed ({} mode)",
        match config.server.mode {
            Mode::Production => "production",
            Mode::Development => "development",
        }
    )];

    let packs = load_packs(&config)?;
    report.push(format!("{} context pack(s) valid", packs.len()));

    if config.api_keys.is_empty() && config.oidc.is_empty() {
        report.push("warning: no [[api_keys]] or [[oidc]] issuers: no caller can authenticate".into());
    }
    let dispatch = runtime::dispatch_setup_from_config(&config)?;
    guarantees_need_dispatch(&config, dispatch.is_some())?;
    report.push(match &dispatch {
        Some(_) => format!(
            "dispatch gateway and manifests valid; {} shared guarantee(s)",
            config.guarantees.len()
        ),
        None => "no dispatch gateway configured".into(),
    });
    let hooks = crate::notifications::webhooks(&config)?;
    if !hooks.is_empty() {
        report.push(format!(
            "{} notification webhook(s); signing secrets set (not contacted)",
            hooks.len()
        ));
    }
    report.push(match crate::agent_binding::mode(&config) {
        crate::agent_binding::AgentBinding::Off => {
            "warning: agent binding is off: runs may declare any agent (development only)".into()
        }
        mode => format!("agent binding: {}", mode.as_str()),
    });
    report.push(match crate::pack_intents::mode(&config) {
        crate::pack_intents::PackIntents::Off => {
            "warning: pack intents are off: intent-scoped rules restrict only runs that declare their intent".into()
        }
        mode => format!("pack intents: {}", mode.as_str()),
    });
    let mut refs: Vec<_> = packs.keys().collect();
    refs.sort();
    for pack_ref in refs {
        if let Some(note) = crate::pack_intents::spread(pack_ref, packs[pack_ref].compiler.pack()) {
            report.push(format!("warning: {note}"));
        }
    }
    for key in config
        .api_keys
        .iter()
        .filter(|k| k.key_sha256 == format!("sha256:{}", "0".repeat(64)))
    {
        report.push(format!(
            "warning: the api key for {} is the example placeholder; no key matches it (`ctx hash-key` prints a real hash)",
            key.principal_id
        ));
    }
    for manifest in dispatch.iter().flat_map(|d| &d.manifests) {
        if !config.adapters.iter().any(|a| a.id == manifest.adapter_id) {
            report.push(format!(
                "warning: {} names adapter {}, which no [[adapters]] entry configures: its calls cannot be sent",
                manifest.capability_id, manifest.adapter_id
            ));
        }
    }
    let unpinned = dispatch
        .as_ref()
        .map(|d| crate::upstream_check::unpinned(&config, d))
        .unwrap_or_default();
    for note in dispatch
        .as_ref()
        .map(runtime::unbounded_capabilities)
        .unwrap_or_default()
        .into_iter()
        .chain(unpinned)
    {
        report.push(format!("warning: {note}"));
    }

    report.push(if let Some(kms) = &config.audit.kms {
        if std::env::var_os(&kms.token_env).is_none() {
            return Err(format!("{} (the KMS token) is not set", kms.token_env));
        }
        format!("audit signing via {} at {} (not contacted)", kms.kind, kms.url)
    } else {
        signer_from_env(&config.audit.signing_seed_env, &config.audit.key_id)?;
        if config.server.mode == Mode::Production {
            format!(
                "warning: audit signing seed in {}: in production keep the key in a KMS ([audit.kms])",
                config.audit.signing_seed_env
            )
        } else {
            format!("audit signing seed in {}", config.audit.signing_seed_env)
        }
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
