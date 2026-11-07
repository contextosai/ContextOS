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
            &providers.action_monitor,
        ];
        let named = [
            ("authority", Some(&providers.authority)),
            ("constraints", Some(&providers.constraints)),
            ("approvals", Some(&providers.approvals)),
        ]
        .into_iter()
        .chain(
            [
                "idempotency",
                "data_flow",
                "boundary",
                "memory",
                "result_screening",
                "action_monitor",
            ]
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
    let private_cas = contextos_adapters::tls::init()?;
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

    if private_cas > 0 {
        report.push(format!(
            "{private_cas} private CA certificate(s) trusted from CONTEXTOS_CA_BUNDLE"
        ));
    }
    if let Some(tls) = &config.server.tls {
        crate::tls_server::server_config(tls).map_err(|e| format!("[server.tls] {e}"))?;
        report.push(match &tls.client_ca_path {
            Some(_) => "TLS certificate and client CA load (clients must present a certificate)".into(),
            None => "TLS certificate loads".into(),
        });
    }
    let packs = load_packs(&config)?;
    report.push(format!("{} context pack(s) valid", packs.len()));
    if !config.pack_dirs.is_empty() {
        report.push(match config.pack_reload_secs {
            0 => format!(
                "{} pack dir(s), reloaded on POST /v1/packs/reload",
                config.pack_dirs.len()
            ),
            secs => format!("{} pack dir(s), reloaded every {secs} s", config.pack_dirs.len()),
        });
    }

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
    let sinks = crate::audit_sinks::sinks(&config)?;
    if !sinks.is_empty() {
        let masked = sinks.iter().filter(|s| !s.config.mask.is_empty()).count();
        report.push(format!(
            "{} audit sink(s), {masked} with masked fields; secrets set (not contacted)",
            sinks.len()
        ));
    }
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
    report.push(format!("user binding: {}", crate::user_binding::mode(&config).as_str()));
    report.push(match crate::pack_intents::mode(&config) {
        crate::pack_intents::PackIntents::Off => {
            "warning: pack intents are off: intent-scoped rules restrict only runs that declare their intent".into()
        }
        mode => format!("pack intents: {}", mode.as_str()),
    });
    report.push(format!(
        "evidence: {}",
        crate::evidence_admission::mode(&config).as_str()
    ));
    if crate::evidence_admission::mode(&config) == crate::evidence_admission::EvidenceMode::Strict {
        report.push(if config.evidence_issuers.is_empty() {
            "warning: strict evidence with no [[evidence_issuers]]: no evidence entry can satisfy a decision's gate"
                .into()
        } else {
            let issuers: Vec<&str> = config.evidence_issuers.iter().map(|i| i.issuer.as_str()).collect();
            format!("evidence issuers: {}", issuers.join(", "))
        });
    }
    if crate::evidence_admission::mode(&config) == crate::evidence_admission::EvidenceMode::Strict {
        let mut refs: Vec<_> = packs.keys().collect();
        refs.sort();
        for pack_ref in refs {
            let pack = packs[pack_ref].compiler.pack();
            for name in crate::evidence_admission::gated(pack) {
                if !config.evidence_subjects.iter().any(|s| s.requirement == name) {
                    report.push(format!(
                        "warning: {pack_ref} requirement {name} has no [[evidence_subjects]] binding: any authentic, \
                         current attestation satisfies it, whatever it is about"
                    ));
                }
            }
            for rule in crate::evidence_admission::rules_reading_gated_context(pack) {
                report.push(format!(
                    "warning: {pack_ref} rule {rule} reads a gated name from request.context, which strict evidence refuses: \
                     the rule never matches"
                ));
            }
        }
    }
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
