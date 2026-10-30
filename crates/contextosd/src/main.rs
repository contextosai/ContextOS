//! `contextosd --config <path>`, `contextosd --check-config <path>` or `contextosd --version`

use std::sync::Arc;
use std::time::Duration;

use contextos_store::{MemoryLog, MemoryStore};
use contextosd::config::StoreConfig;
use contextosd::runtime::dispatch_setup_from_config;
use contextosd::{Config, build_state, router};

#[cfg(feature = "mimalloc")]
#[global_allocator]
static ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn fail(message: impl std::fmt::Display) -> ! {
    tracing::error!(%message, "startup failed");
    eprintln!("contextosd: {message}");
    std::process::exit(2);
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    if matches!(args.as_slice(), [_, flag] if flag == "--version") {
        println!("contextosd {}", env!("CARGO_PKG_VERSION"));
        return;
    }
    if let [_, flag, path] = args.as_slice()
        && flag == "--check-config"
    {
        match contextosd::check::check_config(std::path::Path::new(path)) {
            Ok(report) => {
                for line in report {
                    if line.starts_with("warning: ") {
                        println!("{line}");
                    } else {
                        println!("ok: {line}");
                    }
                }
                return;
            }
            Err(e) => {
                eprintln!("contextosd: {path}: {e}");
                std::process::exit(2);
            }
        }
    }
    let telemetry = contextosd::telemetry::init().unwrap_or_else(|e| fail(e));
    let path = match args.as_slice() {
        [_, flag, path] if flag == "--config" => path.clone(),
        _ => fail("usage: contextosd --config <path> | --check-config <path> | --version"),
    };
    let config = Config::load(std::path::Path::new(&path)).unwrap_or_else(|e| fail(e));
    let signer = contextosd::audit_signer(&config).await.unwrap_or_else(|e| fail(e));
    let packs = contextosd::load_packs(&config).unwrap_or_else(|e| fail(e));
    for (pack_ref, pack) in &packs {
        tracing::info!(%pack_ref, tenant = %pack.tenant_id, "loaded context pack");
    }
    let dispatch = dispatch_setup_from_config(&config).unwrap_or_else(|e| fail(e));
    for note in dispatch
        .as_ref()
        .map(contextosd::runtime::unbounded_capabilities)
        .unwrap_or_default()
    {
        tracing::warn!("{note}");
    }
    if config.server.mode == contextosd::config::Mode::Production {
        let guards = &config.guards;
        if guards.required_release_refs.as_ref().is_some_and(Vec::is_empty) {
            tracing::warn!("production: required_release_refs = [] opts out of model and evaluator pins");
        }
        if guards.require_user_role == Some(false) {
            tracing::warn!("production: require_user_role = false lets policy evaluate the compiler's default role");
        }
        if config.completion_score_floors().is_none() {
            tracing::warn!("production: completion_requires_scores = false lets runs complete with unjudged effects");
        }
    }
    let timeout = Duration::from_millis(config.server.request_timeout_ms);
    let app = match &config.store {
        StoreConfig::Memory => {
            tracing::warn!("using in-memory store: state is lost on restart");
            router(
                build_state(
                    &config,
                    Arc::new(MemoryStore::new()),
                    MemoryLog::new(),
                    signer,
                    packs,
                    dispatch,
                )
                .unwrap_or_else(|e| fail(e)),
                timeout,
            )
        }
        StoreConfig::Postgres {
            url_env,
            max_connections,
        } => {
            let url = std::env::var(url_env).unwrap_or_else(|_| fail(format!("{url_env} is not set")));
            let store = contextos_store::postgres::PostgresStore::connect(&url, *max_connections)
                .await
                .unwrap_or_else(|e| fail(e));
            store.migrate().await.unwrap_or_else(|e| fail(e));
            let store = Arc::new(store);
            router(
                build_state(&config, store.clone(), (*store).clone(), signer, packs, dispatch)
                    .unwrap_or_else(|e| fail(e)),
                timeout,
            )
        }
    };
    let listener = tokio::net::TcpListener::bind(config.server.listen)
        .await
        .unwrap_or_else(|e| fail(e));
    tracing::info!(listen = %config.server.listen, "contextosd listening");
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
            tracing::info!("shutting down");
        })
        .await
        .unwrap_or_else(|e| fail(e));
    telemetry.shutdown().await;
}
