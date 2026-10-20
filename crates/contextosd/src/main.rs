//! `contextosd --config <path>`

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use contextos_store::{MemoryLog, MemoryStore};
use contextosd::config::StoreConfig;
use contextosd::runtime::dispatch_setup_from_config;
use contextosd::{Config, build_state, load_pack, router, signer_from_env};
use tracing_subscriber::EnvFilter;

fn fail(message: impl std::fmt::Display) -> ! {
    tracing::error!(%message, "startup failed");
    eprintln!("contextosd: {message}");
    std::process::exit(2);
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(EnvFilter::from_default_env())
        .init();
    let args: Vec<String> = std::env::args().collect();
    let path = match args.as_slice() {
        [_, flag, path] if flag == "--config" => path.clone(),
        _ => fail("usage: contextosd --config <path>"),
    };
    let config = Config::load(std::path::Path::new(&path)).unwrap_or_else(|e| fail(e));
    let signer = signer_from_env(&config.audit.signing_seed_env, &config.audit.key_id).unwrap_or_else(|e| fail(e));
    let mut packs = HashMap::new();
    for pack_path in &config.packs {
        let text = std::fs::read_to_string(pack_path).unwrap_or_else(|e| fail(format!("{}: {e}", pack_path.display())));
        let (pack_ref, pack) = load_pack(&text).unwrap_or_else(|e| fail(format!("{}: {e}", pack_path.display())));
        tracing::info!(%pack_ref, tenant = %pack.tenant_id, "loaded context pack");
        packs.insert(pack_ref, pack);
    }
    let dispatch = dispatch_setup_from_config(&config).unwrap_or_else(|e| fail(e));
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
}
