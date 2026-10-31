//! `towerd --config <path>`, or `towerd --version`

use std::sync::Arc;

use contextos_store::{MemoryLog, MemoryStore};
use towerd::config::StoreConfig;
use towerd::{Config, Tower, api, intel};

fn fail(message: impl std::fmt::Display) -> ! {
    tracing::error!(%message, "startup failed");
    eprintln!("towerd: {message}");
    std::process::exit(2);
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    if matches!(args.as_slice(), [_, flag] if flag == "--version") {
        println!("towerd {}", env!("CARGO_PKG_VERSION"));
        return;
    }
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();
    // Before any client exists: every one trusts the private CAs it names.
    match contextos_adapters::tls::init() {
        Ok(0) => {}
        Ok(n) => tracing::info!(certificates = n, "trusting private CAs from CONTEXTOS_CA_BUNDLE"),
        Err(e) => fail(e),
    }
    let path = match args.as_slice() {
        [_, flag, path] if flag == "--config" => path.clone(),
        _ => fail("usage: towerd --config <path> | --version"),
    };
    let config = Config::load(std::path::Path::new(&path)).unwrap_or_else(|e| fail(e));
    let signer =
        towerd::signer_from_env(&config.journal.signing_seed_env, &config.journal.key_id).unwrap_or_else(|e| fail(e));
    let model: Option<Arc<dyn intel::Model>> = if config.intelligence.provider == "anthropic" {
        Some(Arc::new(
            intel::Anthropic::from_config(&config.intelligence).unwrap_or_else(|e| fail(e)),
        ))
    } else {
        tracing::info!("intelligence is off: everything deterministic still works");
        None
    };
    let listen = config.server.listen;
    let app = match config.store.clone() {
        StoreConfig::Memory => {
            tracing::warn!("in-memory store: declarations, reviews, guardrails and waivers are lost on restart");
            let tower = Arc::new(
                Tower::build(config, Arc::new(MemoryStore::new()), MemoryLog::new(), signer, model)
                    .unwrap_or_else(|e| fail(e)),
            );
            tower.spawn_collectors();
            tower.spawn_journal_recovery();
            api::router(tower)
        }
        StoreConfig::Postgres {
            url_env,
            max_connections,
        } => {
            let url = std::env::var(&url_env).unwrap_or_else(|_| fail(format!("{url_env} is not set")));
            let store = contextos_store::postgres::PostgresStore::connect(&url, max_connections)
                .await
                .unwrap_or_else(|e| fail(e));
            store.migrate().await.unwrap_or_else(|e| fail(e));
            let store = Arc::new(store);
            let tower = Arc::new(
                Tower::build(config, store.clone(), (*store).clone(), signer, model).unwrap_or_else(|e| fail(e)),
            );
            tower.spawn_collectors();
            tower.spawn_journal_recovery();
            api::router(tower)
        }
    };
    let listener = tokio::net::TcpListener::bind(listen).await.unwrap_or_else(|e| fail(e));
    tracing::info!(%listen, "towerd listening");
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
        .unwrap_or_else(|e| fail(e));
}
