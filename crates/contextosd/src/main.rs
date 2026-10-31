//! `contextosd --config <path>`, `contextosd --check-config <path>`,
//! `contextosd --pin-mcp-tools <path>` or `contextosd --version`

use std::sync::Arc;
use std::time::Duration;

use contextos_store::{MemoryLog, MemoryStore};
use contextosd::config::StoreConfig;
use contextosd::runtime::dispatch_setup_from_config;
use contextosd::{Config, build_state, router};

#[cfg(feature = "mimalloc")]
#[global_allocator]
static ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;

const USAGE: &str = "\
usage: contextosd <command>

  --config <path>         serve with this configuration
  --check-config <path>   validate the configuration and its environment, then exit
  --pin-mcp-tools <path>  print upstream MCP tool digests to pin in capability manifests
  --migrate <path>        create or upgrade the PostgreSQL schema (as a role that owns it)
  --version               print the version
  --help                  print this help

Try it locally: ./examples/dev-server.sh. Configuration: docs/GUIDE.md section 3.";

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
    if matches!(args.as_slice(), [_, flag] if flag == "--help" || flag == "-h") {
        println!("{USAGE}");
        return;
    }
    let known = ["--config", "--check-config", "--pin-mcp-tools", "--migrate"];
    if !matches!(args.as_slice(), [_, flag, _] if known.contains(&flag.as_str())) {
        eprintln!("{USAGE}");
        std::process::exit(2);
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
    if let [_, flag, path] = args.as_slice()
        && flag == "--pin-mcp-tools"
    {
        let config = Config::load(std::path::Path::new(path)).unwrap_or_else(|e| fail(e));
        match contextosd::upstream_check::pin_report(&config).await {
            Ok(lines) => {
                for line in lines {
                    println!("{line}");
                }
                return;
            }
            Err(e) => {
                eprintln!("contextosd: {path}: {e}");
                std::process::exit(2);
            }
        }
    }
    if let [_, flag, path] = args.as_slice()
        && flag == "--migrate"
    {
        let config = Config::load(std::path::Path::new(path)).unwrap_or_else(|e| fail(e));
        let StoreConfig::Postgres { url_env, .. } = &config.store else {
            fail("--migrate needs a PostgreSQL store; the in-memory store has no schema")
        };
        let url = std::env::var(url_env).unwrap_or_else(|_| fail(format!("{url_env} is not set")));
        let store = contextos_store::postgres::PostgresStore::connect(&url, 1)
            .await
            .unwrap_or_else(|e| fail(e));
        store.migrate().await.unwrap_or_else(|e| fail(e));
        println!("contextosd: schema is current");
        return;
    }
    let telemetry = contextosd::telemetry::init().unwrap_or_else(|e| fail(e));
    let path = match args.as_slice() {
        [_, flag, path] if flag == "--config" => path.clone(),
        _ => unreachable!("arguments were checked above"),
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
        if config.audit.kms.is_none() {
            tracing::warn!(
                "production: the audit signing key is a seed in the environment; keep it in a KMS ([audit.kms])"
            );
        }
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
            // A current schema needs no DDL, so the runtime role may lack the right to
            // create tables; otherwise migrate now, which needs that right.
            if !store.schema_current().await.unwrap_or_else(|e| fail(e)) {
                store.migrate().await.unwrap_or_else(|e| {
                    fail(format!(
                        "{e}; the schema needs migrating: run `contextosd --migrate <config>` with \
                         {url_env} naming a role that owns the schema"
                    ))
                });
            }
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
