//! Inbound TLS, and mutual TLS, for deployments without a terminating proxy.
//!
//! With `[server.tls]` the server speaks only HTTPS (HTTP/2 and HTTP/1.1 by ALPN) with
//! the certificate chain and key it names. With `client_ca_path` it also requires
//! every client to present a certificate that CA issued: only workloads holding one
//! (a service mesh's or SPIFFE X.509 SVIDs, for example) can open a connection. The
//! caller is still authenticated by its token; mTLS decides who may connect at all.
//!
//! Certificates rotate without a restart: every `reload_secs` the files are checked,
//! and when one has changed the configuration is rebuilt for new connections. A
//! rotation that fails to load keeps serving the previous certificate and logs why.
//!
//! Without a proxy in front, the server bounds slow or abusive clients itself:
//!
//! - **Connections.** At most `max_connections` are open at once; past that, new
//!   connections wait in the kernel's accept queue until one closes.
//! - **TLS handshake.** A client has 10 seconds to complete it.
//! - **Idle connections.** A connection with no request in progress (and no response
//!   still being sent) for `header_timeout_secs` is closed, over either protocol: a
//!   client that connects and sends nothing, or idles between requests, frees its slot.
//! - **HTTP/1.1 headers.** A client has `header_timeout_secs` from a request's first
//!   byte to finish its headers, so one trickling headers is disconnected.
//! - **HTTP/2.** Requests are framed and multiplexed, at most 200 at a time on one
//!   connection, and the server pings every 30 seconds, closing a connection whose
//!   ping goes unanswered for 20. HTTP/2 has no header-read timeout: a client that
//!   stalls mid-request holds its own stream and one of the `max_connections` slots,
//!   nothing more.
//! - **Accept failures.** A failed accept (out of file descriptors, for one) pauses
//!   from 5 milliseconds, doubling up to one second, instead of spinning.

mod idle;

use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};

use hyper_util::rt::{TokioExecutor, TokioTimer};
use hyper_util::server::conn::auto;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use serde::{Deserialize, Serialize};

/// How long a client may take to complete the TLS handshake.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// How long in-flight requests may take to finish on shutdown.
const DRAIN_TIMEOUT: Duration = Duration::from_secs(30);
/// The first and the longest pause after a failed accept.
const ACCEPT_BACKOFF_MIN: Duration = Duration::from_millis(5);
const ACCEPT_BACKOFF_MAX: Duration = Duration::from_secs(1);
/// HTTP/2: ping an idle connection this often, and close it when a ping goes
/// unanswered this long.
const H2_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);
const H2_KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(20);
/// Concurrent requests (streams) on one HTTP/2 connection.
const H2_MAX_STREAMS: u32 = 200;

/// `[server.tls]`.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    /// PEM file with the server certificate, then its intermediates.
    pub cert_path: PathBuf,
    /// PEM file with the server's private key (PKCS#8, PKCS#1 or SEC1).
    pub key_path: PathBuf,
    /// PEM file of the CAs that issue client certificates. Set: every client must
    /// present one (mutual TLS). Unset: clients are not asked for a certificate.
    #[serde(default)]
    pub client_ca_path: Option<PathBuf>,
    /// How often to check the files for a rotated certificate; 0 never reloads.
    #[serde(default = "default_reload")]
    pub reload_secs: u64,
    /// Most connections open at once (at least 1); further clients wait to be accepted.
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
    /// Seconds a connection may sit with no request in progress, and an HTTP/1.1
    /// client may take to send a request's headers, before it is closed (at least 1).
    #[serde(default = "default_header_timeout")]
    pub header_timeout_secs: u64,
}

fn default_reload() -> u64 {
    60
}

fn default_max_connections() -> usize {
    10_000
}

fn default_header_timeout() -> u64 {
    30
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn read_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, String> {
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(path)
        .map_err(|e| format!("{}: {e}", path.display()))?
        .collect::<Result<_, _>>()
        .map_err(|e| format!("{}: {e}", path.display()))?;
    if certs.is_empty() {
        return Err(format!("{}: holds no certificate", path.display()));
    }
    Ok(certs)
}

/// The rustls configuration `tls` describes.
pub fn server_config(tls: &TlsConfig) -> Result<Arc<rustls::ServerConfig>, String> {
    if tls.max_connections == 0 {
        return Err("max_connections must be at least 1".into());
    }
    if tls.header_timeout_secs == 0 {
        return Err("header_timeout_secs must be at least 1".into());
    }
    let certs = read_certs(&tls.cert_path)?;
    let key = PrivateKeyDer::from_pem_file(&tls.key_path).map_err(|e| format!("{}: {e}", tls.key_path.display()))?;
    let builder = rustls::ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?;
    let builder = match &tls.client_ca_path {
        Some(path) => {
            let mut roots = rustls::RootCertStore::empty();
            for ca in read_certs(path)? {
                roots.add(ca).map_err(|e| format!("{}: {e}", path.display()))?;
            }
            let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider())
                .build()
                .map_err(|e| format!("{}: {e}", path.display()))?;
            builder.with_client_cert_verifier(verifier)
        }
        None => builder.with_no_client_auth(),
    };
    let mut config = builder
        .with_single_cert(certs, key)
        .map_err(|e| format!("{}: {e}", tls.cert_path.display()))?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

fn modified(tls: &TlsConfig) -> Vec<Option<SystemTime>> {
    [Some(&tls.cert_path), Some(&tls.key_path), tls.client_ca_path.as_ref()]
        .into_iter()
        .flatten()
        .map(|p| std::fs::metadata(p).and_then(|m| m.modified()).ok())
        .collect()
}

/// Keeps the configuration current as the files rotate.
fn watch(tls: TlsConfig, current: Arc<RwLock<Arc<rustls::ServerConfig>>>) {
    if tls.reload_secs == 0 {
        return;
    }
    tokio::spawn(async move {
        let mut seen = modified(&tls);
        loop {
            tokio::time::sleep(Duration::from_secs(tls.reload_secs)).await;
            let now = modified(&tls);
            if now == seen {
                continue;
            }
            match server_config(&tls) {
                Ok(config) => {
                    // The slot only ever holds a whole configuration, so a poisoned
                    // lock still holds a usable one.
                    *current.write().unwrap_or_else(std::sync::PoisonError::into_inner) = config;
                    seen = now;
                    tracing::info!(cert = %tls.cert_path.display(), "reloaded the TLS certificate");
                }
                // Files mid-rotation may not match yet; keep serving and try again.
                Err(error) => tracing::warn!(%error, "TLS certificate reload failed; keeping the previous one"),
            }
        }
    });
}

/// HTTP/1.1 with a header-read timeout and HTTP/2 with keepalive, chosen by ALPN.
fn connection_builder(tls: &TlsConfig) -> auto::Builder<TokioExecutor> {
    let mut builder = auto::Builder::new(TokioExecutor::new());
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(Duration::from_secs(tls.header_timeout_secs));
    builder
        .http2()
        .timer(TokioTimer::new())
        .max_concurrent_streams(H2_MAX_STREAMS)
        .keep_alive_interval(H2_KEEPALIVE_INTERVAL)
        .keep_alive_timeout(H2_KEEPALIVE_TIMEOUT);
    builder
}

/// Serves `app` over TLS on `listener` until `shutdown` resolves, then lets requests
/// in progress finish (up to 30 seconds).
pub async fn serve(
    listener: tokio::net::TcpListener,
    app: axum::Router,
    tls: TlsConfig,
    shutdown: impl std::future::Future<Output = ()>,
) -> Result<(), String> {
    let current = Arc::new(RwLock::new(server_config(&tls)?));
    let slots = Arc::new(tokio::sync::Semaphore::new(tls.max_connections));
    let builder = connection_builder(&tls);
    let idle_limit = Duration::from_secs(tls.header_timeout_secs);
    watch(tls, current.clone());
    let graceful = hyper_util::server::graceful::GracefulShutdown::new();
    tokio::pin!(shutdown);
    let mut backoff = ACCEPT_BACKOFF_MIN;
    loop {
        // A slot first: at the cap, connections wait in the accept queue.
        let slot = tokio::select! {
            slot = slots.clone().acquire_owned() => slot.map_err(|e| e.to_string())?,
            () = &mut shutdown => break,
        };
        let (stream, peer) = tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok(accepted) => {
                    backoff = ACCEPT_BACKOFF_MIN;
                    accepted
                }
                Err(error) => {
                    // Out of file descriptors, every accept fails until a connection
                    // closes: pause rather than spin.
                    tracing::warn!(%error, pause = ?backoff, "accept failed");
                    tokio::select! {
                        () = tokio::time::sleep(backoff) => {}
                        () = &mut shutdown => break,
                    }
                    backoff = (backoff * 2).min(ACCEPT_BACKOFF_MAX);
                    continue;
                }
            },
            () = &mut shutdown => break,
        };
        // The slot only ever holds a whole configuration (see `watch`).
        let config = current
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let acceptor = tokio_rustls::TlsAcceptor::from(config);
        let activity = idle::Activity::new();
        let service = hyper_util::service::TowerToHyperService::new(idle::Counted {
            app: app.clone(),
            activity: activity.clone(),
        });
        let builder = builder.clone();
        let watcher = graceful.watcher();
        tokio::spawn(async move {
            let _slot = slot;
            let stream = match tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await {
                Ok(Ok(stream)) => stream,
                Ok(Err(error)) => {
                    tracing::debug!(%peer, %error, "TLS handshake refused");
                    return;
                }
                Err(_) => {
                    tracing::debug!(%peer, "TLS handshake timed out");
                    return;
                }
            };
            let connection = builder.serve_connection_with_upgrades(hyper_util::rt::TokioIo::new(stream), service);
            tokio::select! {
                _ = watcher.watch(connection.into_owned()) => {}
                () = activity.idle(idle_limit) => tracing::debug!(%peer, "closed an idle connection"),
            }
        });
    }
    drop(listener);
    if tokio::time::timeout(DRAIN_TIMEOUT, graceful.shutdown()).await.is_err() {
        tracing::warn!("requests still in progress after 30 seconds; closing");
    }
    Ok(())
}
