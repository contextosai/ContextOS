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

use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use serde::{Deserialize, Serialize};

/// How long a client may take to complete the TLS handshake.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// How long in-flight requests may take to finish on shutdown.
const DRAIN_TIMEOUT: Duration = Duration::from_secs(30);

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
}

fn default_reload() -> u64 {
    60
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
                    if let Ok(mut slot) = current.write() {
                        *slot = config;
                    }
                    seen = now;
                    tracing::info!(cert = %tls.cert_path.display(), "reloaded the TLS certificate");
                }
                // Files mid-rotation may not match yet; keep serving and try again.
                Err(error) => tracing::warn!(%error, "TLS certificate reload failed; keeping the previous one"),
            }
        }
    });
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
    watch(tls, current.clone());
    let graceful = hyper_util::server::graceful::GracefulShutdown::new();
    let builder = hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new());
    tokio::pin!(shutdown);
    loop {
        let (stream, peer) = tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok(accepted) => accepted,
                Err(error) => {
                    tracing::warn!(%error, "accept failed");
                    continue;
                }
            },
            () = &mut shutdown => break,
        };
        let Ok(config) = current.read().map(|c| c.clone()) else {
            continue;
        };
        let acceptor = tokio_rustls::TlsAcceptor::from(config);
        let service = hyper_util::service::TowerToHyperService::new(app.clone());
        let builder = builder.clone();
        let watcher = graceful.watcher();
        tokio::spawn(async move {
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
            let _ = watcher.watch(connection.into_owned()).await;
        });
    }
    drop(listener);
    if tokio::time::timeout(DRAIN_TIMEOUT, graceful.shutdown()).await.is_err() {
        tracing::warn!("requests still in progress after 30 seconds; closing");
    }
    Ok(())
}
