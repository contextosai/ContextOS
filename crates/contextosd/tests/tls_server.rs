//! `[server.tls]`: HTTPS, required client certificates, and certificate rotation without
//! a restart. Certificates are generated with `openssl` for each run (the test is
//! skipped without it), so no private key lives in the repository.

use std::path::Path;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use contextosd::tls_server::{TlsConfig, serve};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName};

fn openssl(dir: &Path, args: &[&str]) -> bool {
    Command::new("openssl")
        .args(args)
        .current_dir(dir)
        .output()
        .is_ok_and(|o| o.status.success())
}

fn ca(dir: &Path, name: &str) -> bool {
    openssl(
        dir,
        &[
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            &format!("{name}.key"),
            "-out",
            &format!("{name}.pem"),
            "-days",
            "2",
            "-subj",
            &format!("/CN={name}"),
        ],
    )
}

/// A certificate `issuer` signed, for 127.0.0.1 (server) or a SPIFFE id (client).
fn leaf(dir: &Path, name: &str, issuer: &str, san: &str) -> bool {
    std::fs::write(dir.join(format!("{name}.ext")), format!("subjectAltName={san}\n")).is_ok()
        && openssl(
            dir,
            &[
                "req",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                &format!("{name}.key"),
                "-out",
                &format!("{name}.csr"),
                "-subj",
                &format!("/CN={name}"),
            ],
        )
        && openssl(
            dir,
            &[
                "x509",
                "-req",
                "-in",
                &format!("{name}.csr"),
                "-CA",
                &format!("{issuer}.pem"),
                "-CAkey",
                &format!("{issuer}.key"),
                "-CAcreateserial",
                "-out",
                &format!("{name}.pem"),
                "-days",
                "2",
                "-extfile",
                &format!("{name}.ext"),
            ],
        )
}

fn certificates(dir: &Path) -> bool {
    ca(dir, "server-ca")
        && leaf(dir, "server", "server-ca", "IP:127.0.0.1")
        && leaf(dir, "server2", "server-ca", "IP:127.0.0.1")
        && ca(dir, "client-ca")
        && leaf(dir, "agent", "client-ca", "URI:spiffe://contextos.test/agent")
}

async fn start(dir: &Path, mutual: bool) -> String {
    let tls = TlsConfig {
        cert_path: dir.join("server.pem"),
        key_path: dir.join("server.key"),
        client_ca_path: mutual.then(|| dir.join("client-ca.pem")),
        reload_secs: 1,
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = axum::Router::new().route("/healthz", axum::routing::get(|| async { "ok" }));
    tokio::spawn(async move { serve(listener, app, tls, std::future::pending()).await.unwrap() });
    format!("https://{addr}/healthz")
}

fn client(dir: &Path, identity: Option<&str>) -> reqwest::Client {
    let ca = reqwest::Certificate::from_pem(&std::fs::read(dir.join("server-ca.pem")).unwrap()).unwrap();
    let mut builder = reqwest::Client::builder().add_root_certificate(ca).https_only(true);
    if let Some(name) = identity {
        let mut pem = std::fs::read(dir.join(format!("{name}.pem"))).unwrap();
        pem.extend(std::fs::read(dir.join(format!("{name}.key"))).unwrap());
        builder = builder.identity(reqwest::Identity::from_pem(&pem).unwrap());
    }
    builder.build().unwrap()
}

/// The certificate the server presents to a new connection.
async fn presented(dir: &Path, url: &str) -> CertificateDer<'static> {
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from_pem_file(dir.join("server-ca.pem")).unwrap())
        .unwrap();
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let addr = url.trim_start_matches("https://").split('/').next().unwrap();
    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let stream = tokio_rustls::TlsConnector::from(Arc::new(config))
        .connect(ServerName::try_from("127.0.0.1").unwrap(), tcp)
        .await
        .unwrap();
    stream.get_ref().1.peer_certificates().unwrap()[0].clone().into_owned()
}

#[tokio::test]
async fn https_mutual_tls_and_rotation() {
    let dir = std::env::temp_dir().join(format!("contextos-tls-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    if !certificates(&dir) {
        eprintln!("skipped: the openssl CLI is not available");
        return;
    }

    // HTTPS: a client trusting the CA connects; plain HTTP does not.
    let url = start(&dir, false).await;
    let ok = client(&dir, None).get(&url).send().await.unwrap();
    assert_eq!(ok.text().await.unwrap(), "ok");
    assert!(reqwest::get(url.replace("https://", "http://")).await.is_err());

    // Mutual TLS: no certificate, no connection; the agent's certificate connects.
    let mutual = start(&dir, true).await;
    assert!(client(&dir, None).get(&mutual).send().await.is_err());
    let ok = client(&dir, Some("agent")).get(&mutual).send().await.unwrap();
    assert_eq!(ok.status(), 200);
    // A certificate from another CA is refused too.
    assert!(client(&dir, Some("server")).get(&mutual).send().await.is_err());

    // Rotation: new files are served to new connections without a restart.
    let before = presented(&dir, &url).await;
    std::fs::copy(dir.join("server2.pem"), dir.join("server.pem")).unwrap();
    std::fs::copy(dir.join("server2.key"), dir.join("server.key")).unwrap();
    let rotated = CertificateDer::from_pem_file(dir.join("server2.pem")).unwrap();
    let mut now = before.clone();
    for _ in 0..40 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        now = presented(&dir, &url).await;
        if now != before {
            break;
        }
    }
    assert_eq!(now, rotated, "the rotated certificate is served");

    // A broken rotation keeps the working certificate.
    std::fs::write(dir.join("server.pem"), "not a certificate").unwrap();
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert_eq!(presented(&dir, &url).await, rotated);
    let _ = std::fs::remove_dir_all(&dir);
}
