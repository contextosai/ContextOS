//! A service behind a private CA is refused until `CONTEXTOS_CA_BUNDLE` names that CA.
//! The CA and the server certificate are generated with `openssl` for each run, so no
//! private key lives in the repository.

use std::path::Path;
use std::process::Command;
use std::sync::Arc;

use contextos_adapters::tls;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn openssl(dir: &Path, args: &[&str]) -> bool {
    Command::new("openssl")
        .args(args)
        .current_dir(dir)
        .output()
        .is_ok_and(|o| o.status.success())
}

/// A CA, and a certificate it signed for 127.0.0.1; `None` without the openssl CLI.
fn private_ca(dir: &Path) -> Option<()> {
    let ok = openssl(
        dir,
        &[
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            "ca.key",
            "-out",
            "ca.pem",
            "-days",
            "2",
            "-subj",
            "/CN=ContextOS test CA",
        ],
    ) && openssl(
        dir,
        &[
            "req",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            "server.key",
            "-out",
            "server.csr",
            "-subj",
            "/CN=127.0.0.1",
        ],
    ) && std::fs::write(dir.join("san.ext"), "subjectAltName=IP:127.0.0.1\n").is_ok()
        && openssl(
            dir,
            &[
                "x509",
                "-req",
                "-in",
                "server.csr",
                "-CA",
                "ca.pem",
                "-CAkey",
                "ca.key",
                "-CAcreateserial",
                "-out",
                "server.pem",
                "-days",
                "2",
                "-extfile",
                "san.ext",
            ],
        );
    ok.then_some(())
}

/// Serves one fixed HTTP response over TLS until the test ends.
async fn tls_server(dir: &Path) -> String {
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(dir.join("server.pem"))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    let key = PrivateKeyDer::from_pem_file(dir.join("server.key")).unwrap();
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                if let Ok(mut tls) = acceptor.accept(stream).await {
                    let mut buf = [0u8; 4096];
                    let _ = tls.read(&mut buf).await;
                    let _ = tls
                        .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok")
                        .await;
                    let _ = tls.shutdown().await;
                }
            });
        }
    });
    format!("https://{addr}/")
}

#[tokio::test]
async fn a_private_ca_is_trusted_only_once_the_bundle_names_it() {
    let dir = std::env::temp_dir().join(format!("contextos-tls-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    if private_ca(&dir).is_none() {
        eprintln!("skipped: the openssl command is not available");
        return;
    }
    let url = tls_server(&dir).await;

    // The bundled public roots do not include a private CA.
    let refused = tls::builder().build().unwrap().get(&url).send().await;
    assert!(refused.is_err(), "a private CA must not be trusted by default");

    // Named in CONTEXTOS_CA_BUNDLE (read once, at startup), it is.
    let roots = tls::read_bundle(dir.join("ca.pem").to_str().unwrap()).unwrap();
    let client = tls::with_roots(reqwest::Client::builder(), &roots).build().unwrap();
    let response = client.get(&url).send().await.unwrap();
    assert_eq!(response.text().await.unwrap(), "ok");

    // A file that holds no certificate is refused, not silently ignored.
    std::fs::write(dir.join("empty.pem"), "not a certificate\n").unwrap();
    assert!(tls::read_bundle(dir.join("empty.pem").to_str().unwrap()).is_err());
    assert!(tls::read_bundle(dir.join("missing.pem").to_str().unwrap()).is_err());
    let _ = std::fs::remove_dir_all(&dir);
}
