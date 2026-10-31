//! Which certificate authorities outgoing TLS connections trust.
//!
//! Every HTTP client the runtime builds (providers, adapters, the KMS, OIDC issuers,
//! notification webhooks, the trace exporter, Tower's sources) trusts the bundled
//! public roots. Services behind a private CA are trusted too when
//! `CONTEXTOS_CA_BUNDLE` names a PEM file of its certificates: [`init`] reads it once
//! at startup, before any client is built, and fails on a file that holds none.
//! Build clients with [`builder`], never `reqwest::Client::builder` directly.

use std::sync::OnceLock;

/// The environment variable naming the PEM bundle of additional trusted CAs.
pub const CA_BUNDLE_ENV: &str = "CONTEXTOS_CA_BUNDLE";

static EXTRA_ROOTS: OnceLock<Vec<reqwest::Certificate>> = OnceLock::new();

/// Reads the CA certificates in a PEM bundle; an error when it holds none.
pub fn read_bundle(path: &str) -> Result<Vec<reqwest::Certificate>, String> {
    let pem = std::fs::read(path).map_err(|e| format!("{CA_BUNDLE_ENV} {path}: {e}"))?;
    let certificates = reqwest::Certificate::from_pem_bundle(&pem)
        .map_err(|e| format!("{CA_BUNDLE_ENV} {path}: not a PEM certificate bundle: {e}"))?;
    if certificates.is_empty() {
        return Err(format!("{CA_BUNDLE_ENV} {path}: holds no certificate"));
    }
    Ok(certificates)
}

/// Loads `CONTEXTOS_CA_BUNDLE`, if set, and returns how many certificates it added.
/// Call once at startup, before building any client; later calls report the same.
pub fn init() -> Result<usize, String> {
    if let Some(roots) = EXTRA_ROOTS.get() {
        return Ok(roots.len());
    }
    let roots = match std::env::var(CA_BUNDLE_ENV) {
        Ok(path) if !path.is_empty() => read_bundle(&path)?,
        _ => Vec::new(),
    };
    Ok(EXTRA_ROOTS.get_or_init(|| roots).len())
}

/// A client builder that trusts the public roots and the configured private CAs.
pub fn builder() -> reqwest::ClientBuilder {
    with_roots(
        reqwest::Client::builder(),
        EXTRA_ROOTS.get().map_or(&[][..], Vec::as_slice),
    )
}

/// Adds `roots` to `builder`'s trust.
pub fn with_roots(builder: reqwest::ClientBuilder, roots: &[reqwest::Certificate]) -> reqwest::ClientBuilder {
    roots
        .iter()
        .cloned()
        .fold(builder, reqwest::ClientBuilder::add_root_certificate)
}
