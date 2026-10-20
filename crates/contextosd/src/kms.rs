//! Audit signing with a key held in a KMS (the spec's key management: signing keys
//! are stored in a KMS and the runtime never holds a raw private key).
//!
//! The supported protocol is the HashiCorp Vault Transit secrets engine (also served by
//! OpenBao and compatible gateways in front of cloud KMSs) with an `ed25519` key:
//!
//! - at startup, `GET {url}/v1/transit/keys/{key}` gives the pinned key version's
//!   public key, which must equal the configured `public_key`; every returned
//!   signature is checked against it;
//! - each group commit signs all its record hashes with one
//!   `POST {url}/v1/transit/sign/{key}` using `batch_input` and the pinned
//!   `key_version`, and each signature must carry that version's `vault:vN:` prefix.
//!
//! The token comes from an environment variable and is sent only to the configured
//! URL. A signer that fails, or returns a signature that does not verify, fails the
//! append; nothing is written unsigned.

use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use contextos_audit::{AuditSigner, RemoteSigner};
use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KmsConfig {
    /// `vault_transit`.
    pub kind: String,
    /// Base URL, e.g. `https://vault.internal:8200` (HTTPS outside development).
    pub url: String,
    /// The Transit key name (an `ed25519` key).
    pub key_name: String,
    /// Environment variable holding the Vault token.
    pub token_env: String,
    /// The Transit key version that signs (pinned: a rotation inside Vault does not
    /// silently change what this `key_id` means).
    pub key_version: u64,
    /// The expected Ed25519 public key (base64url, unpadded) of that version. Startup
    /// fails if the KMS reports another, so a hijacked endpoint cannot substitute its own.
    pub public_key: String,
    /// Transit mount path (default `transit`).
    #[serde(default = "default_mount")]
    pub mount: String,
}

fn default_mount() -> String {
    "transit".into()
}

struct VaultTransit {
    http: reqwest::Client,
    sign_url: String,
    token: String,
    key_version: u64,
}

const STD: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

#[async_trait::async_trait]
impl RemoteSigner for VaultTransit {
    async fn sign_batch(&self, messages: &[String]) -> Result<Vec<Vec<u8>>, String> {
        let batch: Vec<Value> = messages
            .iter()
            .map(|m| json!({"input": STD.encode(m.as_bytes())}))
            .collect();
        let response = self
            .http
            .post(&self.sign_url)
            .header("X-Vault-Token", &self.token)
            .json(&json!({"batch_input": batch, "key_version": self.key_version}))
            .send()
            .await
            .map_err(|_| "the KMS is unreachable".to_owned())?;
        if !response.status().is_success() {
            return Err(format!("the KMS refused to sign ({})", response.status()));
        }
        let body: Value = response
            .json()
            .await
            .map_err(|_| "the KMS answered malformed JSON".to_owned())?;
        body["data"]["batch_results"]
            .as_array()
            .ok_or_else(|| "the KMS answer has no batch results".to_owned())?
            .iter()
            .map(|result| {
                // "vault:v<version>:<base64 signature>"
                let signature = result["signature"]
                    .as_str()
                    .ok_or_else(|| "the KMS did not sign an entry".to_owned())?;
                // By the pinned version only.
                let encoded = signature
                    .strip_prefix(&format!("vault:v{}:", self.key_version))
                    .ok_or_else(|| "the KMS signed with another key version".to_owned())?;
                STD.decode(encoded)
                    .map_err(|_| "the KMS returned an undecodable signature".to_owned())
            })
            .collect()
    }
}

/// Builds the audit signer for a Vault Transit key: checks the pinned version's public
/// key against the configured one and returns a signer that signs remotely.
pub async fn vault_transit_signer(config: &KmsConfig, key_id: &str, development: bool) -> Result<AuditSigner, String> {
    if config.kind != "vault_transit" {
        return Err(format!(
            "unsupported KMS kind {:?} (supported: vault_transit)",
            config.kind
        ));
    }
    if !development && !config.url.starts_with("https://") {
        return Err("[audit.kms] url must be https outside development mode".into());
    }
    let pinned = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&config.public_key)
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
        .and_then(|b| ed25519_dalek::VerifyingKey::from_bytes(&b).ok())
        .ok_or_else(|| "[audit.kms] public_key must be a base64url Ed25519 public key".to_owned())?;
    let token = std::env::var(&config.token_env).map_err(|_| format!("{} is not set", config.token_env))?;
    let http = reqwest::Client::builder()
        .https_only(!development)
        .timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| e.to_string())?;
    let base = config.url.trim_end_matches('/');
    let key: Value = http
        .get(format!("{base}/v1/{}/keys/{}", config.mount, config.key_name))
        .header("X-Vault-Token", &token)
        .send()
        .await
        .map_err(|_| "the KMS is unreachable".to_owned())?
        .error_for_status()
        .map_err(|e| format!("the KMS refused the key lookup ({})", e.status().unwrap_or_default()))?
        .json()
        .await
        .map_err(|_| "the KMS answered malformed JSON".to_owned())?;
    if key["data"]["type"] != "ed25519" {
        return Err(format!("the Transit key {} must be of type ed25519", config.key_name));
    }
    let version = config.key_version.to_string();
    let public = key["data"]["keys"][&version]["public_key"]
        .as_str()
        .and_then(|k| STD.decode(k).ok())
        .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
        .and_then(|b| ed25519_dalek::VerifyingKey::from_bytes(&b).ok())
        .ok_or_else(|| format!("the KMS has no Ed25519 public key for version {version}"))?;
    if public != pinned {
        return Err("the KMS public key does not match [audit.kms] public_key".into());
    }
    let remote = VaultTransit {
        http,
        sign_url: format!("{base}/v1/{}/sign/{}", config.mount, config.key_name),
        token,
        key_version: config.key_version,
    };
    Ok(AuditSigner::remote(key_id, public, Arc::new(remote)))
}
