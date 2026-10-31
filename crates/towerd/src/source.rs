//! A runtime tenant Tower reads (`audit:read`) and, for the fleet kill switch, acts on
//! (`control`). Every call goes through the runtime's own API, so the runtime's scopes,
//! tenancy and audit apply to Tower exactly as to any other client.

use std::time::Duration;

use base64::Engine;
use contextos_audit::{AuditEntry, KeyRing};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::config::SourceConfig;

#[derive(Debug, thiserror::Error)]
pub enum SourceError {
    #[error("{0} is not set")]
    MissingToken(String),
    #[error("request failed: {0}")]
    Http(String),
    #[error("{status} {code}: {message}")]
    Refused { status: u16, code: String, message: String },
    #[error("unexpected response: {0}")]
    Shape(String),
}

/// One page of the tenant's audit chain.
#[derive(Debug, Deserialize)]
pub struct Page {
    pub entries: Vec<AuditEntry>,
    pub next: Option<u64>,
    #[serde(default)]
    pub head: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct Source {
    pub config: SourceConfig,
    token: String,
    control_token: Option<String>,
    http: reqwest::Client,
}

impl Source {
    pub fn new(config: SourceConfig) -> Result<Self, SourceError> {
        let token =
            std::env::var(&config.token_env).map_err(|_| SourceError::MissingToken(config.token_env.clone()))?;
        let control_token = config.control_token_env.as_ref().and_then(|v| std::env::var(v).ok());
        let http = contextos_adapters::tls::builder()
            .timeout(Duration::from_secs(20))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| SourceError::Http(e.to_string()))?;
        Ok(Self {
            config,
            token,
            control_token,
            http,
        })
    }

    /// A source with its keys given directly (tests and embedding).
    pub fn with_tokens(config: SourceConfig, token: String, control_token: Option<String>) -> Self {
        let http = contextos_adapters::tls::builder()
            .timeout(Duration::from_secs(20))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("a default TLS client builds");
        Self {
            config,
            token,
            control_token,
            http,
        }
    }

    pub fn id(&self) -> &str {
        &self.config.id
    }

    pub fn can_control(&self) -> bool {
        self.control_token.is_some()
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.config.url.trim_end_matches('/'))
    }

    async fn send(&self, request: reqwest::RequestBuilder) -> Result<Value, SourceError> {
        let response = request
            .send()
            .await
            .map_err(|e| SourceError::Http(e.without_url().to_string()))?;
        let status = response.status();
        let body: Value = response.json().await.unwrap_or(Value::Null);
        if !status.is_success() {
            return Err(SourceError::Refused {
                status: status.as_u16(),
                code: body["error"]["code"].as_str().unwrap_or("error").to_owned(),
                message: body["error"]["message"].as_str().unwrap_or_default().to_owned(),
            });
        }
        Ok(body)
    }

    pub async fn get(&self, path: &str) -> Result<Value, SourceError> {
        self.send(self.http.get(self.url(path)).bearer_auth(&self.token)).await
    }

    pub async fn deployment(&self) -> Result<Value, SourceError> {
        self.get("/v1/deployment").await
    }

    pub async fn packs(&self) -> Result<Value, SourceError> {
        self.get("/v1/packs").await
    }

    pub async fn evidence(&self, run_id: &str) -> Result<Value, SourceError> {
        self.get(&format!("/v1/runs/{}/evidence", encode(run_id))).await
    }

    pub async fn entries(&self, from: u64, limit: usize) -> Result<Page, SourceError> {
        let body = self
            .get(&format!("/v1/audit/entries?from={from}&limit={limit}"))
            .await?;
        serde_json::from_value(body).map_err(|e| SourceError::Shape(e.to_string()))
    }

    /// The tenant chain's published signing keys, as a verifier's key ring.
    pub async fn keys(&self) -> Result<KeyRing, SourceError> {
        let body = self.send(self.http.get(self.url("/v1/audit/keys"))).await?;
        key_ring(&body).map_err(SourceError::Shape)
    }

    /// Revokes or restores a target on this runtime with its `control` key.
    pub async fn revocation(&self, revoke: bool, kind: &str, target: &str, reason: &str) -> Result<Value, SourceError> {
        let token = self.control_token.as_ref().ok_or_else(|| {
            SourceError::MissingToken(
                self.config
                    .control_token_env
                    .clone()
                    .unwrap_or_else(|| "control_token_env".into()),
            )
        })?;
        let path = if revoke {
            "/v1/revocations"
        } else {
            "/v1/revocations/restore"
        };
        self.send(
            self.http
                .post(self.url(path))
                .bearer_auth(token)
                .json(&json!({"kind": kind, "target": target, "reason": reason})),
        )
        .await
    }
}

fn encode(segment: &str) -> String {
    segment
        .bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

/// A key ring from `{"keys": [{"kid", "alg", "public_key", "retired_at"?}]}`. A malformed
/// entry fails the whole ring rather than becoming a trusted key.
pub fn key_ring(body: &Value) -> Result<KeyRing, String> {
    let mut ring = KeyRing::new();
    let mut seen = std::collections::HashSet::new();
    for key in body["keys"].as_array().ok_or("no keys")? {
        let kid = key["kid"].as_str().unwrap_or_default();
        if kid.is_empty() || key["alg"] != "ed25519" || !seen.insert(kid.to_owned()) {
            return Err("each key needs a unique kid and alg ed25519".into());
        }
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(key["public_key"].as_str().unwrap_or_default())
            .ok()
            .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
            .and_then(|b| ed25519_dalek::VerifyingKey::from_bytes(&b).ok())
            .ok_or("invalid public key")?;
        match key["retired_at"].as_str() {
            Some(at) if contextos_contract::validation::is_contract_timestamp(at) => {
                ring.insert_retired(kid, bytes, at);
            }
            Some(_) => return Err("invalid retired_at".into()),
            None => ring.insert(kid, bytes),
        }
    }
    Ok(ring)
}
