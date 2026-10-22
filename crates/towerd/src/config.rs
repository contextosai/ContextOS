//! `towerd` configuration (TOML). As in `contextosd`, the file holds no secrets: keys
//! are hashes, and credentials are named by environment variable.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::Deserialize;

/// Roles a caller may hold.
pub const ROLES: [&str; 5] = ["viewer", "owner", "risk", "operator", "admin"];

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub server: ServerConfig,
    #[serde(default)]
    pub store: StoreConfig,
    pub journal: JournalConfig,
    /// Runtime tenants Tower governs.
    #[serde(default)]
    pub sources: Vec<SourceConfig>,
    #[serde(default)]
    pub api_keys: Vec<ApiKey>,
    #[serde(default)]
    pub intelligence: IntelligenceConfig,
    #[serde(default)]
    pub collector: CollectorConfig,
    /// The Tower UI build (`tower/dist`).
    #[serde(default)]
    pub tower: Option<TowerConfig>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    pub listen: SocketAddr,
    #[serde(default)]
    pub development: bool,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields, tag = "kind", rename_all = "snake_case")]
pub enum StoreConfig {
    #[default]
    Memory,
    Postgres {
        url_env: String,
        #[serde(default = "default_connections")]
        max_connections: u32,
    },
}

fn default_connections() -> u32 {
    8
}

/// Tower signs its own governance actions (reviews, waivers, guardrails, intelligence
/// use) into its own hash-chained journal.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JournalConfig {
    pub signing_seed_env: String,
    pub key_id: String,
}

/// One runtime tenant: a `contextosd` URL and a tenant-bound `audit:read` key.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceConfig {
    pub id: String,
    pub url: String,
    /// Environment variable holding the `audit:read` key for this tenant.
    pub token_env: String,
    /// Environment variable holding a `control` key, for the fleet kill switch.
    #[serde(default)]
    pub control_token_env: Option<String>,
    #[serde(default)]
    pub business_unit: Option<String>,
    #[serde(default)]
    pub region: Option<String>,
    #[serde(default)]
    pub environment: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiKey {
    pub key_sha256: String,
    pub principal_id: String,
    pub roles: Vec<String>,
    /// Teams whose agents an `owner` may declare and fix.
    #[serde(default)]
    pub teams: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntelligenceConfig {
    /// `anthropic` or `off`.
    #[serde(default = "default_provider")]
    pub provider: String,
    #[serde(default = "default_key_env")]
    pub api_key_env: String,
    #[serde(default = "default_model")]
    pub model: String,
    #[serde(default = "default_effort")]
    pub effort: String,
    #[serde(default = "default_base_url")]
    pub base_url: String,
    /// Tool-use turns a question may take.
    #[serde(default = "default_max_turns")]
    pub max_turns: usize,
}

impl Default for IntelligenceConfig {
    fn default() -> Self {
        Self {
            provider: default_provider(),
            api_key_env: default_key_env(),
            model: default_model(),
            effort: default_effort(),
            base_url: default_base_url(),
            max_turns: default_max_turns(),
        }
    }
}

fn default_provider() -> String {
    "off".into()
}
fn default_key_env() -> String {
    "ANTHROPIC_API_KEY".into()
}
fn default_model() -> String {
    "claude-opus-5-5".into()
}
fn default_effort() -> String {
    "high".into()
}
fn default_base_url() -> String {
    "https://api.anthropic.com".into()
}
fn default_max_turns() -> usize {
    8
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CollectorConfig {
    #[serde(default = "default_poll")]
    pub poll_ms: u64,
    /// Recent run summaries kept for search and drill-down (raw evidence stays in the runtime).
    #[serde(default = "default_recent")]
    pub recent_runs: usize,
    /// Hours of per-agent activity kept for trends and anomaly baselines.
    #[serde(default = "default_hours")]
    pub hours: usize,
}

impl Default for CollectorConfig {
    fn default() -> Self {
        Self {
            poll_ms: default_poll(),
            recent_runs: default_recent(),
            hours: default_hours(),
        }
    }
}

fn default_poll() -> u64 {
    2_000
}
fn default_recent() -> usize {
    50_000
}
fn default_hours() -> usize {
    24 * 30
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TowerConfig {
    pub dir: PathBuf,
}

/// Keys published in examples/tower; refused unless `[server] development`.
const PUBLISHED: [&str; 5] = [
    "dev-ciso-0123456789abcdef0123456789abcde",
    "dev-owner-0123456789abcdef0123456789abcd",
    "dev-risk-a-0123456789abcdef0123456789abc",
    "dev-risk-b-0123456789abcdef0123456789abc",
    "dev-oncall-0123456789abcdef0123456789abc",
];

fn hash_key(raw: &str) -> String {
    use sha2::Digest;
    format!("sha256:{}", hex::encode(sha2::Sha256::digest(raw.as_bytes())))
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("cannot read {0}: {1}")]
    Read(PathBuf, std::io::Error),
    #[error("invalid configuration: {0}")]
    Parse(String),
    #[error("{0}")]
    Invalid(String),
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|e| ConfigError::Read(path.to_owned(), e))?;
        Self::parse(&text)
    }

    pub fn parse(text: &str) -> Result<Self, ConfigError> {
        let config: Config = toml::from_str(text).map_err(|e| ConfigError::Parse(e.to_string()))?;
        config.check()?;
        Ok(config)
    }

    fn check(&self) -> Result<(), ConfigError> {
        let mut ids = std::collections::BTreeSet::new();
        for source in &self.sources {
            if source.id.is_empty() || !ids.insert(&source.id) {
                return Err(ConfigError::Invalid(format!(
                    "source ids must be unique and non-empty: {:?}",
                    source.id
                )));
            }
            let url = source
                .url
                .parse::<reqwest::Url>()
                .map_err(|_| ConfigError::Invalid(format!("source {}: invalid url", source.id)))?;
            if url.scheme() != "https" && !self.server.development {
                return Err(ConfigError::Invalid(format!(
                    "source {}: url must use https",
                    source.id
                )));
            }
        }
        for key in &self.api_keys {
            let hex = key.key_sha256.strip_prefix("sha256:").unwrap_or_default();
            if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()) {
                return Err(ConfigError::Invalid(format!(
                    "api key for {} must be a lowercase sha256: hash",
                    key.principal_id
                )));
            }
            if let Some(role) = key.roles.iter().find(|r| !ROLES.contains(&r.as_str())) {
                return Err(ConfigError::Invalid(format!(
                    "api key for {} has unknown role {role:?}",
                    key.principal_id
                )));
            }
            if key.roles.is_empty() {
                return Err(ConfigError::Invalid(format!(
                    "api key for {} needs a role",
                    key.principal_id
                )));
            }
        }
        // The example keys are published; only a development Tower accepts them.
        if !self.server.development {
            for key in &self.api_keys {
                if PUBLISHED.iter().any(|raw| hash_key(raw) == key.key_sha256) {
                    return Err(ConfigError::Invalid(format!(
                        "api key for {} is a published example key; generate your own with `ctx hash-key`",
                        key.principal_id
                    )));
                }
            }
        }
        if !matches!(self.intelligence.provider.as_str(), "anthropic" | "off") {
            return Err(ConfigError::Invalid(
                "[intelligence] provider must be anthropic or off".into(),
            ));
        }
        if !matches!(
            self.intelligence.effort.as_str(),
            "low" | "medium" | "high" | "xhigh" | "max"
        ) {
            return Err(ConfigError::Invalid(
                "[intelligence] effort must be low, medium, high, xhigh or max".into(),
            ));
        }
        Ok(())
    }
}
