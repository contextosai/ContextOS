//! Server configuration (TOML). Secrets are never stored in the file: the file names
//! environment variables that hold them, and API keys are configured only as hashes.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::Deserialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    #[default]
    Production,
    /// Enables development-only conveniences; never use with real tenants.
    Development,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    pub listen: SocketAddr,
    #[serde(default = "default_max_body")]
    pub max_body_bytes: usize,
    #[serde(default = "default_timeout")]
    pub request_timeout_ms: u64,
    #[serde(default)]
    pub mode: Mode,
}

fn default_max_body() -> usize {
    4 * 1024 * 1024
}

fn default_timeout() -> u64 {
    15_000
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, tag = "kind", rename_all = "snake_case")]
pub enum StoreConfig {
    Memory,
    Postgres {
        /// Environment variable holding the connection URL.
        url_env: String,
        #[serde(default = "default_connections")]
        max_connections: u32,
    },
}

fn default_connections() -> u32 {
    32
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditConfig {
    /// Environment variable holding the 32-byte ed25519 seed as hex.
    pub signing_seed_env: String,
    pub key_id: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiKey {
    /// `sha256:<hex>` of the raw key.
    pub key_sha256: String,
    pub tenant_id: String,
    pub principal_id: String,
    pub scopes: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupportConfig {
    pub implementation_id: String,
    pub implementation_version: String,
    /// Controls this deployment actually enforces through its integrated providers.
    /// Declaring a control here is a claim about the deployment, not a grant.
    pub controls: Vec<String>,
    pub profiles: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityConfig {
    /// Trust domain of agent principals admitted by this deployment.
    pub trust_domain: String,
    /// Principal id the gateway uses for its own observations.
    pub gateway_principal_id: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteProvider {
    pub url: String,
    /// Environment variable holding this service's bearer credential.
    #[serde(default)]
    pub token_env: Option<String>,
    #[serde(default = "default_provider_timeout")]
    pub timeout_ms: u64,
}

fn default_provider_timeout() -> u64 {
    2_000
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProvidersConfig {
    pub authority: RemoteProvider,
    pub constraints: RemoteProvider,
    pub approvals: RemoteProvider,
    #[serde(default)]
    pub idempotency: Option<RemoteProvider>,
    /// Data-governance service; when set, data sent to destinations must pass the
    /// kernel's data-flow policy evaluation.
    #[serde(default)]
    pub data_flow: Option<RemoteProvider>,
    /// Execution-boundary controller; when set, run start, resume and every dispatch
    /// require the kernel to find the run's boundary active.
    #[serde(default)]
    pub boundary: Option<RemoteProvider>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdapterKind {
    Mcp,
    Http,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdapterConfig {
    pub id: String,
    pub kind: AdapterKind,
    pub endpoint: String,
    /// Environment variable holding the provider credential issued by your broker.
    #[serde(default)]
    pub token_env: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub server: ServerConfig,
    pub store: StoreConfig,
    pub audit: AuditConfig,
    pub support: SupportConfig,
    #[serde(default)]
    pub api_keys: Vec<ApiKey>,
    /// OIDC issuers whose JWTs authenticate callers.
    #[serde(default)]
    pub oidc: Vec<crate::oidc::OidcConfig>,
    /// Overload protection (see [`crate::limits`]).
    #[serde(default)]
    pub limits: crate::limits::LimitsConfig,
    /// Context Pack JSON files to load at startup.
    #[serde(default)]
    pub packs: Vec<PathBuf>,
    /// Reviewed capability manifest JSON files to pin at startup.
    #[serde(default)]
    pub capabilities: Vec<PathBuf>,
    #[serde(default)]
    pub identity: Option<IdentityConfig>,
    /// Remote fact services; dispatch is disabled without them.
    #[serde(default)]
    pub providers: Option<ProvidersConfig>,
    #[serde(default)]
    pub adapters: Vec<AdapterConfig>,
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
        for key in &self.api_keys {
            let hex = key.key_sha256.strip_prefix("sha256:").unwrap_or_default();
            if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()) {
                return Err(ConfigError::Invalid(format!(
                    "api key for {} must be a lowercase sha256: hash",
                    key.principal_id
                )));
            }
            if key.tenant_id.is_empty() || key.principal_id.is_empty() || key.scopes.is_empty() {
                return Err(ConfigError::Invalid(
                    "api keys need a tenant, principal and scopes".into(),
                ));
            }
        }
        self.limits.check().map_err(ConfigError::Invalid)?;
        let development = self.server.mode == Mode::Development;
        for issuer in &self.oidc {
            issuer.check(development).map_err(ConfigError::Invalid)?;
        }
        if self.server.max_body_bytes == 0 || self.server.max_body_bytes > 64 * 1024 * 1024 {
            return Err(ConfigError::Invalid("max_body_bytes must be in (0, 64 MiB]".into()));
        }
        Ok(())
    }
}
