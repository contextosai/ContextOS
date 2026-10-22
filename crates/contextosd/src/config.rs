//! Server configuration (TOML). Secrets are never stored in the file: the file names
//! environment variables that hold them, and API keys are configured only as hashes.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    #[default]
    Production,
    /// Enables development-only conveniences; never use with real tenants.
    Development,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
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

#[derive(Debug, Clone, Deserialize, Serialize)]
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

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuditConfig {
    /// Environment variable holding the 32-byte ed25519 seed as hex (development, or
    /// a secret store that only hands out seeds). Unused when `kms` is set.
    #[serde(default)]
    pub signing_seed_env: String,
    pub key_id: String,
    /// Sign with a key held in a KMS instead (the runtime then never holds it).
    #[serde(default)]
    pub kms: Option<crate::kms::KmsConfig>,
    /// Public keys of retired signing keys. Entries they signed stay verifiable after a
    /// rotation: verifiers trust them, and `GET /v1/audit/keys` publishes them, but
    /// nothing signs with them.
    #[serde(default)]
    pub retired_keys: Vec<RetiredKey>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RetiredKey {
    pub kid: String,
    /// Base64url (unpadded) of the 32-byte Ed25519 public key, as `GET /v1/audit/keys`
    /// published it.
    pub public_key: String,
    /// When the key stopped signing: it verifies only entries emitted up to then, so a
    /// retired key that later leaks cannot sign new history.
    pub retired_at: String,
}

impl RetiredKey {
    pub fn verifying_key(&self) -> Option<ed25519_dalek::VerifyingKey> {
        use base64::Engine as _;
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&self.public_key)
            .ok()?;
        ed25519_dalek::VerifyingKey::from_bytes(&bytes.try_into().ok()?).ok()
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApiKey {
    /// `sha256:<hex>` of the raw key.
    pub key_sha256: String,
    pub tenant_id: String,
    pub principal_id: String,
    pub scopes: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SupportConfig {
    pub implementation_id: String,
    pub implementation_version: String,
    /// Controls this deployment actually enforces through its integrated providers.
    /// Declaring a control here is a claim about the deployment, not a grant.
    pub controls: Vec<String>,
    pub profiles: Vec<String>,
}

/// Guards on agent behaviour.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GuardsConfig {
    /// Identical tool calls (same capability and arguments, new operation) a run may
    /// make before the next is refused with `loop_detected`; 0 disables the guard.
    #[serde(default = "default_identical_calls")]
    pub identical_tool_calls: u64,
    /// Refuse a new operation whose effect is identical (same capability and
    /// arguments) to one the run already applied, unless the capability is
    /// `repeatable`: `effect_repeated`. On by default.
    #[serde(default = "default_true")]
    pub refuse_repeated_effects: bool,
    /// Tokens every model-call reservation covers at least, so an executor cannot
    /// reserve (and self-settle) a model call for nothing.
    #[serde(default = "default_model_call_tokens")]
    pub model_call_min_tokens: u64,
    /// Release artifact types every run's execution contract must pin in
    /// `release_refs` (e.g. `["model_profile", "evaluator_suite"]`), so each decision
    /// records which model and evaluators produced it. Unset: `model_profile` and
    /// `evaluator_suite` in production, none in development; `[]` opts out explicitly.
    #[serde(default)]
    pub required_release_refs: Option<Vec<String>>,
    /// Refuse runs whose user claims carry no `role`, so policy never evaluates a role
    /// nobody asserted (the reference compiler defaults it; see the threat model).
    /// Unset: on in production, off in development.
    #[serde(default)]
    pub require_user_role: Option<bool>,
    /// Admit recalled memory (`deps.promoted_memory`) that no memory-governance service
    /// can verify. Without `[providers.memory]`, production refuses such memory unless
    /// this is set; with it, every item is verified against promoted state regardless.
    #[serde(default)]
    pub trust_supplied_memory: bool,
    /// Refuse to start with a capability that lacks an `input_schema` or
    /// `output_schema`, so every call's arguments and results are checked against a
    /// reviewed shape (read-only tools too: their results carry most injected content).
    #[serde(default)]
    pub require_tool_schemas: bool,
    /// Online validation: a run may complete only when every decision that applied an
    /// effect holds an independent score whose `policy` and `safety` meet these floors.
    /// Unset: on in production (policy 1.0, safety 0.9), off in development; `true` uses
    /// those floors, `false` opts out explicitly, a table sets them.
    #[serde(default)]
    pub completion_requires_scores: Option<CompletionScores>,
}

/// `[guards] completion_requires_scores`: on or off, or explicit floors.
#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(untagged)]
pub enum CompletionScores {
    Enabled(bool),
    Floors(ScoreFloors),
}

/// The floors `completion_requires_scores = true` and production use.
pub const DEFAULT_SCORE_FLOORS: ScoreFloors = ScoreFloors {
    policy_floor: 1.0,
    safety_floor: 0.9,
};

/// Score floors for [`GuardsConfig::completion_requires_scores`], each in 0..=1.
#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScoreFloors {
    pub policy_floor: f64,
    pub safety_floor: f64,
}

fn default_model_call_tokens() -> u64 {
    1_000
}

fn default_true() -> bool {
    true
}

fn default_identical_calls() -> u64 {
    5
}

impl Default for GuardsConfig {
    fn default() -> Self {
        Self {
            identical_tool_calls: default_identical_calls(),
            refuse_repeated_effects: true,
            model_call_min_tokens: default_model_call_tokens(),
            required_release_refs: None,
            require_user_role: None,
            trust_supplied_memory: false,
            require_tool_schemas: false,
            completion_requires_scores: None,
        }
    }
}

/// Principals whose conformance reports and control evidence this deployment trusts,
/// with the Ed25519 keys their attestations are signed with (see [`crate::attest`]).
/// Each principal names its tenant; an assessment uses those of the caller's tenant
/// only. The caller of an assessment never supplies these.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConformanceConfig {
    #[serde(default)]
    pub trusted_assessors: Vec<crate::attest::TrustedSigner>,
    #[serde(default)]
    pub trusted_evidence_observers: Vec<crate::attest::TrustedSigner>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityConfig {
    /// Trust domain of agent principals admitted by this deployment.
    pub trust_domain: String,
    /// Principal id the gateway uses for its own observations.
    pub gateway_principal_id: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
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

#[derive(Debug, Clone, Deserialize, Serialize)]
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
    /// Memory-governance service; enables governed memory lifecycle operations.
    #[serde(default)]
    pub memory: Option<RemoteProvider>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AdapterKind {
    Mcp,
    Http,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdapterConfig {
    pub id: String,
    pub kind: AdapterKind,
    pub endpoint: String,
    /// Environment variable holding the provider credential issued by your broker.
    #[serde(default)]
    pub token_env: Option<String>,
}

/// One registered result schema.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResultSchemaConfig {
    #[serde(rename = "ref")]
    pub schema_ref: String,
    pub path: PathBuf,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
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
    /// Runtime guards on agent behaviour.
    #[serde(default)]
    pub guards: GuardsConfig,
    /// Trust anchors for conformance assessment (`POST /v1/conformance/assess`).
    #[serde(default)]
    pub conformance: ConformanceConfig,
    /// Retention of runs' personal content (see [`crate::retention`]); off by default.
    #[serde(default)]
    pub retention: crate::retention::RetentionConfig,
    /// Context Pack JSON files to load at startup.
    #[serde(default)]
    pub packs: Vec<PathBuf>,
    /// Schemas delegated runs' results must meet, by the `output_schema_ref` a
    /// delegation names: `[[result_schemas]] ref = "schema://…", path = "…json"`.
    #[serde(default)]
    pub result_schemas: Vec<ResultSchemaConfig>,
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
    /// The TOML text this configuration was parsed from (served by `GET /v1/config`).
    #[serde(skip)]
    pub source: String,
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
    /// `[guards] required_release_refs`, with the mode's default when unset.
    pub fn required_release_refs(&self) -> Vec<String> {
        self.guards.required_release_refs.clone().unwrap_or_else(|| {
            if self.server.mode == Mode::Production {
                vec!["model_profile".into(), "evaluator_suite".into()]
            } else {
                Vec::new()
            }
        })
    }

    /// `[guards] completion_requires_scores`, with the mode's default when unset.
    pub fn completion_score_floors(&self) -> Option<ScoreFloors> {
        match self.guards.completion_requires_scores {
            Some(CompletionScores::Floors(floors)) => Some(floors),
            Some(CompletionScores::Enabled(true)) => Some(DEFAULT_SCORE_FLOORS),
            Some(CompletionScores::Enabled(false)) => None,
            None => (self.server.mode == Mode::Production).then_some(DEFAULT_SCORE_FLOORS),
        }
    }

    /// `[guards] require_user_role`, with the mode's default when unset.
    pub fn require_user_role(&self) -> bool {
        self.guards
            .require_user_role
            .unwrap_or(self.server.mode == Mode::Production)
    }

    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|e| ConfigError::Read(path.to_owned(), e))?;
        Self::parse(&text)
    }

    pub fn parse(text: &str) -> Result<Self, ConfigError> {
        let mut config: Config = toml::from_str(text).map_err(|e| ConfigError::Parse(e.to_string()))?;
        config.check()?;
        text.clone_into(&mut config.source);
        Ok(config)
    }

    fn check(&self) -> Result<(), ConfigError> {
        if let Some(CompletionScores::Floors(floors)) = self.guards.completion_requires_scores
            && ![floors.policy_floor, floors.safety_floor]
                .iter()
                .all(|f| (0.0..=1.0).contains(f))
        {
            return Err(ConfigError::Invalid(
                "[guards] completion_requires_scores floors must be between 0 and 1".into(),
            ));
        }
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
            // A misspelt scope would silently grant nothing; refuse it instead.
            if let Some(unknown) = key
                .scopes
                .iter()
                .find(|s| !crate::oidc::KNOWN_SCOPES.contains(&s.as_str()))
            {
                return Err(ConfigError::Invalid(format!(
                    "api key for {} has unknown scope {unknown:?}",
                    key.principal_id
                )));
            }
        }
        // The example keys are published; a production deployment must not accept them.
        if self.server.mode == Mode::Production {
            const PUBLISHED: [&str; 6] = [
                "dev-key-0123456789abcdef0123456789abcdef",
                "dev-judge-0123456789abcdef0123456789abcd",
                "dev-ops-0123456789abcdef0123456789abcdef",
                "dev-admin-0123456789abcdef0123456789abcd",
                "dev-review-0123456789abcdef0123456789abc",
                "dev-tower-0123456789abcdef0123456789abcd",
            ];
            if let Some(key) = self.api_keys.iter().find(|k| {
                PUBLISHED
                    .iter()
                    .any(|raw| crate::auth::hash_api_key(raw) == k.key_sha256)
            }) {
                return Err(ConfigError::Invalid(format!(
                    "api key for {} is a published example key; generate your own with `ctx hash-key`",
                    key.principal_id
                )));
            }
        }
        // Separation of duties holds per principal, not per key: an evaluator's
        // principal may not also run or admit agents through another key.
        let runs = |p: &str| {
            self.api_keys
                .iter()
                .any(|k| k.principal_id == p && k.scopes.iter().any(|s| s == "admit" || s == "dispatch"))
        };
        if let Some(key) = self
            .api_keys
            .iter()
            .find(|k| k.scopes.iter().any(|s| s == "evaluate" || s == "meter") && runs(&k.principal_id))
        {
            return Err(ConfigError::Invalid(format!(
                "principal {} cannot both evaluate or meter and admit or dispatch",
                key.principal_id
            )));
        }
        // Whoever proposes or approves configuration does not also run agents under it.
        if let Some(key) = self
            .api_keys
            .iter()
            .find(|k| k.scopes.iter().any(|s| s == "config") && runs(&k.principal_id))
        {
            return Err(ConfigError::Invalid(format!(
                "principal {} cannot both hold config and admit or dispatch",
                key.principal_id
            )));
        }
        if self.audit.kms.is_some() != self.audit.signing_seed_env.is_empty() {
            return Err(ConfigError::Invalid(
                "set exactly one of [audit] signing_seed_env or [audit.kms]".into(),
            ));
        }
        for retired in &self.audit.retired_keys {
            if retired.kid.is_empty()
                || retired.kid == self.audit.key_id
                || retired.verifying_key().is_none()
                || !contextos_contract::validation::is_contract_timestamp(&retired.retired_at)
            {
                return Err(ConfigError::Invalid(format!(
                    "retired audit key {:?} needs its own kid, a valid Ed25519 public key and a retired_at time",
                    retired.kid
                )));
            }
        }
        self.limits.check().map_err(ConfigError::Invalid)?;
        self.retention.check().map_err(ConfigError::Invalid)?;
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

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE: &str = include_str!("../../../deploy/contextosd.example.toml");

    #[test]
    fn the_example_parses_and_unknown_scopes_are_refused() {
        Config::parse(EXAMPLE).unwrap();
        let typo = EXAMPLE.replace(r#""audit:read"]"#, r#""audit_read"]"#);
        assert_ne!(typo, EXAMPLE);
        let error = Config::parse(&typo).unwrap_err().to_string();
        assert!(error.contains("unknown scope"), "{error}");
        let second_key = format!(
            "{EXAMPLE}\n[[api_keys]]\nkey_sha256 = \"sha256:{}\"\ntenant_id = \"tenant_acme_prod\"\nprincipal_id = \"svc_orchestrator\"\nscopes = [\"evaluate\"]\n",
            "1".repeat(64)
        );
        let error = Config::parse(&second_key).unwrap_err().to_string();
        assert!(error.contains("cannot both evaluate"), "{error}");
        // Published example keys are refused in production (the example file is).
        let published = EXAMPLE.replace(
            &format!("sha256:{}", "0".repeat(64)),
            &crate::auth::hash_api_key("dev-key-0123456789abcdef0123456789abcdef"),
        );
        assert_ne!(published, EXAMPLE);
        let error = Config::parse(&published).unwrap_err().to_string();
        assert!(error.contains("published example key"), "{error}");
    }
}
