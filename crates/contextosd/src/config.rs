//! Server configuration (TOML). Secrets are never stored in the file: the file names
//! environment variables that hold them, and API keys are configured only as hashes.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

mod sections;
pub use crate::guards::{CompletionScores, DEFAULT_SCORE_FLOORS, GuardsConfig, ScoreFloors};
pub use sections::*;

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// The listener, request limits and mode.
    pub server: ServerConfig,
    /// Where runs, ledgers and the audit chain are kept.
    pub store: StoreConfig,
    /// The audit chain's signing key.
    pub audit: AuditConfig,
    /// What this deployment declares it implements (`RuntimeSupportDeclaration`).
    pub support: SupportConfig,
    /// API keys, configured as hashes only (`ctx hash-key`).
    #[serde(default)]
    pub api_keys: Vec<ApiKey>,
    /// OIDC issuers whose JWTs authenticate callers.
    #[serde(default)]
    pub oidc: Vec<crate::oidc::OidcConfig>,
    /// Services trusted to vouch for gated evidence (see [`crate::evidence_issuers`]).
    #[serde(default)]
    pub evidence_issuers: Vec<crate::evidence_issuers::EvidenceIssuerConfig>,
    /// What each gated requirement's evidence must be about (see
    /// [`crate::evidence_subjects`]).
    #[serde(default)]
    pub evidence_subjects: Vec<crate::evidence_subjects::EvidenceSubject>,
    /// Overload protection (see [`crate::limits`]).
    #[serde(default)]
    pub limits: crate::limits::LimitsConfig,
    /// Runtime guards on agent behaviour.
    #[serde(default)]
    pub guards: GuardsConfig,
    /// Trusted business-resource limits shared by unrelated agent runs.
    #[serde(default)]
    pub guarantees: Vec<contextos_gateway::SharedGuarantee>,
    /// Webhooks told when escalations open and resolve (see [`crate::notifications`]).
    #[serde(default)]
    pub notifications: Vec<crate::notifications::WebhookConfig>,
    /// Destinations the audit chain is delivered to, with masked payload fields (see
    /// [`crate::audit_sinks`]).
    #[serde(default)]
    pub audit_sinks: Vec<crate::audit_sinks::AuditSinkConfig>,
    /// Trust anchors for conformance assessment (`POST /v1/conformance/assess`).
    #[serde(default)]
    pub conformance: ConformanceConfig,
    /// Retention of runs' personal content (see [`crate::retention`]); off by default.
    #[serde(default)]
    pub retention: crate::retention::RetentionConfig,
    /// Context Pack JSON files to load at startup.
    #[serde(default)]
    pub packs: Vec<PathBuf>,
    /// Directories whose JSON files (recursively; names starting with `.` skipped) are
    /// Context Packs, loaded at startup and re-read on reload (see
    /// [`crate::pack_registry`]).
    #[serde(default)]
    pub pack_dirs: Vec<PathBuf>,
    /// Re-read `packs` and `pack_dirs` this often and add new pack versions; 0 (the
    /// default) reads them at startup and on `POST /v1/packs/reload` only.
    #[serde(default)]
    pub pack_reload_secs: u64,
    /// Schemas delegated runs' results must meet, by the `output_schema_ref` a
    /// delegation names: `[[result_schemas]] ref = "schema://…", path = "…json"`.
    #[serde(default)]
    pub result_schemas: Vec<ResultSchemaConfig>,
    /// Reviewed capability manifest JSON files to pin at startup.
    #[serde(default)]
    pub capabilities: Vec<PathBuf>,
    /// Manifests of versions `capabilities` replaced, kept while operations claimed
    /// under them may still need reconciliation or attestation. Never dispatched.
    #[serde(default)]
    pub retired_capabilities: Vec<PathBuf>,
    /// Agent trust domain and the gateway's own principal; defaults suit one deployment.
    #[serde(default)]
    pub identity: Option<IdentityConfig>,
    /// Remote fact services; dispatch is disabled without them.
    #[serde(default)]
    pub providers: Option<ProvidersConfig>,
    /// Providers that perform effects: MCP servers or HTTP services.
    #[serde(default)]
    pub adapters: Vec<AdapterConfig>,
    /// Opt-in profile holding consequential workflows to every safety mechanism they
    /// rely on (see [`crate::workflow_readiness`]). Unset: not checked.
    #[serde(default)]
    pub readiness: Option<crate::workflow_readiness::ReadinessConfig>,
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

    /// `[guards] require_completion_contracts`, with the mode's default when unset.
    pub fn require_completion_contracts(&self) -> bool {
        self.guards
            .require_completion_contracts
            .unwrap_or(self.server.mode == Mode::Production)
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
        crate::agent_binding::check(&config).map_err(ConfigError::Invalid)?;
        crate::user_binding::check(&config).map_err(ConfigError::Invalid)?;
        crate::evidence_admission::check(&config).map_err(ConfigError::Invalid)?;
        crate::evidence_issuers::Issuers::new(&config.evidence_issuers).map_err(ConfigError::Invalid)?;
        crate::evidence_subjects::check(&config.evidence_subjects).map_err(ConfigError::Invalid)?;
        crate::workflow_readiness::check(&config).map_err(ConfigError::Invalid)?;
        crate::notifications::check(&config).map_err(ConfigError::Invalid)?;
        crate::audit_sinks::check(&config).map_err(ConfigError::Invalid)?;
        contextos_gateway::circuit_breakers::validate(&config.guards.circuit_breakers).map_err(ConfigError::Invalid)?;
        if let Some(review) = &config.guards.approval_review {
            review.validate().map_err(ConfigError::Invalid)?;
        }
        if let Some(monitor) = &config.guards.action_monitor {
            monitor.validate().map_err(ConfigError::Invalid)?;
            if config.providers.as_ref().is_none_or(|p| p.action_monitor.is_none()) {
                return Err(ConfigError::Invalid(
                    "[guards.action_monitor] needs [providers.action_monitor]".into(),
                ));
            }
        }
        if let Some(step_up) = &config.guards.approval_step_up {
            step_up.validate().map_err(ConfigError::Invalid)?;
        }
        if let Some(url) = &config.server.public_url {
            crate::protected_resource::check_public_url(url, config.server.mode == Mode::Development)
                .map_err(ConfigError::Invalid)?;
        }
        crate::mcp_transport::check_allowed_origins(&config.server.allowed_origins).map_err(ConfigError::Invalid)?;
        text.clone_into(&mut config.source);
        Ok(config)
    }

    fn check(&self) -> Result<(), ConfigError> {
        let (mut ids, mut capabilities) = (std::collections::HashSet::new(), std::collections::HashSet::new());
        if self.guarantees.len() > 128 {
            return Err(ConfigError::Invalid("too many shared guarantees".into()));
        }
        for rule in &self.guarantees {
            rule.validate().map_err(ConfigError::Invalid)?;
            if !ids.insert(&rule.id) || rule.capability_ids.iter().any(|c| !capabilities.insert(c)) {
                return Err(ConfigError::Invalid(
                    "shared guarantee ids and capability coverage must be unique".into(),
                ));
            }
        }
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
                    "api key for {} must be a lowercase sha256: hash (print one with `ctx hash-key`)",
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
        // Whoever widens a task on its principal's behalf does not also run it.
        if let Some(key) = self
            .api_keys
            .iter()
            .find(|k| k.scopes.iter().any(|s| s == "authorize") && runs(&k.principal_id))
        {
            return Err(ConfigError::Invalid(format!(
                "principal {} cannot both authorize tasks and admit or dispatch",
                key.principal_id
            )));
        }
        // Whoever attests that a started effect did not apply does not also run it.
        if let Some(key) = self
            .api_keys
            .iter()
            .find(|k| k.scopes.iter().any(|s| s == "attest") && runs(&k.principal_id))
        {
            return Err(ConfigError::Invalid(format!(
                "principal {} cannot both attest absence and admit or dispatch",
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
        // Whoever runs a task cannot also widen it.
        let authorizer = second_key.replace(r#"scopes = ["evaluate"]"#, r#"scopes = ["authorize"]"#);
        let error = Config::parse(&authorizer).unwrap_err().to_string();
        assert!(error.contains("cannot both authorize tasks"), "{error}");
        // Nor attest that its effects did not apply.
        let attester = second_key.replace(r#"scopes = ["evaluate"]"#, r#"scopes = ["attest"]"#);
        let error = Config::parse(&attester).unwrap_err().to_string();
        assert!(error.contains("cannot both attest absence"), "{error}");
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
