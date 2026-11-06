//! The configuration's sections, each a table of the TOML file. Doc comments here are
//! the descriptions in `docs/CONFIG.md` and the published configuration schema.

use std::net::SocketAddr;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, Default, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    #[default]
    Production,
    /// Enables development-only conveniences; never use with real tenants.
    Development,
}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// Socket address to listen on, such as `0.0.0.0:8080`.
    pub listen: SocketAddr,
    /// Largest request body accepted, in bytes.
    #[serde(default = "default_max_body")]
    pub max_body_bytes: usize,
    /// Time a request may take before the server answers 504.
    #[serde(default = "default_timeout")]
    pub request_timeout_ms: u64,
    /// `production` refuses development-only conveniences and warns about weak settings.
    #[serde(default)]
    pub mode: Mode,
    /// The URL clients reach this server at, for OAuth protected resource metadata
    /// (see [`crate::protected_resource`]). Unset: no metadata is published.
    #[serde(default)]
    pub public_url: Option<String>,
    /// Browser origins, besides `public_url`'s, that may call the MCP endpoint.
    #[serde(default)]
    pub allowed_origins: Vec<String>,
}

fn default_max_body() -> usize {
    4 * 1024 * 1024
}

fn default_timeout() -> u64 {
    15_000
}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields, tag = "kind", rename_all = "snake_case")]
pub enum StoreConfig {
    Memory,
    Postgres {
        /// Environment variable holding the connection URL.
        url_env: String,
        /// PostgreSQL connection pool size.
        #[serde(default = "default_connections")]
        max_connections: u32,
    },
}

fn default_connections() -> u32 {
    32
}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AuditConfig {
    /// Environment variable holding the 32-byte ed25519 seed as hex (development, or
    /// a secret store that only hands out seeds). Unused when `kms` is set.
    #[serde(default)]
    pub signing_seed_env: String,
    /// Key id (`kid`) recorded on every entry the current key signs.
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

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RetiredKey {
    /// The retired key's id, as recorded on the entries it signed.
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

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ApiKey {
    /// `sha256:<hex>` of the raw key.
    pub key_sha256: String,
    /// Tenant the key acts in.
    pub tenant_id: String,
    /// Principal the key authenticates.
    pub principal_id: String,
    /// API scopes granted, such as `admit`, `dispatch` or `audit:read`.
    pub scopes: Vec<String>,
    /// The agent ids this key is issued for (see [`crate::agent_binding`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_ids: Option<Vec<String>>,
}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SupportConfig {
    /// Implementation id published in the support declaration.
    pub implementation_id: String,
    /// Implementation version published in the support declaration.
    pub implementation_version: String,
    /// Controls this deployment actually enforces through its integrated providers.
    /// Declaring a control here is a claim about the deployment, not a grant.
    pub controls: Vec<String>,
    /// Conformance profiles this deployment claims.
    pub profiles: Vec<String>,
}

/// Principals whose conformance reports and control evidence this deployment trusts,
/// with the Ed25519 keys their attestations are signed with (see [`crate::attest`]).
/// Each principal names its tenant; an assessment uses those of the caller's tenant
/// only. The caller of an assessment never supplies these.
#[derive(Debug, Clone, Default, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConformanceConfig {
    /// Principals whose conformance reports are trusted.
    #[serde(default)]
    pub trusted_assessors: Vec<crate::attest::TrustedSigner>,
    /// Principals whose control evidence is trusted.
    #[serde(default)]
    pub trusted_evidence_observers: Vec<crate::attest::TrustedSigner>,
}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IdentityConfig {
    /// Trust domain of agent principals admitted by this deployment.
    pub trust_domain: String,
    /// Principal id the gateway uses for its own observations.
    pub gateway_principal_id: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RemoteProvider {
    /// Base URL of the service.
    pub url: String,
    /// Environment variable holding this service's bearer credential.
    #[serde(default)]
    pub token_env: Option<String>,
    /// Time a call may take before it counts as failed.
    #[serde(default = "default_provider_timeout")]
    pub timeout_ms: u64,
}

fn default_provider_timeout() -> u64 {
    2_000
}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProvidersConfig {
    /// Authority service: who may act for whom.
    pub authority: RemoteProvider,
    /// Constraints service: verified observations for the controls a pack requires.
    pub constraints: RemoteProvider,
    /// Approvals service: human approval requests and decisions.
    pub approvals: RemoteProvider,
    /// Provider idempotency status service, for reconciling unknown outcomes.
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
    /// Result-screening service; judges every confirmed effect's output before the
    /// agent sees it.
    #[serde(default)]
    pub result_screening: Option<RemoteProvider>,
    /// Resource identity service; maps identifiers to canonical ids for guarantees with
    /// `resource_canonicalizer = "provider"`.
    #[serde(default)]
    pub resource_identity: Option<RemoteProvider>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AdapterKind {
    Mcp,
    Http,
}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AdapterConfig {
    /// Adapter id that capability manifests name.
    pub id: String,
    /// Protocol: `mcp` (Streamable HTTP) or `http`.
    pub kind: AdapterKind,
    /// The provider's URL.
    pub endpoint: String,
    /// Replicas of the same provider, tried after `endpoint`. A call moves on only when
    /// its request never left, or (read-only capabilities) when its response was lost
    /// or the endpoint answered 502, 503 or 504; three consecutive failures eject an
    /// endpoint for 30 seconds, doubling up to five minutes. Each must serve the same
    /// tools and share the provider's state; OAuth tokens name `endpoint` as their
    /// resource unless `oauth.resource` is set.
    #[serde(default)]
    pub fallback_endpoints: Vec<String>,
    /// Environment variable holding the provider credential issued by your broker.
    #[serde(default)]
    pub token_env: Option<String>,
    /// Obtain provider tokens with the OAuth client credentials grant instead of a
    /// fixed token (see [`crate::runtime::oauth_broker`]).
    #[serde(default)]
    pub oauth: Option<OAuthClientConfig>,
    /// MCP only: how a tool result becomes the tool output. `flat` (the default) is the
    /// original mapping; `mcp_result_v1` preserves structured content losslessly.
    #[serde(default)]
    pub result_projection: Option<ResultProjectionConfig>,
}

/// OAuth 2.0 client credentials for one adapter's provider.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OAuthClientConfig {
    /// Token endpoint of the authorization server.
    pub token_url: String,
    /// OAuth client id.
    pub client_id: String,
    /// Environment variable holding the client secret.
    pub client_secret_env: String,
    /// Scope to request, if the server needs one.
    #[serde(default)]
    pub scope: Option<String>,
    /// RFC 8707 resource the token is for; defaults to the adapter's endpoint.
    #[serde(default)]
    pub resource: Option<String>,
    /// Replace a cached token this long before it expires.
    #[serde(default = "default_refresh_before")]
    pub refresh_before_seconds: u64,
}

fn default_refresh_before() -> u64 {
    60
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ResultProjectionConfig {
    Flat,
    McpResultV1,
}

/// One registered result schema.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResultSchemaConfig {
    /// The `output_schema_ref` delegations name.
    #[serde(rename = "ref")]
    pub schema_ref: String,
    /// JSON Schema file the result must meet.
    pub path: PathBuf,
}
