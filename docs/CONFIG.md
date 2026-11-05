# contextosd configuration reference

Generated from the server's configuration types by
`CONTEXTOS_BLESS=1 cargo test -p contextosd --test generated`; do not edit by hand.
The same schema is `deploy/contextosd-config.schema.json` and
`contextosd --config-schema`. [GUIDE.md](GUIDE.md) explains when to use each
setting; `contextosd --check-config` validates a file and its environment.

Unknown keys are refused. Tables written `[[name]]` repeat.

## Top-level keys

| Key | Type | Default | Description |
|---|---|---|---|
| `adapters` | array of tables | `[]` | Providers that perform effects: MCP servers or HTTP services. |
| `api_keys` | array of tables | `[]` | API keys, configured as hashes only (`ctx hash-key`). |
| `audit` | table | required | The audit chain's signing key. |
| `audit_sinks` | array of tables | `[]` | Destinations the audit chain is delivered to, with masked payload fields (see `audit_sinks`). |
| `capabilities` | array of string | `[]` | Reviewed capability manifest JSON files to pin at startup. |
| `conformance` | table | see below | Trust anchors for conformance assessment (`POST /v1/conformance/assess`). |
| `evidence_issuers` | array of tables | `[]` | Services trusted to vouch for gated evidence (see `evidence_issuers`). |
| `evidence_subjects` | array of tables | `[]` | What each gated requirement's evidence must be about (see `evidence_subjects`). |
| `guarantees` | array of tables | `[]` | Trusted business-resource limits shared by unrelated agent runs. |
| `guards` | table | see below | Runtime guards on agent behaviour. |
| `identity` | table | unset | Agent trust domain and the gateway's own principal; defaults suit one deployment. |
| `limits` | table | see below | Overload protection (see `limits`). |
| `notifications` | array of tables | `[]` | Webhooks told when escalations open and resolve (see `notifications`). |
| `oidc` | array of tables | `[]` | OIDC issuers whose JWTs authenticate callers. |
| `pack_dirs` | array of string | `[]` | Directories whose JSON files (recursively; names starting with `.` skipped) are Context Packs, loaded at startup and re-read on reload (see `pack_registry`). |
| `pack_reload_secs` | integer | `0` | Re-read `packs` and `pack_dirs` this often and add new pack versions; 0 (the default) reads them at startup and on `POST /v1/packs/reload` only. |
| `packs` | array of string | `[]` | Context Pack JSON files to load at startup. |
| `providers` | table | unset | Remote fact services; dispatch is disabled without them. |
| `result_schemas` | array of tables | `[]` | Schemas delegated runs' results must meet, by the `output_schema_ref` a delegation names: `[[result_schemas]] ref = "schema://…", path = "…json"`. |
| `retention` | table | see below | Retention of runs' personal content (see `retention`); off by default. |
| `retired_capabilities` | array of string | `[]` | Manifests of versions `capabilities` replaced, kept while operations claimed under them may still need reconciliation or attestation. Never dispatched. |
| `server` | table | required | The listener, request limits and mode. |
| `store` | table | required | Where runs, ledgers and the audit chain are kept. |
| `support` | table | required | What this deployment declares it implements (`RuntimeSupportDeclaration`). |

## `[[adapters]]`

| Key | Type | Default | Description |
|---|---|---|---|
| `endpoint` | string | required | The provider's URL. |
| `id` | string | required | Adapter id that capability manifests name. |
| `kind` | `"mcp"` \| `"http"` | required | Protocol: `mcp` (Streamable HTTP) or `http`. |
| `oauth` | table | unset | Obtain provider tokens with the OAuth client credentials grant instead of a fixed token (see `runtime::oauth_broker`). |
| `result_projection` | `"flat"` \| `"mcp_result_v1"` | unset | MCP only: how a tool result becomes the tool output. `flat` (the default) is the original mapping; `mcp_result_v1` preserves structured content losslessly. |
| `token_env` | string | unset | Environment variable holding the provider credential issued by your broker. |

## `[[api_keys]]`

| Key | Type | Default | Description |
|---|---|---|---|
| `agent_ids` | array of string | unset | The agent ids this key is issued for (see `agent_binding`). |
| `key_sha256` | string | required | `sha256:<hex>` of the raw key. |
| `principal_id` | string | required | Principal the key authenticates. |
| `scopes` | array of string | required | API scopes granted, such as `admit`, `dispatch` or `audit:read`. |
| `tenant_id` | string | required | Tenant the key acts in. |

## `[audit]`

| Key | Type | Default | Description |
|---|---|---|---|
| `key_id` | string | required | Key id (`kid`) recorded on every entry the current key signs. |
| `kms` | table | unset | Sign with a key held in a KMS instead (the runtime then never holds it). |
| `retired_keys` | array of tables | `[]` | Public keys of retired signing keys. Entries they signed stay verifiable after a rotation: verifiers trust them, and `GET /v1/audit/keys` publishes them, but nothing signs with them. |
| `signing_seed_env` | string | `""` | Environment variable holding the 32-byte ed25519 seed as hex (development, or a secret store that only hands out seeds). Unused when `kms` is set. |

### `[[audit.retired_keys]]`

| Key | Type | Default | Description |
|---|---|---|---|
| `kid` | string | required | The retired key's id, as recorded on the entries it signed. |
| `public_key` | string | required | Base64url (unpadded) of the 32-byte Ed25519 public key, as `GET /v1/audit/keys` published it. |
| `retired_at` | string | required | When the key stopped signing: it verifies only entries emitted up to then, so a retired key that later leaks cannot sign new history. |

## `[[audit_sinks]]`

| Key | Type | Default | Description |
|---|---|---|---|
| `batch` | integer | `100` | Entries per request. |
| `id` | string | required | Sink id, used in metrics and delivery cursors. |
| `kinds` | array of string | `[]` | Entry kinds to deliver; every kind when empty. |
| `mask` | array of string | `[]` | Payload fields to mask (see the module documentation). |
| `mask_key_env` | string | unset | Environment variable holding the masking key (at least 32 bytes); required with `mask`. |
| `secret_env` | string | required | Environment variable holding the request signing secret (at least 32 bytes). |
| `start` | `"genesis"` \| `"head"` | `"genesis"` | `genesis` (default): deliver each tenant's whole chain; `head`: from now on. |
| `url` | string | required | HTTPS endpoint (HTTP only in development). |

## `[conformance]`

Principals whose conformance reports and control evidence this deployment trusts, with the Ed25519 keys their attestations are signed with (see `attest`). Each principal names its tenant; an assessment uses those of the caller's tenant only. The caller of an assessment never supplies these.

| Key | Type | Default | Description |
|---|---|---|---|
| `trusted_assessors` | array of tables | `[]` | Principals whose conformance reports are trusted. |
| `trusted_evidence_observers` | array of tables | `[]` | Principals whose control evidence is trusted. |

### `[[conformance.trusted_assessors]]`

A trusted principal and the Ed25519 key its attestations are signed with.

| Key | Type | Default | Description |
|---|---|---|---|
| `principal` | any | required | The signer's principal, including its tenant. |
| `public_key` | string | required | Base64 (standard) of the 32-byte Ed25519 public key. |

### `[[conformance.trusted_evidence_observers]]`

A trusted principal and the Ed25519 key its attestations are signed with.

| Key | Type | Default | Description |
|---|---|---|---|
| `principal` | any | required | The signer's principal, including its tenant. |
| `public_key` | string | required | Base64 (standard) of the 32-byte Ed25519 public key. |

## `[[evidence_issuers]]`

`[[evidence_issuers]]`: one service trusted to vouch for named facts.

| Key | Type | Default | Description |
|---|---|---|---|
| `algorithm` | string | required | Its signing algorithm (`EdDSA`, `ES256`, `ES384`, `RS256`, `PS256`, …). |
| `issuer` | string | required | Exact `iss` of its attestations. |
| `jwks` | string | required | Its public keys as a JWK Set (JSON text, as the issuer publishes it). A `kid` in an attestation's header selects one; several keys allow rotation. |
| `max_validity_seconds` | integer | required | The longest `valid_until - observed_at` it may claim. |
| `satisfies` | array of string | required | The `required_evidence` names it may satisfy. |
| `tenants` | array of string | required | Tenants whose runs may rely on it. |

## `[[evidence_subjects]]`

`[[evidence_subjects]]`.

| Key | Type | Default | Description |
|---|---|---|---|
| `canonicalizer` | `"exact"` \| `"ascii_casefold"` | `"exact"` | How subjects are compared. |
| `from` | string | required | JSON Pointer into `{"request": …, "run_context": …}` to a string or number. |
| `prefix` | string | `""` | Prepended to the run's value to form the expected `sub`. |
| `requirement` | string | required | The `required_evidence` name this binds. |

## `[[guarantees]]`

| Key | Type | Default | Description |
|---|---|---|---|
| `amount_pointer` | string | required | JSON pointer to the amount in the call's arguments, such as `/amount_minor`. |
| `capability_ids` | array of string | required | Capabilities whose effects draw on this limit. |
| `id` | string | required | Guarantee id, recorded on every reservation. |
| `limit` | integer | required | Total amount all runs together may commit per resource. |
| `owner_after_seconds` | integer | unset | How old a hold is before its owner is told (default 1,800 seconds). |
| `owner_route` | string | unset | The notification webhook that tells this guarantee's business owner about a hold older than `owner_after_seconds` (see `hold_owners`). Routing only: not part of the pinned definition. |
| `resource_canonicalizer` | `"exact"` \| `"ascii_casefold"` \| `"provider"` | unset | How the extracted identifier is made canonical (see `resource_identity`); omitted from the definition when `exact`. |
| `resource_pointer` | string | required | JSON pointer to the resource identifier in the call's arguments, such as `/order_id`. |
| `unit` | string | required | Unit of `limit` and the amounts, such as `INR_minor`. |

## `[guards]`

Guards on agent behaviour.

| Key | Type | Default | Description |
|---|---|---|---|
| `agent_binding` | `"required"` \| `"observe"` \| `"off"` | unset | Whether a run's declared agent must be one its caller's credential is issued for (`required`, `observe`, `off`; see `agent_binding`). Unset: `required` with the `contextos.enterprise` profile, `observe` otherwise. |
| `approval_step_up` | table | unset | Approvals above an amount, or of named capabilities, count only after the approver's recent strong sign-in (see `contextos_gateway::step_up`). |
| `completion_requires_scores` | boolean \| table | unset | Online validation: a run may complete only when every decision that applied an effect holds an independent score whose `policy` and `safety` meet these floors. Unset: on in production (policy 1.0, safety 0.9), off in development; `true` uses those floors, `false` opts out explicitly, a table sets them. |
| `evidence` | `"strict"` \| `"caller"` | unset | What may satisfy a decision's evidence gate (`strict`, `caller`; see `evidence_admission`). Unset: `strict` with the `contextos.enterprise` profile, which requires it, `caller` otherwise. |
| `identical_tool_calls` | integer | `5` | Identical tool calls (same capability and arguments, new operation) a run may make before the next is refused with `loop_detected`; 0 disables the guard. |
| `model_call_min_tokens` | integer | `1000` | Tokens every model-call reservation covers at least, so an executor cannot reserve (and self-settle) a model call for nothing. |
| `pack_intents` | `"required"` \| `"observe"` \| `"off"` | unset | Whether a run's intent must be one its Context Pack's rules name (`required`, `observe`, `off`; see `pack_intents`). Unset: `required` with the `contextos.enterprise` profile, `observe` otherwise. |
| `refuse_repeated_effects` | boolean | `true` | Refuse a new operation whose effect is identical (same capability and arguments) to one the run already applied, unless the capability is `repeatable`: `effect_repeated`. On by default. |
| `require_completion_contracts` | boolean | unset | Refuse to start with an effectful MCP capability that declares no `recovery.completion`, so a finished result is confirmed by the state the tool reports, not by the absence of `isError`. Unset: on in production, off in development. (Effectful HTTP capabilities always need one.) |
| `require_task_authorization` | boolean | `false` | Refuse runs that can apply effects unless they state what their principal authorized (`task_authorization`), so no effect relies on the agent's own reading of the request. |
| `require_tool_schemas` | boolean | `false` | Refuse to start with a capability that lacks an `input_schema` or `output_schema`, so every call's arguments and results are checked against a reviewed shape (read-only tools too: their results carry most injected content). |
| `require_user_role` | boolean | unset | Refuse runs whose user claims carry no `role`, so policy never evaluates a role nobody asserted (the reference compiler defaults it; see the threat model). Unset: on in production, off in development. |
| `required_release_refs` | array of string | unset | Release artifact types every run's execution contract must pin in `release_refs` (e.g. `["model_profile", "evaluator_suite"]`), so each decision records which model and evaluators produced it. Unset: `model_profile` and `evaluator_suite` in production, none in development; `[]` opts out explicitly. |
| `trust_supplied_memory` | boolean | `false` | Admit recalled memory (`deps.promoted_memory`) that no memory-governance service can verify. Without `[providers.memory]`, production refuses such memory unless this is set; with it, every item is verified against promoted state regardless. |
| `user_binding` | `"required"` \| `"observe"` \| `"off"` | unset | Whether a run's declared user must be the user its caller's delegated token acts for (`required`, `observe`, `off`; see `user_binding`). Unset: `observe`. |

## `[limits]`

| Key | Type | Default | Description |
|---|---|---|---|
| `burst` | number | `1000.0` | Default per-tenant bucket size. |
| `heartbeat_ms` | integer | `5000` | How often replicas record their heartbeat for shared tenant limits. |
| `max_concurrent_dispatch` | integer | `256` | Default per-tenant governed effects in progress at once. |
| `max_in_flight` | integer | `4096` | Requests in progress across all tenants; beyond it the server answers 503. |
| `requests_per_second` | number | `500.0` | Default per-tenant request rate (token bucket refill), shared across replicas. |
| `tenants` | array of tables | `[]` | Per-tenant overrides of the defaults. |

### `[[limits.tenants]]`

| Key | Type | Default | Description |
|---|---|---|---|
| `burst` | number | unset | This tenant's bucket size; unset uses the default. |
| `max_concurrent_dispatch` | integer | unset | This tenant's concurrent effects; unset uses the default. |
| `requests_per_second` | number | unset | This tenant's request rate; unset uses the default. |
| `tenant_id` | string | required | The tenant these limits apply to. |

## `[[notifications]]`

| Key | Type | Default | Description |
|---|---|---|---|
| `id` | string | required | Webhook id, which guarantees name in `owner_route` and metrics label. |
| `link_template` | string | unset | Link to the decision, with `{escalation_id}`, `{run_id}` and `{tenant_id}` replaced (for example your Tower URL). |
| `max_attempts` | integer | `12` | Attempts per event before it is given up (logged and counted). |
| `secret_env` | string | required | Environment variable holding the signing secret (at least 32 bytes). |
| `url` | string | required | HTTPS endpoint (HTTP only in development). |

## `[[oidc]]`

| Key | Type | Default | Description |
|---|---|---|---|
| `agent_claim` | string | unset | Claim naming the agent the token is issued for (for example `sub` of a SPIFFE JWT-SVID, or `azp`), checked against the run's declared agent at admission. |
| `agents` | table of any | see below | Maps an `agent_claim` value to the agent ids it may run as. Empty: the claim value itself is the agent id. |
| `algorithms` | array of string | `["RS256","ES256"]` | Accepted signature algorithms (asymmetric only). |
| `audience` | string | required | Required `aud` value. |
| `delegation` | table | unset | Accept RFC 8693 delegated tokens: the caller is the actor, acting for a user. |
| `issuer` | string | required | Exact `iss` value. |
| `jwks_url` | string | unset | HTTPS URL of the issuer's JWKS (HTTP is allowed only in development mode). Unset: discovered from the issuer's OpenID Provider Metadata. |
| `leeway_seconds` | integer | `60` | Clock skew tolerated on `exp` and `nbf`. |
| `refresh_seconds` | integer | `300` | How often the JWKS is fetched again. |
| `scope_claim` | string | `"scope"` | Space-separated string or array of scopes. |
| `tenant_claim` | string | `"tenant_id"` | Claim path naming the tenant: a string, an array or an object keyed by name (Keycloak's `organization`). It must name exactly one of `tenants`. |
| `tenant_map` | table of any | see below | Maps `tenant_claim` values (for example Keycloak organization aliases) to tenant ids. Empty: the claim value itself is the tenant id. |
| `tenants` | array of string | required | Tenants this issuer may assert. A token naming any other tenant is rejected. |

## `[[result_schemas]]`

One registered result schema.

| Key | Type | Default | Description |
|---|---|---|---|
| `path` | string | required | JSON Schema file the result must meet. |
| `ref` | string | required | The `output_schema_ref` delegations name. |

## `[retention]`

| Key | Type | Default | Description |
|---|---|---|---|
| `batch` | integer | `500` | Runs erased per sweep at most. |
| `run_content_days` | integer | unset | Erase a run's personal content this many days after admission; unset keeps it. |
| `sweep_interval_ms` | integer | `60000` | How often the erasure sweep runs. |

## `[server]`

| Key | Type | Default | Description |
|---|---|---|---|
| `allowed_origins` | array of string | `[]` | Browser origins, besides `public_url`'s, that may call the MCP endpoint. |
| `listen` | string | required | Socket address to listen on, such as `0.0.0.0:8080`. |
| `max_body_bytes` | integer | `4194304` | Largest request body accepted, in bytes. |
| `mode` | `"production"` \| `"development"` | `"production"` | `production` refuses development-only conveniences and warns about weak settings. |
| `public_url` | string | unset | The URL clients reach this server at, for OAuth protected resource metadata (see `protected_resource`). Unset: no metadata is published. |
| `request_timeout_ms` | integer | `15000` | Time a request may take before the server answers 504. |

## `[store]`


### `store` with `kind = "memory"`

| Key | Type | Default | Description |
|---|---|---|---|
| `kind` | `"memory"` | required |  |

### `store` with `kind = "postgres"`

| Key | Type | Default | Description |
|---|---|---|---|
| `kind` | `"postgres"` | required |  |
| `max_connections` | integer | `32` | PostgreSQL connection pool size. |
| `url_env` | string | required | Environment variable holding the connection URL. |

## `[support]`

| Key | Type | Default | Description |
|---|---|---|---|
| `controls` | array of string | required | Controls this deployment actually enforces through its integrated providers. Declaring a control here is a claim about the deployment, not a grant. |
| `implementation_id` | string | required | Implementation id published in the support declaration. |
| `implementation_version` | string | required | Implementation version published in the support declaration. |
| `profiles` | array of string | required | Conformance profiles this deployment claims. |
