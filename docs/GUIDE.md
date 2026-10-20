# Using the ContextOS runtime

## 1. Embed the kernel in your agent (no server)

The kernel is pure and deterministic, so it can run inside the agent process on the hot
path. Every binding exposes the same operations (see `crates/contextos-embed`).

Python (`bindings/python`, built with maturin):

```python
import contextos
compiled = contextos.compile(pack, request, run_context, {"evidence": evidence})
for gate in compiled["runtime_controls"]["evidence_gates"]:
    if not gate["commit_allowed"]:
        ...  # do not commit this decision; gather the unresolved evidence
decision = contextos.evaluate_authorization(authorization_input)
```

Node (`bindings/node`, N-API; async calls run on the libuv pool):

```js
import { kernel } from "@contextos/kernel";
const compiled = await kernel.call("compile", { pack, request, run_context });
```

Any WebAssembly host (`bindings/wasm`; the module imports nothing):

```js
const ctx = await load(await fs.readFile("contextos_wasm.wasm"));
const { action_digest } = ctx.call("digest_action_binding", binding);
```

Embedding gives you deterministic decisions. Durable effect safety — single dispatch,
reconciliation, conserved budgets, the audit chain — needs the stores, which the
gateway (in-process in Rust, or `contextosd`) provides.

## 2. Run `contextosd`

```sh
ctx hash-key            # paste a ≥32-character key; configure only the hash
contextosd --config deploy/contextosd.example.toml
```

Callers authenticate with a bearer token: an API key (configured only as its hash),
or a JWT from an OIDC issuer you configure:

```toml
[[oidc]]
issuer = "https://login.example.com/"        # exact iss
audience = "contextosd"                      # required aud
jwks_url = "https://login.example.com/.well-known/jwks.json"
tenants = ["tenant_acme_prod"]               # tenants this issuer may assert
tenant_claim = "tenant_id"                   # default
scope_claim = "scope"                        # default; string or array
algorithms = ["RS256", "ES256"]              # default; HS* and none are refused
```

Keys are fetched in the background (every `refresh_seconds`, and soon after an unknown
`kid`, at most once per 30 s); `/readyz` reports not ready until every issuer's keys
have loaded. Tokens need `kid`, `iss`, `aud`, `sub` and `exp`. Scopes recognized:
`compile`, `admit`, `dispatch`, `audit:read`.

| Route | Scope | Use |
|---|---|---|
| `POST /v1/compile` | `compile` | Compile a pinned pack |
| `POST /v1/runs` | `admit` | Admit a run: compile, negotiate, pin policy, open ledgers |
| `POST /v1/runs/{run_id}/tool-calls` | `dispatch` | Govern and dispatch one tool call |
| `POST /v1/contracts/negotiate` | `admit` | Check a contract against this deployment |
| `POST /v1/schemas/{schema}/validate` | any | Validate a payload against a published schema |
| `POST /v1/runs/{run_id}/operations/{operation_id}/input` | `dispatch` | Answer a tool's input request and continue |
| `POST /v1/runs/{run_id}/operations/{operation_id}/reconcile` | `reconcile` | Resolve an unknown effect |
| `GET /v1/audit/verify` | `audit:read` | Verify the tenant's signed audit chain |
| `GET /metrics`, `/healthz`, `/readyz` | – | Operations |

Tool-call results use `contextos.tool_result.v1`:

| `status` | Meaning | Caller action |
|---|---|---|
| `ok` / `completed` | effect confirmed (read-only / effectful) | continue |
| `paused` | approval pending, or effect outcome unknown | wait for approval or reconcile; never blind-retry |
| `blocked` | authority, policy, constraint or budget refused | do not retry unchanged |
| `rejected` | malformed, unpinned, unsurfaced or incompatible reuse | fix the call |
| `failed` | provider definitively did not apply the effect | may retry per the capability's recovery policy |

### Tools that ask for input

An MCP tool may answer `input_required` instead of running. The result is `paused` with
`provide_requested_input`, and `output.result.inputRequests` holds the questions. Answer
them by resending the *same* tool call with the answers:

```sh
curl -X POST …/v1/runs/$RUN/operations/$OP/input -d '{"tool_call": <the original call>,
  "input_responses": {"reason": {"action": "accept", "content": {"reason": "damaged"}}}}'
```

The continuation is a new attempt of the same operation and is governed again end to
end. Answers cannot change the action: a call with different arguments, destination or
amount is refused. Answers must match the requested keys and schema, each request can
be answered once, and form fields that look like secrets (passwords, PINs, codes) are
refused outright. Only form elicitation is supported. Each answered round uses one of
the capability's `recovery.max_attempts`, so a capability that may ask for input needs
`max_attempts` of at least rounds + 1 and a `retry_delays_seconds` entry of `0` per
round. The responder and a digest of the answers are audited, not the answers.

### Reconciling unknown effects

A `paused` result with `reconcile_effect_before_retry` means the effect may or may not
have happened (lost response, timeout, an effectful tool error, or an MCP task still
running). The operation's budget stays reserved and retries are refused until it is
resolved:

```sh
# Ask the provider (MCP tasks/get on the task handle the attempt returned)
curl -X POST …/v1/runs/$RUN/operations/$OP/reconcile -d '{"source":"provider"}'
# Or assert the outcome you verified, citing the evidence (recorded with your identity)
curl -X POST …/v1/runs/$RUN/operations/$OP/reconcile -d '{"source":"operator",
  "outcome":"not_applied","evidence_ref":{"artifact_type":"provider_ledger_extract",
  "artifact_id":"payments-2026-10-20","version":"1","sha256":"sha256:…"}}'
```

`status` is `resolved`, `pending` (still running), `no_change` (nothing unknown to
resolve; conflicting facts need escalation) or `rejected` with reasons such as
`reconcile_requires_operator`. A recorded fact cannot be overwritten by a later
contradicting assertion. Grant `reconcile` only to operators and automation that verify
outcomes at the provider.

## 3. Integrate your services

Dispatch needs three fact services you operate (see `crates/contextos-adapters/src/remote.rs`
for the request/response contracts and `examples/support-refund/dev_services.py` for a
minimal, development-only implementation):

- **Authority broker** — verifies the agent's mandate and returns grants plus verified,
  current, unrevoked observations for the exact binding.
- **Control plane** — attests that each required independent control (isolation, egress
  mediation, data-flow policy…) is active for this action digest and pinned policy.
- **Approval service** — opens requests bound to the action digest and returns verified
  decisions and approver entitlements.

Capabilities are admitted only from reviewed manifests (`ctx manifest <file>`); protocol
discovery is never permission. Adapters: MCP `2026-07-28` (stateless Streamable HTTP) or
HTTP/JSON, HTTPS only, no redirects, credentials from your broker.

## 4. Operate

- **Store:** PostgreSQL. Grant the runtime role `SELECT, INSERT, UPDATE` on
  `contextos_documents` and `SELECT, INSERT` only on `contextos_audit_log` (updates and
  deletes are also blocked by trigger).
- **Keys:** the audit signing seed comes from your KMS/HSM via environment. Rotate by
  adding the new public key to verifiers before switching writers.
- **Declare only what you enforce:** `[support].controls` is a claim that your providers
  enforce those controls. Runs that need more are refused at admission.
- **Traces:** set `OTEL_EXPORTER_OTLP_ENDPOINT` (and optionally `OTEL_SERVICE_NAME`,
  `OTEL_RESOURCE_ATTRIBUTES`, `OTEL_EXPORTER_OTLP_HEADERS`) to export spans over
  OTLP/HTTP. A caller's W3C `traceparent` becomes the parent of the request span, so
  each governed dispatch appears inside the agent's distributed trace. Build with
  `--no-default-features` to leave the exporter out entirely.
- **Metrics:** `contextos_http_requests_total`, `contextos_http_request_duration_ms`,
  `contextos_dispatch_outcomes_total{status}`. Logs are JSON with a `contextos.dispatch`
  span per tool call (run, operation, capability, digest, status, reasons).
- **Image:** `Dockerfile` builds a distroless, non-root image. Releases publish it to
  GHCR signed with cosign (keyless) and with build provenance; verify before deploying.
- **Kubernetes:** `deploy/helm/contextosd` (see its README).
