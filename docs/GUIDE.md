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

### Executors and failover

Admission returns `executor_generation`. The executor driving the run sends it as the
`ContextOS-Executor-Generation` header on every effectful request (tool calls, input,
reconcile, close); without it the server answers `428`. If the executor dies, a
replacement reads `GET /v1/runs/{run_id}` and calls `POST /v1/runs/{run_id}/takeover`
with the `expected_generation` it observed. The run moves to a new generation through
the kernel's suspend and resume transitions, and the old executor's requests are
refused with `executor_stale` from then on.

The gateway re-checks ownership immediately before claiming an operation, so nothing
new starts under a stale generation once a takeover commits. An effect already in
flight at that moment is recorded as claimed in the operation ledger; the new executor
sees it and reconciles it rather than repeating it. Adapters forward the generation as
`X-ContextOS-Executor-Generation` so providers that support target-side fencing can
enforce it too.

### Decisions, evidence and audit export

Report a decision with `POST /v1/runs/{run_id}/decisions` (executor, fenced):
`decision_key`, `decision_version`, `status` (`DECIDED`, `DEFERRED`, `REJECTED`,
`ESCALATED`, `IN_FLIGHT`, `CLOSED`), optional `outcome`/`allowed_outcomes`/`outputs`/
`rationale`, and the `tool_calls` it relied on (`tool_call_id` and `operation_id`).
The gateway verifies each tool call against the run's operation ledgers
(`lineage_unverified` otherwise), takes policy decisions from the pins made at
admission and usage from the run's budget ledger, refuses `DECIDED`/`CLOSED` while the
compiled context's evidence gate for that decision is open (`evidence_gate_open`),
signs the record into the audit chain and returns it with a replay packet.

`GET /v1/runs/{run_id}/evidence` returns the run's admission, lifecycle state, budget
ledger with its compaction archives, and its decisions with replay packets.
`GET /v1/audit/entries?from=&limit=` pages the tenant's signed chain out for SIEM
ingestion; entries verify offline with the published keys.

### Completing and cancelling runs

- `POST /v1/runs/{run_id}/complete` (executor, fenced) succeeds only when no effect is
  unknown or partial, every delegated child is closed and nothing is in flight;
  otherwise `409` with `required_effect_unsatisfied`, `children_unsettled` or
  `effects_in_flight`.
- `POST /v1/runs/{run_id}/fail` (executor, fenced) marks the run failed.
- `POST /v1/runs/{run_id}/cancel` (scope `admit`, no generation needed) fences the
  executor, cancels and closes every child (settling its spend into the parent), and
  acknowledges once dispatch has stopped. If an effect is still in flight the run stays
  `cancel_requested` with `retry_cancel_after_dispatch_settles`; call it again.

A run with 128 unresolved effects pauses new dispatch until some are reconciled.

### Delegating to child runs (subagent lanes)

Admit a child with the usual `POST /v1/runs` body for the child, plus an
`AgentDelegationEnvelope` under `delegation`. The child's budget and deadline come
from the envelope (`sub_budget`, `expires_at`), not the request. The gateway refuses a
delegation whose capabilities, deadline or sub-budget exceed the parent, whose issuer
is not the parent's agent or whose subject is not the child's, or whose
`parent_claim_hash` is not the parent's `compiled_context_hash`. The sub-budget is
reserved from the parent before the child exists. The child's tool surface is narrowed
to the envelope's capabilities and classification ceiling, and `read_only` children
get no effectful capabilities at all.

Child actions are authorized like any other, against grants from your authority
broker: the broker must return a grant chain from the root mandate to the child's
agent, each grant narrowing its parent (`parent_grant_ref`), and must list the
gateway's principal among `trusted_observers` so the run links the gateway attests are
accepted. Brokers receive `root_run_id`, `parent_run_id`, `delegation_id` and
`ancestry` with each request.

Close a child with `POST /v1/runs/{child}/close` and `{"decision": "accept"}` (or
`"reject"`). Closing locks the child's remaining capacity so nothing more can be spent,
settles the child's usage into the parent and releases the rest. A child with
unresolved effects cannot close (`409`, `delegation_effects_unresolved`) until they are
reconciled.

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
- **Overload protection:** `[limits]` caps concurrent requests per instance
  (`max_in_flight`, default 4096; beyond it, `503` with `Retry-After`), request rate
  per tenant (`requests_per_second` / `burst`, default 500 / 1000; `429` with
  `Retry-After`) and governed effects in progress per tenant (`max_concurrent_dispatch`,
  default 256). `[[limits.tenants]]` overrides any of these for one tenant. Limits
  apply after authentication; health probes and metrics are exempt.
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
