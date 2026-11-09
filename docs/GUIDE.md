# Using the ContextOS runtime

## 1. Embed the kernel in your agent (no server)

The kernel is pure and deterministic, so it can run inside the agent process on the hot
path. Every binding exposes the same operations (see `crates/contextos-embed`).

Python (`bindings/python`, built with maturin; see its
[README](../bindings/python/README.md) to install):

```python
import contextos
compiled = contextos.compile(pack=pack, request=request, run_context=run_context,
                             deps={"evidence": evidence})
for gate in compiled["runtime_controls"]["evidence_gates"]:
    if not gate["commit_allowed"]:
        ...  # do not commit this decision; gather the unresolved evidence
decision = contextos.evaluate_authorization(authorization_input)
```

Node (`bindings/node`, N-API; async calls run on the libuv pool). The kernel addon is
not published; build it from this repository (see `bindings/node/README.md`):

```js
import { kernel } from "./bindings/node/index.mjs";
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

## 2. Govern an existing Python agent over HTTP

`contextos.client` is a standard-library-only client for `contextosd` (put
`bindings/python` on `PYTHONPATH`; see its [README](../bindings/python/README.md)). It
holds the executor generation (which process currently owns the run) for you and turns
non-success results into exceptions, so agent code cannot mistake a pause or refusal
for a result. To try it locally, `./examples/dev-server.sh` starts a server and prints
its URL and token; `admission_body` below is a run like
[`run.json`](../examples/support-refund/requests/run.json):

```python
from contextos.client import Client, ToolBlocked, ToolPaused, governed_tool

client = Client("https://contextos.internal", token=os.environ["CONTEXTOS_TOKEN"])
run = client.admit(admission_body)

@governed_tool(run, "adp_payments.issue_refund", approval_mode="destructive",
               idempotency_key=lambda order_id, **_: f"refund:{order_id}")
def issue_refund(order_id: str, customer_id: str, amount_minor: int): ...

try:
    issue_refund("ord_881", "cus_77", 1200)          # dispatched by the gateway
except ToolPaused as paused:                          # approval, input or unknown outcome
    ...                                               # wait, answer or reconcile; never blind-retry
except ToolBlocked as blocked:
    ...                                               # authority, policy or budget refused it
run.record_decision("support.refund.execute", "DECIDED", outcome="refund_issued",
                    tool_calls=[{"tool_call_id": "...", "operation_id": "refund:ord_881"}])
run.complete()
```

Register `governed_tool` functions as your framework's tools (LangGraph, OpenAI Agents
SDK, CrewAI and others accept plain Python callables); the decorated body never runs
locally. [integrations/](integrations/README.md) has a guide and a runnable example for
each popular framework, covering tools, model-call budgets, pauses and approvals,
checkpoints, subagents and decisions. After a crash, `client.attach(...).take_over()` resumes the run and fences the
old process.

For asyncio agents, `contextos.aio` has the same client as coroutines (`AsyncClient`,
`AsyncRun`; `governed_tool` on an `AsyncRun` makes async tools). It stays
standard-library only by running each request in a worker thread, so the event loop
never blocks on the network.

The same client exists for Node.js and other `fetch` runtimes, with TypeScript types:

```ts
import { Client, ToolPaused, ToolBlocked, governedTool } from "contextos-client";

const client = new Client("https://contextos.internal", { token: process.env.CONTEXTOS_TOKEN! });
const run = await client.admit(admissionBody);
const issueRefund = governedTool(run, "adp_payments.issue_refund", {
  approvalMode: "destructive", idempotencyKey: (a) => `refund:${a.order_id}`,
});
await issueRefund({ order_id: "ord_881", customer_id: "cus_77", amount_minor: 1200 });
```

### Or connect any MCP host

Every admitted run is also an MCP server at `POST /v1/runs/{run_id}/mcp` (Streamable
HTTP, JSON responses; the stateless `2026-07-28` profile, with `initialize` answered
for older hosts). Point an MCP-capable agent host at it with the caller's token and
the executor generation as headers, for example:

```json
{
  "mcpServers": {
    "contextos": {
      "type": "http",
      "url": "https://contextos.internal/v1/runs/run_123/mcp",
      "headers": {
        "Authorization": "Bearer ${CONTEXTOS_TOKEN}",
        "ContextOS-Executor-Generation": "2"
      }
    }
  }
}
```

Hosts that only start local (stdio) servers use the bridge built into `contextosd`,
which forwards each message to the run's endpoint and decides nothing itself:

```json
{
  "mcpServers": {
    "contextos": {
      "command": "contextosd",
      "args": ["--mcp-stdio", "https://contextos.internal/v1/runs/run_123/mcp"],
      "env": {"CONTEXTOS_TOKEN": "…", "CONTEXTOS_EXECUTOR_GENERATION": "2"}
    }
  }
}
```

The endpoint checks the transport before reading a message. A request carrying a
browser `Origin` is refused (`403 origin_not_allowed`) unless the origin is
`[server] public_url`'s or listed in `[server] allowed_origins`, so a web page cannot
reach the server through DNS rebinding. Hosts and SDKs send no `Origin` and are not
affected. An unsupported `MCP-Protocol-Version` header is refused with
`400 protocol_version_unsupported`, and responses echo the version the request used.
A request without an `id` is refused with `400`; only `notifications/*` may omit it.

Hosts that implement MCP authorization can discover where to get that token. Set
`[server] public_url` to the URL clients reach the server at. A `401` then names the
run's OAuth protected resource metadata (RFC 9728) in `WWW-Authenticate`
(`resource_metadata="…/.well-known/oauth-protected-resource/v1/runs/{run_id}/mcp"`).
The metadata lists your OIDC issuers as `authorization_servers` and `dispatch` as the
scope, and a `403` for a missing scope says which one (`error="insufficient_scope"`).
Set the issuer's `audience` to the public URL so tokens are bound to this server
(RFC 8707). The caller's token never reaches providers: adapters get their own
credentials from the broker.

The host sees only the run's surfaced capabilities, with their reviewed input schemas
and risk annotations, under tool names model APIs accept (`[A-Za-z0-9_-]{1,64}`:
`adp_payments.issue_refund` is listed as `adp_payments_issue_refund`, with the
capability id in `title` and `_meta["io.contextos/capabilityId"]`; a call may name
either). Names that would collide, or run past 64 characters, end in a short digest of
the capability id, so each names exactly one capability. Each `tools/call` runs the full governed pipeline. Refusals come
back as tool errors whose `structuredContent` carries the status and reason codes, so
the model sees that the action did not happen. Operation identity comes from
`_meta["io.contextos/idempotencyKey"]` when given; otherwise effectful calls derive it
from the capability and arguments, so a host that retries a call it thinks failed
cannot apply the effect twice. The same derivation means two calls in one run with
identical capability and arguments are one operation: once the first applied, the
second is not sent and comes back `paused` with `retry_unsafe` (while the first is in
flight, `operation_in_flight`). When equal calls are meant as separate
effects (two equal top-ups), give each its own `io.contextos/idempotencyKey` and mark
the capability `"repeatable": true` (see "Repeated effects"). Cited evidence goes in `_meta["io.contextos/evidenceRefs"]`,
and the host's own call id, if it has one, in `_meta["io.contextos/toolCallId"]`. Every
result names the call and its operation in `_meta` (`io.contextos/toolCallId`,
`io.contextos/operationId`), which is what a DecisionRecord cites. Keep one effect on
one route: a call keyed explicitly and a call keyed by derivation are different
operations, but the gateway sends only one of them; it refuses the other
(`effect_repeated`, see "Repeated effects" below), even when the two race.
A tool's `input_required` is passed through with `requestState`, and the host's retry
with `inputResponses` continues the same operation.

Give capability manifests an `input_schema` (JSON Schema) and `description`: the
schema is shown to hosts and enforced on every call (`arguments_invalid`), and
violations report argument paths only, never values. An `output_schema` is enforced on
what the tool returns: a confirmed effect whose output does not conform is still
recorded and settled (it happened), but the output is withheld from the agent, the
result carries `output_schema_violation` and the obligation `verify_effect_out_of_band`,
and the violation is audited (paths only). With an output schema, no other raw output
reaches the agent either: a tool's request for input is reduced to its
`inputRequests`, and the output of a failed or unresolved call is withheld.

## 3. Run `contextosd`

The HTTP API is described by OpenAPI 3.1 in `openapi/contextosd.v1.json`, also served
at `GET /v1/openapi.json`. Request and record bodies reference the normative ContextOS
JSON Schemas by `$id`, so generated clients in any language validate against the spec
itself. Tests keep the document and the router in step and validate live request
and response bodies against it.

```sh
ctx hash-key            # paste a ≥32-character key; configure only the hash
contextosd --check-config deploy/contextosd.example.toml
contextosd --migrate deploy/contextosd.example.toml    # PostgreSQL schema, as its owner
contextosd --config deploy/contextosd.example.toml
```

Every configuration key, with its type, default and meaning, is in
[CONFIG.md](CONFIG.md), generated from the server's own types. The same schema is
`deploy/contextosd-config.schema.json` (or `contextosd --config-schema`); TOML editors
that read `#:schema` comments, as the example file has, complete and check keys with
it. Every metric `/metrics` exports is listed in [METRICS.md](METRICS.md).

To try a configuration on your machine first, `./examples/dev-server.sh` runs the
quickstart's development configuration. Moving that example to production mode
switches on defaults that its development files do not meet; each refusal names its
setting:

| Refusal | Why | Meet it, or opt out |
|---|---|---|
| `--check-config`: an effectful MCP capability needs `recovery.completion` | a finished MCP result must say which reported state settles it | add `recovery.completion` to the manifest, or `[guards] require_completion_contracts = false` |
| `422 memory_unverified` | recalled memory must be verified against promoted state | `[providers.memory]`, or `[guards] trust_supplied_memory = true` |
| `422 release_ref_missing` | each run pins the model and evaluators that produce its decisions | pin `model_profile` and `evaluator_suite` in the contract's `release_refs`, or `[guards] required_release_refs = []` |
| `422 contract_rejected` (`required_control_unsupported`) | the contract requires controls the deployment does not declare | declare them in `[support] controls`, only if your providers enforce them |
| `endpoint must use https` | production refuses plaintext providers and adapters | serve them over HTTPS |

`--check-config` runs the validation startup performs and exits: the configuration,
its packs and pinned capability manifests, the dispatch gateway, that the signing seed
or KMS token and the PostgreSQL URL variables are set, and that the listen address is
free (it binds it once). It does not contact the key service or connect to the store.
`examples/doctor.sh --config <path>` runs it after checking that this system can run
the binaries at all (platform, glibc, Python for the examples), and names the
alternative when it cannot.

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

Without `jwks_url`, the key set's URL is discovered from the issuer's OpenID Provider
Metadata (`<issuer>/.well-known/openid-configuration`, whose `issuer` must match).
Claims are named by path: a key the token holds (including namespaced names such as
`https://example.com/tenant`), else a dot path (`realm_access.roles`), or a JSON
Pointer (`/resource_access/api.v2/roles`). `tenant_claim` may hold a string, a list or
an object keyed by name (Keycloak's `organization`); after `[oidc.tenant_map]` (claim
value to tenant id) it must name exactly one of `tenants`.
Keys are fetched in the background (every `refresh_seconds`, and soon after an unknown
`kid`, at most once per 30 s); `/readyz` reports not ready until every issuer's keys
have loaded. Tokens need `kid`, `iss`, `aud`, `sub` and `exp`. Scopes recognized:
`compile`, `admit`, `dispatch`, `audit:read`.

#### Bind runs to the agent the credential is issued for

A token proves the principal; the agent a run declares (`run_context.agent.agent_id`)
is named by the caller. Agent binding checks the declared agent against the agents the
credential is issued for:

```toml
[[oidc]]
# …
agent_claim = "sub"          # e.g. a SPIFFE JWT-SVID: agent ids are SPIFFE IDs
# or map client ids to agent ids:
# agent_claim = "azp"
# [oidc.agents]
# support-client = ["agt_support"]

[[api_keys]]
# …
agent_ids = ["agt_support"]  # a key issued to one agent service

[guards]
agent_binding = "required"   # or "observe", "off"
```

`required` refuses an unbound agent (`403 agent_not_bound`); it is the default when
`[support] profiles` includes `contextos.enterprise`, and startup then refuses an OIDC
issuer without `agent_claim` or an `admit` key without `agent_ids`. `observe`, the
default otherwise, admits the run, counts it in
`contextos_agent_binding_mismatches_total{mode}` and records `bound: false`: turn it on,
watch the counter reach zero, then switch to `required`. Every `run_admitted` entry
records `agent_binding` (`mode`, `bound`, `source`). Delegated runs inherit their
parent's binding (`bound: "inherited"`); their agent is the one the parent's
delegation names, and `named_by_credential` says whether the admitting credential
names it too. SPIRE's OIDC discovery provider publishes the
JWKS for JWT-SVIDs, so they need no other integration. X.509 SVIDs can restrict who
may connect at all (`[server.tls] client_ca_path`, under Operate), but they do not
name the agent: binding still comes from the token.

#### Bind runs to the user the agent acts for

A run's `run_context.user` (who the agent acts for, and in which role) is also named by
the caller, and pack rules are keyed by `user.role`. An identity provider that issues
delegated tokens (RFC 8693) can vouch for it: Keycloak's token exchange delegation
gives the agent a token whose `sub` is the user and whose `act` names the agent
([Keycloak guide](integrations/keycloak.md)).

```toml
[[oidc]]
# …
agent_claim = "azp"
[oidc.delegation]
actor_claim = "act"                         # default
actor_agent_claim = "client_id"             # the agent: act.client_id, mapped through [oidc.agents]
user_roles_claim = "realm_access.roles"     # optional: the roles the user holds
max_chain = 4                               # default: actors one token may chain (1 to 16)

[guards]
user_binding = "required"    # or "observe" (default), "off"
```

A token carrying the actor claim authenticates the actor (`act.sub`, the caller and
`admitted_by`) acting for the user (`sub`); a token without it is an ordinary token and
names no user; an actor claim without a `sub`, or naming the subject itself, rejects
the token. At admission, `required` refuses (`403 user_not_bound`, detail `no_user`,
`other_user` or `role_not_held`) a run whose credential names no user, whose
`user.user_id` is not that user, or whose `user.role` the user does not hold (when
`user_roles_claim` is set). Startup then refuses an issuer without `[oidc.delegation]`
and an API key with `admit`. `observe` admits, counts
`contextos_user_binding_mismatches_total{reason}` and records `bound: false`. Every
`run_admitted` records `user_binding` (`mode`, `bound`, `reason`, `source`), never the
user id. Delegated runs inherit their parent's binding. No profile turns `required`
on: agents that act for no user are legitimate, so turn it on for deployments whose
agents always act for a signed-in user.

When work passes through several agents, each token exchange nests the previous actor
(`act: {sub: "agent-b", act: {sub: "assistant-a"}}`: agent-b acts now, for
assistant-a, which acted for the user). The whole chain is read, current actor first,
and kept on the run; a delegated child run inherits its parent's. A chain longer than
`max_chain`, naming an actor twice, or naming the user as an actor rejects the token.
`run_admitted` records `delegation` with the chain's `depth` and `chain_digest`
(SHA-256 over the user and actors in order), never the identities. The kill switch
(section 8) can then stop the user, one exact chain, or any actor on it.

#### Hold runs to the intents their pack governs

A rule scoped to an intent (`applies_to.intent`) is evaluated only for runs that
declare that intent, and the caller declares it. A pack whose refund rules are scoped
to `support.refund` restricts nothing for a run that declares `general.query`, yet its
refund tool is still surfaced. So admission checks the intent the compiler resolved
against the intents the pack's rules name:

```toml
[guards]
pack_intents = "required"    # or "observe", "off"
```

`required` refuses any other intent (`422 intent_not_governed`); it is the default
with the `contextos.enterprise` profile. `observe`, the default otherwise, admits the
run, counts it in `contextos_pack_intent_mismatches_total{mode}` and records
`pack_intent: {"mode", "governed": false}` in `run_admitted`. A pack with no
intent-scoped rules governs every intent alike. A pack that serves more than one intent
should give each one its own rules: a run that declares one intent is not held to
another's, and `--check-config` warns about every pack that governs several intents
and scopes a restrictive rule to any of them.

| Route | Scope | Use |
|---|---|---|
| `POST /v1/compile` | `compile` | Compile a pinned pack |
| `POST /v1/runs` | `admit` | Admit a run: compile, negotiate, pin policy, open ledgers |
| `POST /v1/runs/{run_id}/tool-calls` | `dispatch` | Govern and dispatch one tool call |
| `POST /v1/contracts/negotiate` | `admit` | Check a contract against this deployment |
| `POST /v1/schemas/{schema}/validate` | any | Validate a payload against a published schema |
| `POST /v1/runs/{run_id}/operations/{operation_id}/input` | `dispatch` | Answer a tool's input request and continue |
| `POST /v1/runs/{run_id}/operations/{operation_id}/reconcile` | `reconcile` | Resolve an unknown effect |
| `POST /v1/runs/{run_id}/operations/{operation_id}/attest-absence` | `attest` | Release a started effect with no fact, on evidence it did not apply |
| `POST /v1/runs/{run_id}/operations/{operation_id}/compensate` | `dispatch` | Undo an applied effect with its declared compensation |
| `POST /v1/runs/{run_id}/compensate` | `dispatch` | Compensate the run's effects newest first (saga) |
| `POST /v1/runs/{run_id}/operations/{operation_id}/outcome` | `outcome:report` | A witness's signed observation that an applied effect reached its postcondition |
| `POST /v1/guarantees/{id}/imports` | `exposure:import` | Import exposure created outside ContextOS into a shared guarantee (one way) |
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

### Check a call before making it

`POST /v1/runs/{run_id}/tool-calls/check` takes the same tool call envelope as
`/tool-calls` and the `dispatch` scope, and answers what dispatch would do with it,
without effect. The call goes through the same pipeline on the same facts: surfacing,
binding, authority, pinned policy, constraints, approvals, the kill switch, the
execution boundary, the loop and repeated-effect guards and data flow. It stops before
approval redemption, budget reservation and the operation claim. Nothing is requested
(no approval request, no escalation), redeemed, reserved or sent:

```json
{"check": {"status": "approval_required", "capability_id": "adp_payments.issue_refund",
  "operation_id": "refund:ord_881", "action_digest": "sha256:…", "reason_codes": [],
  "obligations": ["await_approval"], "message": "Approval is required before this effect.",
  "operation_exists": false, "not_evaluated": ["budget_reservation", "operation_claim"],
  "audit_sequence": 41}}
```

`status` is `allowed`, `approval_required`, `escalation_required`, `blocked` or
`rejected`, with the reason codes and obligations dispatch would return. Use it to
offer only the actions an agent or a person may take, to let a planner choose
arguments a policy accepts, or to debug a refusal without causing an effect. Clients
expose it as `run.check_tool_call(...)` (Python) and `run.checkToolCall(...)` (Node).

- **Advisory.** The facts a check reads can change before the call: an approval can
  expire, an operator can revoke the capability. Budget, shared-guarantee capacity
  (`shared_guarantee_capacity` appears in `not_evaluated` for guaranteed capabilities)
  and the operation claim are decided only at dispatch, atomically. A check never
  authorizes anything; only dispatch does.
- **Audited.** Each check appends one `tool_call_check` entry (capability, operation,
  action digest, status, reason codes), so a principal probing which arguments a policy
  allows leaves a record. The intermediate entries a dispatch writes (the authorization
  decision, refusals) are not written for a check.
- **Retries.** `operation_exists: true` means the run already has an operation with
  this id, so dispatch treats the call as that operation's retry (duplicate and
  reconciliation rules apply), not as a new effect.
- **Fencing.** The executor generation header is optional, since a check has no
  effect; when it is sent, a stale executor's check is refused like its dispatch.

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

The gate checks what the run request supplied, not the evidence itself: a requirement
is met by a truthy key in the request's `context` or by an evidence entry labelled
`verified` and `current` by whoever admitted the run. Build the context and evidence in
a service you trust (not the agent), or treat the gate as a check on the agent's
reasoning rather than a proof.

Strict evidence closes the first of those paths:

```toml
[guards]
evidence = "strict"    # or "caller"
```

`strict` refuses a run whose `request.input.context` has a key naming any
`required_evidence` item of a DecisionSpec in its pack, whatever the value
(`422 evidence_in_request_context`, with the names under `detail.requirements`). Supply
those facts as evidence entries instead. The `contextos.enterprise` profile requires
`strict`, and it is the default there; `caller`, the default otherwise, keeps the
compiler's behaviour, including the caller's labels on evidence entries.

Under `strict` those labels are not the caller's either. Each entry carries an
`attestation`: a compact JWS from a configured issuer whose payload is
`{iss, sub, satisfies, content_hash, observed_at, valid_until, source_version}`, with
`content_hash` the `sha256:` hash of the entry's `content`.

```toml
[[evidence_issuers]]
issuer = "https://kyc.example.com"         # exact iss
tenants = ["tenant_acme_prod"]
satisfies = ["identity_verified"]          # the gated names it may vouch for
max_validity_seconds = 86400               # the longest valid_until - observed_at it may claim
algorithm = "EdDSA"                        # asymmetric only
jwks = '''{"keys": [{"kty": "OKP", "crv": "Ed25519", "kid": "k1", "x": "…"}]}'''
```

Before compiling, contextosd verifies each entry and sets the labels the compiler
reads. `integrity` is `verified` only when the signature is the issuer's, the issuer
serves the run's tenant, every name the entry `satisfies` is signed and one the issuer
may satisfy, and the content matches its hash. `freshness` is `current` only for a
verified entry with `observed_at <= now < valid_until` within the issuer's maximum
validity, `stale` after `valid_until`, `unknown` otherwise. The entry keeps the signed
times and a `verification` record (`evaluated_at`, `issuer`, `subject`,
`source_version`, the labels and `reasons` such as `expired`, `signature_invalid` or
`content_mismatch`). The replay case stores the relabelled entries, so a replay a day
later reaches the same decision without consulting the clock.

An authentic attestation is not necessarily about this run: a current identity check
for customer A says nothing about a refund to customer B. Bind each requirement to the
subject it concerns, read from the run's own request or run context:

```toml
[[evidence_subjects]]
requirement = "identity_verified"
from = "/request/input/context/customer_id"   # JSON Pointer into {request, run_context}
prefix = "customer:"                           # attestations name "customer:<id>"
canonicalizer = "ascii_casefold"               # or "exact" (default)

[[evidence_subjects]]
requirement = "order_eligible"
from = "/request/input/context/order_id"
prefix = "order:"
```

An entry whose attestation `sub` is missing, or differs from the run's value (after
the prefix and canonicalizer), no longer satisfies that requirement; so does any entry
when the run has no value at `from`. Other requirements the entry satisfies are
unaffected. `verification.subjects` records each check (`bound`,
`evidence_subject_mismatch`, `evidence_subject_missing`). With `from =
"/run_context/user/user_id"` and user binding (`[guards] user_binding = "required"`),
the subject is the user the identity provider says the run acts for. The request's
values are the caller's statement of what the run is about; that the agent then acts
on the same customer or order is what a task authorization's `resource_ids` and
`destination_ids` enforce.

`--check-config` warns when strict evidence has no issuers (no entry can satisfy a
gate), names every gated requirement without an `[[evidence_subjects]]` binding (any
authentic, current attestation satisfies it, whatever it is about), and names every
pack rule that reads a gated name from `request.context`, since strict evidence
refuses that context and the rule can never match.

`GET /v1/runs/{run_id}/evidence` returns the run's admission, lifecycle state, budget
ledger with its compaction archives, and its decisions with replay packets.
`GET /v1/audit/entries?from=&limit=` pages the tenant's signed chain out for SIEM
ingestion; entries verify offline with the published keys.

### Deliver the audit chain to a SIEM, masked

Rather than polling, configure audit sinks: the leader replica delivers every
tenant's chain in order, in signed batches, and masks the payload fields you name.

```toml
[[audit_sinks]]
id = "siem"
url = "https://siem.example.com/contextos"
secret_env = "CONTEXTOS_SIEM_SECRET"      # signs each request, as notifications are
mask = ["email", "/arguments/*/account_number"]
mask_key_env = "CONTEXTOS_SIEM_MASK_KEY"  # at least 32 bytes; required with mask
# kinds = ["authorization_decision", "dispatch_completed"]   # default: every kind
# batch = 100                                                  # 1..=500
# start = "head"                                               # default: "genesis"
```

Each request is `{"sink", "tenant_id", "from_sequence", "to_sequence", "entries"}`
with a `ContextOS-Signature` header (see escalation notifications). A sink never skips
an entry: a refused or failed batch is sent again, with backoff up to five minutes,
before anything later, and its cursor moves only past accepted entries. Delivery is at
least once, so drop duplicates by `(tenant_id, sequence)`. `kinds` filters what is sent;
the cursor still passes the rest. `contextos_audit_sink_batches_total{sink, outcome}`
counts batches.

`mask` names payload fields: an entry starting with `/` is a JSON Pointer where `*`
matches any member or index; any other entry is a member name masked wherever it
occurs. A masked value becomes `masked:hmac-sha256:<hex>`, an HMAC of its canonical JSON
under the sink's mask key: equal values give equal tokens, so the SIEM can still
correlate one customer across entries, and without the key a token cannot be tested
against guesses. A masked entry says so in `masked: {scheme, paths}`.

Masking keeps the chain verifiable. An entry's record hash covers its payload's digest,
not the payload, so a masked copy still proves its place in the chain and its
signature. `ctx audit-verify` checks every spine and every unmasked payload, and lists
the masked entries under `payload_unverified_sequences`: their payloads are the sink's
masked copy, not evidence of what was recorded. To prove a masked payload, fetch the
entry from `GET /v1/audit/entries`.

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

### Bind the run to what the principal asked

Broker grants say what an agent *may* do. They don't say what its principal asked for
in this run. Pack rules that read `request.context` see what the request *stated*, not
the arguments the agent later sends. Agents routinely go beyond the request without
any attack: [AuthorizationBench](https://arxiv.org/abs/2610.27548) measured this in
19% of trajectories across current models and harnesses, independent of reasoning
effort. Agents that asked the user often asked only after acting.

Admit the run with a `task_authorization`. It holds `AuthorityGrant` scopes describing
what was asked, fixed before the agent acts:

```json
"task_authorization": {
  "issued_by": {"principal_id": "usr_771", "principal_type": "person",
                "trust_domain": "contextos.dev", "tenant_id": "tenant_acme_prod"},
  "out_of_scope": "deny",
  "scopes": [{"root_run_id": "run_demo_1", "purpose_ids": ["support.refund"],
    "capability_ids": ["adp_payments.issue_refund"], "resource_ids": ["ord_881"],
    "destination_ids": ["cus_77"], "classification_labels": ["CONFIDENTIAL"],
    "argument_constraints": [], "amount_ceiling": {"minor_units": 120000, "currency": "INR"}}]
}
```

Every effect must then fall inside one of the scopes, checked on the actual action
binding with the same rules as broker grants.

- **Outside the scopes:** the action is refused (`outside_task_authorization` plus the
  dimension, such as `task_scope_amount` or `task_scope_resource`). With
  `"out_of_scope": "ask"`, it instead pauses for an exact approval of that action
  (obligations `await_approval` and `confirm_with_principal`), so the principal is
  asked *before* it happens. The clients surface that pause as an approval, so each
  framework's human-in-the-loop path handles it.
- **Read-only capabilities** need no scope unless `"read_only": "scoped"`.
- **It only narrows.** A task authorization never widens what the broker grants, so
  whoever supplies it needs no extra trust. Derive it from the principal's confirmed
  instruction, and cite that confirmation in `confirmation_ref`.
- **What it is bound to:** every authorization decision composes a `task_authorization`
  guardrail outcome, and action bindings, approvals and control attestations name its
  pinned reference (`policy_refs`). `run_admitted` records the references.
- **Delegated runs** keep their parent's task authorizations and may only add narrower
  ones.

**Limits on the task as a whole.** Scopes bound each action; a scope with an INR 1200
ceiling still admits a refund of 1100 followed by one of 1200. When the principal
asked for a total ("refund up to INR 1200"), or for a number of actions ("send one
reply"), add `limits`:

```json
"limits": {"max_effects": 1, "amount_total": {"minor_units": 120000, "currency": "INR"}}
```

- **What counts:** every effect of the run that issued the task authorization and of
  the runs delegated from it, inside the scopes or approved outside them. Reads are not
  counted. An effect in another currency than `amount_total` exceeds it. Amounts and
  resources are read through the capability's `amount` and `resource_pointers`: a
  capability that declares no amount passes every ceiling and total, and one with no
  resource pointers passes every resource list. `--check-config` warns about each
  effectful capability missing either.
- **When it is checked:** at authorization (an effect past a limit is outside the task:
  `task_scope_extent`, denied or, with `ask`, waiting for an exact approval), and again
  when the effect is charged, after its operation is claimed and before it is sent. The
  charge is a compare-and-swap, so of parallel effects racing for the last of a limit
  only one is sent. An approved effect is charged even past the limit.
- **When it is returned:** only when the provider definitively did not apply the effect.
  An unknown or partial outcome keeps its charge, even if reconciliation later finds it
  was not applied. A retry of the same operation is not charged twice.
- **Corrections:** lowering a limit narrows the authorization; raising or dropping one
  widens it. What the task already used carries over.

**Corrections mid-run.** When the principal corrects the task (another recipient, a
lower amount, a goal that changed), replace the run's own task authorization with
`PUT /v1/runs/{run_id}/task-authorization`, sending
`{"expected_revision": n, "task_authorization": {…}}` (0 as admitted). The response
says whether it `narrowed` or `widened` and gives the new revision.

- **Narrowing** is open to the executor's own key (`dispatch`): an agent may always
  restrict itself. Narrowing means every scope narrows a current one, reads are no
  less scoped, `deny` is not replaced by `ask`, and every limit is kept and no higher.
  A scope without `amount_ceiling` authorizes no amount, so adding a ceiling to it
  widens.
- **Widening** needs a key with the `authorize` scope and neither `admit` nor
  `dispatch`, so whoever runs the task cannot enlarge it. It also needs the
  principal's `confirmation_ref` and the same `issued_by`. Give `authorize` to the
  service that talks to the principal (your app backend), never to the agent's
  orchestrator. The configuration refuses a principal holding `authorize` together
  with `admit` or `dispatch`.
- **Old approvals and claims stop applying.** The task reference is part of every
  action digest, so an approval given under the previous authorization (say, for
  the old recipient) no longer matches. An operation claimed under it cannot be
  retried as the same operation; reconcile it instead.
- **Who issued it is fixed.** An amendment that changes `issued_by` or
  `confirmation_ref` counts as widening, however narrow its scopes, so whoever runs
  the task cannot rewrite the record of who authorized it.
- **What is recorded:** each amendment is audited as `task_authorization_amended`,
  with the old and new references, the change, the amending principal and the
  confirmation. The record is appended before the amendment takes effect, so none
  goes live unrecorded; if the commit then fails, a best-effort
  `task_authorization_amendment_aborted` follows, and the run's admission (its
  revision and the referenced digest) is the authority on what applies. A delegated run's inherited authorizations never change; it may only
  amend its own.

**Measuring it.** Proposals outside the task show up in
`contextos_dispatch_refusals_total{reason="outside_task_authorization"}`, broken down
by `task_scope_*` (`task_scope_extent` when the task's limits are reached). Asks that a principal later approved are your over-asking (the
"incorrect denials" of an adoption trial). Corrections are counted in
`contextos_task_authorization_amendments_total{change}`.

`[guards] require_task_authorization = true` refuses runs that can apply effects
without one (`task_authorization_required`). The Python and Node clients build the
shape with `task_authorization(...)`/`task_scope(...)` (`taskAuthorization`/`taskScope`).

### Gate effects on what the agent has read

Text an agent reads can steer it: a support ticket, a web page or an email can carry
instructions. Nothing screens that reliably, so `[guards.information_flow]` does not
judge content. It tracks what each run's agent has received and decides what the run
may do next, before any provider is called.

Each run carries two labels that only rise:

- **integrity**: `trusted` until the agent receives output from a capability whose
  manifest does not declare `"output_integrity": "trusted"`. Undeclared output is
  untrusted.
- **classification**: the most sensitive `output_classification` the agent has
  received (`PUBLIC` < `INTERNAL` < `CONFIDENTIAL` < `RESTRICTED`; default
  `INTERNAL`).

Label capabilities in their manifests:

```json
"flow": {"output_integrity": "trusted", "output_classification": "CONFIDENTIAL", "egress_ceiling": "INTERNAL"}
```

Declare `trusted` only for output your own systems produce (a ledger balance, an order
status). Never declare it for free text that customers, the web or email could have
written. `egress_ceiling` is the most sensitive data the capability may carry out when
it `sends_data` or names recipients (`destination_pointers`).

```toml
[guards.information_flow]
mode = "enforce"             # or "observe": audit only
untrusted_effects = "ask"    # an effect after untrusted input: allow | ask | deny
classified_egress = "deny"   # data above a sink's egress_ceiling: allow | ask | deny
rule_of_two = true           # untrusted + CONFIDENTIAL + egress/external effect: ask at least
initial_integrity = "trusted"
initial_classification = "PUBLIC"
```

The guard composes a guardrail outcome (`rule_id: information_flow`) with the run's
other policy outcomes, so `ask` is an approval of the exact action digest, and `deny`
is a denial. Reason codes say which rule matched: `flow_untrusted_effect`,
`flow_classified_egress`, `flow_rule_of_two`. Every match is audited
(`information_flow_decision`) with the run's labels, never the content. Use `observe`
first to see how often each rule would match before enforcing it.

- Read-only calls stay allowed in an untrusted run unless they send data out. A search
  whose query leaves the deployment counts as egress.
- A delegated child starts with its parent's labels. When it closes, its labels flow
  back into the parent, except when the parent rejects the output of an
  `isolate_until_accepted` child.
- Each run pins the runtime guards' policy it was admitted under (`guard_policy_ref`,
  which also covers the action monitor), and every decision cites it. A run admitted
  while no runtime guard was on cannot cite it, so a call the guard would not allow is
  refused (`flow_policy_unpinned`) rather than approved.
- Labels are per run, not per value. The guard cannot tell which argument came from
  which output, so it errs towards asking. Labels never fall within a run, so start a
  new run for work that must not inherit what an earlier step read.
- At startup, contextosd lists the capabilities that declare no `flow` labels.

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

Register the schemas delegations name in `scope.output_schema_ref`:

```toml
[[result_schemas]]
ref = "schema://orders/refund-evidence.v1"
path = "schemas/refund-evidence.v1.json"
```

A child whose envelope names a registered schema can then be accepted only if it
recorded at least one decision and every decision's `outputs` conform to it
(`child_output_invalid` otherwise, checked again once the child's capacity is locked);
the parent can still reject it. Once any schema is registered, and always in
production mode, a delegation naming an unregistered one is refused
(`output_schema_unregistered`). A schema that does not
compile stops startup.

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
have happened (lost response, timeout, an effectful tool error, an MCP task still
running, or an HTTP `202`/`206`/`207`: acceptance is not completion). The operation's budget stays reserved and retries are refused until it is
resolved:

```sh
# Ask the provider (MCP tasks/get on the task handle, or the HTTP status endpoint below)
curl -X POST …/v1/runs/$RUN/operations/$OP/reconcile -d '{"source":"provider"}'
# Or assert the outcome you verified, citing the evidence (recorded with your identity)
curl -X POST …/v1/runs/$RUN/operations/$OP/reconcile -d '{"source":"operator",
  "outcome":"not_applied","evidence_ref":{"artifact_type":"provider_ledger_extract",
  "artifact_id":"payments-2026-10-20","version":"1","sha256":"sha256:…"}}'
```

An HTTP provider that answers `202` can be queried too when the capability's reviewed
manifest declares its completion contract. The adapter then sends
`GET {endpoint}/{status_tool}/{id}`, where `id` is the `id` from the `202` body, and
reads the job state at `state_pointer`:

```json
"recovery": {"strategy": "query", "max_attempts": 1, "retry_delays_seconds": [],
  "completion": {"status_tool": "refund_status", "state_pointer": "/state",
    "confirmed": ["succeeded"], "partial": ["partially_refunded"], "not_applied": ["canceled"]}}
```

Only listed states settle the effect. List under `not_applied` only terminal states in
which the provider guarantees the job will never apply. Any other state, a missing job
(`404`) or a failed lookup stays unknown, because absence is not proof of
non-application.

The same contract decides a finished `2xx`, and every effectful HTTP capability must
declare it. A provider may answer `200` with a body that says `pending` or `failed`,
so a success status alone never confirms an effect. The body's state at
`state_pointer` decides the outcome: listed states settle it, and any other state, or
a missing one, stays unknown and keeps the body's `id` for the lookup. `contextosd`
refuses to start with an effectful capability on an HTTP adapter whose manifest has no
`completion`, and the adapter does not send such a call. Read-only HTTP capabilities
need none: a `2xx` other than `202`, `206` or `207` stands.

A client error from an effectful HTTP capability is unknown too, unless the manifest
lists that status. The same applies to HTTP client errors from an MCP endpoint. HTTP
does not promise that a handler which answered `400` or `422` changed nothing first. Treating such an answer as not applied would release shared
exposure and permit a retry that applies the effect twice. List only the statuses the
provider documents as returned before any effect:

```json
"recovery": {"strategy": "manual_reconcile", "max_attempts": 1, "retry_delays_seconds": [],
  "not_applied_statuses": [400, 401, 403, 422]}
```

Read-only capabilities have no effect to apply. For them, `400`, `401`, `403`, `404`,
`405`, `413`, `415` and `422` remain definitive.

#### Migrating an HTTP integration

Since this release every effectful capability on an `http` adapter needs
`recovery.completion`, and `contextosd` refuses to start without it. The startup error
names the manifest, the capability and the adapter, so starting once lists what to
migrate. For each capability:

1. Find the field in which the provider reports the effect's state. Most providers
   return the same resource from the call and from a status lookup, for example a
   refund object with `status: pending | succeeded | failed | canceled`.
2. Declare where to read it and which states are final. List under `not_applied` only
   states in which the provider guarantees the effect did not and will not apply.
   Leave out states such as `failed` unless the provider documents that. An unlisted
   state stays unknown and is reconciled, which is the safe outcome.

   ```json
   "recovery": {"strategy": "query", "max_attempts": 1, "retry_delays_seconds": [],
     "completion": {"status_tool": "refunds", "state_pointer": "/status",
       "confirmed": ["succeeded"], "not_applied": ["canceled"]},
     "not_applied_statuses": [400, 401, 403]}
   ```

3. Optionally list in `not_applied_statuses` the client errors the provider documents
   as returned before any effect (see above).
4. Deploy the updated manifest to every replica. Operations that were already unknown
   before the upgrade keep their state; reconcile them as before.

A provider that reports no state cannot have its success checked. Put such a provider
behind an MCP server or a service that does report a state, rather than declaring a
contract its responses cannot satisfy: every call would stay unknown.

#### MCP tools that report a state

A finished MCP result without `isError` is the tool saying it succeeded, but a tool
can finish while its job is still `pending`, or report `failed` in its content. When
an effectful MCP capability declares `recovery.completion`, the state at its
`state_pointer` inside `structuredContent` decides, as for HTTP: a listed state
settles the call, and a missing or unlisted one stays unknown and is reconciled.
`status_tool` is not needed (MCP looks tasks up with `tasks/get`):

```json
"completion": {"state_pointer": "/status", "confirmed": ["succeeded"],
  "not_applied": ["canceled"]}
```

`[guards] require_completion_contracts` (on in production, off in development)
refuses to start with an effectful MCP capability that has no completion contract.
Without one, a result without `isError` is confirmed.

`status` is `resolved`, `pending` (still running), `no_change` (nothing unknown to
resolve; conflicting facts need escalation) or `rejected` with reasons such as
`reconcile_requires_operator`. A recorded fact cannot be overwritten by a later
contradicting assertion. Grant `reconcile` only to operators and automation that verify
outcomes at the provider.

Whoever ran the agent cannot release what its effect holds on its own word: the
principal that admitted the run may ask the provider or assert `confirmed`, and its
assertion of `not_applied` or `partial` is refused (`403 reconcile_not_independent`).
Give on-call or reconciliation automation its own key with `reconcile`; it does not
admit the run, so it sends no executor generation (`Client.reconcile(run_id, …)` in
the Python client). Either way, `not_applied` for an attempt whose dispatch started and
recorded nothing is refused (`dispatch_active`) and needs an attestation of absence.

An attempt whose dispatch started and which recorded nothing (its executor died
mid-call) is refused as `dispatch_active`: the call may still land. If the provider's
records show no effect, a principal with the `attest` scope (never together with
`admit` or `dispatch`) releases it with `POST
…/operations/$OP/attest-absence`, citing the records and the time they were checked
through: at least the attempt's start plus the capability's timeout plus 5 minutes.
It advances the run's executor generation, so the executor that sent the call must
take the run over, and is signed as `effect_absence_attested` before anything else
changes. A dispatch that stalls more than 120 seconds before calling the provider
sends nothing (`dispatch_stalled`). See "Attesting absence" in
[shared guarantees](SHARED_GUARANTEES.md).

### Upgrading a capability with operations open

An operation keeps the `capability_ref` it was claimed under, and a retry under any
other version is refused (`operation_binding_mismatch`): the new version may read the
same arguments differently, and an approval of the old action does not cover it. The
new version starts new operations only. Before pinning it, list the old version's
open operations (hold inspection, or runs still `running`) and decide for each:
resolve it under the old version, or let it be refused and start new, separately
approved work.

To resolve operations after the upgrade, keep the old manifest in
`retired_capabilities`:

```toml
capabilities = ["deploy/capabilities/issue_refund-v4.json"]
retired_capabilities = ["deploy/capabilities/issue_refund-v3.json"]
```

A retired version is used only to reconcile, attest and record operations claimed
under it, with its own adapter, protocol tool, completion contract and timeout. It is
never dispatched, and the startup guards for dispatched tools do not apply to it.
Without it, those operations are refused as `capability_not_pinned` and what they hold
stays held. Remove it once none of its operations is open.

### Compensating applied effects

When a workflow fails after some effects applied, undo them with the compensations
their manifests declare: `run.compensate(operation_id)` for one effect, or
`run.compensate_all()` to compensate the run newest first, stopping at any effect in
doubt. Each compensation is a new governed operation with its own authority, policy,
approval and budget, and runs at most once per effect. See
[COMPENSATION.md](COMPENSATION.md).

### Outcome contracts

A provider confirming a refund call says it accepted the call, not that the refund
posted to the right order for the right amount. A capability can require that from a
second source, a witness, before the run counts the effect as done:

```json
"outcome": {"witness": "https://ledger.internal.example", "postcondition": "refund_posted",
            "within_seconds": 900, "binds": "effect", "on_missed": "escalate"},
"recovery": {"reference_pointer": "/refund_id", …}
```

- **What a reading establishes (`binds`, required).** `"effect"`: this particular
  effect completed. The reading must name, as `receipt`, the provider's own reference
  for the effect, which the runtime takes from the finished result at
  `recovery.reference_pointer` (MCP `structuredContent`, or the HTTP body; required
  with `"effect"`), and one reading closes one effect
  (`outcome_attestation_reused`). Two equal refunds of one order need two readings.
  `"state"`: the resource is in the postcondition's state; one reading taken after
  several effects on the resource may close each of them. Use `"effect"` for money
  movement.
- **The witness** is an `[[evidence_issuers]]` issuer whose `satisfies` lists the
  postcondition; contextosd refuses to start otherwise.
- **After the effect is applied** (confirmed or partial, at dispatch or by
  reconciliation), the outcome is pending (audited `outcome_pending`) and
  `complete` refuses with `outcome_pending`. Before dispatch the contract is recorded
  for the action; a call that cannot be recorded is refused (`outcome_index_full`).
  The operation ledger is the source of truth: the deadline runs from the ledger's
  first observation of the effect, so a process that crashes before recording the
  outcome loses neither it nor its clock; while the ledger has not resolved the effect,
  `complete` still refuses; an effect the provider definitively did not apply (or that
  was never dispatched) retires its outcome (`not_applicable`) and frees its place in
  the run's and tenant's limits (1,024 and 10,000 open outcomes). The outcome is owed
  by one attempt at a time: a retry takes it over before it is claimed and arms it
  before anything is sent, so the earlier attempt's negative result never retires the
  retry's outcome. A dispatch that stops between recording the outcome and arming it
  (a crash, a stalled process) has its outcome abandoned after 300 seconds
  (`outcome_abandoned`), which frees its place; if that dispatch resumes, it refuses
  the call with `outcome_not_armed` and sends nothing, and the call can be sent again.
- **The witness, or a service relaying its signed reading** (the scope is
  `outcome:report`; the signature is what is trusted), posts `{"attestation": "<JWS>"}`
  to `POST /v1/runs/{run_id}/operations/{operation_id}/outcome`. The payload is
  `{iss, sub, satisfies, observed_at, valid_until, amount?, receipt?}`. It is accepted
  when the witness signed it, serves the tenant and signed the postcondition, it is
  current, `sub` is the action's resource (the shared guarantee's canonical resource
  when the capability has one), `amount` (`{minor_units, currency}`) is the action's
  amount when it has one, it was observed after the effect applied and, for
  `"effect"`, `receipt` is the effect's reference (`outcome_receipt_mismatch`;
  `outcome_receipt_missing` when the provider reported none, which leaves the outcome
  to its escalation). Accepted, it is audited (`outcome_witnessed`, the token by
  digest) and the run may complete.
- **Past `within_seconds`**, the governance sweep opens one escalation for the
  operation (`reason_codes: ["outcome_missed"]`), which notifications deliver like any
  other. The outcome stays pending: a late reading still closes it (`late: true`).
  Each pass reads up to 1,000 open outcomes from where the last one stopped, so an
  overdue outcome is reached within `ceil(open / 1000)` passes however many others
  are not yet due.
- **Decisions and evidence.** A `DECIDED` or `CLOSED` decision citing such an effect is
  refused with 409 `outcome_pending` until it is witnessed; then its tool lineage entry
  cites the reading (`artifact_refs: ["outcome:<attestation digest>"]`) and the replay
  transcript binds it. The run's evidence bundle lists its `outcomes`.
- **Signing readings while you build a witness:** `ctx attest --claims claims.json
  --seed-env SEED` prints the compact EdDSA JWS and the JWK Set to configure. The
  clients relay a reading with `Client.report_outcome(run_id, operation_id, token)`
  (Python) or `run.reportOutcome(operationId, token)` (Node).

[examples/outcome-witness](../examples/outcome-witness/README.md) runs the refund
this way: the provider confirms, the run waits, the ledger's reading closes it.

## 4. Integrate your services

Dispatch needs three fact services you operate (see `crates/contextos-adapters/src/remote.rs`
for the request/response contracts and `examples/support-refund/dev_services.py` for a
minimal, development-only implementation):

- **Authority broker** — verifies the agent's mandate and returns grants plus verified,
  current, unrevoked observations for the exact binding.
- **Control plane** — attests that each required independent control (isolation, egress
  mediation, data-flow policy…) is active for this action digest and pinned policy.
- **Approval service** — opens requests bound to the action digest and returns verified
  decisions and approver entitlements. With `[guards.approval_step_up]`, approvals
  above an amount, or of named capabilities, count only after a strong, recent
  sign-in by every approver.
  - **What the service reports.** Beside the decisions, an `assurance` map keyed by
    `approval_id`: `{"acr", "amr", "auth_time"}` from the approver's ID token.
  - **Rule.** Each approved decision needs an accepted `acr` or `amr` value, and an
    `auth_time` at most `max_age_seconds` before it.
  - **Otherwise.** The approval is not used. The call waits for an approval again
    (`approval_step_up_required`, obligation `approve_with_step_up`), and the refusal
    is audited (`approval_step_up_refused`).

  ```toml
  [guards.approval_step_up]
  # Minor units of the action's bound amount, per currency. An amount in a currency
  # without a threshold always needs step-up.
  amount_at_least = [{ currency = "USD", minor_units = 100000 }]
  # capabilities = ["adp_iam.grant_admin"]   # always, whatever the amount
  amr_values = ["mfa", "hwk"]     # or acr_values = ["phr"]
  max_age_seconds = 300
  ```
  With `[guards.approval_review]`, an approval counts only if it was decided at least
  `min_review_seconds` after it was requested, so a reflexive click on a
  consequential action does not release it:

  ```toml
  [guards.approval_review]
  min_review_seconds = 30
  # Unscoped, it covers every approval; scope it like step-up:
  # capabilities = ["adp_payments.issue_refund"]
  # amount_at_least = [{ currency = "USD", minor_units = 100000 }]
  ```

  - The request time is the gateway's own record of when it asked the approval
    service. For requests it did not make, it is the request's `not_before`.
  - With several approvers, the fastest decision decides.
  - A decision under the floor is not used. The call needs an approval again
    (`approval_review_too_fast`, obligation `review_again`), and the refusal is audited
    with the measured seconds (`approval_review_too_fast`). Those entries show which
    approvals were rubber-stamped.
  - With or without a floor, the gateway audits `approval_requested` the first time it
    asks for an approval and `approval_redeemed` when one is redeemed, with the
    approvers, `decided_at` and `decision_seconds`. Tower's Approvals page
    (`GET /api/approvals`) folds them into decision-time distributions per capability
    and per approver.

  With `[guards.approval_timeout]`, an approval request nobody decides does not leave
  its run waiting unnoticed:

  ```toml
  [guards.approval_timeout]
  timeout_seconds = 1800        # 60 to 604800
  on_timeout = "escalate"       # or "deny"
  # capabilities = ["adp_payments.issue_refund"]   # every approval when empty
  ```

  - The governance sweep (on the leader) finds requests with no redemption
    `timeout_seconds` after the gateway asked and audits `approval_timed_out` with how
    long each waited.
  - `escalate` opens an escalation for the run, so the request shows in the escalation
    inbox and the `contextos_escalations_open` gauge. A decision that arrives later still
    counts.
  - `deny` refuses any later decision on that request (`approval_timed_out`); the run
    must start a new operation if it still needs the effect.
  - `/metrics` exports `contextos_approvals_requested_total`,
    `contextos_approvals_redeemed_total` (by capability),
    `contextos_approval_decision_seconds` and `contextos_approvals_timed_out_total`.
- **Execution-boundary controller** (optional, `[providers.boundary]`) — returns the
  run's `BoundaryRequirement` (isolation mode, grants, process restrictions, resource
  ceilings, required controls) and a current verified `BoundaryObservation`. With it,
  run start, resume and every dispatch require the kernel's
  `evaluate_boundary_readiness` to find the boundary active now; a boundary that fails
  mid-run blocks the next effect. Without it, boundary controls (`isolation.required`,
  `network.mediated`, `credentials.brokered`) are proven per action by the control
  plane's attestations.
- **Memory-governance service** (optional, `[providers.memory]`) — for each memory
  lifecycle record a run submits (`POST /v1/runs/{run_id}/memory`: propose, promote,
  correct, delete), returns the trusted context: allowed readers and operations,
  which operations need review, maximum retention, the verified access observation
  and the data-flow request and policy for writing into memory. The kernel's
  `validate_memory_lifecycle` decides (review bound to the exact record, reader scope,
  retention, data-flow policy, and verified propagation for deletions); every decision
  is audited and only allowed records become the memory's state
  (`GET /v1/memory/{record_id}`). Without the service, memory operations are refused.
  With it, memory a run recalls (`deps.promoted_memory`) is verified at admission: each
  item's `memory_ref` must name a record whose state is `promote` or `correct`, within
  its retention, whose `readers` include the run's user or agent (readership is
  rechecked at recall, not only at promotion), and whose `memory_ref.sha256` is the
  digest of the recalled `content`; and two recalled memories may not hold different
  values for the same key (`memory_conflict`), so contradictory facts never reach one
  context; and each key is held by the record that most recently promoted or corrected
  it, so recalling an older value, or one whose current value was deleted, is refused
  (`memory_superseded`). A key is the exact `memory_ref.artifact_id` within its owner and
  namespace;
  anything else is refused (`memory_unverified`). Without the service, production
  refuses recalled memory unless `[guards] trust_supplied_memory = true`.
- **Data-governance service** (optional, `[providers.data_flow]`) — for each authorized
  action that sends data (a capability whose manifest names recipients in
  `destination_pointers`, or declares `"sends_data": true` for a fixed recipient),
  returns the `DataFlowRequest` (source artifacts and their verified classifications,
  processor and residency observations, stage, any transformation) and the pinned
  `DataFlowPolicy`. The gateway checks the request is bound to this exact action
  (contract, run, operation, action digest, purpose) and names the recipient the
  arguments bind, or the adapter for a fixed recipient; a call naming several
  distinct recipients is refused. Then the kernel's
  `evaluate_data_flow` decides; the decision is audited. Unknown or unverifiable facts
  block.
- **Result-screening service** (optional, `[providers.result_screening]`) — for each
  confirmed effect, receives the run, capability, its risk and the tool's output, and
  answers `{"verdict": "pass" | "withhold" | "redact", "pointers": [...],
  "reason_codes": [...]}`. Use it for your prompt-injection, secret or personal-data
  classifier; ContextOS ships the port, not a classifier.
  - The effect stands either way; only what the agent sees changes.
  - `withhold` returns no output and the obligation `verify_effect_out_of_band`.
  - `redact` replaces each pointed-at value with `"[redacted]"`.
  - A failing or malformed answer withholds.
  - Every non-`pass` verdict is audited (`result_screened`) with pointers and reasons,
    never content.
- **Action monitor** (optional, `[providers.action_monitor]`, thresholds in
  `[guards.action_monitor]`) — before every effectful or data-sending call, receives the
  run, the capability, the action binding (arguments, resources, recipients, amount) and
  the run's trajectory (its last 16 monitored calls with their scores, and their sum).
  It answers `{"suspicion": 0..1, "reason_codes": [...]}`. This is the trusted-monitor
  pattern from AI-control work: plug in your monitor model or rules. ContextOS ships the
  port and the response:

  ```toml
  [guards.action_monitor]
  ask_at = 0.5            # an approval of the exact action (action_monitor_ask)
  deny_at = 0.9           # denied (action_monitor_deny)
  run_budget = 2.0        # summed suspicion past which every call needs an approval
  on_unavailable = "ask"  # or "deny"; "allow" fails open
  ```

  - The score composes a guardrail outcome, so approvals bind the exact action.
  - The call to the monitor runs alongside the other authorization reads.
  - Every score is added to the run's trajectory, whatever the decision. So many
    mildly suspicious calls reach `run_budget` (`action_monitor_run_budget`) where
    no single threshold would catch them.
  - Calls not allowed outright are audited (`action_monitored`) with the score and
    reason codes, never the arguments.
  - The monitor sees arguments, so run it inside your trust boundary.

#### When a dependency fails

Every service ContextOS asks for a decision fails closed: when it cannot answer, the
call is refused with a reason code that names it, and nothing reaches the provider.
There is no fail-open switch, because a decision made without its facts is not a
governed decision. Services that only carry records out of ContextOS retry instead,
and never hold up governed work.

| Dependency | When it fails | What you see |
|---|---|---|
| Authority service | the call is blocked before anything is sent | `blocked`, `authority_unavailable` |
| Constraints service | blocked | `blocked`, `constraints_unavailable` |
| Approvals service | blocked; an approval cannot be requested or redeemed | `blocked`, `approval_unavailable` |
| Data-governance service | an action that sends data is refused | `data_flow_unavailable` |
| Boundary controller | run start, resume and dispatch are refused | `boundary_unavailable` |
| Memory-governance service | memory operations are refused | `memory_policy_unavailable` |
| Resource identity service | calls under a guarantee with `resource_canonicalizer = "provider"` are refused | `shared_guarantee_identity_unavailable` |
| Result-screening service | the effect stands; its output is withheld from the agent | `result_screening_unavailable`, audited `result_screened` |
| Action monitor | monitored calls need an approval (`on_unavailable = "ask"`), or are denied | `action_monitor_unavailable`, audited `action_monitored` |
| Provider (adapter) | a request that never left moves to the next `fallback_endpoints` entry, or is `not_dispatched` and safe to retry; once it may have been sent, the outcome is unknown and is reconciled, never retried blindly | `not_dispatched`, or `reconcile_effect_before_retry` |
| PostgreSQL | requests that need the store answer `503`; nothing is dispatched without its claim | `store_unavailable` |
| Audit signing (KMS) | requests that must record an entry answer `503` | `audit_unavailable` |
| OIDC issuer (JWKS) | keys already fetched keep working; a refresh failure is logged and retried; `/readyz` fails until the first keys load | log `jwks refresh failed` |
| Audit sinks | delivery resumes from the sink's cursor with backoff; nothing is lost | `contextos_audit_sink_batches_total{outcome}` |
| Notification webhooks | retried up to `max_attempts`, then abandoned | `contextos_notifications_total{outcome="abandoned"}` |

Capabilities are admitted only from reviewed manifests (`ctx manifest <file>`); protocol
discovery is never permission.

To start a manifest for an MCP tool, save the server's tool list and draft one:

```sh
npx @modelcontextprotocol/inspector --cli https://tools.internal/mcp --method tools/list > tools.json
ctx init-tool --mcp tools.json --tool issue_refund --adapter adp_payments > issue_refund.json
```

The draft copies the tool's input and output schemas and its upstream pins
(`upstream_tool_digest`, `upstream_description_digest`). Everything that grants or
bounds authority is a `"REVIEW: …"` string listing the allowed values: purpose, desired
effect, each risk dimension, approval mode, resource, destination and amount pointers,
recovery strategy, artifact refs, and the description agents will read (the server's
own text is quoted for you, since agents should not read it unreviewed). The tool's
annotations appear only as untrusted hints. `ctx manifest` and contextosd refuse the
file while any `REVIEW:` string remains, and `ctx manifest` lists where. A manifest
that loads still gets `notes` for what a reviewer should look at again: an effectful
tool with no `amount` or `resource_pointers`, a tool named like a destructive call
(`delete`, `drop`, `replace`, ...) declared reversible or approved below
`destructive`, and an effectful, non-repeatable tool with no `intent` key. contextosd
logs the first two at startup. Adapters: MCP `2026-07-28` (stateless Streamable HTTP) or
HTTP/JSON, HTTPS only, no redirects, credentials from your broker.

Under `idempotent_retry`, the provider key (`Idempotency-Key`, MCP
`io.contextos/idempotencyKey`) is `ctxos:v1:<sha256>` over tenant, run and operation id,
so runs reusing an `idempotency_key` never alias at a provider shared across runs or
tenants; it is persisted with the operation and reused unchanged on every retry
(operations claimed before this format keep their original `ctxos:<operation_id>` key).

An MCP adapter maps a finished tool result into the tool output with a selectable
projection. `flat` (the default, for existing output schemas) puts `structuredContent`
members at the top level and presentation under `content`, so a structured member named
`content` is lost and absent and `null` structured content look alike. New capabilities
should select the lossless projection, and existing ones migrate their output schemas
when they switch:

```toml
[[adapters]]
id = "adp_payments"
kind = "mcp"
endpoint = "https://payments.internal/mcp"
result_projection = "mcp_result_v1"
# output: {"mcp_result": {"structured_content_present", "structured_content",
#          "content", "is_error"}}
```

Providers that require OAuth, as MCP servers increasingly do, get tokens through the
client credentials grant instead of a fixed `token_env`:

```toml
[[adapters]]
id = "adp_payments"
kind = "mcp"
endpoint = "https://payments.internal/mcp"
[adapters.oauth]
token_url = "https://idp.internal/oauth2/token"
client_id = "contextos-gateway"
client_secret_env = "CONTEXTOS_PAYMENTS_CLIENT_SECRET"
scope = "payments.refund"          # optional
# resource = "…"                   # RFC 8707 audience; defaults to the endpoint
# refresh_before_seconds = 60
```

- **The grant.** The client authenticates with HTTP Basic, and the token is requested
  for the provider as its `resource`.
- **Caching.** Tokens are cached and replaced before they expire (halfway through the
  lifetime for short-lived ones). One fetch runs at a time.
- **Failure.** A token that cannot be obtained fails the call before anything is sent
  (`not_dispatched`), so it is safe to retry.
- **Rules.** The token endpoint follows the same transport rules as provider
  endpoints: HTTPS, no redirects, bounded responses. Set either `token_env` or
  `oauth`, not both.

A provider that runs as several replicas (or in several regions) can list them, so
one being down does not stop governed work:

```toml
[[adapters]]
id = "adp_payments"
kind = "mcp"
endpoint = "https://payments-a.internal/mcp"
fallback_endpoints = ["https://payments-b.internal/mcp"]
```

- **What moves on.** A call goes to the next endpoint when its request never left
  (connection refused, DNS or TLS failure), which is safe for any effect because
  nothing was delivered. A read-only capability's call also moves on after a lost
  response or a `502`, `503` or `504`. An effectful call that may have been delivered
  never does: its outcome is unknown and is reconciled, exactly as with one endpoint.
  A `500` moves no call on: the endpoint answered, and the error is as often the
  tool's own, which every replica would repeat.
- **One time budget.** The capability's `timeout_ms` covers every attempt. A read-only
  call gives each attempt an equal share of what remains, so a hung endpoint is given
  up in time for the next to answer; an effectful call gives its attempt all of it,
  so a hang stays unknown and is never resent.
- **Ejection.** Three consecutive failures (unreachable, lost, or any `5xx`) eject an endpoint for 30 seconds, doubling
  with each ejection up to five minutes, and a success restores it. Ejected endpoints
  are tried last rather than skipped, so no call is refused without an attempt. Each
  ejection is logged as a warning with the endpoint.
- **Same provider.** Replicas must share the provider's state (an idempotency key or
  task id sent to one must be known to the others) and serve the same tools: upstream
  pins are checked against whichever endpoint answers. OAuth tokens name `endpoint` as
  their resource unless `oauth.resource` says otherwise.
- **Same trust domain.** Every endpoint receives the same request, credential
  included. List only endpoints you would hand the primary's token to; a fallback on
  another origin is logged as a warning at startup.

An MCP server can change what a tool does without renaming it. Agents only ever see
your reviewed manifest, but the calls still go to the server's current tool. Pin each
capability to the upstream definition you reviewed:

```sh
contextosd --pin-mcp-tools contextosd.toml
# adp_payments.issue_refund: "upstream_tool_digest": "sha256:…", "upstream_description_digest": "sha256:…"
```

Copy the digests into the capability manifest, and review them like any other change.

- **When it is checked.** Each replica lists the server's tools at startup and every
  5 minutes. `upstream_tool_digest` covers the name, input and output schemas and
  annotations.
- **Drift.** While the upstream tool differs from its pin, or is gone, the capability
  refuses calls with `upstream_tool_drifted`, before anything is reserved or sent.
- **Description changes.** A changed `upstream_description_digest` is reported but
  not refused, because agents see the manifest's description, not the server's.
- **Before the first check.** Until a replica has checked a pinned tool once since it
  started, calls are refused with `upstream_tool_unverified` (retryable), so a restart
  never serves a tool nobody checked.
- **Unreachable server.** After that, the last verdict stands.
- **Metrics and alerts.** `contextos_upstream_tool{capability,status}` reports each
  status. `ContextOSUpstreamToolDrifted`, `…DescriptionChanged` and
  `…CheckUnavailable` alert on them.
- **Enterprise profile.** Every effectful MCP capability must pin
  `upstream_tool_digest`. Elsewhere `--check-config` warns about each unpinned one.

## 5. Gate Context Pack releases

A pack or policy change is a change to what agents may do, so gate it on replayed
cases before release. Every admitted run's inputs are kept and exported with
`GET /v1/runs/{run_id}/replay-case`; collect a corpus (a JSON array of those cases),
then:

```sh
ctx gate --baseline pack-v5.json --candidate pack-v6.json --cases cases.json \
         [--acknowledge acknowledgements.json]
```

Each case is compiled under both packs. The gate **fails** (exit 1) on any
unacknowledged widening (a capability newly surfaced, the most restrictive policy
verdict loosening from deny to approval to allow, an evidence gate newly allowing
commit) and on any case the candidate cannot compile. Narrowings are reported but pass.
Acknowledgements belong to the release owner, never to the candidate pack, and each
names exactly what it accepts: `{"capabilities": ["adp_crm.lookup"],
"evidence_gates": ["support.refund.execute"], "policy_loosening": ["<case name>"],
"compile_expansion": ["<case name>"]}`. A policy acknowledgement covers only the
replay cases it names, so it cannot approve a loosening on a case nobody reviewed.

### Inspect and try a pack

`ctx inspect PACK` summarizes a pack for review. It lists the intents and the rules
scoped to each (effect, condition, `else`, approval gate, obligations, prohibitions,
decision binding), the tools with their approval modes, permissions and argument
constraints, the approval gates, and each decision with its required evidence and the
rules that bind it. It also lists `problems`: names a rule or permission uses that the
pack does not define, duplicate rule ids, and rules without a rationale. The compiler
does not refuse those names at load, and a mistyped approval gate or decision binding
only shows when its rule applies.

`ctx repl --pack PACK --run RUN` tries a pack interactively on one case, starting from
an admission body or replay case:

```text
ctx> set request.input.context.refund_amount 4200
ctx> decide          # verdict, rules, obligations, capabilities, evidence gates
ctx> set run_context.user.role "supervisor"
ctx> plan            # this principal's plan for the intent
ctx> reset
```

Each answer is one JSON line, so a script can be piped in (`help` lists the commands).

### Share rules across packs

Rules that several packs need (no refund during an open chargeback, a data-residency
deny) belong in one rule library, imported by each pack, rather than copied. `ctx
build` assembles a pack from a pack source:

```json
{"pack_source": "contextos.pack_source.v1",
 "base": "../pack.json",
 "patch": {"pack_meta": {"pack_version": "5.3.0"}},
 "imports": [{"library": "libraries/chargebacks.json", "intent": "support.refund"}]}
```

```sh
ctx build examples/support-refund/authoring/pack.source.json \
          --out examples/support-refund/authoring/pack-5.3.0.json
```

- `base` is a pack, or another pack source (up to 8 deep, no cycles); paths are
  relative to the file that names them.
- `patch` is a JSON merge patch (RFC 7386) over the base.
- `imports` names rule libraries: `{"rule_library": "contextos.rule_library.v1",
  "library_id", "version", "policy_bundles": [...]}`. An import may take some
  `bundles`, set their `priority`, and scope them to one `intent`, so every imported
  rule applies to that intent only. Scoping narrows and never redirects: a rule that
  already names another intent is refused. A bundle id already in the pack is refused.

The output is an ordinary context-pack.v2 document, validated and compiled before it
is written. Admission, the release gate, pack tests and plans see no difference, so a
built pack is reviewed, tested and gated like a hand-written one, and the runtime never
resolves an import. The report lists every input with its digest and where each
imported bundle came from. Commit the built pack beside its source and run `ctx build
SOURCE --check PACK` in CI: it exits 1 when the committed pack no longer matches its
sources, for example after a library changed.

### Author packs with a coding agent

[`skills/contextos-pack-authoring`](../skills/contextos-pack-authoring/SKILL.md) is an
agent skill for writing and changing packs. It has the agent write the requirement as
cases first, then the rules, then a pack test per case, and check the change with
`scripts/check_pack.sh`. That script checks the schema, flags names that do not
resolve (approval gates, decision bindings, prohibited capabilities, permissions), and
runs the tests, a decision plan per role and the release gate against the released
version. The agent reports widenings to the release owner rather than acknowledging
them. Install it as [skills/README.md](../skills/README.md) describes. Its reference
spells out how the runtime composes rules (default deny, highest priority decides,
`else` branches) and the usual mistakes.

### Test a pack before release

The release gate says how a candidate differs from the baseline; it cannot say
whether either pack is right. Pack tests state what the pack must decide, and
`ctx test` checks them offline, through the same compiler and policy composition
admission uses:

```sh
ctx test --pack examples/support-refund/pack.json examples/support-refund/pack_test.json \
         [--junit results.xml]
```

A suite names a base case and, per test, a JSON merge patch (RFC 7386) over it, so a
test lists only what differs, and the expectations it checks:

```json
{"suite": "support refunds",
 "base": "requests/run.json",
 "tests": [
   {"name": "a refund over INR 3000 needs finance approval",
    "with": {"request": {"input": {"context": {"refund_amount": 4200}}}},
    "expect": {"verdict": "require_approval",
               "rules": ["R_REFUND_REQUIRES_IDV", "R_HIGH_VALUE_REQUIRES_APPROVAL"]}},
   {"name": "a read-only run does not surface the refund tool",
    "with": {"run_context": {"safety_mode": "read_only"}},
    "expect": {"capabilities": {"exclude": ["adp_payments.issue_refund"]}}}]}
```

- `base` is `{request, run_context, deps?}`. It, or any of its parts, may be a file
  path relative to the suite: an admission body like `run.json`, or a replay case from
  `GET /v1/runs/{run_id}/replay-case`, so a test can start from a recorded run. Only
  `request`, `run_context` and `deps` are kept from such a file.
- `with` may set only `request`, `run_context` and `deps`; `null` removes a field.
- `expect` checks only what it names: `compile` (`compiles` or `refused`), `verdict`
  (`deny`, `escalate`, `require_approval`, `allow`, composed as admission composes
  it), `rules` and `obligations` (exact sets), `capabilities` (`include` must be
  surfaced, `exclude` must not, as `adapter_id.capability`), and `evidence_gates`
  (decision key to whether commit is allowed). A test that names nothing, or a refused
  case that expects more, is an `error`, never a pass.

`ctx test` prints each test's result and the difference it found (for example
`verdict: expected allow, got require_approval`), exits 1 if any test fails or errs,
and with `--junit` also writes JUnit XML for CI. Run it beside `ctx gate` on every
pack change: tests catch a pack that is wrong, and the gate catches a change nobody
acknowledged.

### Plan what a principal may do

Before any request exists, `ctx plan` says what a pack lets one principal (user,
agent, tenant) do for an intent: which rules always apply, which never do, and which
depend on the request, and on exactly what.

```sh
ctx plan --pack examples/support-refund/pack.json \
         --run examples/support-refund/requests/run.json [--intent support.refund]
```

Each rule condition is evaluated with everything but `request` known. A part that
reads only the principal is decided (the high-value rule's `user.role ==
"support_agent"` check is true for this agent and disappears); what remains is a
residual JsonLogic condition over `request.*`, exact for every request:

```json
{"intent": "support.refund", "verdict": "conditional",
 "possible_verdicts": ["deny", "require_approval", "allow"],
 "conditions": [{"==": [{"var": "request.context.identity_verified"}, true]},
                {">": [{"var": "request.context.refund_amount"}, 3000]}],
 "rules": [{"rule_id": "R_REFUND_REQUIRES_IDV", "branch": "then", "effect": "allow",
            "applies": "when", "condition": {"==": [...]}, "obligations": ["order_lookup"]},
           {"rule_id": "R_REFUND_REQUIRES_IDV", "branch": "else", "effect": "deny",
            "applies": "unless", "condition": {"==": [...]}},
           {"rule_id": "R_HIGH_VALUE_REQUIRES_APPROVAL", "effect": "require_approval",
            "applies": "when", "condition": {">": [...]}, "approval_gate": "GATE_FINANCE_APPROVAL"}]}
```

- `applies` is `always`, `when` (the condition holds) or `unless` (it does not, for a
  rule's `else` branch). Rules that never apply to this principal are left out; for a
  supervisor the high-value rule is absent and `possible_verdicts` is `deny, allow`.
- `verdict` is stated when nothing depends on the request (an intent no rule covers is
  `deny`, as admission's default). Otherwise it is `conditional`, and
  `possible_verdicts` lists what some assignment of the conditions reaches, composed as
  admission composes it. Conditions are treated as independent, so the list can include
  a verdict no real request reaches, never omit one a request does. Past 10 distinct
  conditions it is `null`.
- A plan covers policy rules. Which tools are surfaced also depends on the run's
  safety mode and evidence; each rule's `prohibits` says what it withholds.

Use it to review a pack change for one role, to show a UI what to ask for before
offering an action, or to confirm that a principal can never reach `allow`.

A running server answers the same question for its loaded packs with `POST /v1/plan`
(`compile` scope), `{"pack_ref", "run_context", "intent"?}` →
`{"pack_ref", "plan"}`; the run context must be the caller's tenant's. A UI can call it
to show, before offering an action, what the request must establish
(`client.plan(pack_ref, run_context)` in Python, `client.plan(packRef, runContext)` in
Node). Nothing is stored or audited.

### Publish pack versions without a restart

Point `pack_dirs` at a directory of pack files and the server loads new versions while
it runs:

```toml
pack_dirs = ["/srv/contextos/packs"]   # JSON files, searched recursively; .git etc. skipped
pack_reload_secs = 30                  # 0 (default): startup and POST /v1/packs/reload only
```

Keep the directory current however packs are published: a git checkout updated by a
sync sidecar, an image or configuration volume, a deploy step. `POST /v1/packs/reload`
(`control` scope) reads it at once, for a pipeline that publishes and then rolls out:

```sh
curl -X POST "$CONTEXTOS/v1/packs/reload" -H "Authorization: Bearer $OPS_TOKEN"
# {"added": [{"pack_ref": "ctxpack.support@5.3.0", "sha256": "sha256:…", …}],
#  "refused": [], "unchanged": 1, "other": {"added": 0, "refused": 0}}
```

A reload only adds versions. Runs, decision records and replay cases cite a pack by
reference, so a reference names one content forever. The first load of a reference
records it as `pack_loaded` and binds it to its digest in the store, before any run
can use it; every later load (a reload, another replica, a restart) must match:

- a file whose reference is loaded or bound with other content is refused
  (`pack_ref_immutable`): change `pack_version` to publish a change;
- at startup such a file stops the server, so editing a pack in place (or
  force-pushing the pack repository) cannot change a reference across a restart;
- a removed file does not unload its version; retire one with a `pack` revocation;
- a pack for a tenant no startup pack names is refused (`tenant_not_configured`);
- an invalid file is refused alone (`invalid`) and the rest still load, while at
  startup any invalid source stops the server;
- a version whose audit entry or binding cannot be written is not added
  (`unrecorded`); the next reload tries again.

Each version is audited once, as `pack_loaded` (reference, digest, file, or `startup`
for a pack the configuration names) in its tenant's chain, when it is first bound.
When several replicas load a new version at once, one claims the binding and writes
the entry while the others wait for it. The claim is a lease timed by wall clock, so
keep replica clocks synchronized (NTP or equivalent): a replica whose clock runs well
behind another's can be taken for stalled while healthy, and the version is then
audited twice (the chain still verifies).
Bindings live in the configured store, so they outlast a restart only with
`kind = "postgres"`. `GET /v1/packs` lists every version with its `sha256`. Loading a
version changes nothing on its own: runs use it only when they name it or a rollout
routes them to it. With several replicas each reads its own copy of the directory, so
reload every replica (or wait one interval) before a rollout names a new version; until
then a replica that has not loaded it answers `pack_not_found`. Write access to the
directory is the authority to publish packs: give it to the release pipeline only.

### Roll out in stages

Load both pack versions, then steer a share of the baseline's new runs to the
candidate (`control` scope), from shadow to 100%:

```sh
curl -X POST "$CONTEXTOS/v1/rollouts" -H "Authorization: Bearer $OPS_TOKEN" -d '{
  "baseline": "ctxpack.support@5.2.0", "candidate": "ctxpack.support@5.3.0",
  "percent": 0, "shadow": true, "reason": "v5.3 shadow"}'
```

Routing is by a hash of tenant and run id (a delegated child follows its parent), so it
is sticky and reproducible; each run pins the pack it was admitted on, and admission
reports `pack_ref` and `rollout`. With `shadow`, runs kept on the baseline are also
compiled under the candidate off the request path and the governance difference
(capabilities, policy, evidence gates) is audited as `shadow_diff`: live evidence for
the next stage that changes no outcome. The run id is chosen by whoever admits the run,
so a caller can steer its runs into or out of the candidate: a rollout is a canary for
the pack's quality, not a control. Never rely on the baseline's rules to restrict a
caller during a rollout.

Before a candidate takes live traffic (`percent > 0`), the server runs the release
gate itself: the replay cases of the runs named in `gate_runs`, plus the case of every
open feedback record, compiled under baseline and candidate. A widening fails it unless
acknowledged per case in `acknowledge` (the same rules as `ctx gate`); a missing or
erased case refuses the change too (close feedback whose case was erased). The passing
gate's cases and report digest are audited with the rollout:

```sh
curl -X POST "$CONTEXTOS/v1/rollouts" -H "Authorization: Bearer $OPS_TOKEN" -d '{
  "baseline": "ctxpack.support@5.2.0", "candidate": "ctxpack.support@5.3.0",
  "percent": 5, "reason": "v5.3 canary", "gate_runs": ["run_8812", "run_9020"],
  "acknowledge": {"policy_loosening": ["run_8812"]}}'
```

`POST /v1/rollouts/clear` returns all new runs
to the baseline; revoking the candidate pack (the kill switch) also stops runs already
on it.

### Close the loop on operator corrections

When a reviewer corrects or overrides an agent, file it against the run
(`POST /v1/runs/{run_id}/feedback`, `evaluate` scope, independent of the run):

```json
{"kind": "correction", "target_surface": "policy", "decision_record_id": "decision_…",
 "summary": "Refund issued without confirming the delivery was damaged.", "expected_outcome": "escalate"}
```

The run's replay case becomes the feedback's replay obligation, so `GET /v1/feedback`
(open feedback, oldest first) is the corpus a candidate change must pass through
`ctx gate` and `ctx scorecard-gate`. A rollout's gate never accepts acknowledgements
for an open feedback case (`feedback_not_waivable`): fix it or close the feedback with
evidence. Pass it to the release gate with
`ctx gate … --feedback open-feedback.json`: the gate fails, listing them under
`missing_replay_obligations`, while any open record's replay case (fetched from
`GET /v1/runs/{run_id}/replay-case`) is missing from `--cases`. An operator closes it as `fixed`, `still_failing`,
`invalid` or `superseded` only with an evidence reference (for example the digest of
the passing gate report): `POST /v1/feedback/{feedback_id}/close`. Filing and closing are
audited.

Erasing a run (by request or retention) redacts its feedback's `summary` and
`expected_outcome`, recording a digest under `content_erased`; the record stays open with
its replay obligation, so an operator closes it explicitly (typically `superseded`, since
the replay case was erased too). Feedback filed after the erasure is redacted at once.

### Gate on trajectories

`ctx gate` compares what a candidate pack *permits*; `ctx trajectory-gate` compares
what agents *did* under it. Replay (or shadow) the same cases under baseline and
candidate, fetch each run's evidence bundle (`GET /v1/runs/{run_id}/evidence`), and
compare per case:

```sh
ctx trajectory-gate --baseline base/*.json --candidate cand/*.json \
  --case-map case-map.json --max-tool-call-ratio 1.5 [--acknowledge ack.json]
```

Pass the audit exports covering those runs with `--audit` (verified first with
`ctx audit-verify`): capabilities called and effects applied then come from the
runtime's signed record, not from what the agent's decisions chose to report. A case
fails when the candidate used a capability the baseline did not, reached
different decision outcomes, applied more effects, made more tool calls than the
ratio allows over the baseline's most, or did not run it at all; a case only the
candidate ran fails unless acknowledged as `unpaired`. Trials of one case
accumulate. Acknowledge an intended change per case:
`{"capabilities": {"refund_big": ["adp_payments.issue_refund"]}, "outcomes": ["refund_big"], "effects": [], "tool_calls": []}`.

### Gate on scorecards

`ctx gate` checks what a candidate *permits*; `ctx scorecard-gate` checks how it
*performs*. Replay the corpus under baseline and candidate, collect each case's
evaluator scorecards (from the evidence bundles, below), and compare:

```sh
ctx scorecard-gate --baseline base.json --candidate cand.json --thresholds limits.json
# files: [{"case": "<name>", "scorecards": [{"policy", "utility", "safety", "latency", "cost"}]}]
# limits: {"policy_floor": 1.0, "safety_floor": 0.95, "max_utility_drop": 0.02,
#          "max_latency_ratio": 1.2, "max_cost_ratio": 1.1, "min_cases": 50}
```

Build the scorecard files from evidence bundles with `ctx scorecards` (one case per run;
`--case-map` maps the run ids of each replay to its case name so baseline and candidate
pair up):

```sh
ctx scorecards evidence/base-*.json --case-map base-runs.json > base.json
```

It fails (exit 1) when any candidate scorecard is below a floor (each one, never an
average), when policy or safety drops on any paired case, when mean utility drops or
latency or cost rise beyond the limits, when a baseline case has no candidate
scorecards or a measured dimension is no longer measured, and when fewer cases pair
than `min_cases`. Floors have no defaults: they are the release owner's decision.

## 6. Budget model calls and replans

Tool calls are not the only spend. Before each model call or replan, the orchestrator
reserves from the run's budget, the same ledger tool calls use, so parallel lanes
cannot overrun it and resume cannot reset it:

```sh
POST /v1/runs/{run_id}/usage/reserve   {"kind": "model_call", "tokens": 4000, "cost_cents": 2}
POST /v1/runs/{run_id}/usage/settle    {"reservation_id": "usage:…", "tokens": 1830}
```

In the clients, `run.budgeted_model_call(tokens=…)` (TypeScript
`run.budgetedModelCall(fn, {tokens})`) reserves before the call and settles after it,
even when the call fails.

A reservation that does not fit is refused (`budget_exhausted`; the clients raise
`BudgetExhausted`, which the loop should treat as a stop, not a retry); replans count against
the run's replan allowance. A model call reserves at least `[guards]
model_call_min_tokens` (default 1,000), so no call is free. Settlement depends on who reports: an LLM gateway or other
metering service holding the `meter` scope (and neither `admit` nor `dispatch`) settles
the usage it measured and releases the rest (usage above the reservation is charged as
audited overage, up to the run's remaining capacity), while the run's own executor
settling is charged the whole reservation, because self-reported usage is not evidence.
The principal that admitted the run cannot meter it. Overage is settled in a second
step after the reservation: a crash between them charges the reservation only (a retry
is refused, since the reservation is no longer open), so a crash can undercharge by the
overage, never overcharge.

To charge measured usage, send each model request through an LLM gateway that holds
the `meter` scope, with the run and reservation in two headers, `ContextOS-Run-Id` and
`ContextOS-Usage-Reservation`. The clients produce them and leave settlement to the
gateway:

```python
with run.budgeted_model_call(tokens=4000, metered=True) as reservation:
    response = model.generate(..., extra_headers=run.metering_headers(reservation))
```

The gateway forwards the request without those headers, reads the usage the provider
reported, and settles the reservation with it. If the call raises before the gateway
settles, the client settles it in full; if the gateway sees no usage in a successful
response it leaves the reservation, which stays reserved until the executor settles it
in full, because unknown usage is never free. One reservation covers one call.

A gateway claims the reservation before it forwards the call (`POST
/v1/runs/{run_id}/usage/claim`, `meter` scope): contextosd refuses a forged, settled or
replan reservation (`404 reservation_not_found`), one already claimed by any meter
(`409 reservation_claimed`, in the store, so across gateway and contextosd replicas)
and a revoked run (`403 revoked`), and answers with the tokens and cost the reservation
covers so the gateway can cap the call's output. A claimed reservation settles as
measured only by the meter that claimed it. Settlement may name the `model` that
served the call. Refused reservations, claims and settlements are audited
(`usage_refused`, `usage_claimed`, `usage_settled`); Tower reports model spend from them.

For the LiteLLM proxy, install [`contextos-litellm`](../integrations/litellm) and add
`contextos_litellm.metering_handler` to `litellm_settings.callbacks`: it claims, caps,
settles measured usage and LiteLLM's computed cost with retries off the response path,
and fails closed. [`examples/metering-proxy`](../examples/metering-proxy) is a
standard-library reference of the same contract for OpenAI Chat Completions and
Responses and Anthropic Messages, streamed or not.

### Checkpoint the orchestrator

Save the orchestrator's own state (plan, step pointer, last verdict) after every Critic
verdict, so a run resumes where it was after failover:

```sh
POST /v1/runs/{run_id}/checkpoint   {"expected_revision": 3, "state": {"step": 4, "verdict": "accept"}}
GET  /v1/runs/{run_id}/checkpoint   # the executor that took over reads it
```

Only the current executor reads or writes (generation fencing), writes are optimistic on
the revision (`checkpoint_conflict` names the current one), the state is at most 256
KiB, each save is audited by digest, and checkpoints are erased with the run (an erased
checkpoint, or a run past its deadline, takes no new one).

### Pin the model and evaluators

Each decision's lineage names the Context Pack and policies it ran under; to make it
name the model and evaluators too, the executor pins them in its execution contract's
`release_refs`, like any release artifact:

```json
"release_refs": [
  {"artifact_type": "model_profile", "artifact_id": "claude-opus-5-5.support", "version": "3", "sha256": "sha256:…"},
  {"artifact_type": "evaluator_suite", "artifact_id": "support.refund.judges", "version": "2", "sha256": "sha256:…"}]
```

Every DecisionRecord of the run then carries `lineage.model_profile` and
`lineage.evaluator_suite` (`id@version`), signed with the record, so a decision can be
replayed against what produced it. To fall back to another model, pin it too (a second
`model_profile` release ref) and name the one that produced each decision in the
decision's `model_profile` (`id@version`; an unpinned model is refused,
`model_not_pinned`); when a model router chose it, report the router's decision id in
`routing_decision_id`. Both are recorded in the signed lineage. `[guards] required_release_refs = ["model_profile",
"evaluator_suite"]` refuses admission (`release_ref_missing`) for a contract that does
not pin them.

### Loop guard

An agent stuck repeating one action is stopped: after `[guards] identical_tool_calls`
(default 5; 0 disables) new operations with the same capability and arguments in a run,
the next is refused with `loop_detected` and the obligation `change_approach`, before
anything is claimed or sent. A run tracks at most 1,024 kinds of call; past that, new
kinds are refused (`loop_guard_saturated`) rather than left uncounted, and a count lost
to contention is audited (`loop_guard_count_lost`). Retrying an existing operation (same operation key) is not
a new call. The count is read with the other authorization facts and written while the
provider works, so the guard adds no serial latency; identical calls racing in parallel
can overshoot by their concurrency.

### Repeated effects

An effect is applied once per run however it is keyed. A new operation whose effect is
identical (same capability and canonical arguments) to one the run already applied, or
may have applied, is refused with `effect_repeated` and the obligation
`reconcile_existing_operation`, naming the operation that applied it. This covers a host
that retries a call under a fresh idempotency key, and one effect sent both as a keyed
tool call and as a derived-key MCP call. The first operation claims the effect
atomically after its own claim and before dispatch, so of identical effects racing in
parallel exactly one is sent. An effect the provider definitively did not apply releases
its claim, so it may be attempted again under a new key; an unknown outcome keeps it,
because the effect may have happened. If the guard's state cannot be written, the
effect is not sent (`effect_guard_unavailable`). Capabilities whose identical calls are distinct
effects (two equal top-ups) set `"repeatable": true` in their manifest; `[guards]
refuse_repeated_effects = false` turns the guard off. A run records at most 1,024
distinct effects; past that, new ones are refused (`effect_guard_saturated`).

### The same request from another run

The repeated-effect guard and provider idempotency keys are scoped to a run. A request
redelivered into a new run (a queue redelivery, a retried webhook, a customer asking a
second channel) is a new effect to them. A capability names the arguments that identify
the business request in its manifest:

```json
"intent": {"key_pointers": ["/order_id", "/amount_minor"], "window_seconds": 86400}
```

The values at those pointers, with the tenant and capability, form the intent key. The
first operation to send the request claims the key tenant-wide, after its own claim and
before dispatch. Another run sending the same request while the claim stands is refused
with `effect_repeated_across_runs` and the obligation `reconcile_existing_operation`;
the audit entry names the run and operation that hold the claim. Of runs racing with
one request, exactly one reaches the provider, across replicas sharing a store.

The claim is released when the provider definitively did not apply the effect, or when
the call is refused before it is sent. An unknown outcome keeps it. After
`window_seconds` (default one day, at most 90 days) the same request counts as a new
one. A call missing an argument the key names is rejected (`intent_key_missing`), and if
the claim cannot be written the effect is not sent (`intent_guard_unavailable`). Choose
pointers that identify the request, not the call: an order and an amount, a ticket id,
a payment reference. Arguments outside the key do not matter, so a reworded note does
not make a new request. With `"provider_key": true`, the provider idempotency key is
derived from the intent instead of the run's operation, so a provider that deduplicates
by key also recognises the request across runs. Repeatable capabilities cannot declare
an intent.

### The user's privilege, not only the agent's

An agent's credential usually reaches far more than any one user may do: the refund
agent's service account can refund any order, whoever asked. A capability can require
that the user the run acts for holds one of a set of roles:

```json
"required_user_roles": ["refund_approver", "support_lead"]
```

The roles are the ones the identity provider puts in the user's delegated token
(`[oidc.delegation] user_roles_claim`), read at admission and kept on the run with its
delegation chain; a delegated child run inherits its parent's. A call is refused before
anything is reserved or sent, and audited as `privilege_refusal`, when the run's
credential named no user (`user_not_delegated`), the issuer does not read roles
(`user_roles_unknown`), or the user holds none of them (`user_role_missing`). The audit
holds the reason, never the user. At most 32 roles of up to 128 bytes.

### Effects aimed at another environment

Agents reach production through credentials they were never meant to use: a staging
task finds a production token, and one call deletes a production volume and its
backups. Scope credentials first; at the tool boundary, a gateway can also serve one
environment and refuse effects aimed at another:

```toml
[guards.environments]
current = "staging"                 # the environment this gateway serves
mode = "required"                   # observe: audit, do not refuse
[[guards.environments.targets]]
capabilities = ["adp_infra.delete_volume", "adp_infra.replace_stack"]
pointer = "/volume_id"              # the argument naming the target
prefixes = { "prod-" = "production", "stg-" = "staging" }   # longest match wins
# unmatched = "allow"               # default "refuse": a target it cannot place is refused
[[guards.environments.targets]]
capabilities = ["adp_payments_live.issue_refund"]
environment = "production"          # every call of these targets production
```

A call whose target is another environment is refused with `environment_mismatch`; one
whose target cannot be placed, with `environment_unresolved`. Either way an
`environment_refusal` audit entry names the gateway's environment, the target's and
whether it was enforced. Capabilities no rule names are not environment-scoped, and a
rule naming a capability that is not configured refuses startup.

Startup also notes a capability named like a destructive call (`delete`, `drop`,
`destroy`, `terminate`, `purge`, `replace` and the like, in its tool or capability name)
that is declared `read_only` or `reversible`, or approved below `destructive`, and
`ctx init-tool` says so in the drafted review text. The name is a hint for the reviewer,
never the decision.

### Starter profiles

[`deploy/profiles`](../deploy/profiles) holds two configurations to start from.
`consequential-tools.toml` enforces the gate: readiness required, repeated effects
refused, agents bound to their credentials, strict evidence, task authorization
required, a review floor and step-up on approvals, breakers on refusal storms and effect
rates, and the environment guard. `observe-first.toml` is the same set reporting
instead of refusing where it can. Append one to your configuration, replace the example
capability ids, and run `contextosd --check-config`: it lists what is still missing.

## 7. Score decisions independently

The system under evaluation cannot score itself. Give each evaluator (a rubric
service, an LLM judge, a human review queue) its own API key or OIDC client with only
the `evaluate` scope, and have it post to
`POST /v1/runs/{run_id}/decisions/{record_id}/scores`:

```json
{"evaluator_ref": "evaluator.refund_quality@3", "policy": 1.0, "utility": 0.8, "safety": 1.0}
```

Independence is judged on authenticated principals: a caller that also holds `admit`
or `dispatch`, or that admitted the run or recorded the decision (whatever token it now
presents), is refused (`evaluator_not_independent`), and a principal holding `evaluate`
on one API key and `admit`/`dispatch` on another is refused at startup. With OIDC, issue
evaluator tokens to separate clients. Policy, utility and safety are the
evaluator's, in `[0, 1]`; the runtime measures cost from the signed decision and
latency (milliseconds from admission to the decision, also the decision's
`budget_usage.wall_clock_ms`). Runs admitted before admission times were kept have no
latency: unknown is never reported as zero.
Each evaluator scores a decision once. Scores are signed into the audit chain and
appear beside their decision in the evidence bundle. Unknown scope names in API-key
configuration are refused at startup.

### Escalations

When policy answers `escalate`, the call is blocked (`policy_escalation`, obligation
`escalate`) and an escalation is opened, one per operation (reopened, with its history,
if the operation escalates again after being resolved), audited as
`escalation_opened`; the result names it in `metadata.escalation_id`. Route it to a
human from `GET /v1/escalations` (`audit:read`). When they have dealt with it, an
operator records the outcome, `handled` or `dismissed`, with a reason:
`POST /v1/escalations/{escalation_id}/resolve` (`control`, audited once). Resolving
grants nothing: if the human decides the action should go ahead, it is retried and
goes through policy and approvals like any other call.

To reach approvers where they are, configure webhooks. The leader replica posts each
`escalation_opened` and `escalation_resolved` from the audit chain:

```toml
[[notifications]]
id = "refund-approvers"
url = "https://hooks.internal.example/contextos"
secret_env = "CONTEXTOS_NOTIFY_SECRET"           # at least 32 bytes
link_template = "https://tower.example/escalations/{escalation_id}"
# max_attempts = 12
```

- **Payload.** Each event is a CloudEvent (`io.contextos.escalation.opened` or
  `.resolved`) with the escalation, run, capability, reason codes or outcome, and the
  link. It never includes tool arguments.
- **Verifying.** Check `ContextOS-Signature: t=<unix>,v1=<hex>`: HMAC-SHA256 over
  `"<t>.<body>"` with the secret. Reject stale timestamps.
- **Duplicates.** Delivery is at least once, so drop repeated event `id`s.
- **History.** A new webhook starts at the chain's head and does not replay history.
- **Failures.** Failed posts back off, and after `max_attempts` the event is given up.
  It is logged and counted in `contextos_notifications_total{webhook,outcome}`, and
  `ContextOSNotificationsFailing` pages.
- **What a notification is.** It tells a person a decision is waiting and grants
  nothing. Approve where approvers sign in, never from the message.
- **Relays.** `examples/notify/` relays events to Slack and PagerDuty.
- **Aged holds.** A shared guarantee's `owner_route` webhook also receives
  `io.contextos.hold.aged` for each of its holds older than `owner_after_seconds`
  (see `SHARED_GUARANTEES.md`, "Tell the business owner"); no other webhook does.

### Require scores before a run completes

Scores are evidence after the fact unless something waits for them. With

```toml
[guards]
completion_requires_scores = { policy_floor = 1.0, safety_floor = 0.9 }
```

a run cannot complete while an effect it applied is not part of any recorded
decision (`effect_undecided`: the runtime tracks every confirmed or partial effect, so
an effect left out of the decision reports still counts), while any decision that
applied an effect has no independent score (`decision_unscored`), or while a score's
`policy` or `safety` is below its floor (`decision_below_floor`); every score counts,
so one dissenting evaluator holds the run. Accepting a delegated child applies the
same check to the child, and a parent cannot complete while any child it closed,
accepted or rejected, has unjudged effects (`child_unjudged`). The executor waits for its evaluators, or the run is failed
or cancelled instead. Production turns this on by default (policy 1.0, safety 0.9);
`completion_requires_scores = true` uses those floors elsewhere and `false` opts out.

## 8. Kill switch

Operators (the `control` scope) revoke a target for their tenant: the whole `tenant`,
a `pack` (release tuple, e.g. `ctxpack.support@5.2.0`), a `principal` (an
authenticated caller: its new runs and the runs it admitted, and any run whose
delegation chain names it), an `agent` (the agent id a run declares; to stop whoever
runs it, revoke the principal), a `user` (every run a delegated credential says acts
for them, and new runs declaring them), a `delegation` (one exact chain of actors for
one user, by the `chain_digest` in `run_admitted`), an `adapter` or a
`capability`. A delegated run must use its parent's pack and cannot be admitted while
its parent is revoked:

```sh
curl -X POST "$CONTEXTOS/v1/revocations" -H "Authorization: Bearer $OPS_TOKEN" \
  -d '{"kind": "capability", "target": "adp_payments.issue_refund", "reason": "incident 4711"}'
```

From the next call, effects of runs bound to a revoked tenant, pack, agent, user,
delegation or principal on their chain, and calls to a revoked adapter or capability,
are blocked before anything is reserved, claimed
or sent (`revoked_<kind>`), and new runs of a revoked tenant, pack, agent, user or
delegation are refused. A call already past authorization completes. `POST /v1/revocations/restore`
with the same body restores the target, and `GET /v1/revocations` lists what is
revoked. Every change is audited before it takes effect, with the operator and reason.
The check runs alongside the other authorization reads, so it adds no serial latency.

### Circuit breakers

A kill switch needs someone to pull it. A circuit breaker pulls it automatically when an
agent, an admitting principal or a tenant does too much too fast across all its runs:

```toml
[[guards.circuit_breakers]]
id = "refund_rate"
scope = "agent"            # agent | principal | tenant
count = "effects"          # effects: attempts sent to providers | refusals: blocked or rejected calls
capabilities = ["adp_payments.issue_refund"]   # empty: every capability (every effectful one for effects)
threshold = 50
window_seconds = 60
trip = "revoke"            # refuse: refuse while over | revoke: also revoke the target
```

The breaker estimates the events in a sliding window (two fixed windows, weighted).
While the estimate is at or over `threshold`, a call it governs is refused before
authorization (`circuit_open`, obligation `wait_for_circuit`). The first refusal in a
window trips the breaker. That is audited (`circuit_breaker_tripped`, with the target and
the estimate) and pages (`ContextOSCircuitBreakerOpen`). With `trip = "revoke"`, the
trip also revokes the scope's target, recorded `by: circuit_breaker:<id>`, so the agent
stays stopped until an operator restores it. Breaker refusals do not count towards a
`refusals` breaker, so it reopens once the agent stops being refused. Calls racing in
parallel may overshoot the threshold by their concurrency: a breaker bounds a
runaway, it is not an exact quota. Scope `agent` is as strong as agent binding: turn
on `[guards] agent_binding` so a credential cannot pose as another agent.

## 9. Erase personal content

A run's user-provided content lives in its replay case (the original request), its
compiled context (task prompt and evidence blocks) and any pending tool input requests.
Once the run is finished, past its deadline, or never started, an operator (`control`
scope) erases them:

```sh
curl -X POST "$CONTEXTOS/v1/runs/$RUN/erase" -H "Authorization: Bearer $OPS_TOKEN" \
  -d '{"reason": "data subject request 88"}'
```

Each document becomes a tombstone recording the operator, time, reason and the digest
of what was removed, audited before the content goes; the replay case then answers
`410`, so erased runs drop out of release-gate corpora. Signed DecisionRecords and
audit entries are not rewritten: keep personal data out of decision outputs and
rationales and cite evidence by reference instead.

### Retention

Set a retention period to erase personal content automatically:

```toml
[retention]
run_content_days = 30   # unset (the default): kept until erased on request
```

The leader replica (smallest id among live replicas) sweeps runs admitted more than
that many days ago every `sweep_interval_ms` (default 60 s), `batch` runs (default 500)
per sweep, and erases each finished run exactly as `POST /v1/runs/{id}/erase` would,
with `contextos.retention` as the operator. Runs still in progress are revisited on a
later sweep, never erased under their executor.

## 10. Assess conformance

Conformance applies to one exact workflow, implementation, release and environment, and
needs current runtime evidence verified by observers you trust. Configure those trust
anchors, each naming its tenant:

```toml
[conformance]
trusted_assessors = [{ principal = { principal_id = "assessor_ci", principal_type = "workload", trust_domain = "acme.internal", tenant_id = "tenant_acme_prod" }, public_key = "<base64 Ed25519>" }]
trusted_evidence_observers = [{ principal = { principal_id = "control_monitor", principal_type = "workload", trust_domain = "acme.internal", tenant_id = "tenant_acme_prod" }, public_key = "<base64 Ed25519>" }]
```

`POST /v1/conformance/assess` (`audit:read`) takes the report, its verification, the
control evidence, the contract, features and the workflow scope. The deployment supplies
its own implementation identity, support declaration, profile registry, clock and the
trust anchors for the caller's tenant, so a caller cannot certify itself. Every
attestation is signed (Ed25519, base64) by the principal it names over
`sha256_canonical({"domain": <domain>, "attested": <object>})`: the report together with
the contract and features by its evaluator (`report_signature`), the report
verification by its observer (`verification_signature`), and each evidence observation
by its observer (`evidence_signatures`); see `contextosd::attest` for the domains. Missing,
stale, synthetic or unverified evidence yields `insufficient_evidence`; every outcome is
audited.

## 11. Verify the audit trail independently

An auditor should not have to trust the system being audited. Export a tenant's chain
(`GET /v1/audit/entries`, paged) and the public signing keys (`GET /v1/audit/keys`,
unauthenticated), then verify offline:

```sh
ctx audit-verify --entries entries.json --keys keys.json
# {"verified": true, "entries": 1532, "last_sequence": 1532, "last_record_hash": "sha256:…"}
```

Every entry's payload digest, record hash and Ed25519 signature are checked, and the
chain's linkage from genesis: an edited, deleted, reordered or foreign-signed entry
fails (exit 1). Pin the published keys out of band (they change only on rotation).

Large chains verify incrementally: keep the last entry of each verified export, then
check only what was appended since (`GET /v1/audit/entries?from=<last_sequence + 1>`):

```sh
ctx audit-verify --entries new.json --keys keys.json --continues last-verified-entry.json
```

The new entries must continue that head exactly (next sequence, linked hash, same
tenant), so a rewritten or truncated history cannot pass as a continuation.

### Evidence packs for a review

For a security or compliance review, build a folder the reviewer can check on their
own from the same export:

```sh
contextosd --check-config contextosd.toml > check.txt
ctx evidence-pack --entries entries.json --keys keys.json \
    --framework soc2 --framework eu-ai-act --config-report check.txt --out pack/
```

Frameworks are `soc2`, `iso42001`, `eu-ai-act` and `owasp-agentic`. The pack is
built only from a chain that verifies, and it is deterministic: the same export and
options give the same files.

| File | What it holds |
|---|---|
| `entries.json`, `keys.json` (and `anchor.json` with `--continues`) | The export and keys exactly as supplied, so `ctx audit-verify` re-checks them |
| `controls.json` | Per framework and control: what ContextOS enforces, the audit event kinds that evidence it, their counts over the period, and a status: `evidenced`, `no_events_in_period` or `outside_audit` (organizational or deployment duties, with a note) |
| `coverage.md` | The period, the verification, what the evidence covers and what it does not (calls that bypass the gateway, content beyond the entries, organizational controls, configuration unless a report is attached), and the control tables |
| `config-report.txt` (or the supplied extension) | The `--config-report` file, included as supplied |
| `manifest.json` | The period, verification result, event counts, control status tally and every file's SHA-256 |

A count shows that a control acted in the period, not that it was configured
everywhere it should be. The configuration report covers that part.

## 12. Operate

For incidents (containment with the kill switch, evidence, recovery, postmortems), see
[INCIDENT.md](INCIDENT.md).

**Production checklist.** Production mode enforces on its own: no published
development keys, HTTPS for providers, adapters and the KMS, scope separation, runs that pin
`model_profile` and `evaluator_suite` in `release_refs` (`[guards]
required_release_refs`, default in production), user claims that state a `role`
(`[guards] require_user_role`, default in production; `user_role_missing`), and
delegations whose result schema is registered (`[[result_schemas]]`), and runs whose
effects are independently scored before they complete
(`[guards] completion_requires_scores`). Opt out of
either only explicitly (`required_release_refs = []`, `require_user_role = false`).
It warns about, but accepts, an audit signing seed in the environment: keep the key in
a KMS (below). Also turn on:

```toml
[guards]
require_tool_schemas = true      # every capability has input and output schemas

[[result_schemas]]               # what delegated runs' results must meet
# ref = "schema://…"
# path = "…"

[retention]
run_content_days = 30            # personal content does not outlive its purpose

[audit.kms]                      # signing key held in a KMS, pinned
# …

[providers.memory]               # if runs recall memory: verified against promoted state
# …
```

Production refuses runs without `user.role` (see the threat model's residual risks).

- **Store:** PostgreSQL (to try one locally without Docker,
  `eval "$(scripts/dev-postgres.sh)"` starts a disposable server and exports
  `CONTEXTOS_DATABASE_URL`). Create or upgrade the schema with a role that owns it,
  before the first start and after each upgrade:

  ```sh
  CONTEXTOS_DATABASE_URL=postgres://contextos_owner@db/contextos contextosd --migrate contextosd.toml
  ```

  The Helm chart runs this as a pre-install and pre-upgrade hook with
  `migration.enabled` (see its README).

  Then run the server as a runtime role with `USAGE` on the schema, `SELECT, INSERT,
  UPDATE` on `contextos_documents`, `SELECT, INSERT` only on `contextos_audit_log`
  (updates and deletes are also blocked by trigger) and `SELECT` on
  `contextos_schema_version`. A server whose schema is current starts without DDL; one
  whose schema needs migrating tries to migrate, and with a runtime role that cannot,
  refuses to start and says to run `--migrate`.
- **Keys:** sign the audit chain with a key held in a KMS, so the runtime never holds
  the private key:

  ```toml
  [audit]
  key_id = "audit-2026-10"
  [audit.kms]
  kind = "vault_transit"          # HashiCorp Vault / OpenBao Transit, ed25519 key
  url = "https://vault.internal:8200"
  key_name = "contextos-audit"
  token_env = "VAULT_TOKEN"
  key_version = 1                  # pinned: a rotation inside Vault does not change this key_id
  public_key = "<base64url Ed25519 public key of that version>"
  ```

  The public key is pinned: startup fails if the KMS reports another (a hijacked or
  misconfigured endpoint cannot substitute its own), the URL must be HTTPS outside
  development, and a signature from any other key version is refused. To rotate in
  Vault, add the new version under a new `key_id` and retire the old one.

  Each group commit signs all its entries in one Transit `batch_input` call, and every
  signature is checked against the key's public key before anything is written; a KMS
  failure fails the append. (`signing_seed_env` holds a seed in process memory instead,
  for development.) To rotate,
  give the servers a new seed and `key_id`, and list the old key under
  `[audit] retired_keys = [{ kid = "…", public_key = "…", retired_at = "…" }]` (the
  key `GET /v1/audit/keys` published, and when it stopped signing), so entries it
  signed keep verifying and stay published. A retired key verifies only entries emitted
  up to `retired_at`, so if it later leaks it cannot sign new history. The rotation
  is recorded once in each tenant's chain: the first entry a new key signs after one a
  retired key signed is `signing_key_rotated` (`{from_kid, to_kid}`). During a rolling
  rotation, set `retired_at` after the last old replica stops;
  give independent verifiers the new key before switching writers.
- **Overload protection:** `[limits]` caps concurrent requests per instance
  (`max_in_flight`, default 4096; beyond it, `503` with `Retry-After`), request rate
  per tenant (`requests_per_second` / `burst`, default 500 / 1000; `429` with
  `Retry-After`) and governed effects in progress per tenant (`max_concurrent_dispatch`,
  default 256). `[[limits.tenants]]` overrides any of these for one tenant. Limits
  apply after authentication; health probes and metrics are exempt. Tenant limits
  are cluster-wide: replicas sharing a store heartbeat every `heartbeat_ms` (default
  5000) and each enforces its share (limit ÷ live replicas, `contextos_replicas` in
  `/metrics`), with no store round trip per request. The split assumes the load
  balancer spreads a tenant's traffic evenly; a dead replica's share returns to the
  others within three heartbeats.
- **Declare only what you enforce:** `[support].controls` is a claim that your providers
  enforce those controls. Runs that need more are refused at admission.
- **Traces:** set `OTEL_EXPORTER_OTLP_ENDPOINT` (and optionally `OTEL_SERVICE_NAME`,
  `OTEL_RESOURCE_ATTRIBUTES`, `OTEL_EXPORTER_OTLP_HEADERS`) to export spans over
  OTLP/HTTP. A caller's W3C `traceparent` becomes the parent of the request span, so
  each governed dispatch appears inside the agent's distributed trace. Build with
  `--no-default-features` to leave the exporter out entirely.
- **Metrics:** `contextos_http_requests_total{route,status}`,
  `contextos_http_request_duration_ms{route}`,
  `contextos_dispatch_outcomes_total{capability,status}`,
  `contextos_dispatch_refusals_total{reason}`, `contextos_admissions_total{pack}` and
  `contextos_decisions_total{status}`. Labels are bounded: capabilities and packs are
  those pinned at startup (anything else counts as `unpinned`); tenants are not a label
  (per-tenant evidence is in the audit chain).
- **Governance gauges** (leader replica only, refreshed each full sweep of the exposure
  ledgers): `contextos_shared_holds{guarantee,state}` (state as in hold inspection),
  `contextos_shared_hold_oldest_seconds{guarantee}`,
  `contextos_shared_receipts_fill_ratio{guarantee}`, `contextos_shared_ledgers_unreadable`,
  `contextos_escalations_open` and `contextos_governance_sweep_completed_timestamp_seconds`.
  Aggregate them with `max`. A hold older than 15 minutes is logged once with its tenant
  and resource digest for your SIEM.
- **Alerts:** the Helm chart's `prometheusRule.enabled` installs rules for all of the
  above; each links its runbook in [INCIDENT.md](INCIDENT.md#alerts).
- **Spans:** `http.request`, with `contextos.compile`, `contextos.admit`,
  `contextos.delegate`, `contextos.dispatch`, `contextos.reconcile`, `contextos.decision`,
  `contextos.score`, `contextos.memory` and `contextos.erase` inside it, each carrying the
  tenant, run and trace ids. Logs are JSON with the same spans.
- **Governed calls:** every tool call (REST, MCP, continuation, check or compensation)
  gets one `contextos.dispatch` span, exported as `execute_tool <capability>` with the
  OpenTelemetry GenAI attributes (`gen_ai.operation.name = "execute_tool"`,
  `gen_ai.tool.name`, `gen_ai.tool.call.id`), so agent-trace views show it as a tool
  step. It also carries `contextos.status`, `contextos.reason_codes`,
  `contextos.operation_id`, `contextos.action_digest`, the stage the pipeline stopped
  in (`contextos.stage`: `fence`, `surface`, `bind`, `authorize`, `reserve`, `claim`,
  `dispatch`, `settle` or `result`) and the milliseconds each stage took
  (`contextos.stages = "fence=0.1 surface=0.2 bind=0.4 authorize=3.1 …"`). A refusal
  sets `error.type` to its first reason code; an infrastructure failure also sets the
  span's status to error.
- **Access log:** one JSON line per governed call on target `contextos::access`, with
  tenant, run, capability, tool call, operation, status, reason codes, stage, stage
  timings and duration. It follows `RUST_LOG`; `RUST_LOG=info,contextos::access=off`
  turns it off and `RUST_LOG=warn,contextos::access=info` keeps only it. The signed
  audit chain stays the record of what happened; the access log is for searching and
  dashboards.
- **Private CAs:** outgoing TLS (providers, adapters, the KMS, OIDC issuers,
  notification webhooks, the OTLP exporter, Tower's sources) trusts the public roots
  bundled in the binary. For services behind your own CA, set `CONTEXTOS_CA_BUNDLE` to
  a PEM file of its certificates; it is read once at startup, which fails on a file
  that holds none, and `--check-config` reports it. PostgreSQL takes its CA in the URL
  (`?sslmode=verify-full&sslrootcert=/path/ca.pem`). The Helm chart mounts the bundle
  with `extraVolumes`, `extraVolumeMounts` and `extraEnv` (see its README).
- **TLS:** most deployments terminate TLS at an ingress or mesh. Without one, serve
  HTTPS directly, and optionally require client certificates (mutual TLS) so only
  workloads holding one can connect:

  ```toml
  [server.tls]
  cert_path = "/etc/contextos/tls/tls.crt"     # chain: certificate, then intermediates
  key_path = "/etc/contextos/tls/tls.key"
  client_ca_path = "/etc/contextos/tls/clients.pem"   # optional: require client certs
  # reload_secs = 60                            # pick up rotated files; 0 never
  # max_connections = 10000                     # past this, clients wait to be accepted
  # header_timeout_secs = 30                    # idle connections and slow headers close
  ```

  HTTP/2 and HTTP/1.1 are offered by ALPN. Rotated files (for example a
  cert-manager Secret) are served to new connections within `reload_secs`; a
  rotation that does not load keeps the previous certificate and logs a warning.
  Callers still authenticate with their token: mTLS decides who may connect, not who
  they are. `--check-config` loads the files. The Helm chart mounts them with
  `extraVolumes` and `extraVolumeMounts`.

  Without a proxy the server bounds slow clients itself: a TLS handshake has 10
  seconds; a connection with no request in progress for `header_timeout_secs` is
  closed, and an HTTP/1.1 request must finish its headers within it; HTTP/2 allows
  200 concurrent requests per connection and closes connections that stop answering
  pings. At most `max_connections` are open at once; further clients wait in the
  accept queue rather than being refused. A failed accept (for example, out of file
  descriptors) backs off up to a second instead of spinning. Set the process's file
  descriptor limit above `max_connections`.
- **Image:** `Dockerfile` builds a distroless, non-root image. Releases publish it to
  GHCR for `linux/amd64` and `linux/arm64` (one tag, each architecture built
  natively), signed with cosign (keyless) and with build provenance; verify before
  deploying.
- **Kubernetes:** `deploy/helm/contextosd` (see its README).

### Backup and restore

Everything `contextosd` remembers is in its PostgreSQL database: documents (runs,
operation and budget ledgers, shared-guarantee exposure, approvals, decisions) and the
audit log. Back up:

- **The database, as one consistent snapshot.** `pg_dump` takes one; continuous
  archiving (base backups plus WAL, point-in-time recovery) loses least. Never back up
  the two tables separately: a ledger and its audit entries must agree.
- **The audit verifying keys,** current and retired (`[audit] retired_keys`), and the
  signing key in your KMS, so restored history still verifies.
- **Configuration, packs and capability manifests,** which belong in version control.
- **The audit chain, continuously, outside the database.** Export
  `GET /v1/audit/entries` to your SIEM or write-once storage, so you can tell what a
  restore removed.

A restore takes the runtime back to the restore point, but your providers do not go
back. Before serving again:

1. Keep agents out: revoke the tenants (section 8), or do not route traffic yet.
2. Verify the restored chain (`GET /v1/audit/verify`, or `ctx audit-verify` on an
   export) and compare its last entry with your external copy. Entries after the
   restore point are gone from the database; the external copy is the record of them.
3. Reconcile with the providers' records for the gap. Operations the restored ledgers
   show as unknown or in flight are reconciled as usual (INCIDENT.md, *Unknown effects*). Effects
   applied after the restore point are absent from the ledgers, so shared guarantees
   undercount them: account for them at the provider, and lower the affected limits
   until the period they cover has passed.
4. Have each executor take its runs over (`attach(...).take_over()`) rather than
   continue from memory; restored runs may be at an older state than the executor
   saw.
5. Restore the tenants.

Rehearse this restore before you rely on it.

## 13. Govern every agent with Tower

`towerd` is the organisation's governance plane over its ContextOS runtimes. The full
developer documentation (architecture, flows, governance model, intelligence, API,
security, a step-by-step guide and operations) is in [docs/tower](tower/README.md). Each
runtime keeps deciding effects; Tower reads every runtime tenant through its API with a
read-only `audit:read` key, verifies each audit entry (digest, hash link, Ed25519
signature) before using it, and answers the organisation's questions: which agents
exist and who owns them, what each can do, which controls that requires and where they
are missing, what changed, and what is going wrong.

```toml
[[sources]]
id = "eu-support"
url = "https://contextosd.eu.internal"
token_env = "TOWER_EU_SUPPORT_AUDIT_KEY"          # audit:read for that tenant
control_token_env = "TOWER_EU_SUPPORT_CONTROL_KEY"  # optional: fleet kill switch
business_unit = "Customer Operations"
```

- **Inventory and accountability.** Agents are discovered from `run_admitted` (which
  agent ran under which pack, contract, controls and model); owners declare purpose,
  users served, lifecycle and regulatory context. An undeclared agent is a finding.
- **Required controls from what an agent can do.** Each agent's authority graph is the
  capabilities of its packs with their ActionRisk; the control profiles it needs follow
  from it (external effects need enterprise, irreversible or physical effects and
  restricted data need high-assurance, delegation needs durable-delegated), and Tower
  reports which required controls each runtime does not declare.
- **Findings, guardrails, waivers.** Built-in checks plus organisation guardrails
  (JsonLogic over agent facts, evaluated by the kernel's evaluator). Waivers are
  time-boxed and decided by someone other than the requester.
- **Reviews and drift.** A risk review approves an agent's current authority; any
  capability added later is drift until reviewed again.
- **Anomalies and the fleet kill switch.** Each agent's last hour against its own week;
  operators revoke an agent or capability on every runtime at once.
- **Intelligence (optional).** With `[intelligence] provider = "anthropic"` and
  `ANTHROPIC_API_KEY`, Claude answers questions about the fleet from read-only tools
  with checked citations, drafts guardrails from plain language (checked against the
  inventory before anyone can save them), drafts intake reviews, briefs anomalies and
  explains runs. It never acts or approves; every use is journalled.
- **Evidence.** Every governance decision is in Tower's signed journal
  (`GET /api/journal`, keys at `/api/journal/keys`), verifiable with `ctx audit-verify`.

Roles: `viewer`, `owner` (their teams' agents), `risk`, `operator`, `admin`. Try it:
`./examples/tower/run.sh --serve`, then open `http://127.0.0.1:8090/tower/`.

### Hold a consequential workflow to the full set of controls

A refund is safe to run unattended only when several separately configured mechanisms
are all in place. Leave any one out and the runtime still works, so nothing reports
the gap. The `[readiness]` profile reports it. It is opt-in:

```toml
[readiness]
mode = "required"                               # "report": warn, do not refuse
capabilities = ["adp_payments.issue_refund"]    # unset: every consequential capability
global_evidence = ["policy.eval"]               # requirements not about one subject
```

A capability is consequential when its `action_risk.effect` is `external_state` or
`physical_world`. For each one, the profile checks:

| Area | Must hold | Without it |
|---|---|---|
| `finality` | `recovery.completion` and `recovery.reference_pointer` | the call is settled by a status code, and the effect has no provider id to reconcile or witness |
| `witness` | an `outcome` contract | the run completes without an independent source confirming the effect |
| `owner` | a `[[guarantees]]` entry covering it, with `owner_route` | concurrent runs can together exceed the business limit; aged holds reach no one |
| `resource` | `resource_pointers` | effects are not tied to the order or account they change |
| `intent` | an `intent` key | the same request redelivered into another run is applied again |

For the deployment as a whole, it checks:

| Area | Must hold | Without it |
|---|---|---|
| `evidence` | `[guards] evidence = "strict"`, and every pack's gated requirement bound in `[[evidence_subjects]]` or listed in `global_evidence` | callers assert their own evidence, or an attestation about customer A satisfies a refund to customer B |
| `actor` | `[guards] agent_binding = "required"` | a run may declare an agent its credential was not issued for |

With `required`, both `contextosd --check-config` and startup refuse the configuration
and list every gap at once:

```text
workflow readiness (required): 3 gap(s) across adp_payments.issue_refund:
  adp_payments.issue_refund [witness]: no outcome contract: the run can complete without an independent witness confirming the effect
  adp_payments.issue_refund [owner]: no covering guarantee names an owner_route: an aged hold reaches no business owner
  deployment [actor]: agent_binding = "observe": a run may declare an agent its credential was not issued for
```

With `report`, each gap is a warning. Start with `report` on an existing deployment,
close the gaps, then switch to `required`. The checks read only the configuration,
packs and manifests: a ready configuration still depends on the witness and the owner
actually answering. Packs reloaded later are not re-checked, so run `--check-config`
in CI before shipping one.

### Check configuration changes in CI

The configuration file stays the source of truth and is reviewed like code. The
`config` scope (deployment administrators; never together with `admit` or `dispatch`)
reads the running configuration (`GET /v1/config`: text, digest, effective values with
defaults resolved, posture findings) and dry-runs a proposed one (`POST
/v1/config/validate`): the startup parser and checks, then every effective change
classified as `tightens`, `loosens` or `changes`. Call it from CI on a pull request and
require an approver for any loosening:

```sh
jq -Rs '{toml: .}' contextosd.toml | curl -sf -H "authorization: Bearer $CONFIG_KEY" \
  -H 'content-type: application/json' -d @- "$CONTEXTOS_URL/v1/config/validate" \
  | jq -e '.valid and (.loosening | length == 0)'
```

Files and environment variables a configuration names are checked only when a server
starts with it.
