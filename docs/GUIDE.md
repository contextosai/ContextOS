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

## 2. Govern an existing Python agent over HTTP

`contextos.client` is a standard-library-only client for `contextosd`. It holds the
executor generation for you and turns non-success results into exceptions, so agent
code cannot mistake a pause or refusal for a result:

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
import { Client, ToolPaused, ToolBlocked, governedTool } from "@contextos/kernel/client";

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
contextosd --config deploy/contextosd.example.toml
```

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
| `POST /v1/runs/{run_id}/operations/{operation_id}/attest-absence` | `attest` | Release a started effect with no fact, on evidence it did not apply |
| `POST /v1/runs/{run_id}/operations/{operation_id}/compensate` | `dispatch` | Undo an applied effect with its declared compensation |
| `POST /v1/runs/{run_id}/compensate` | `dispatch` | Compensate the run's effects newest first (saga) |
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
  counted. An effect in another currency than `amount_total` exceeds it.
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

## 4. Integrate your services

Dispatch needs three fact services you operate (see `crates/contextos-adapters/src/remote.rs`
for the request/response contracts and `examples/support-refund/dev_services.py` for a
minimal, development-only implementation):

- **Authority broker** — verifies the agent's mandate and returns grants plus verified,
  current, unrevoked observations for the exact binding.
- **Control plane** — attests that each required independent control (isolation, egress
  mediation, data-flow policy…) is active for this action digest and pinned policy.
- **Approval service** — opens requests bound to the action digest and returns verified
  decisions and approver entitlements.
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

Capabilities are admitted only from reviewed manifests (`ctx manifest <file>`); protocol
discovery is never permission. Adapters: MCP `2026-07-28` (stateless Streamable HTTP) or
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
the next stage that changes no outcome.

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
The principal that admitted the run cannot meter it.

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
[`examples/metering-proxy`](../examples/metering-proxy) is a reference gateway for
OpenAI Chat Completions and Responses and Anthropic Messages, streamed or not.

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
authenticated caller: its new runs and the runs it admitted), an `agent` (the agent id
a run declares; to stop whoever runs it, revoke the principal), an `adapter` or a
`capability`. A delegated run must use its parent's pack and cannot be admitted while
its parent is revoked:

```sh
curl -X POST "$CONTEXTOS/v1/revocations" -H "Authorization: Bearer $OPS_TOKEN" \
  -d '{"kind": "capability", "target": "adp_payments.issue_refund", "reason": "incident 4711"}'
```

From the next call, effects of runs bound to a revoked tenant, pack or agent, and calls
to a revoked adapter or capability, are blocked before anything is reserved, claimed
or sent (`revoked_<kind>`), and new runs of a revoked tenant, pack or agent are
refused. A call already past authorization completes. `POST /v1/revocations/restore`
with the same body restores the target, and `GET /v1/revocations` lists what is
revoked. Every change is audited before it takes effect, with the operator and reason.
The check runs alongside the other authorization reads, so it adds no serial latency.

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

## 12. Operate

For incidents (containment with the kill switch, evidence, recovery, postmortems), see
[INCIDENT.md](INCIDENT.md).

**Production checklist.** Production mode enforces on its own: no published
development keys, HTTPS endpoints and KMS, scope separation, runs that pin
`model_profile` and `evaluator_suite` in `release_refs` (`[guards]
required_release_refs`, default in production), user claims that state a `role`
(`[guards] require_user_role`, default in production; `user_role_missing`), and
delegations whose result schema is registered (`[[result_schemas]]`), and runs whose
effects are independently scored before they complete
(`[guards] completion_requires_scores`). Opt out of
either only explicitly (`required_release_refs = []`, `require_user_role = false`).
Also turn on:

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

- **Store:** PostgreSQL. Grant the runtime role `SELECT, INSERT, UPDATE` on
  `contextos_documents` and `SELECT, INSERT` only on `contextos_audit_log` (updates and
  deletes are also blocked by trigger).
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
- **Spans:** `http.request`, with `contextos.compile`, `contextos.admit`,
  `contextos.delegate`, `contextos.dispatch` (run, operation, capability, digest,
  status, reasons), `contextos.continue`, `contextos.reconcile`, `contextos.decision`,
  `contextos.score`, `contextos.memory` and `contextos.erase` inside it, each carrying the
  tenant, run and trace ids. Logs are JSON with the same spans.
- **Image:** `Dockerfile` builds a distroless, non-root image. Releases publish it to
  GHCR signed with cosign (keyless) and with build provenance; verify before deploying.
- **Kubernetes:** `deploy/helm/contextosd` (see its README).

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
