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
locally. After a crash, `client.attach(...).take_over()` resumes the run and fences the
old process.

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
and risk annotations. Each `tools/call` runs the full governed pipeline. Refusals come
back as tool errors whose `structuredContent` carries the status and reason codes, so
the model sees that the action did not happen. Operation identity comes from
`_meta["io.contextos/idempotencyKey"]` when given; otherwise effectful calls derive it
from the capability and arguments, so a host that retries a call it thinks failed
cannot apply the effect twice. Cited evidence goes in `_meta["io.contextos/evidenceRefs"]`.
A tool's `input_required` is passed through with `requestState`, and the host's retry
with `inputResponses` continues the same operation.

Give capability manifests an `input_schema` (JSON Schema) and `description`: the
schema is shown to hosts and enforced on every call (`arguments_invalid`), and
violations report argument paths only, never values.

## 3. Run `contextosd`

The HTTP API is described by OpenAPI 3.1 in `openapi/contextosd.v1.json`, also served
at `GET /v1/openapi.json`. Request and record bodies reference the normative ContextOS
JSON Schemas by `$id`, so generated clients in any language validate against the spec
itself. Tests keep the document and the router in step and validate live request
and response bodies against it.

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
the next stage that changes no outcome. `POST /v1/rollouts/clear` returns all new runs
to the baseline; revoking the candidate pack (the kill switch) also stops runs already
on it.

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

A reservation that does not fit is refused (`budget_exhausted`); replans count against
the run's replan allowance. A model call reserves at least `[guards]
model_call_min_tokens` (default 1,000), so no call is free. Settlement depends on who reports: an LLM gateway or other
metering service holding the `meter` scope (and neither `admit` nor `dispatch`) settles
the usage it measured and releases the rest (usage above the reservation is charged as
audited overage, up to the run's remaining capacity), while the run's own executor
settling is charged the whole reservation, because self-reported usage is not evidence.
The principal that admitted the run cannot meter it. Pass the
reservation id to your model gateway (for example in a request header) so it can meter
the call.

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

## 11. Operate

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
- **Metrics:** `contextos_http_requests_total`, `contextos_http_request_duration_ms`,
  `contextos_dispatch_outcomes_total{status}`. Logs are JSON with a `contextos.dispatch`
  span per tool call (run, operation, capability, digest, status, reasons).
- **Image:** `Dockerfile` builds a distroless, non-root image. Releases publish it to
  GHCR signed with cosign (keyless) and with build provenance; verify before deploying.
- **Kubernetes:** `deploy/helm/contextosd` (see its README).
