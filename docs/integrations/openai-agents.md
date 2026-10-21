# OpenAI Agents SDK under ContextOS

This guide puts an OpenAI Agents SDK agent under `contextosd`: every tool call is
governed by the gateway, every model call spends the run's budget, refusals and pauses
map onto the SDK's tool-error and human-in-the-loop mechanisms, and the run ends with a
signed DecisionRecord. It targets the Python SDK (`openai-agents` 0.24) and covers the
TypeScript SDK (`@openai/agents` 0.20) alongside; the APIs mirror each other. The
runnable versions are [examples/frameworks/openai-agents](../../examples/frameworks/openai-agents/README.md)
and [examples/frameworks/openai-agents-js](../../examples/frameworks/openai-agents-js/README.md).

The integration is your tools, one `ModelProvider` wrapper and a tool-error function.
The SDK's `Runner` keeps its loop; the gateway enforces everything that matters for
safety, and the integration only makes sure the agent asks it and tells the model the
truth about what happened.

## 1. Install

```sh
pip install "openai-agents==0.24.0"
npm install @openai/agents@0.20.0 zod@4.6.7
```

`contextos.client` is standard-library only; vendor `bindings/python/contextos` or
install it from your internal index. The Node client is `bindings/node/client.mjs`
(`@contextos/kernel/client`).

## 2. Admit a run

Admit one ContextOS run per agent task, before calling `Runner.run`:

```python
from contextos.client import Client

client = Client(base_url, token=os.environ["CONTEXTOS_TOKEN"])
run = client.admit(admission_body)        # holds the executor generation
```

The run, not the SDK, holds the task's authority, budget and deadline. An SDK run that
outlives a crash is resumed under the same ContextOS run (section 6).

## 3. Governed tools as function tools

A `governed_tool` keeps its signature and docstring, so `function_tool` builds the
schema from it; the body never runs, each call goes to the gateway:

```python
from agents import Agent, ModelSettings, function_tool
from contextos.client import governed_tool

@governed_tool(run, "adp_orders.lookup", approval_mode="read_only")
def lookup_order(order_id: str) -> dict:
    """Look up an order's status, amount (amount_minor) and refund eligibility."""

@governed_tool(run, "adp_payments.issue_refund", approval_mode="destructive",
               idempotency_key=lambda order_id, **_: f"refund:{order_id}",
               tool_call_id=lambda order_id, **_: f"tc_refund_{order_id}", evidence_refs=EVIDENCE)
def issue_refund(order_id: str, customer_id: str, amount_minor: int) -> dict:
    """Issue a refund for an order to its customer, in minor units of the order's currency."""

agent = Agent(
    name="support", instructions=INSTRUCTIONS, model="gpt-6.1-sol",
    model_settings=ModelSettings(parallel_tool_calls=False),
    tools=[function_tool(lookup_order, failure_error_function=governed_failure),
           function_tool(issue_refund, failure_error_function=governed_failure, needs_approval=True)],
)
```

Derive the idempotency key and tool-call id from the arguments, never from the SDK's
`call_id`: the model mints a new `call_id` each time it repeats itself, and deriving the
key from it would let a repeated refund through as a new operation. Sync tools run in a
worker thread (`asyncio.to_thread`), so the blocking client does not stall the loop.

In TypeScript, `tool()` takes a zod schema and calls the governed function:

```ts
import { Agent, tool } from "@openai/agents";
import { z } from "zod";

const issueRefund = governedTool(run, "adp_payments.issue_refund", {
  approvalMode: "destructive", idempotencyKey: (a) => `refund:${a.order_id}`,
  toolCallId: (a) => `tc_refund_${a.order_id}`, evidenceRefs: EVIDENCE,
});
const refundTool = tool({
  name: "issue_refund",
  description: "Issue a refund for an order to its customer, in minor units of the order's currency.",
  parameters: z.object({ order_id: z.string(), customer_id: z.string(), amount_minor: z.number().int() }),
  execute: (args) => issueRefund(args),
  errorFunction: governedFailure,
  needsApproval: true,
});
```

## 4. Budget every model call

Reserve before each model call and settle after it, through a `ModelProvider` that wraps
every model the runner resolves:

```python
from agents import Model, ModelProvider, RunConfig, Runner
from agents.models.multi_provider import MultiProvider

class BudgetedModel(Model):
    def __init__(self, run, inner: Model, tokens: int = 1000):
        self.run, self.inner, self.tokens = run, inner, tokens

    async def get_response(self, *args, **kwargs):
        reservation = self.run.reserve_usage("model_call", tokens=self.tokens)  # budget_exhausted raises
        try:
            return await self.inner.get_response(*args, **kwargs)
        finally:
            self.run.settle_usage(reservation)

    async def stream_response(self, *args, **kwargs):
        reservation = self.run.reserve_usage("model_call", tokens=self.tokens)
        try:
            async for event in self.inner.stream_response(*args, **kwargs):
                yield event
        finally:
            self.run.settle_usage(reservation)

    def get_retry_advice(self, request):
        return self.inner.get_retry_advice(request)

class BudgetedProvider(ModelProvider):
    def __init__(self, run, inner: ModelProvider):
        self.run, self.inner = run, inner

    def get_model(self, model_name):
        return BudgetedModel(self.run, self.inner.get_model(model_name))

config = RunConfig(model_provider=BudgetedProvider(run, MultiProvider()), trace_include_sensitive_data=False)
result = await Runner.run(agent, goal, run_config=config, max_turns=8)
```

Why not `RunHooks.on_llm_start`/`on_llm_end`: they fire once per turn, `on_llm_end` does
not fire when the call raises (the reservation would stay held), and the SDK's model
retries happen between them unbudgeted. The wrapper sits under the retry loop, so every
attempt reserves and every reservation settles. Settling as the executor charges the
whole reservation; pass the reservation id to an LLM gateway with the `meter` scope to
charge measured usage instead (GUIDE section 6).

The provider applies only to agents whose `model` is a name (or unset). An agent built
with a `Model` instance bypasses `RunConfig.model_provider`; wrap that instance in
`BudgetedModel` yourself. In TypeScript, pass the provider to the `Runner`:

```ts
const budgetedModel = (run, inner: Model): Model => ({
  getResponse: (request) => budgeted(run, () => inner.getResponse(request)),
  async *getStreamedResponse(request) {
    const reservation = await run.reserveUsage("model_call", { tokens: 1000 });
    try { yield* inner.getStreamedResponse(request); } finally { await run.settleUsage(reservation); }
  },
  getRetryAdvice: (args) => inner.getRetryAdvice?.(args),
});
const runner = new Runner({
  modelProvider: { getModel: async (name) => budgetedModel(run, await new OpenAIProvider().getModel(name)) },
  traceIncludeSensitiveData: false,
});
```

When the budget is spent the reservation is refused and `Runner.run` raises; record a
`REJECTED` or `DEFERRED` decision, or fail the run. Do not catch it and retry.

## 5. Map outcomes to SDK behavior

Governed calls raise `ToolPaused`, `ToolBlocked`, `ToolRejected` or `ToolFailed`. The SDK
turns a tool's exception into model-visible text with the tool's failure function, and
its default (Python `failure_error_function`, TypeScript `errorFunction`) answers
**"An error occurred while running the tool. Please try again."** That is wrong for every
governed outcome. Replace it:

```python
def governed_failure(ctx, error: Exception) -> str:
    stops = isinstance(error, ToolPaused) and error.kind in ("approval", "input", "unknown_outcome")
    if isinstance(error, ToolOutcome) and not stops:
        return refusal(error)        # "NOT DONE (blocked: …). The action did not take effect; do not retry it."
    raise error                      # stops the run
```

`ToolPaused.kind` says what a pause waits on, so the failure function does not match
obligation or reason codes itself:

| Gateway result | What the SDK does |
|---|---|
| `blocked`, `rejected`, `failed` | Tool output is the refusal text; the model explains instead of retrying. |
| `paused`, `kind == "duplicate"` (`retry_unsafe`, `operation_in_flight`) | A repeat of an operation that already exists. Refusal text: "ALREADY REQUESTED (retry_unsafe): this exact action was submitted before and was not repeated." |
| `paused`, `kind == "approval"` | Wait in the tool call while a reviewer decides, then re-send the same call (below). Raised again, it stops the run. |
| `paused`, `kind == "input"` | Raise. Answer with `run.provide_input(paused, envelope, responses)`. |
| `paused`, `kind == "unknown_outcome"` | Raise. The effect may have happened: `run.reconcile(operation_id)` first. |
| `ContextOSHTTPError` (transport, `executor_stale`) | Raise. Never text; the outcome of an effect is unknown. |

A function that raises propagates out of `Runner.run`, wrapped: Python raises
`UserError("Error running tool …")` with the `ToolPaused` as `__cause__`; TypeScript
throws a `ToolCallError` whose `error` is the `ToolOutcome` (and whose `state` is the
`RunState` at that point):

```python
try:
    result = await Runner.run(agent, goal, run_config=config)
except UserError as error:
    if not isinstance(error.__cause__, ToolPaused):
        raise
    paused = error.__cause__        # wait for approval, answer input or reconcile; never retry blindly
```

**Approvals.** Two layers, used together. The SDK's `needs_approval` (`needsApproval`)
interrupts *before* a tool runs: `result.interruptions` lists the pending
`ToolApprovalItem`s, your reviewer calls `state.approve(item)` or `state.reject(item)`
on `state = result.to_state()` (TypeScript: `result.state`), and `Runner.run(agent, state)`
resumes. Approving there grants nothing at the gateway: the call is still authorized,
and the approval service bound to the action digest still has the final say.

When the gateway itself pauses for approval (`kind == "approval"`), it has decided only
now, as the call arrived: after the SDK's approval point, and a running tool cannot raise
an SDK interruption. For an approval a reviewer gives promptly, wait inside the tool
call, then re-send the identical call (same arguments, same operation key), which
redeems that exact approval. The model never sees the pause. Wrap each governed
function before `function_tool` (TypeScript: around `execute`); this is what the
examples do, exercised end to end by `./examples/frameworks/run.sh openai-agents
--approval` (and `openai-agents-js`), where the lookup and the refund both pause:

```python
def awaiting_reviewer(function):
    @functools.wraps(function)                      # keeps the signature for the tool schema
    def call(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except ToolPaused as paused:
            if paused.kind != "approval":
                raise                               # mapped by governed_failure
            wait_for_reviewer(paused.report["approval_request_id"])
            return function(*args, **kwargs)        # the same call, redeemed
    return call

lookup_order, issue_refund = map(awaiting_reviewer, tools(run))
```

If the wait can outlast the process, let the pause raise instead (the run stops as
above) and resume, once approved, from a `RunState` checkpointed before the call
(section 6): the runner re-sends the same call, which redeems the approval. That needs
an SDK interruption, and so a checkpoint, before every call the gateway can pause; the
examples do not exercise that route.

## 6. Checkpoint and resume

The SDK's `RunState` serializes the conversation, the current agent, pending approvals
and decisions (`state.to_json()`, `state.to_string()`; TypeScript `state.toString()`).
It is the SDK's state, not the run's authority. Save it as the ContextOS checkpoint at
each interruption, after the reviewer's decisions, so a replacement executor can resume
where the run was:

```python
state = result.to_state()
for item in result.interruptions:
    state.approve(item)                             # your reviewer's decision
revision = run.checkpoint({"sdk_run_state": state.to_json()}, revision)["revision"]
result = await Runner.run(agent, state, run_config=config)
```

After a crash, take the run over (the old executor is fenced, `executor_stale`), rebuild
the tools and provider on the new handle, and load the state:

```python
from agents import RunState

run = client.attach(run_id, trace_id, principal_chain).take_over()
agent = build_agent(run)                            # tools bound to the new generation
saved = run.latest_checkpoint()["state"]["sdk_run_state"]
state = await RunState.from_json(agent, saved)      # TS: await RunState.fromString(agent, str)
result = await Runner.run(agent, state, run_config=RunConfig(model_provider=BudgetedProvider(run, MultiProvider())))
```

The checkpoint is fenced by generation, optimistic on its revision and at most 256 KiB;
a long conversation needs a session store and only a pointer in the checkpoint. The SDK
does not authenticate serialized state, so load it only from the checkpoint, never from
the client. Resuming cannot reset the budget, and effects already confirmed are refused
as repeats (`retry_unsafe`).

## 7. Handoffs and agents as tools: delegate to child runs

A **handoff** passes the conversation to another agent inside the same `Runner.run`. It
runs under the same ContextOS run, the same tools' authority and the same budgeted
provider. Use handoffs to switch instructions, not to narrow authority.

To give a subagent less authority, make it an **agent as a tool** backed by a child run
in a delegated lane, with its own budgeted provider:

```python
lane = run.delegate(child_admission, envelope)      # effect_policy "read_only", sub_budget, capabilities
lookup_in_lane, _ = tools(lane)                     # governed on the child run
researcher = Agent(name="research", instructions="Research only.", model="gpt-6-luna",
                   tools=[function_tool(lookup_in_lane, failure_error_function=governed_failure)])
research_order = researcher.as_tool(
    tool_name="research_order", tool_description="Look an order up (read-only).",
    run_config=RunConfig(model_provider=BudgetedProvider(lane, MultiProvider())),
    failure_error_function=governed_failure)
orchestrator = Agent(name="support", instructions=INSTRUCTIONS, tools=[research_order, refund_tool])
result = await Runner.run(orchestrator, goal, run_config=config)
run.close_child(lane, "accept")                     # settles its spend into the parent
```

The envelope is built as in [examples/agent-loop/agent.py](../../examples/agent-loop/agent.py).
The lane's tool surface is narrowed to the envelope's capabilities, and a `read_only`
lane gets no effectful capability at all: a refund attempted there comes back
`rejected: capability_not_surfaced`. The child's model calls reserve from its
`sub_budget`, so size `total_tokens` for them (1,000 tokens per call at least). The
parent cannot complete until every child is closed (`children_unsettled`). TypeScript:
`researcher.asTool({ toolName, toolDescription, runConfig })`.

## 8. The MCP alternative

Every run is also an MCP server at `POST /v1/runs/{run_id}/mcp`. Point
`MCPServerStreamableHttp` at it with the caller's token and the executor generation:

```python
from agents.mcp import MCPServerStreamableHttp

def contextos_meta(ctx):                            # operation key, call id and evidence per call
    if ctx.tool_name == "adp_payments.issue_refund":
        order_id = ctx.arguments["order_id"]
        return {"io.contextos/idempotencyKey": f"refund:{order_id}",
                "io.contextos/toolCallId": f"tc_refund_{order_id}", "io.contextos/evidenceRefs": EVIDENCE}
    return None

def contextos_ids(ctx):                             # the result's _meta, kept off the model's input
    meta = ctx.result_meta or {}
    return {key: meta[key] for key in ("io.contextos/toolCallId", "io.contextos/operationId") if key in meta}

async with MCPServerStreamableHttp(
    name="contextos",
    params={"url": f"{base_url}/v1/runs/{run.run_id}/mcp",
            "headers": {"Authorization": f"Bearer {token}",
                        "ContextOS-Executor-Generation": str(run.executor_generation)}},
    tool_meta_resolver=contextos_meta, custom_data_extractor=contextos_ids, cache_tools_list=True,
) as server:
    agent = Agent(name="support", instructions=INSTRUCTIONS, model="gpt-6.1-sol",
                  mcp_servers=[server], mcp_config={"include_server_in_tool_names": True})
    result = await Runner.run(agent, goal, run_config=config)
```

The tools are the run's surfaced capabilities with their reviewed input schemas. Their
names are capability ids such as `adp_payments.issue_refund`, and OpenAI function names
allow only letters, digits, `_` and `-`; `include_server_in_tool_names` exposes them as
`mcp_contextos__adp_payments_issue_refund` and still calls the server by the original
name (TypeScript: `mcpConfig: { includeServerInToolNames: true }`, and
`new MCPServerStreamableHttp({ url, requestInit: { headers }, toolMetaResolver, customDataExtractor })`).
Every result's `_meta` names the call and its operation (`io.contextos/toolCallId`,
`io.contextos/operationId`). The SDK hands it to `custom_data_extractor` as
`result_meta` (TypeScript `resultMeta`), and what the extractor returns lands on the
`ToolCallOutputItem`'s `custom_data` (`customData`) in `result.new_items`, never in the
model's input; read the ids from there for the DecisionRecord. Refusals arrive as tool
output with the gateway's text (`ContextOS paused: retry_unsafe. This call had no
effect; do not retry it unchanged. …`), not exceptions, so an approval pause does not
stop the run; use function tools where you need that. Keep one effect on one route: a
refund keyed `refund:ord_881` through function tools and the same refund over MCP
without that key are two operations. Model calls are not governed by
MCP: keep the budgeted provider. After a takeover, reconnect with the new generation.

## 9. Record the decision and complete

The DecisionRecord cites ContextOS tool-call ids and operation ids, not the SDK's
`call_id`s. Derive them as in section 3 (over MCP, read them from the results'
`_meta`, section 8):

```python
decision = run.record_decision("support.refund.execute", "DECIDED", outcome="refund_issued",
                               tool_calls=[{"tool_call_id": "tc_refund_ord_881", "operation_id": "refund:ord_881"}],
                               rationale={"strategy": str(result.final_output)[:500]})
run.complete()
```

`complete` is refused while an effect is unknown or partial, a child is open, or anything
is in flight. Decide whether the effect happened from the governed results (the example
watches `RunHooks.on_tool_end`), not from the model's final answer.

## 10. Pitfalls

- **The default failure function.** "Please try again" turns every refusal and pause into
  an invitation to retry. Set `failure_error_function` (`errorFunction`) on every
  governed tool, and on `as_tool` wrappers too. `failure_error_function=None` raises
  everything, including refusals the model should hear about.
- **`tool_error_formatter`.** `RunConfig.tool_error_formatter` rewrites only the
  default failure function's message; it does not see a custom one, and it cannot tell a
  pause from a refusal. Leave governed tools to `governed_failure`.
- **Parallel tool calls.** The runner executes a turn's function calls concurrently.
  Set `parallel_tool_calls=False` (`parallelToolCalls: false`) on agents that must look
  before they act. Two identical refunds in one turn share an operation key either way:
  one runs, the other is refused.
- **Retries.** SDK model retries (`ModelSettings.retry`) are budgeted by the wrapper, one
  reservation per attempt. Do not add tool-level retries around governed calls; a lost
  response is a pause to reconcile, and the client already retries what the server did
  not process (`429`, `503`).
- **`max_turns`.** `MaxTurnsExceeded` (default 10 turns) is a local limit that resets with
  the process. The run's budget survives restarts, takeovers and parallel lanes; use
  `max_turns` as a loop backstop, and when it trips, record the decision before failing.
- **Tool-call ids.** `call_id` is the model's, unique per invocation, and the SDK may
  skip an exact replay of a completed one on resume. ContextOS ids and keys are yours.
- **Approval is not authorization.** `needs_approval` and `state.approve()` are your
  reviewer's decision in your process. The gateway still authorizes the call, and an
  `always_approve=True` decision never carries over to ContextOS.
- **Tracing.** Traces go to OpenAI by default and include tool inputs and outputs
  (order data, refund ids). Set `trace_include_sensitive_data=False`
  (`traceIncludeSensitiveData: false`) or `OPENAI_AGENTS_TRACE_INCLUDE_SENSITIVE_DATA=false`,
  and disable tracing where no OpenAI key is configured. The signed audit chain is the
  record; traces are for debugging.
- **Blocking calls.** The Python client is synchronous. Sync tools run in threads, but
  the budget calls in `BudgetedModel` run on the event loop; under heavy concurrency move
  them to `asyncio.to_thread`.
- **Offline tests.** `agents.testing.ScriptedModel` (`ScriptedModel` from
  `@openai/agents/testing`) implements `Model`, so scripted runs go through the same
  provider, budget and tools as real ones.

## References

- Agents: https://openai.github.io/openai-agents-python/agents/
- Tools, `function_tool`, `failure_error_function`, agents as tools: https://openai.github.io/openai-agents-python/tools/
- Models and model providers: https://openai.github.io/openai-agents-python/models/
- Running agents, `RunConfig`, `max_turns`: https://openai.github.io/openai-agents-python/running_agents/
- Lifecycle hooks: https://openai.github.io/openai-agents-python/ref/lifecycle/
- Human-in-the-loop and `RunState`: https://openai.github.io/openai-agents-python/human_in_the_loop/
- Handoffs: https://openai.github.io/openai-agents-python/handoffs/
- Multi-agent orchestration: https://openai.github.io/openai-agents-python/multi_agent/
- MCP: https://openai.github.io/openai-agents-python/mcp/
- Tracing: https://openai.github.io/openai-agents-python/tracing/
- Testing (`ScriptedModel`): https://openai.github.io/openai-agents-python/ref/testing/
- TypeScript: https://openai.github.io/openai-agents-js/guides/tools/, https://openai.github.io/openai-agents-js/guides/models/,
  https://openai.github.io/openai-agents-js/guides/human-in-the-loop/, https://openai.github.io/openai-agents-js/guides/mcp/
- OpenAI model ids: https://developers.openai.com/api/docs/models
