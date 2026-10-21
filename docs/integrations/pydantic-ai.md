# Pydantic AI

[Pydantic AI](https://pydantic.dev/docs/ai/) runs the agent loop: it calls the model,
validates tool arguments, runs tools and feeds their results back. ContextOS governs
what that loop can do. Every tool call goes through `contextosd` (authorization,
exact binding, idempotent effects, approvals, audit), every model request spends the
run's budget, and the run ends with a verified DecisionRecord.

This guide uses Pydantic AI 2.58. The runnable example is
[examples/frameworks/pydantic-ai](../../examples/frameworks/pydantic-ai/):

```sh
./examples/frameworks/run.sh pydantic-ai
```

## 1. Install

```sh
pip install "pydantic-ai-slim[anthropic]==2.58.0"    # or [openai], or both
```

Add the `mcp` extra only if you connect over MCP (section 8). The ContextOS client
(`bindings/python/contextos`) uses the standard library only.

## 2. Admit a run

```python
from contextos.client import Client

client = Client("https://contextos.internal", token=os.environ["CONTEXTOS_TOKEN"])
run = client.admit(admission_body)        # holds run_id and the executor generation
```

One run governs one agent task. Admit it before `agent.run(...)` and complete it
after; the `Run` handle is what your tools and model wrapper close over (or pass it as
`deps`).

## 3. Govern the tools

Write each tool as a `governed_tool` signature. Pydantic AI builds the tool schema from
the signature and docstring; the body never runs, the gateway dispatches the call:

```python
from contextos.client import governed_tool

@governed_tool(run, "adp_orders.lookup", approval_mode="read_only")
def lookup_order(order_id: str) -> dict:
    """Look up an order's status, amount (amount_minor) and refund eligibility."""

@governed_tool(run, "adp_payments.issue_refund", approval_mode="destructive",
               idempotency_key=lambda order_id, **_: f"refund:{order_id}",
               tool_call_id=lambda order_id, **_: f"tc_refund_{order_id}",
               evidence_refs=["kg:order:ord_881#snapshot_kg_2026_05_03_T0930"])
def issue_refund(order_id: str, customer_id: str, amount_minor: int) -> dict:
    """Issue a refund for an order to its customer, in minor units of its currency."""
```

A governed call that does not simply succeed raises `ToolPaused`, `ToolBlocked`,
`ToolRejected` or `ToolFailed` (from `contextos.client`). Pydantic AI would treat
those as crashes, so wrap the toolset and translate them once, for every tool:

```python
from contextos.client import ToolOutcome, ToolPaused
from pydantic_ai import ApprovalRequired, CallDeferred, FunctionToolset, ToolFailed, WrapperToolset

def not_done(outcome: ToolOutcome) -> str:
    reasons = ", ".join(outcome.reason_codes) or outcome.status
    if isinstance(outcome, ToolPaused) and outcome.kind == "duplicate":
        return f"ALREADY REQUESTED ({reasons}): this exact action was submitted before and was not repeated."
    return f"NOT DONE ({outcome.status}: {reasons}). The action did not take effect; do not retry it."

class ContextOSToolset(WrapperToolset):
    async def call_tool(self, name, tool_args, ctx, tool):
        try:
            return await super().call_tool(name, tool_args, ctx, tool)
        except ToolPaused as paused:
            meta = {"operation_id": paused.operation_id, "reason_codes": paused.reason_codes}
            if paused.kind == "approval":
                raise ApprovalRequired(metadata=meta)
            if paused.kind in ("unknown_outcome", "input"):
                raise CallDeferred(metadata=meta)
            raise ToolFailed(not_done(paused))           # e.g. a duplicate (retry_unsafe)
        except ToolOutcome as outcome:                    # blocked, rejected, failed
            raise ToolFailed(not_done(outcome))

toolset = ContextOSToolset(FunctionToolset([lookup_order, issue_refund], sequential=True))
```

| ContextOS outcome | Raise in the toolset | What happens in Pydantic AI |
|---|---|---|
| `ok` / `completed` | return the output | normal tool return |
| `blocked`, `rejected`, `failed`, `paused` with `kind` `duplicate` or `other` | `ToolFailed(text)` | tool return with `outcome='failed'`; the model reads that it did not happen, or was already requested and not repeated |
| `paused`, `kind == "approval"` | `ApprovalRequired` | run ends with `DeferredToolRequests.approvals` |
| `paused`, `kind` `unknown_outcome` or `input` | `CallDeferred` | run ends with `DeferredToolRequests.calls` |

Use `ToolFailed`, not `ModelRetry`, for refusals. `ModelRetry` tells the model to fix
its call and try again, which is the wrong message for a refund that policy refused
or that already happened, and it spends the tool's retry budget. `ToolFailed` is a
terminal result the model sees and adapts to. Keep `ModelRetry` for your own argument
checks before anything is dispatched.

## 4. Approvals and unknown effects: deferred tools

Give the agent `DeferredToolRequests` as a possible output, so a pause ends the run
cleanly instead of raising:

```python
from pydantic_ai import Agent, DeferredToolRequests, DeferredToolResults, ToolApproved, ToolDenied

agent = Agent(model, instructions=INSTRUCTIONS, toolsets=[toolset],
              output_type=[str, DeferredToolRequests])
result = await agent.run(goal)
if isinstance(result.output, DeferredToolRequests):
    save(result.all_messages(), result.output)            # see section 6
```

The human's decision of record is made in your approval service, which ContextOS asked
for approval bound to the exact action digest. When it is granted, resume the agent
with the approval; the toolset re-sends the identical call (same arguments, same
idempotency key) and the gateway redeems the approval:

```python
results = DeferredToolResults()
for call in requests.approvals:
    results.approvals[call.tool_call_id] = ToolApproved() if granted(call) else ToolDenied("Not approved.")
result = await agent.run(message_history=messages, deferred_tool_results=results)
```

- Approving in Pydantic AI only lets the loop re-send the call. If the approval
  service has not granted it, the gateway pauses it again; nothing is applied.
- Do not use `ToolApproved(override_args=...)`: the approval is bound to the original
  arguments, so changed arguments are a different action and need their own approval.
- Do not rely on `requires_approval=True` or `ApprovalRequiredToolset` alone. They are
  local and unbound to the action; keep them only as UX in front of the governed call.

For an unknown effect (`CallDeferred` for `kind == "unknown_outcome"`), never
re-send. Reconcile the operation, then resume with the result you established:

```python
for call in requests.calls:
    op = requests.metadata[call.tool_call_id]["operation_id"]
    resolved = run.reconcile(op)                          # asks the provider
    results.calls[call.tool_call_id] = describe(resolved) # or ToolFailed("refund not applied")
```

A tool that asked for input (`kind == "input"`) is answered with
`run.provide_input(paused, envelope, responses)`, which continues the same operation.

## 5. Budget every model request

Wrap the model so each request reserves from the run's budget first, the same ledger
tool calls spend:

```python
from contextlib import asynccontextmanager
from contextos.client import ContextOSHTTPError
from pydantic_ai.exceptions import UsageLimitExceeded
from pydantic_ai.models.wrapper import WrapperModel

class BudgetedModel(WrapperModel):
    def __init__(self, wrapped, run, tokens=1000):
        super().__init__(wrapped)
        self.run, self.tokens = run, tokens

    async def _reserve(self):
        try:
            return await asyncio.to_thread(self.run.reserve_usage, "model_call", tokens=self.tokens)
        except ContextOSHTTPError as refused:
            if refused.code == "budget_exhausted":
                raise UsageLimitExceeded(f"run budget exhausted: {refused.detail}") from None
            raise

    async def request(self, messages, settings, params):
        reservation = await self._reserve()
        try:
            return await super().request(messages, settings, params)
        finally:
            await asyncio.to_thread(self.run.settle_usage, reservation)

    @asynccontextmanager
    async def request_stream(self, messages, settings, params, run_context=None):
        reservation = await self._reserve()
        try:
            async with super().request_stream(messages, settings, params, run_context) as stream:
                yield stream
        finally:
            await asyncio.to_thread(self.run.settle_usage, reservation)

agent = Agent(BudgetedModel("anthropic:claude-sonnet-5-5", run), ...)
```

Settling as the executor charges the whole reservation. To charge measured usage, pass
the reservation id to your LLM gateway (for example as a request header through the
provider's HTTP client) and let it settle with the `meter` scope; see
[GUIDE section 6](../GUIDE.md#6-budget-model-calls-and-replans).

[`UsageLimits`](https://pydantic.dev/docs/ai/core-concepts/agent/#usage-limits) is
still a useful local backstop (`request_limit`, `tool_calls_limit`), but it counts in
one process for one `agent.run`. It is not shared by parallel agents, not conserved
when another executor takes the run over or a fallback model retries, and starts from
zero in each resumed `agent.run` unless you pass `usage=`. The run's budget in
`contextosd` is shared, durable and enforced on the server.

With `FallbackModel`, wrap each member (`FallbackModel(BudgetedModel(a, run),
BudgetedModel(b, run))`) so a failed-over attempt is reserved too. Wrapping the
fallback as a whole reserves once for several attempts.

## 6. Checkpoint and resume

Pydantic AI's state between steps is its message history. Save it with the
orchestrator's own state as a ContextOS checkpoint, which only the current executor
can read or write:

```python
from pydantic_ai.messages import ModelMessagesTypeAdapter

history = ModelMessagesTypeAdapter.dump_python(result.all_messages(), mode="json")
revision = run.checkpoint({"messages": history, "step": "awaiting_approval"}, revision)["revision"]
```

After a crash, the replacement executor takes the run over, which fences the old one
(`executor_stale`), and continues from the checkpoint:

```python
run = client.attach(run_id, trace_id, principal_chain).take_over()
saved = run.latest_checkpoint()
messages = ModelMessagesTypeAdapter.validate_python(saved["state"]["messages"])
result = await agent.run(message_history=messages, deferred_tool_results=results)
```

A tool call the old executor had in flight is in the operation ledger. Re-sending it
with the same idempotency key returns its recorded outcome or a pause to reconcile; it
never applies twice. Checkpoints are capped at 256 KiB, so for long histories store the
messages elsewhere and checkpoint a reference and digest.

With [durable execution](https://pydantic.dev/docs/ai/capabilities/durable_execution/overview/)
(Temporal, DBOS, Prefect), governed tool calls run inside activities or steps that the
engine may retry. That is safe because the idempotency key comes from the arguments,
not the attempt. A new worker must take the run over before dispatching.

## 7. Delegate to child runs

Pydantic AI's [agent delegation](https://pydantic.dev/docs/ai/guides/multi-agent-applications/)
calls a second agent from a tool. Give that agent its own ContextOS child run in a
narrowed lane, so it can only do what the envelope allows:

```python
@parent_agent.tool
async def research_order(ctx: RunContext[Run], order_id: str) -> dict:
    """Have the research agent gather evidence about an order (read-only)."""
    lane = ctx.deps.delegate(child_admission, envelope)   # effect_policy "read_only"
    try:
        @governed_tool(lane, "adp_orders.lookup", approval_mode="read_only")
        def lookup_order(order_id: str) -> dict:
            """Look up an order."""
        result = await research_agent.run(f"Research {order_id}", deps=lane,
                                          toolsets=[ContextOSToolset(FunctionToolset([lookup_order]))],
                                          usage=ctx.usage)
        return result.output
    finally:
        ctx.deps.close_child(lane, "accept")              # settles its spend into the parent
```

The envelope (see [GUIDE: Delegating to child runs](../GUIDE.md#delegating-to-child-runs-subagent-lanes)
and [examples/agent-loop](../../examples/agent-loop/agent.py)) names the lane's
capabilities, sub-budget and deadline, reserved from the parent before the child
exists. A `read_only` child gets no effectful capability at all, whatever tools its
agent is given. Wrap the research agent's model in `BudgetedModel(model, lane)` so its
requests spend the lane's budget. Passing `usage=ctx.usage` only aggregates Pydantic
AI's local counters. The parent cannot complete while a child is open
(`children_unsettled`).

## 8. Or connect over MCP

Every run is also an MCP server at `POST /v1/runs/{run_id}/mcp`. `MCPToolset` (which
replaces `MCPServerStreamableHTTP` in Pydantic AI 2.x; extra `mcp`) connects to it:

```python
from pydantic_ai.mcp import MCPToolset

contextos = MCPToolset(
    f"{CONTEXTOS_URL}/v1/runs/{run.run_id}/mcp",
    headers={"Authorization": f"Bearer {token}",
             "ContextOS-Executor-Generation": str(run.executor_generation)},
    tool_error_behavior="failed",
)
agent = Agent(BudgetedModel(model, run), toolsets=[contextos])
```

The agent sees only the run's surfaced capabilities with their reviewed schemas.
Refusals come back as MCP tool errors; set `tool_error_behavior="failed"` so they
become `ToolFailed` results. The default, `"retry"`, turns them into `ModelRetry` and
invites the model to try again. Effectful calls derive their operation key from the
capability and arguments; to set it, cite evidence or name the call, pass `_meta` from
a `process_tool_call` callback:

```python
async def with_meta(ctx, call_tool, name, args):
    return await call_tool(name, args, metadata={
        "io.contextos/idempotencyKey": f"refund:{args['order_id']}",
        "io.contextos/toolCallId": f"tc_refund_{args['order_id']}",
        "io.contextos/evidenceRefs": EVIDENCE})
```

Every result carries `_meta["io.contextos/toolCallId"]` and
`_meta["io.contextos/operationId"]`, the ids the DecisionRecord cites. Keep each effect
on one route: a call keyed in `_meta` and one keyed by derivation are two operations.

After a takeover the generation changes; build a new `MCPToolset` with the new header.
The MCP path still needs `BudgetedModel` for model requests, and the DecisionRecord is
still recorded over HTTP.

## 9. Record the decision and complete

```python
run.record_decision("support.refund.execute", "DECIDED", outcome="refund_issued",
                    tool_calls=[{"tool_call_id": "tc_refund_ord_881", "operation_id": "refund:ord_881"}],
                    rationale={"strategy": result.output[:500]})
run.complete()
evidence = run.evidence()
```

The gateway verifies each cited tool call against its own ledgers
(`lineage_unverified` otherwise). `complete` is refused while an effect is unknown, a
child is open or a call is in flight. Record `REJECTED` or `ESCALATED` when the agent
did not act, and `run.fail()` when it gives up.

## Pitfalls

- **Parallel tool calls.** Models often emit several tool calls in one response, and
  Pydantic AI runs them concurrently. Mark effectful tools `sequential=True` (per tool
  or on the toolset). The gateway keeps duplicates from applying twice either way, but
  concurrent identical calls can overshoot the loop guard by their concurrency.
- **Retries.** Do not raise `ModelRetry` for a governed outcome, and do not loop on a
  paused call. Retries Pydantic AI makes for invalid arguments happen before dispatch
  and are fine. Provider SDK retries cover model requests only.
- **`tool_call_id`.** Pydantic AI's `ctx.tool_call_id` comes from the model and changes
  between attempts. Derive the ContextOS `tool_call_id` and idempotency key from the
  arguments, as `governed_tool` does, so the DecisionRecord can cite the call and a
  re-sent call maps to the same operation. Keep Pydantic AI's id only for matching
  `DeferredToolResults`.
- **Blocking I/O.** `contextos.client` is synchronous. Pydantic AI runs synchronous
  tools in a thread; in async code such as a model wrapper, call it through
  `asyncio.to_thread`.
- **Local approval is not authority.** `requires_approval`, `ToolApproved` and
  `UsageLimits` shape the loop. Authority, approval and budget are decided by
  `contextosd`.

## References

- Toolsets and `WrapperToolset`: https://pydantic.dev/docs/ai/tools-toolsets/toolsets/
- Tools, `ModelRetry`, `ToolFailed`: https://pydantic.dev/docs/ai/tools-toolsets/tools/
- Deferred tools and approval: https://pydantic.dev/docs/ai/tools-toolsets/deferred-tools/
- Usage limits: https://pydantic.dev/docs/ai/core-concepts/agent/#usage-limits
- Message history: https://pydantic.dev/docs/ai/core-concepts/message-history/
- `WrapperModel`: https://pydantic.dev/docs/ai/api/models/wrapper/
- `FunctionModel` and `TestModel`: https://pydantic.dev/docs/ai/guides/testing/
- MCP client: https://pydantic.dev/docs/ai/mcp/client/
- Multi-agent applications: https://pydantic.dev/docs/ai/guides/multi-agent-applications/
- Durable execution: https://pydantic.dev/docs/ai/capabilities/durable_execution/overview/
