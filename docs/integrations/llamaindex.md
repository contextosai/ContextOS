# Govern a LlamaIndex agent with ContextOS

LlamaIndex agents (`FunctionAgent`, `ReActAgent`, `AgentWorkflow`) are workflows: the
framework runs the loop, calls the LLM, and calls tools. ContextOS sits underneath: each
tool call goes to `contextosd`, which authorizes it against the run's contract, binds it
exactly, dispatches it once, records it and signs it into the audit chain, and every
model call spends the same run budget. The agent holds no authority of its own.

This guide uses `llama-index-core` 0.14 and the Python client in
`bindings/python/contextos/` (`aio.py` for asyncio). The runnable version is
[`examples/frameworks/llamaindex`](../../examples/frameworks/llamaindex/agent.py).

## Install

```sh
pip install "llama-index-core==0.14.25" "llama-index-llms-openai==0.8.3"
```

The ContextOS client is standard library only: put `bindings/python` on `PYTHONPATH` or
vendor it. LlamaIndex tools and LLM calls are async, so use `contextos.aio`:
`AsyncClient` and `AsyncRun` have the client's methods as coroutines (each request runs
in a worker thread), which keeps the event loop free (the example does).

## Admit a run

Admit before you build the agent: the tools and the LLM wrapper hold the run handle.

```python
from contextos.aio import AsyncClient

client = AsyncClient("https://contextos.internal", token=os.environ["CONTEXTOS_TOKEN"])
run = await client.admit(admission_body)   # an AsyncRun; contract, run context, request: docs/GUIDE.md §3
```

## Governed tools

Declare each capability with `governed_tool`; the decorated body never runs locally.
Derive the idempotency key from the arguments, so a replayed step maps to the same
operation, and derive the tool call id the same way if a DecisionRecord will cite it.
On an `AsyncRun` the governed function is a coroutine.

```python
from contextos.client import governed_tool, ToolOutcome, ToolPaused

@governed_tool(run, "adp_payments.issue_refund", approval_mode="destructive",
               idempotency_key=lambda order_id, **_: f"refund:{order_id}",
               tool_call_id=lambda order_id, **_: f"tc_refund_{order_id}",
               evidence_refs=["kg:order:ord_881#snapshot_kg_2026_05_03_T0930"])
async def refund(order_id: str, customer_id: str, amount_minor: int) -> dict:
    """Issue a refund for an order to its customer, in minor units."""
```

Register an async wrapper as a `FunctionTool`. A parameter annotated `Context` is
injected by the agent and hidden from the model's schema; you need it for approvals.

```python
from llama_index.core.tools import FunctionTool
from llama_index.core.workflow import Context

async def issue_refund(ctx: Context, order_id: str, customer_id: str, amount_minor: int) -> str:
    try:
        return json.dumps(await refund(order_id, customer_id, amount_minor))
    except ToolOutcome as outcome:
        return not_done(outcome)      # see "Map outcomes" below

tool = FunctionTool.from_defaults(async_fn=issue_refund, name="issue_refund", description=refund.__doc__)
```

Do not let the exception escape. `FunctionAgent` turns a tool exception into an error
result containing `str(e)`, which tells the model little and invites a retry.

## Budget every model call

Wrap the LLM. LlamaIndex's [instrumentation](https://developers.llamaindex.ai/python/framework/module_guides/observability/instrumentation/)
events and spans can observe calls, but the dispatcher swallows handler exceptions, so
they cannot refuse one. A wrapper `FunctionCallingLLM` can: it reserves before the
provider is called and settles after.

```python
from llama_index.core.llms.function_calling import FunctionCallingLLM

class BudgetedLLM(FunctionCallingLLM):
    inner: LLM
    _run: Any = PrivateAttr()

    def __init__(self, inner, run, **kw):
        super().__init__(inner=inner, **kw)
        self._run = run

    @property
    def metadata(self):
        return self.inner.metadata

    async def achat(self, messages, **kw):                 # self._run is the AsyncRun
        async with self._run.budgeted_model_call(tokens=4000):   # BudgetExhausted raises here
            return await self.inner.achat(messages, **kw)

    async def astream_chat(self, messages, **kw):          # FunctionAgent streams by default
        reservation = await self._run.reserve_usage("model_call", tokens=4000)
        async def stream():
            try:
                async for chunk in await self.inner.astream_chat(messages, **kw):
                    yield chunk
            finally:
                await self._run.settle_usage(reservation)
        return stream()

    # acomplete: the same pattern. Sync chat/complete variants need a sync Run
    # (`with run.budgeted_model_call(tokens=...)`).
    def _prepare_chat_with_tools(self, tools, **kw):
        return self.inner._prepare_chat_with_tools_compat(tools, **kw)

    def get_tool_calls_from_response(self, response, error_on_no_tool_call=True, **kw):
        return self.inner.get_tool_calls_from_response(response, error_on_no_tool_call, **kw)
```

`FunctionCallingLLM.achat_with_tools` calls `_prepare_chat_with_tools` and then
`achat`, so delegating those two keeps the provider's tool formatting and routes every
call through the reservation. A refused reservation raises `BudgetExhausted`
(`.reasons` names the limit) out of `agent.run`; stop there and fail or complete the run,
do not catch and continue. Reserve at least `[guards] model_call_min_tokens` (1,000 by
default). Settling as the executor charges the whole reservation. To charge measured
tokens, reserve with `metered=True` and send `run.metering_headers(reservation)` on the
request through an LLM gateway holding the `meter` scope, which settles with what the
provider reported ([examples/metering-proxy](../../examples/metering-proxy) is a reference; GUIDE §6). With
`llama_index.llms.openai.OpenAI(..., api_base="https://llm-gateway.internal/v1")` as
`inner`, call keyword arguments reach the SDK's `create`, so `extra_headers` works:

```python
    async def achat(self, messages, **kw):
        async with self._run.budgeted_model_call(tokens=4000, metered=True) as reservation:
            return await self.inner.achat(messages, extra_headers=self._run.metering_headers(reservation), **kw)
```

In `astream_chat`, pass the same headers and settle only if the stream raises, ignoring a
404 (the gateway settled first). One reservation covers one call.

## Map outcomes

The client raises one exception per non-success status. What the model and the
workflow should see:

| Exception | Typical reason codes | Tool result / action |
|---|---|---|
| `ToolBlocked` | policy, authority, `budget_exhausted`, `loop_detected` | "not done" text with the reasons; do not retry unchanged |
| `ToolRejected` | `capability_not_surfaced`, `arguments_invalid` | "not done"; the model may fix the call |
| `ToolFailed` | provider refused the effect | "not done"; retry only per the capability's recovery policy |
| `ToolPaused`, `kind == "approval"` | `approval_required` | human-in-the-loop, below |
| `ToolPaused`, `kind == "unknown_outcome"` | `reconcile_effect_before_retry` | "outcome unknown"; reconcile out of band |
| `ToolPaused`, `kind == "duplicate"` | `retry_unsafe` | "already requested"; the operation already exists |
| `ToolPaused`, `kind == "input"` | `provide_requested_input` | answer with `await run.provide_input(...)`, same operation |

`paused.kind` classifies a pause by what it waits on, so you do not match obligation
or reason codes yourself:

```python
def not_done(outcome: ToolOutcome) -> str:
    reasons = ", ".join(outcome.reason_codes) or outcome.status
    kind = outcome.kind if isinstance(outcome, ToolPaused) else None
    if kind == "duplicate":
        return f"ALREADY REQUESTED ({reasons}): this exact action was submitted before and was not repeated."
    if kind == "unknown_outcome":
        return f"OUTCOME UNKNOWN ({reasons}): the action may have happened and is being reconciled; do not retry it."
    return f"NOT DONE ({outcome.status}: {reasons}). The action did not take effect; do not retry it."
```

For a duplicate the earlier call with that key did happen; the refused repeat did
not. Track what succeeded in your own state (the example sets `refunded` only on a
success result), not in what the model claims.

### Approval pauses: InputRequiredEvent / HumanResponseEvent

Use the workflow's [human-in-the-loop](https://developers.llamaindex.ai/python/framework/understanding/agent/human_in_the_loop/)
events. The approval decision itself is made in the ContextOS approval service, bound
to the action digest; the human response only resumes the step. This is what
`./examples/frameworks/run.sh llamaindex --approval` runs.

```python
from llama_index.core.workflow import HumanResponseEvent, InputRequiredEvent

except ToolPaused as paused:
    if paused.kind != "approval":
        return not_done(paused)
    pending[paused.operation_id] = paused
    await ctx.wait_for_event(
        HumanResponseEvent, waiter_id=paused.operation_id,
        requirements={"operation_id": paused.operation_id},
        waiter_event=InputRequiredEvent(prefix="approve refund?", operation_id=paused.operation_id))
    return not_done(paused)       # reached only if the replayed call paused again
```

```python
handler = agent.run(user_msg=goal)
async for event in handler.stream_events():
    if isinstance(event, InputRequiredEvent):
        paused = pending.pop(event.operation_id)
        await ask_reviewer(paused)      # the reviewer decides in the approval service
        handler.ctx.send_event(HumanResponseEvent(response="approved", operation_id=event.operation_id))
result = await handler
```

`wait_for_event` pauses by raising and replays the whole tool step when the response
arrives, so the governed call before it runs again: that replay is the re-send. It
redeems the approval only because it is identical (same arguments, and the idempotency
key and tool call id are derived from them), and it is governed end to end again; if
the approval was not granted, it pauses again and the model is told so. Filter the
wait with `requirements` on the operation id: every waiting step listens for
`HumanResponseEvent`, and an unfiltered response would replay an earlier one too. In a
high-value run the gate covers every call of the run, so the lookup pauses as well;
give read-only tools a derived key and call id so their re-send redeems too.

### Unknown outcomes

`paused.kind == "unknown_outcome"` (`reconcile_effect_before_retry`) means the effect may have happened. The operation stays
reserved and retries are refused until someone resolves it with
`await run.reconcile(operation_id)` (provider query) or an operator assertion with evidence
(GUIDE §3, "Reconciling unknown effects"). Tell the model it is unresolved and end the
step; `run.complete()` refuses with `required_effect_unsatisfied` until it is resolved.

## Checkpoint and resume

Two kinds of state, kept separately:

- **The framework's Context**: memory, chat history, workflow state.
  `ctx.to_dict(serializer=JsonSerializer())` and `Context.from_dict(agent, data,
  serializer=JsonSerializer())` ([Maintaining state](https://developers.llamaindex.ai/python/framework/understanding/agent/state/)).
- **The ContextOS checkpoint**: the orchestrator's own pointer, fenced by executor
  generation, revisioned, audited by digest, at most 256 KiB.

Save the Context where you keep large state and checkpoint its location and digest,
plus your step pointer, in ContextOS after each step that matters:

```python
data = handler.ctx.to_dict(serializer=JsonSerializer())
blob = store.put(json.dumps(data))
revision = (await run.checkpoint({"ctx": blob.ref, "sha256": blob.sha256, "step": "refund"}, revision))["revision"]
```

A replacement executor takes the run over, which fences the old process
(`executor_stale`), rebuilds the tools and the LLM wrapper on the new handle, and
restores:

```python
run = await (await client.attach(run_id, trace_id, principal_chain)).take_over()
saved = await run.latest_checkpoint()
agent = FunctionAgent(tools=governed_tools(run), llm=BudgetedLLM(model, run), system_prompt=INSTRUCTIONS)
ctx = Context.from_dict(agent, json.loads(store.get(saved["state"]["ctx"])), serializer=JsonSerializer())
handler = agent.run(ctx=ctx)       # a workflow waiting for input waits again; send the response
```

Tools built on the old `Run` keep the old generation and are refused, so never reuse
them. Calls that were in flight are not repeated by the restore: the same key returns
the recorded operation. The budget is not reset by resume.

## Multi-agent handoff → delegation

In an `AgentWorkflow`, give each sub-agent its own child run instead of sharing the
parent's tools. Admit the child with an `AgentDelegationEnvelope` (`run.delegate`, see
GUIDE §3 "Delegating to child runs" and `examples/agent-loop/agent.py` for the full
envelope). A `read_only` lane is surfaced no effectful capability at all.

```python
lane = await run.delegate(child_admission, envelope)    # effect_policy "read_only", sub_budget
research = FunctionAgent(name="research", description="Looks orders up.",
                         tools=governed_tools(lane, only=["lookup_order"]),   # your factory, on the lane
                         llm=BudgetedLLM(model, lane), can_handoff_to=["support"])
support = FunctionAgent(name="support", tools=governed_tools(run), llm=BudgetedLLM(model, run))
workflow = AgentWorkflow(agents=[research, support], root_agent="research")
result = await workflow.run(user_msg=goal)
await run.close_child(lane, "accept")  # settles the lane's spend into the parent
```

The research agent's model calls spend the lane's sub-budget (size `sub_budget.total_tokens`
for them), and an attempt to act
from it is refused (`capability_not_surfaced`). Close every child before
`run.complete()` (`children_unsettled` otherwise).

## Or connect over MCP

Each run is an MCP server at `POST /v1/runs/{run_id}/mcp`. With
[`llama-index-tools-mcp`](https://developers.llamaindex.ai/python/examples/tools/mcp/):

```python
from llama_index.tools.mcp import BasicMCPClient, aget_tools_from_mcp_url

url = f"{base}/v1/runs/{run.run_id}/mcp"
mcp = BasicMCPClient(url, headers={"Authorization": f"Bearer {token}",
                                   "ContextOS-Executor-Generation": str(run.executor_generation)})
tools = await aget_tools_from_mcp_url(url, client=mcp)
```

The agent then sees only the run's surfaced capabilities with their reviewed schemas,
and refusals arrive as tool errors whose `structuredContent` carries status and reason
codes. Effectful calls derive their operation key from capability and arguments unless
`_meta["io.contextos/idempotencyKey"]` is given. Every result's `_meta` names
`io.contextos/toolCallId` and `io.contextos/operationId`, which a DecisionRecord can
cite; keep one effect on one route, since an explicitly keyed call and a derived-key
call are different operations (the second is refused, `effect_repeated`). You still budget model calls with the
LLM wrapper, and after a takeover you must rebuild the client with the new generation.

## Record the decision and complete

```python
await run.record_decision("support.refund.execute", "DECIDED", outcome="refund_issued",
                          tool_calls=[{"tool_call_id": "tc_refund_ord_881", "operation_id": "refund:ord_881"}],
                          rationale={"strategy": str(result)[:500]})
await run.complete()
evidence = await run.evidence()
```

The gateway verifies every cited tool call against its ledgers (`lineage_unverified`
otherwise). Cite what your tools observed, not what the model said.

## Pitfalls

- **Tool exceptions become text.** Catch `ToolOutcome` in the tool and return a clear
  "not done" result; never return a success-shaped string for a refusal.
- **Replay on `wait_for_event`.** Anything before the wait runs again. Keep the
  governed call keyed by arguments; never use a random idempotency key.
- **Parallel tool calls.** `FunctionAgent` runs tool calls in parallel by default. Set
  `allow_parallel_tool_calls=False` when one call's result should inform the next.
- **Retries in the provider client.** LLM client retries are new model calls; they
  stay inside one reservation only if they happen inside the wrapper call.
- **Blocking the loop.** `contextos.client` is synchronous; from async code use
  `contextos.aio` (`AsyncClient`, `AsyncRun`).
- **Unpinned model.** Pin the model in the contract's `release_refs` so decisions name
  it (GUIDE §6, "Pin the model and evaluators").

Official docs: [Agents](https://developers.llamaindex.ai/python/framework/understanding/agent/),
[Tools](https://developers.llamaindex.ai/python/framework/module_guides/deploying/agents/tools/),
[Multi-agent](https://developers.llamaindex.ai/python/framework/understanding/agent/multi_agent/),
[Custom LLMs](https://developers.llamaindex.ai/python/framework/module_guides/models/llms/usage_custom/).
