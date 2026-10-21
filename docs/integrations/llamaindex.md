# Govern a LlamaIndex agent with ContextOS

LlamaIndex agents (`FunctionAgent`, `ReActAgent`, `AgentWorkflow`) are workflows: the
framework runs the loop, calls the LLM, and calls tools. ContextOS sits underneath: each
tool call goes to `contextosd`, which authorizes it against the run's contract, binds it
exactly, dispatches it once, records it and signs it into the audit chain, and every
model call spends the same run budget. The agent holds no authority of its own.

This guide uses `llama-index-core` 0.14 and the Python client in
`bindings/python/contextos/client.py`. The runnable version is
[`examples/frameworks/llamaindex`](../../examples/frameworks/llamaindex/agent.py).

## Install

```sh
pip install "llama-index-core==0.14.25" "llama-index-llms-openai==0.8.3"
```

The ContextOS client is standard library only: put `bindings/python` on `PYTHONPATH` or
vendor it. It is synchronous; LlamaIndex tools are async, so call it with
`asyncio.to_thread` to keep the event loop free (the example does).

## Admit a run

Admit before you build the agent: the tools and the LLM wrapper hold the run handle.

```python
from contextos.client import Client

client = Client("https://contextos.internal", token=os.environ["CONTEXTOS_TOKEN"])
run = client.admit(admission_body)     # contract, run context, request; see docs/GUIDE.md §3
```

## Governed tools

Declare each capability with `governed_tool`; the decorated body never runs locally.
Derive the idempotency key from the arguments, so a replayed step maps to the same
operation, and derive the tool call id the same way if a DecisionRecord will cite it.

```python
from contextos.client import governed_tool, ToolOutcome, ToolPaused

@governed_tool(run, "adp_payments.issue_refund", approval_mode="destructive",
               idempotency_key=lambda order_id, **_: f"refund:{order_id}",
               tool_call_id=lambda order_id, **_: f"tc_refund_{order_id}",
               evidence_refs=["kg:order:ord_881#snapshot_kg_2026_05_03_T0930"])
def refund(order_id: str, customer_id: str, amount_minor: int) -> dict:
    """Issue a refund for an order to its customer, in minor units."""
```

Register an async wrapper as a `FunctionTool`. A parameter annotated `Context` is
injected by the agent and hidden from the model's schema; you need it for approvals.

```python
from llama_index.core.tools import FunctionTool
from llama_index.core.workflow import Context

async def issue_refund(ctx: Context, order_id: str, customer_id: str, amount_minor: int) -> str:
    try:
        return json.dumps(await asyncio.to_thread(refund, order_id, customer_id, amount_minor))
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

    async def achat(self, messages, **kw):
        reservation = self._run.reserve_usage("model_call", tokens=4000)   # budget_exhausted raises here
        try:
            return await self.inner.achat(messages, **kw)
        finally:
            self._run.settle_usage(reservation)

    async def astream_chat(self, messages, **kw):          # FunctionAgent streams by default
        reservation = self._run.reserve_usage("model_call", tokens=4000)
        async def stream():
            try:
                async for chunk in await self.inner.astream_chat(messages, **kw):
                    yield chunk
            finally:
                self._run.settle_usage(reservation)
        return stream()

    # chat, stream_chat, complete variants: the same pattern.
    def _prepare_chat_with_tools(self, tools, **kw):
        return self.inner._prepare_chat_with_tools_compat(tools, **kw)

    def get_tool_calls_from_response(self, response, error_on_no_tool_call=True, **kw):
        return self.inner.get_tool_calls_from_response(response, error_on_no_tool_call, **kw)
```

`FunctionCallingLLM.achat_with_tools` calls `_prepare_chat_with_tools` and then
`achat`, so delegating those two keeps the provider's tool formatting and routes every
call through the reservation. A refused reservation raises `ContextOSHTTPError` with
code `budget_exhausted` out of `agent.run`; stop there and fail or complete the run,
do not catch and continue. Reserve at least `[guards] model_call_min_tokens` (1,000 by
default). Settling as the executor charges the whole reservation; to charge measured
tokens, pass the reservation id to an LLM gateway holding the `meter` scope and let it
settle (GUIDE §6).

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
| `ToolPaused`, `kind == "input"` | `provide_requested_input` | answer with `run.provide_input(...)`, same operation |

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
to the action digest; the human response only tells the tool to re-send the call.

```python
from llama_index.core.workflow import HumanResponseEvent, InputRequiredEvent

except ToolPaused as paused:
    if paused.kind != "approval":
        return not_done(paused)
    answer = await ctx.wait_for_event(
        HumanResponseEvent, waiter_id=paused.operation_id,
        waiter_event=InputRequiredEvent(prefix="approve refund?", operation_id=paused.operation_id))
    if answer.response != "approved":
        return not_done(paused)
    return json.dumps(await asyncio.to_thread(refund, order_id, customer_id, amount_minor))
```

```python
handler = agent.run(user_msg=goal)
async for event in handler.stream_events():
    if isinstance(event, InputRequiredEvent):
        handler.ctx.send_event(HumanResponseEvent(response=await ask_reviewer(event)))
result = await handler
```

`wait_for_event` pauses by raising and replays the whole tool call when the response
arrives, so the governed call before it runs twice. That is safe only because the
idempotency key is derived from the arguments: the replay is the same operation. The
re-sent call after approval is governed end to end again; if the approval was not
granted, it pauses again and the model is told so.

### Unknown outcomes

`paused.kind == "unknown_outcome"` (`reconcile_effect_before_retry`) means the effect may have happened. The operation stays
reserved and retries are refused until someone resolves it with
`run.reconcile(operation_id)` (provider query) or an operator assertion with evidence
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
revision = run.checkpoint({"ctx": blob.ref, "sha256": blob.sha256, "step": "refund"}, revision)["revision"]
```

A replacement executor takes the run over, which fences the old process
(`executor_stale`), rebuilds the tools and the LLM wrapper on the new handle, and
restores:

```python
run = client.attach(run_id, trace_id, principal_chain).take_over()
saved = run.latest_checkpoint()
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
lane = run.delegate(child_admission, envelope)          # effect_policy "read_only", sub_budget
research = FunctionAgent(name="research", description="Looks orders up.",
                         tools=governed_tools(lane, only=["lookup_order"]),   # your factory, on the lane
                         llm=BudgetedLLM(model, lane), can_handoff_to=["support"])
support = FunctionAgent(name="support", tools=governed_tools(run), llm=BudgetedLLM(model, run))
workflow = AgentWorkflow(agents=[research, support], root_agent="research")
result = await workflow.run(user_msg=goal)
run.close_child(lane, "accept")       # settles the lane's spend into the parent
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
call are different operations. You still budget model calls with the
LLM wrapper, and after a takeover you must rebuild the client with the new generation.

## Record the decision and complete

```python
run.record_decision("support.refund.execute", "DECIDED", outcome="refund_issued",
                    tool_calls=[{"tool_call_id": "tc_refund_ord_881", "operation_id": "refund:ord_881"}],
                    rationale={"strategy": str(result)[:500]})
run.complete()
evidence = run.evidence()
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
- **Blocking the loop.** The client is synchronous; use `asyncio.to_thread`.
- **Unpinned model.** Pin the model in the contract's `release_refs` so decisions name
  it (GUIDE §6, "Pin the model and evaluators").

Official docs: [Agents](https://developers.llamaindex.ai/python/framework/understanding/agent/),
[Tools](https://developers.llamaindex.ai/python/framework/module_guides/deploying/agents/tools/),
[Multi-agent](https://developers.llamaindex.ai/python/framework/understanding/agent/multi_agent/),
[Custom LLMs](https://developers.llamaindex.ai/python/framework/module_guides/models/llms/usage_custom/).
