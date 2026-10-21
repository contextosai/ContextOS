# Govern a Microsoft Agent Framework agent with ContextOS

[Microsoft Agent Framework](https://learn.microsoft.com/agent-framework/overview/) (the
successor to AutoGen and Semantic Kernel agents) runs the tool-calling loop for you: an
`Agent` over a chat client, with function invocation, middleware, approvals and
workflows. ContextOS sits underneath: each tool call goes to `contextosd`, which
authorizes it against the run's contract, binds it exactly, dispatches it once, records
it and signs it into the audit chain, and every model call spends the same run budget.
The agent holds no authority of its own.

This guide uses `agent-framework-core` 1.22 (Python) and the asyncio client in
`bindings/python/contextos/aio.py`. The runnable version is
[`examples/frameworks/microsoft-agent-framework`](../../examples/frameworks/microsoft-agent-framework/agent.py).
In 1.x the agent class is `Agent` (formerly `ChatAgent`) and the tool decorator is
`tool` (`ai_function` remains an alias).

## Install

```sh
pip install "agent-framework-core==1.22.0" "agent-framework-openai==1.17.0"
```

`agent-framework` installs every connector; the two packages above are enough here.
Put `bindings/python` on `PYTHONPATH` or vendor it. The framework is asyncio, so use
`contextos.aio`: `AsyncClient` and `AsyncRun` have the client's methods as coroutines
(each request runs in a worker thread), so middleware never blocks the event loop.

## Admit a run

```python
from contextos.aio import AsyncClient

client = AsyncClient("https://contextos.internal", token=os.environ["CONTEXTOS_TOKEN"])
run = await client.admit(admission_body)   # an AsyncRun; contract, run context, request: docs/GUIDE.md §3
```

## Governed tools

Declare each capability with `governed_tool` and register it with `tool`. The body
never runs locally. On an `AsyncRun` it is a coroutine, which the framework awaits; on a
synchronous `Run` it also works, since the framework runs synchronous tools in a worker
thread (the example does that). Derive the idempotency key (and the
tool call id a DecisionRecord will cite) from the arguments.

```python
from agent_framework import Agent, tool
from contextos.client import governed_tool

@governed_tool(run, "adp_payments.issue_refund", approval_mode="destructive",
               idempotency_key=lambda order_id, **_: f"refund:{order_id}",
               tool_call_id=lambda order_id, **_: f"tc_refund_{order_id}",
               evidence_refs=["kg:order:ord_881#snapshot_kg_2026_05_03_T0930"])
async def issue_refund(order_id: str, customer_id: str, amount_minor: int) -> dict:
    """Issue a refund for an order to its customer, in minor units."""

agent = Agent(client=chat_client, name="support", instructions=INSTRUCTIONS,
              tools=[tool(lookup_order), tool(issue_refund)],
              middleware=[budget(run), governed_outcomes])
```

Leave the framework's `approval_mode` at `never_require` for governed tools: ContextOS
decides when approval is needed, per action, from policy. A framework approval on top
grants nothing ContextOS would refuse; use it only as extra UX.

## Budget every model call: chat middleware

[Chat middleware](https://learn.microsoft.com/en-us/agent-framework/agents/middleware/)
runs once per model call inside the function-invocation loop
([pipeline](https://learn.microsoft.com/en-us/agent-framework/concepts/agents/agent-pipeline)),
so it is the seam: reserve before `call_next`, settle after. Outside streaming,
`async with run.budgeted_model_call(tokens=...)` would do both; a stream settles in a
cleanup hook, so the middleware reserves and settles explicitly.

```python
from agent_framework import ChatContext, ChatResponse, Message, chat_middleware
from contextos.client import BudgetExhausted

def budget(run):                                      # an AsyncRun
    @chat_middleware
    async def reserve_model_call(context: ChatContext, call_next) -> None:
        try:
            reservation = await run.reserve_usage("model_call", tokens=4000)
        except BudgetExhausted:
            if context.stream:
                raise
            context.result = ChatResponse(messages=[Message(role="assistant",
                contents=["Stopping: the run's budget is exhausted."])])
            return                                    # no model call, no tool calls: the loop ends

        async def settle() -> None:
            await run.settle_usage(reservation)

        if context.stream:                            # settle once the stream is consumed
            context.stream_cleanup_hooks.append(settle)
            await call_next()
            return
        try:
            await call_next()
        finally:
            await settle()
    return reserve_model_call
```

Setting `context.result` without calling `call_next` skips the provider; raising
`MiddlewareTermination` in chat middleware does not carry a result, so set it on the
context. In a streaming run the example re-raises instead, so the run fails closed.
Reserve at least `[guards] model_call_min_tokens` (1,000 by default). Settling as the
executor charges the whole reservation. To charge measured tokens, send
`run.metering_headers(reservation)` on the request through an LLM gateway holding the
`meter` scope, which settles with what the provider reported
([examples/metering-proxy](../../examples/metering-proxy) is a reference; GUIDE §6). `context.kwargs` reach the
chat client, and the OpenAI clients (`OpenAIChatClient(base_url="https://llm-gateway.internal/v1")`)
send `extra_headers` with the request, so add them before `call_next`:

```python
        context.kwargs["extra_headers"] = {**context.kwargs.get("extra_headers", {}),
                                           **run.metering_headers(reservation)}
```

Then settle only when `call_next` raises, ignoring a 404 (the gateway settled first): a
failed call the gateway did not settle is charged in full. One reservation covers one
call.

## Map outcomes: function middleware

The client raises one exception per non-success status. Function middleware wraps each
tool invocation, so catch them there and set what the model sees. Without it the
framework turns the exception into the result `Error: Function failed.`, which does
not say whether the action happened.

```python
from agent_framework import Content, FunctionInvocationContext, function_middleware
from contextos.client import ToolOutcome, ToolPaused

def not_done(outcome: ToolOutcome) -> str:
    reasons = ", ".join(outcome.reason_codes) or outcome.status
    kind = outcome.kind if isinstance(outcome, ToolPaused) else None
    if kind == "duplicate":
        return f"ALREADY REQUESTED ({reasons}): this exact action was submitted before and was not repeated."
    if kind == "unknown_outcome":
        return f"OUTCOME UNKNOWN ({reasons}): the action may have happened and is being reconciled; do not retry it."
    return f"NOT DONE ({outcome.status}: {reasons}). The action did not take effect; do not retry it."

@function_middleware
async def governed_outcomes(context: FunctionInvocationContext, call_next) -> None:
    try:
        await call_next()
    except ToolPaused as paused:
        if paused.kind == "approval" and "approval_response" not in context.metadata:
            call_id = context.metadata["call_id"]
            occurrence = context.metadata.get("function_call_occurrence_id") or call_id
            call = Content.from_function_call(call_id=call_id, name=context.function.name,
                                              arguments=dict(context.arguments), id=occurrence)
            context.result = Content.from_function_approval_request(
                id=occurrence, function_call=call, additional_properties={"operation_id": paused.operation_id})
        else:
            context.result = not_done(paused)
    except ToolOutcome as outcome:
        context.result = not_done(outcome)
```

| Exception | Typical reason codes | Result |
|---|---|---|
| `ToolBlocked` | policy, authority, `budget_exhausted`, `loop_detected` | "not done"; do not retry unchanged |
| `ToolRejected` | `capability_not_surfaced`, `arguments_invalid` | "not done"; the model may fix the call |
| `ToolFailed` | provider refused the effect | "not done"; retry only per the capability's recovery policy |
| `ToolPaused`, `kind == "approval"` | `approval_required` | framework approval request, below |
| `ToolPaused`, `kind == "unknown_outcome"` | `reconcile_effect_before_retry` | "outcome unknown"; reconcile out of band |
| `ToolPaused`, `kind == "duplicate"` | `retry_unsafe` | "already requested"; the operation already exists |
| `ToolPaused`, `kind == "input"` | `provide_requested_input` | answer with `await run.provide_input(...)`, same operation |

`paused.kind` classifies a pause by what it waits on, so the middleware does not match
obligation or reason codes itself. For a duplicate the earlier call with that key did happen; the refused repeat did
not. Decide what succeeded from tool results, not from the model's text.

### Approval pauses → function approval requests

A `function_approval_request` set as the middleware's result is passed through to the
caller as one of `response.user_input_requests`, the framework's
[tool approval](https://learn.microsoft.com/en-us/agent-framework/agents/tools/tool-approval)
flow. Use the call's occurrence id as the request id (another id is a deprecated
binding), and keep the pause under it (`PENDING[occurrence] = paused` in the
middleware) so the caller can show the reviewer the bound action. The caller answers
with the same `AgentSession`; `./examples/frameworks/run.sh microsoft-agent-framework
--approval` runs exactly this:

```python
session = agent.create_session()
response = await agent.run(goal, session=session)
while response.user_input_requests:
    answers = []
    for request in response.user_input_requests:
        approved = await ask_reviewer(PENDING.pop(request.id))   # decided in the approval service
        answers.append(request.to_function_approval_response(approved))
    response = await agent.run(Message(role="user", contents=answers), session=session)
```

On approval the framework re-invokes the call through the middleware with
`context.metadata["approval_response"]` set and the same arguments; the idempotency key
derived from them makes it the same operation, which redeems the exact approval and is
governed end to end again. Each `agent.run` returns only its own messages, so collect
tool results across runs. In a high-value run the gate covers every call of the run,
so the lookup pauses as well; give read-only tools a derived key and call id so their
re-send redeems too. The decision that counts is made in the ContextOS
approval service, bound to the action digest: if it has not approved, the replay
pauses again and the middleware reports "not done" instead of asking twice. A rejected
request never reaches the tool.

### Unknown outcomes

`paused.kind == "unknown_outcome"` (`reconcile_effect_before_retry`) means the effect
may have happened. Retries are refused
until it is resolved with `await run.reconcile(operation_id)` or an operator assertion with
evidence (GUIDE §3, "Reconciling unknown effects"); `run.complete()` refuses with
`required_effect_unsatisfied` until then.

## Checkpoint and resume

Two kinds of state, kept separately:

- **The framework's**: an `AgentSession` (`session.to_dict()` /
  `AgentSession.from_dict(data)`, [sessions](https://learn.microsoft.com/en-us/agent-framework/agents/conversations/session)),
  or for workflows a `CheckpointStorage` such as `FileCheckpointStorage`
  (`WorkflowBuilder(..., checkpoint_storage=storage)`, resumed with
  `workflow.run(checkpoint_id=..., checkpoint_storage=storage)`,
  [checkpoints](https://learn.microsoft.com/en-us/agent-framework/workflows/checkpoints)).
- **The ContextOS checkpoint**: the orchestrator's pointer, fenced by executor
  generation, revisioned, audited by digest, at most 256 KiB.

Keep the framework state in your store and checkpoint its reference and digest in
ContextOS after each step that matters:

```python
blob = store.put(json.dumps(session.to_dict()))     # or the workflow checkpoint id
revision = (await run.checkpoint({"session": blob.ref, "sha256": blob.sha256, "step": "refund"}, revision))["revision"]
```

A replacement executor takes the run over (the old process is fenced with
`executor_stale`), rebuilds tools and middleware on the new handle, and restores:

```python
run = await (await client.attach(run_id, trace_id, principal_chain)).take_over()
saved = await run.latest_checkpoint()
lookup_order, issue_refund = governed_tools(run)
agent = Agent(client=chat_client, tools=[tool(lookup_order), tool(issue_refund)],
              middleware=[budget(run), governed_outcomes], instructions=INSTRUCTIONS)
session = AgentSession.from_dict(json.loads(store.get(saved["state"]["session"])))
response = await agent.run(next_input, session=session)
```

Tools built on the old `Run` hold the old generation and are refused. A pending
approval request restored with the session can still be answered; the replay is the
same operation. The budget is not reset by resume.

## Multi-agent handoff → delegation

Whether you compose agents with `agent.as_tool()` or the handoff, group-chat and
sequential builders in `agent-framework-orchestrations`
([handoff](https://learn.microsoft.com/en-us/agent-framework/workflows/orchestrations/handoff)),
give each sub-agent its own child run. Admit it with an `AgentDelegationEnvelope`
(`run.delegate`, GUIDE §3 "Delegating to child runs"; `examples/agent-loop/agent.py`
has the full envelope). A `read_only` lane is surfaced no effectful capability.

```python
lane = await run.delegate(child_admission, envelope)    # effect_policy "read_only", sub_budget
lane_lookup, _ = governed_tools(lane)
research = Agent(client=chat_client, name="research", instructions="Look orders up.",
                 tools=[tool(lane_lookup)], middleware=[budget(lane), governed_outcomes])
support = Agent(client=chat_client, name="support", instructions=INSTRUCTIONS,
                tools=[research.as_tool(), tool(issue_refund)], middleware=[budget(run), governed_outcomes])
response = await support.run(goal, session=support.create_session())
await run.close_child(lane, "accept")  # settles the lane's spend into the parent
```

The sub-agent's model calls spend the lane's sub-budget (size `sub_budget.total_tokens`
for them); an attempt to act from the lane is refused (`capability_not_surfaced`).
Close every child before `run.complete()` (`children_unsettled` otherwise).

## Or connect over MCP

Each run is an MCP server at `POST /v1/runs/{run_id}/mcp`. Use
[`MCPStreamableHTTPTool`](https://learn.microsoft.com/en-us/agent-framework/agents/tools/local-mcp-tools):

```python
from agent_framework import MCPStreamableHTTPTool

contextos = MCPStreamableHTTPTool(
    name="contextos", url=f"{base}/v1/runs/{run.run_id}/mcp", approval_mode="never_require",
    header_provider=lambda _: {"Authorization": f"Bearer {token}",
                               "ContextOS-Executor-Generation": str(run.executor_generation)})
async with Agent(client=chat_client, tools=[contextos], middleware=[budget(run)]) as agent:
    response = await agent.run(goal)
```

The agent sees only the run's surfaced capabilities with their reviewed schemas.
Refusals arrive as MCP tool errors whose `structuredContent` carries status and reason
codes. Effectful calls derive their operation key from capability and arguments unless
`_meta["io.contextos/idempotencyKey"]` is given. Every result's `_meta` names
`io.contextos/toolCallId` and `io.contextos/operationId`, which a DecisionRecord can
cite; keep one effect on one route, since an explicitly keyed call and a derived-key
call are different operations (the second is refused, `effect_repeated`). `header_provider` reads the generation
per request, so it follows a takeover. Chat middleware still budgets the model calls.

## Record the decision and complete

```python
await run.record_decision("support.refund.execute", "DECIDED", outcome="refund_issued",
                          tool_calls=[{"tool_call_id": "tc_refund_ord_881", "operation_id": "refund:ord_881"}],
                          rationale={"strategy": response.text[:500]})
await run.complete()
evidence = await run.evidence()
```

The gateway verifies every cited tool call against its ledgers (`lineage_unverified`
otherwise). Cite what the tools returned, not what the model said.

## Pitfalls

- **Exceptions become generic tool errors.** Without the function middleware the model
  sees `Error: Function failed.` and may retry; it must see that the action did not happen.
- **`MiddlewareFailure` vs results.** Raise `MiddlewareFailure` only to abort the whole
  run; a governed refusal is a normal tool result.
- **Middleware order.** Middleware runs in list order; put the outcome mapping
  innermost if other middleware inspects results.
- **Parallel tool calls.** Models may emit several calls in one turn and the framework
  runs them concurrently; each is governed separately, and keys keep repeats safe.
- **Session-bound approvals.** Approval responses bind to requests recorded in the
  same `AgentSession`; keep and restore the session with the run.
- **Unpinned model.** Pin the model in the contract's `release_refs` so decisions name
  it (GUIDE §6, "Pin the model and evaluators").

Official docs: [Overview](https://learn.microsoft.com/agent-framework/overview/),
[Tools](https://learn.microsoft.com/en-us/agent-framework/agents/tools/),
[Middleware](https://learn.microsoft.com/en-us/agent-framework/agents/middleware/),
[Tool approval](https://learn.microsoft.com/en-us/agent-framework/agents/tools/tool-approval),
[Workflows human-in-the-loop](https://learn.microsoft.com/en-us/agent-framework/workflows/human-in-the-loop).
