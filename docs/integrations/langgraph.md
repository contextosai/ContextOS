# LangGraph under ContextOS

This guide puts a LangGraph agent under `contextosd`: every tool call is governed by the
gateway, every model call spends the run's budget, refusals and pauses map onto
LangGraph's own error and human-in-the-loop mechanisms, and the run ends with a signed
DecisionRecord. It targets LangGraph 1.2 and LangChain 1.4 (`langchain.agents.create_agent`,
which builds a LangGraph `StateGraph` with a model node and a `ToolNode`). The runnable
version is [examples/frameworks/langgraph](../../examples/frameworks/langgraph/README.md).

The integration is one `AgentMiddleware` and your existing tools. The gateway enforces
everything that matters for safety; the middleware only makes sure the agent asks it and
tells the model the truth about what happened.

## 1. Install

```sh
pip install "langgraph==1.2.16" "langchain==1.4.6" "langchain-anthropic==1.7.6"
pip install "langgraph-checkpoint-postgres"     # a durable checkpointer, for failover (section 6)
```

`contextos.client` is standard-library only; vendor `bindings/python/contextos` or
install it from your internal index.

## 2. Admit a run

Admit one ContextOS run per agent task, before building the graph, and use the run id as
the LangGraph `thread_id` so the two are found together:

```python
from contextos.client import Client

client = Client("https://contextos.internal", token=os.environ["CONTEXTOS_TOKEN"])
run = client.admit(admission_body)      # holds the executor generation
config = {"configurable": {"thread_id": run.run_id}}
```

## 3. Register governed tools

`create_agent` accepts plain callables and builds each tool's schema from its signature
and docstring, so a `governed_tool` function is a LangGraph tool as it stands. Its body
never runs; the call is sent to the gateway, which authorizes, dispatches and audits it.

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

Derive `idempotency_key` from the arguments that identify the effect, never from
LangGraph's `tool_call["id"]`: the model mints a new id on every attempt, so a key built
from it would let a repeated refund through as a new operation.

## 4. Budget every model call and govern every tool call

One middleware does both. `wrap_model_call` wraps the model node, so a reservation is
taken before each call (including each retry and each fallback, if those middlewares sit
outside it) and the loop cannot call the model once the budget is spent.
`wrap_tool_call` wraps each tool execution inside `ToolNode`, which is where the client's
typed exceptions arrive.

```python
from langchain.agents import create_agent
from langchain.agents.middleware import AgentMiddleware
from langchain.messages import ToolMessage
from langgraph.types import interrupt
from contextos.client import ToolBlocked, ToolFailed, ToolPaused, ToolRejected


def refusal(outcome) -> str:
    reasons = ", ".join(outcome.reason_codes) or outcome.status
    kind = outcome.kind if isinstance(outcome, ToolPaused) else None
    if kind == "duplicate":
        return f"ALREADY REQUESTED ({reasons}): this exact action was submitted before and was not repeated."
    if kind == "unknown_outcome":
        return f"OUTCOME UNKNOWN ({reasons}): the action may have happened and is being reconciled; do not retry it."
    return f"NOT DONE ({outcome.status}: {reasons}). The action did not take effect; do not retry it."


class ContextOS(AgentMiddleware):
    def __init__(self, run, tokens: int = 4000):
        super().__init__()
        self.run, self.tokens = run, tokens

    def wrap_model_call(self, request, handler):
        with self.run.budgeted_model_call(tokens=self.tokens):   # BudgetExhausted raises first
            return handler(request)

    def wrap_tool_call(self, request, handler):
        call = request.tool_call
        try:
            return handler(request)
        except ToolPaused as paused:
            if paused.kind != "approval":
                return self.error(call, refusal(paused))     # duplicate, unknown outcome, ...
            answer = interrupt({"approval_request_id": paused.report["approval_request_id"],
                                "tool": call["name"], "args": call["args"]})
            return self.error(call, f"{refusal(paused)} Reviewer: {answer}")
        except (ToolBlocked, ToolRejected, ToolFailed) as outcome:
            return self.error(call, refusal(outcome))

    @staticmethod
    def error(call, text):
        return ToolMessage(text, tool_call_id=call["id"], name=call["name"], status="error")


agent = create_agent("anthropic:claude-sonnet-5-5", tools=[lookup_order, issue_refund],
                     system_prompt=INSTRUCTIONS, middleware=[ContextOS(run)], checkpointer=checkpointer)
```

Executor settlement charges the whole reservation. In production, pass the reservation id
to the LLM gateway that meters the call (`meter` scope) instead of calling
`settle_usage` yourself; it settles what was measured and releases the rest.

For `agent.ainvoke` and async tools (MCP tools are async-only), also implement
`awrap_model_call` and `awrap_tool_call` (the same mapping, awaiting `handler`), with
`contextos.aio` so the event loop never blocks on `contextosd`:

```python
    async def awrap_model_call(self, request, handler):
        async with AsyncRun(self.run).budgeted_model_call(tokens=self.tokens):   # from contextos.aio
            return await handler(request)
```

`governed_tool(AsyncRun(run), ...)` makes a governed tool async. When a reservation is
refused, `BudgetExhausted` (from `contextos.client`) propagates out of `agent.invoke`.
Catch it there, record a `DEFERRED` or `REJECTED` decision if you can, and `run.fail()`
or `run.complete()`; do not catch it inside the graph.

## 5. Map outcomes to LangGraph behavior

| Client exception | Meaning | What the middleware does |
|---|---|---|
| `ToolBlocked` | authority, policy, constraint or budget refused it | error `ToolMessage`: not done, do not retry |
| `ToolRejected` | malformed, unsurfaced or incompatible reuse | error `ToolMessage`: not done |
| `ToolFailed` | the provider definitively did not apply it | error `ToolMessage`: not done |
| `ToolPaused`, `kind == "approval"` | approval pending | `interrupt()`; resume after the approval service decides |
| `ToolPaused`, `kind == "duplicate"` / `"unknown_outcome"` | a repeat of an existing operation, or an outcome that is unknown | error `ToolMessage`; an operator reconciles an unknown outcome (GUIDE section 3, "Reconciling unknown effects") |

The interrupt reaches the caller as `result["__interrupt__"]`. Approval itself happens
in your approval service, bound to the action digest; LangGraph only waits. Resume the
same thread when the approver has decided (the example exercises this with
`./examples/frameworks/run.sh langgraph --approval`):

```python
from langgraph.types import Command

result = agent.invoke({"messages": [{"role": "user", "content": goal}]}, config)
while result.get("__interrupt__"):
    request = result["__interrupt__"][0].value
    wait_for_decision(request["approval_request_id"])   # your approval service
    result = agent.invoke(Command(resume="approved"), config)
```

On resume LangGraph re-runs the interrupted node from the start, so the middleware sends
the same governed call again with the same operation key. That is a governed retry, not
a blind one: approved, it runs once; still pending, it pauses again and the model is told
it did not happen. LangChain's `HumanInTheLoopMiddleware` can additionally ask a person
before the call leaves the process, but it is not the approval of record; only the
gateway's approval check lets the effect run.

A tool that asks for input (`kind == "input"`) can be handled the same way: put
`paused.input_requests` in the interrupt, then answer with `run.provide_input(...)`
(GUIDE section 3, "Tools that ask for input").

## 6. Checkpoint and resume after failover

There are two checkpoints and they hold different things:

- LangGraph's checkpointer holds the conversation and the graph's position, per
  `thread_id`. For failover it must be durable and shared (`PostgresSaver`), not
  `InMemorySaver`.
- The ContextOS checkpoint holds the orchestrator's own state and is fenced by executor
  generation: only the executor that currently owns the run can read or write it. Store
  what a successor needs to find the LangGraph thread, plus your plan and last verdict.

```python
revision = run.checkpoint({"thread_id": run.run_id, "step": "act"}, expected_revision=0)["revision"]
```

A replacement executor takes the run over, which fences the old process, reads the
ContextOS checkpoint and resumes the LangGraph thread from its last saved step:

```python
from langgraph.checkpoint.postgres import PostgresSaver

run = client.attach(run_id, trace_id, principal_chain).take_over()
state = run.latest_checkpoint()["state"]
with PostgresSaver.from_conn_string(DB_URI) as checkpointer:
    agent = create_agent(model, tools=[*register_tools(run)], middleware=[ContextOS(run)],
                         checkpointer=checkpointer)
    result = agent.invoke(None, {"configurable": {"thread_id": state["thread_id"]}})
```

Register the tools and middleware against the taken-over `run`: from the takeover on, the
old executor's requests are refused with `executor_stale`. If the old executor died in
the middle of a tool step, LangGraph re-runs that step and the gateway answers from its
operation ledger: an effect still in flight comes back paused with
`reconcile_effect_before_retry`, and a completed one with `retry_unsafe`. Neither is
applied again, and `refusal()` words them as "ALREADY REQUESTED" and "OUTCOME UNKNOWN",
not "not done": the original call may have taken effect.

## 7. Subagents and handoffs: delegate to child runs

A LangGraph subagent is usually another agent wrapped as a tool of the supervisor. Give
each subagent its own child run, admitted with an `AgentDelegationEnvelope`, so its tools
and budget are narrowed by the gateway rather than by the prompt. A `read_only` lane gets
no effectful capabilities at all.

```python
from langchain.tools import tool

@tool
def research_order(order_id: str) -> str:
    """Research an order in a read-only lane and report what was found."""
    lane = run.delegate(child_admission(order_id), research_envelope(run, order_id))

    @governed_tool(lane, "adp_orders.lookup", approval_mode="read_only")
    def lookup(order_id: str) -> dict:
        """Look up an order's status, amount and refund eligibility."""

    researcher = create_agent(model, tools=[lookup], middleware=[ContextOS(lane, tokens=1000)])
    accepted = False
    try:
        out = researcher.invoke({"messages": [{"role": "user", "content": f"Look up {order_id}."}]})
        accepted = True
        return out["messages"][-1].text
    finally:
        run.close_child(lane, "accept" if accepted else "reject")   # settles its spend into the parent
```

The envelope (scope, `sub_budget`, `effect_policy: "read_only"`, `parent_claim_hash`) is
built as in [examples/agent-loop/agent.py](../../examples/agent-loop/agent.py). The child's
model calls reserve from the child's sub-budget, which was reserved from the parent. The
parent cannot complete until every child is closed (`children_unsettled`), and a child
with unresolved effects cannot close. A supervisor that calls several subagents in one
turn runs them concurrently; each is its own child run, so that is safe.

## 8. The MCP alternative

Every run is also an MCP server at `POST /v1/runs/{run_id}/mcp`. LangChain's `MCPAdapter`
(`pip install "langchain[mcp]"`, beta in 1.4) turns its surfaced capabilities into tools:

```python
from fastmcp import Client as MCPClient
from fastmcp.client.transports import StreamableHttpTransport
from langchain.mcp import MCPAdapter

transport = StreamableHttpTransport(f"{base_url}/v1/runs/{run.run_id}/mcp", headers={
    "Authorization": f"Bearer {token}", "ContextOS-Executor-Generation": str(run.executor_generation)})
async with MCPAdapter(MCPClient(transport)) as adapter:
    tools = await adapter.list_tools()
    for t in tools:
        t.name = t.name.replace(".", "_")      # model APIs reject dots in tool names
    agent = create_agent(model, tools, middleware=[ContextOS(run)])
    result = await agent.ainvoke({"messages": [{"role": "user", "content": goal}]}, config)
```

The tools carry the capabilities' reviewed input schemas, and renaming them is safe: the
adapter calls the server by the MCP tool's own name. Refusals arrive as error
`ToolMessage`s with the gateway's text (for example `ContextOS paused: retry_unsafe. This
call had no effect; do not retry it unchanged.`), so `wrap_tool_call` sees no exception;
inspect `status == "error"` there if you need to interrupt on approval. Operation keys
are derived from capability and arguments, so a repeated call cannot apply twice. Every
result carries `_meta["io.contextos/toolCallId"]` and `_meta["io.contextos/operationId"]`,
which a DecisionRecord can cite. The adapter does not send per-call `_meta`, so it
cannot set `io.contextos/idempotencyKey`, `io.contextos/toolCallId` or cite
`io.contextos/evidenceRefs`; use `governed_tool` for effects that must cite evidence or use
a key of your choosing, and keep each effect on one route (an explicitly keyed call and a
derived-key call are two operations; the second is refused as `effect_repeated`). After a
takeover, rebuild the transport with the new generation.

## 9. Record the decision and complete

The DecisionRecord cites ContextOS tool-call ids and operation ids, not LangGraph's
`tool_call["id"]`. Derive them as in section 3 so you know them without parsing messages:

```python
decision = run.record_decision("support.refund.execute", "DECIDED", outcome="refund_issued",
                               tool_calls=[{"tool_call_id": "tc_refund_ord_881", "operation_id": "refund:ord_881"}],
                               rationale={"strategy": result["messages"][-1].text[:500]})
run.complete()
```

`complete` is refused while an effect is unknown or partial, a child is open, or anything
is in flight.

## 10. Pitfalls

- **Exceptions turned into strings.** `ToolNode`'s `handle_tool_errors=True`, a tool's
  `handle_tool_error=True`, or a broad `ToolErrorMiddleware` turns `ToolPaused` into
  text such as an exception repr, which a model reads as "try again". Keep governed
  exceptions for the ContextOS middleware, and place it inside any error middleware.
- **Automatic retries.** `ToolRetryMiddleware` and `ModelRetryMiddleware` retry
  unclassified exceptions by default. Exclude `ToolOutcome` and `ContextOSHTTPError` with
  `retry_on`, or a pause is retried until it is refused as `retry_unsafe` and a refused
  reservation is retried against an exhausted budget.
- **Middleware order.** The first middleware in the list is the outermost. Put
  `ContextOS` last so every retry and fallback attempt inside it is budgeted and every
  tool outcome is mapped before other middleware sees it.
- **Parallel tool calls.** `ToolNode` runs a turn's tool calls concurrently. The gateway
  serializes what must be serialized: two identical refunds in one turn share an
  operation key, so one runs and the other is refused.
- **Tool-call ids.** LangGraph's ids are the model's; ContextOS ids are yours. Never derive
  idempotency keys or DecisionRecord lineage from the model's.
- **Side effects before `interrupt()`.** The node re-runs on resume. Anything before the
  interrupt must be idempotent; a governed call with a stable key is.
- **Local limits are not the budget.** `ModelCallLimitMiddleware` and
  `ToolCallLimitMiddleware` count per process and reset with it. The run's budget ledger
  survives restarts, takeovers and parallel lanes.
- **Legacy `create_react_agent`.** It is deprecated in LangGraph 1.x and has no middleware;
  use `create_agent`, or wrap the model node and pass a `ToolNode(..., wrap_tool_call=...)`
  in your own `StateGraph`.

## References

- Agents and `create_agent`: https://docs.langchain.com/oss/python/langchain/agents
- Custom middleware (`wrap_model_call`, `wrap_tool_call`): https://docs.langchain.com/oss/python/langchain/middleware/custom
- Built-in middleware (retry, limits, tool errors): https://docs.langchain.com/oss/python/langchain/middleware/built-in
- Human-in-the-loop: https://docs.langchain.com/oss/python/langchain/human-in-the-loop
- Interrupts: https://docs.langchain.com/oss/python/langgraph/interrupts
- Persistence and checkpointers: https://docs.langchain.com/oss/python/langgraph/persistence
- Subagents: https://docs.langchain.com/oss/python/langchain/multi-agent/subagents
- MCP: https://docs.langchain.com/oss/python/langchain/mcp
- Testing with fake models: https://docs.langchain.com/oss/python/langchain/test
- Claude model ids: https://platform.claude.com/docs/en/about-claude/models/overview
