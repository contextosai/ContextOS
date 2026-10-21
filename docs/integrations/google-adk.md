# Google Agent Development Kit (Python)

ADK runs the agent loop: the model, tool calls, sub-agents and sessions. ContextOS
governs what that loop is allowed to do. Each tool call goes through `contextosd`, which
authorizes it against the exact arguments, dispatches it once per operation key, charges
it to the run's budget and signs it into the audit chain. Your ADK code changes in four
places: the tools, the model callbacks, the tool error callback, and the end of the run.

A runnable example is in [`examples/frameworks/google-adk`](../../examples/frameworks/google-adk/):

```sh
./examples/frameworks/run.sh google-adk
```

This page was written against `google-adk==2.12.0` (Python 3.11 or later).

## Install

```sh
pip install google-adk==2.12.0            # add the [mcp] extra for McpToolset
export PYTHONPATH=/path/to/ContextOS/bindings/python
```

`contextos.client` uses only the standard library. ADK is asyncio, so use
`contextos.aio`: `AsyncClient` and `AsyncRun` have the client's methods as coroutines,
each request running in a worker thread, so tools and callbacks never block the event
loop.

## Admit a run

Admit the run before you build the agent. The tools and callbacks need the run handle,
which carries the executor generation.

```python
from contextos.aio import AsyncClient

client = AsyncClient(os.environ["CONTEXTOS_URL"], token=os.environ["CONTEXTOS_TOKEN"])
run = await client.admit(admission_body)  # POST /v1/runs: contract, context, budget; an AsyncRun
```

Admit one ContextOS run per unit of governed work, and treat the ADK session as that
run's conversation. Running several ADK invocations in one session against one run is
fine. Do not share one run between unrelated sessions.

## Governed tools as ADK function tools

ADK builds a `FunctionDeclaration` from a function's signature and docstring.
`governed_tool` keeps both: it uses `functools.wraps`, and `inspect.signature` follows
`__wrapped__`. Built on an `AsyncRun`, a governed function is a coroutine, which ADK
awaits, and it can be passed to `FunctionTool` unchanged:

```python
from contextos.client import governed_tool
from google.adk.tools import FunctionTool

@governed_tool(run, "adp_orders.lookup", approval_mode="read_only")
async def lookup_order(order_id: str) -> dict:
    """Look up an order's status, amount (amount_minor) and refund eligibility."""

@governed_tool(run, "adp_payments.issue_refund", approval_mode="destructive",
               idempotency_key=lambda order_id, **_: f"refund:{order_id}",
               tool_call_id=lambda order_id, **_: f"tc_refund_{order_id}",
               evidence_refs=["kg:order:ord_881#snapshot_kg_2026_05_03_T0930"])
async def issue_refund(order_id: str, customer_id: str, amount_minor: int) -> dict:
    """Issue a refund for an order to its customer, in minor units of the order's currency."""

tools = [FunctionTool(lookup_order), FunctionTool(issue_refund)]
```

With 2.12.0 the declarations come out as the signatures say, for example
`issue_refund(order_id: string, customer_id: string, amount_minor: integer)`, all
required. The bodies never run. Do not add a `tool_context` parameter to a governed
function: ADK would inject it, and the binding would send it to the gateway as an
argument. If a tool needs the context, write a wrapper with its own signature that
calls the governed function.

Derive `idempotency_key` from the arguments that identify the effect. A model that
repeats the call, or an ADK replay after a crash, then maps to the same operation, and
the gateway refuses to apply it twice (`retry_unsafe`).

## Budget each model call

Reserve from the run's budget before each model call and settle after it. That is the
same ledger tool calls use, so a looping agent stops at the budget and a resumed run
does not start a fresh budget. Where one function makes the call,
`async with run.budgeted_model_call(tokens=...)` reserves and settles around it; ADK
splits the call across callbacks, so reserve in one and settle in the others:

```python
from contextos.client import BudgetExhausted
from google.adk.models import LlmResponse
from google.genai import types

reservations = {}

async def before_model(callback_context, llm_request):
    key = (callback_context.invocation_id, callback_context.agent_name)
    try:
        reservations[key] = await run.reserve_usage("model_call", tokens=4000)
    except BudgetExhausted as refused:         # refused.reasons names the limit
        # A truthy response skips the model call.
        return LlmResponse(content=types.Content(role="model", parts=[types.Part(
            text=f"Stopping: the run's budget refused another model call ({refused.code}).")]))

async def settle(callback_context):
    key = (callback_context.invocation_id, callback_context.agent_name)
    if reservation := reservations.pop(key, None):
        await run.settle_usage(reservation)

async def after_model(callback_context, llm_response):
    if not llm_response.partial:              # called per chunk when streaming
        await settle(callback_context)

async def on_model_error(callback_context, llm_request, error):
    await settle(callback_context)            # after_model does not run on errors
```

Pass all three to the `LlmAgent` (`before_model_callback`, `after_model_callback`,
`on_model_error_callback`). To cover every agent in a tree, put the same logic in a
`BasePlugin` registered on the `Runner`, since agent callbacks apply only to the agent
they are set on. A reservation is at least `[guards] model_call_min_tokens` (1,000 by
default).

When the executor settles, the whole reservation is charged, because self-reported
usage is not evidence. To charge measured usage, send `run.metering_headers(reservation)`
with the request to an LLM gateway that holds the `meter` scope
(`Gemini(model=..., base_url="https://llm-gateway.internal")`), and let it settle with what
the provider reported. ADK merges `llm_request.config.http_options.headers` into the
request, so add them in `before_model`:

```python
    http = llm_request.config.http_options = llm_request.config.http_options or types.HttpOptions()
    http.headers = {**(http.headers or {}), **run.metering_headers(reservations[key])}
```

Then `after_model` only drops the reservation, and `on_model_error` settles it, ignoring
a 404 (`ContextOSHTTPError.status`: the gateway settled first): a failed call the
gateway did not settle is charged in full. One reservation covers one call.
[examples/metering-proxy](../../examples/metering-proxy) is a reference gateway; it reads OpenAI and Anthropic
usage, so a Gemini gateway must read `usageMetadata` the same way. ADK's `RunConfig.max_llm_calls` still applies, but it counts calls in one
process only. The ContextOS budget holds across processes, lanes and takeovers.

## Map governed outcomes

A governed call that does not succeed raises a `ToolOutcome` subclass. Without a
handler, ADK propagates the exception and ends the invocation. Use
`on_tool_error_callback` to turn each outcome into a tool result that the model can
read:

```python
from contextos.client import ToolOutcome, ToolPaused

def on_tool_error(tool, args, tool_context, error):
    if not isinstance(error, ToolOutcome):
        return None                                   # not ours: let ADK handle it
    kind = error.kind if isinstance(error, ToolPaused) else None
    reasons = ", ".join(error.reason_codes) or error.status
    if kind == "unknown_outcome":
        pending_reconcile.append(error.operation_id)
        return {"error": f"OUTCOME UNKNOWN ({reasons}): the action may have happened and is being "
                         "reconciled; do not retry it."}
    if kind == "duplicate":
        return {"error": f"ALREADY REQUESTED ({reasons}): this exact action was submitted before "
                         "and was not repeated."}
    if kind == "approval" and tool_context.tool_confirmation is None:
        tool_context.request_confirmation(
            hint=f"{tool.name} is waiting for approval.",
            payload={"approval_request_id": error.report["approval_request_id"]})
        tool_context.actions.skip_summarization = True    # end the turn here, no model call
        return {"error": "Awaiting approval; the call has not run."}
    return {"error": f"NOT DONE ({error.status}: {reasons}). The action did not take effect; do not retry it."}
```

- **Duplicate (`kind == "duplicate"`, `retry_unsafe`).** The same operation was already
  requested; tell the model it was not repeated, not that it did not happen.
- **Blocked, rejected, failed.** Tell the model that the action did not happen and why.
  Retrying a `blocked` call unchanged gives the same answer. A `failed` call may be
  retried only as the capability's recovery policy allows. The gateway enforces that
  policy, so the model can call the tool again with the same key.
- **Approval (`kind == "approval"`).** ADK's
  [tool confirmation](https://adk.dev/tools-custom/confirmation/) pauses the
  invocation and emits an `adk_request_confirmation` call to your client. The approval
  is decided in your approval service, not by the ADK confirmation. Set
  `skip_summarization`, or ADK hands the error to the model and the invocation goes on.
  When the human has decided, send the confirmation `FunctionResponse` back (with the
  `invocation_id` if the app is resumable). ADK then runs the same call again. It carries
  the same operation key, so the gateway checks the approval against the action digest
  and dispatches the call once or refuses it. The example exercises this with
  `run.sh google-adk --approval`:

  ```python
  async for event in runner.run_async(user_id=user, session_id=sid, new_message=message):
      confirmations += [c for c in event.get_function_calls() if c.name == "adk_request_confirmation"]
  # ... once the approval service has decided:
  message = types.Content(role="user", parts=[types.Part(function_response=types.FunctionResponse(
      id=c.id, name="adk_request_confirmation", response={"confirmed": True})) for c in confirmations])
  ```

  Do not use `FunctionTool(require_confirmation=True)` for this: that asks before the
  gateway has decided whether approval is needed.
- **Input required (`kind == "input"`).** `error.input_requests` holds the
  questions. Answer them with `await run.provide_input(error, envelope, responses)`, where
  `envelope` is `await run.envelope(...)` rebuilt with the call's arguments, key and
  `tool_call_id`. That continues the same operation. Do not answer by calling the tool again.
- **Unknown outcome (`kind == "unknown_outcome"`).** The effect may have happened.
  Do not tell the model either way. Call `await run.reconcile(operation_id)` (provider query)
  or have an operator assert the outcome with evidence. `complete` is refused until it
  is resolved.

A long-running tool (`LongRunningFunctionTool`) suits work that the provider finishes
later. For governed effects, the gateway's operation ledger already tracks that state.
Map the pause as shown above instead of returning `None` and polling from the model.

## Checkpoint and resume

ADK sessions store the conversation and `state`. A ContextOS checkpoint stores the
orchestrator's own position, fenced by executor generation. Use both. Keep the session
in a durable `SessionService`, and checkpoint a pointer to it after each step that
matters:

```python
revision = (await run.checkpoint({"session_id": session.id, "step": "refund", "verdict": "accept"},
                                 revision))["revision"]
```

After a crash, the replacement process takes the run over, which fences the old
process, and then continues from the checkpoint:

```python
run = await (await client.attach(run_id, trace_id, principal_chain)).take_over()
saved = await run.latest_checkpoint()        # {"state": {...}, "revision": n}
session = await session_service.get_session(app_name=APP, user_id=user, session_id=saved["state"]["session_id"])
```

Rebuild the tools and callbacks with the new `run` handle, which has the new
generation. The old handle's calls are refused with `executor_stale`. If the app is
resumable (`App(..., resumability_config=ResumabilityConfig(is_resumable=True))`), ADK
re-runs tool calls that never got a response. Governed calls are keyed, so a call that
had already been dispatched is not applied again: the gateway reports it or holds it
for reconciliation. See [Resume](https://adk.dev/runtime/resume/).

Do not keep the executor generation or tokens in session `state`. State is persisted
and shown to the agent.

## Sub-agents and AgentTool

An ADK sub-agent shares its parent's tools and process. A ContextOS delegation gives
it its own child run, with narrowed capabilities, its own sub-budget and, for research,
no effects at all. Admit the lane, build the sub-agent from the lane's tools, and close
the lane when the parent is done with it:

```python
lane = await run.delegate(child_admission, envelope)  # effect_policy "read_only", allowed_capabilities, sub_budget
lane_lookup, _ = make_tools(lane)                 # governed_tool bound to the child run
researcher = LlmAgent(name="researcher", model=MODEL, tools=[FunctionTool(lane_lookup)],
                      before_model_callback=..., after_model_callback=...)   # reserve from `lane`
root = LlmAgent(name="support_agent", model=MODEL, tools=[AgentTool(agent=researcher), FunctionTool(issue_refund)])
# ... run the invocation ...
await run.close_child(lane, "accept")             # settles the lane's spend into the parent
```

The envelope fields are listed in
[Delegating to child runs](../GUIDE.md#delegating-to-child-runs-subagent-lanes), and
[`examples/agent-loop/agent.py`](../../examples/agent-loop/agent.py) has a complete one.
Bind the lane's budget callbacks to `lane`, not `run`. A lane has no effectful
capabilities, so a refund tool given to it by mistake is refused by the gateway. Use
`AgentTool` for lanes: it returns a result to the parent. Agent transfer (`sub_agents`)
hands the conversation over instead, and the parent cannot close the lane until it
regains control. The parent cannot `complete` while a child is open
(`children_unsettled`).

## Or connect through MCP

Every admitted run is also an MCP server. `McpToolset` can use it directly, with no
`governed_tool` functions (needs `google-adk[mcp]`):

```python
from google.adk.tools.mcp_tool import McpToolset
from google.adk.tools.mcp_tool.mcp_session_manager import StreamableHTTPConnectionParams

toolset = McpToolset(connection_params=StreamableHTTPConnectionParams(
    url=f"{CONTEXTOS_URL}/v1/runs/{run.run_id}/mcp",
    headers={"Authorization": f"Bearer {token}",
             "ContextOS-Executor-Generation": str(run.executor_generation)}))
agent = LlmAgent(name="support_agent", model=MODEL, tools=[toolset], ...)
# ... run ...
await toolset.close()
```

The model sees the run's surfaced capabilities under their capability ids (for example
`adp_payments.issue_refund`), with their reviewed input schemas. A refusal comes back as
a tool error (`isError`), with `structuredContent` carrying `status`, `reason_codes`,
`obligations` and `operation_id`, so no error callback is needed for the model to see
it. Operation keys come from the capability and arguments unless you set
`_meta["io.contextos/idempotencyKey"]`. Evidence goes in
`_meta["io.contextos/evidenceRefs"]`, and your own call id in
`_meta["io.contextos/toolCallId"]`. After a takeover the generation header is stale:
build a new toolset, or use `header_provider` to read the current generation.

A DecisionRecord cites each call by `tool_call_id` and `operation_id`. Every MCP result,
success or refusal, returns both in `_meta` (`io.contextos/toolCallId`,
`io.contextos/operationId`; the gateway assigns an `mcp_…` call id when you send none),
so an MCP call can be cited. Keep each effect on one route: a call keyed in `_meta` and
one keyed by derivation are two operations; once one has applied, the gateway refuses
the other (`effect_repeated`).

## Record the decision and complete

Record the decision from what the gateway reported, not from the model's final text,
then complete the run:

```python
await run.record_decision("support.refund.execute", "DECIDED", outcome="refund_issued",
                          tool_calls=[{"tool_call_id": "tc_refund_ord_881", "operation_id": "refund:ord_881"}],
                          rationale={"strategy": summary[:500]})
await run.complete() # refused while an effect is unknown, a child is open or a call is in flight
evidence = await run.evidence()
```

The gateway checks each cited call against the run's operation ledger
(`lineage_unverified` otherwise) and signs the record into the audit chain. Pin the
Gemini model as a `model_profile` release ref so that the record names the model
([Pin the model](../GUIDE.md#pin-the-model-and-evaluators)).

## Pitfalls

- **Parallel function calls.** Gemini can return several calls in one turn. ADK runs
  them concurrently. Async governed tools overlap on the event loop; synchronous tools
  would run inline on it, one after another, unless you pass `run_config=RunConfig(tool_thread_pool_config=ToolThreadPoolConfig())`
  (both from `google.adk.agents.run_config`) to `run_async`. Each
  governed call is authorized separately, and identical effects share an operation key,
  so a duplicated refund in one turn is still applied once.
- **Retries.** Leave retries to the gateway's recovery policy. Do not wrap governed
  tools in retry decorators, and do not let an error callback re-invoke them. The
  client retries only `429` and `503`, which the server did not process.
- **Exceptions.** Without `on_tool_error_callback`, a `ToolOutcome` aborts the
  invocation. Return `None` for exceptions you do not recognize, so real bugs still
  surface. If a model call fails, `on_model_error_callback` is the only place to
  settle its reservation.
- **Loop guard.** After `[guards] identical_tool_calls` identical new operations, the
  next is blocked with `loop_detected` and the obligation `change_approach`. Pass that
  to the model like any other refusal.
- **AI Studio and Vertex AI.** `GOOGLE_API_KEY` (or `GEMINI_API_KEY`) selects the
  Gemini API. `GOOGLE_GENAI_USE_ENTERPRISE=true` (formerly `GOOGLE_GENAI_USE_VERTEXAI`)
  with `GOOGLE_CLOUD_PROJECT` and `GOOGLE_CLOUD_LOCATION` selects Vertex AI on Google
  Cloud, and the `ENTERPRISE` variable wins if both are set. Model availability differs
  by region. Aliases such as `gemini-flash-latest` may not resolve on regional
  endpoints, so pin an exact id such as `gemini-3.8-flash`
  ([models](https://ai.google.dev/gemini-api/docs/models)).
- **Offline runs.** Subclass `BaseLlm` and implement `generate_content_async` to script
  the model, as the example does. Callbacks, tools and sessions behave as they do with
  Gemini.

## ADK references

- [Callbacks](https://adk.dev/callbacks/types-of-callbacks/) and [plugins](https://adk.dev/plugins/)
- [Function tools](https://adk.dev/tools-custom/function-tools/), including
  [long-running tools](https://adk.dev/tools-custom/function-tools/#long-run-tool)
- [Action confirmations](https://adk.dev/tools-custom/confirmation/)
- [MCP tools](https://adk.dev/tools-custom/mcp-tools/)
- [Multi-agent workflows](https://adk.dev/workflows/)
- [Session state](https://adk.dev/sessions/state/) and [resume](https://adk.dev/runtime/resume/)
- [Gemini models in ADK](https://adk.dev/agents/models/google-gemini/) and
  [RunConfig](https://adk.dev/runtime/runconfig/)
