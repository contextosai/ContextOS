# CrewAI under ContextOS

This guide puts a CrewAI crew under `contextosd`: every tool call is governed by the
gateway, every model call spends the run's budget, refusals and pauses map onto CrewAI's
own tool-failure and hook mechanisms, and the run ends with a signed DecisionRecord. It
targets CrewAI 1.15 (`Agent`, `Task`, `Crew`, `Process`, `crewai.tools.tool`, the
`crewai.hooks` interception layer and the `crewai_event_bus`). The runnable version is
[examples/frameworks/crewai](../../examples/frameworks/crewai/README.md).

The integration is a tool adapter, one `before_llm_call` hook and two event listeners.
The gateway enforces everything that matters for safety; the adapter only makes sure the
crew asks it and that the model is told the truth about what happened.

## 1. Install

```sh
pip install "crewai==1.15.28"                # native OpenAI provider included
pip install "crewai[anthropic]==1.15.28"     # for anthropic/... models
```

Turn off CrewAI's anonymous telemetry and trace upload before `crewai` is imported. A
governed run's prompts and tool arguments belong in its audited evidence, not in a
third-party collector:

```python
import os
os.environ.setdefault("CREWAI_DISABLE_TELEMETRY", "true")
os.environ.setdefault("OTEL_SDK_DISABLED", "true")
os.environ.setdefault("CREWAI_TRACING_ENABLED", "false")
```

## 2. Admit a run

One crew run is one ContextOS run. Admit it before building the crew; the `Run` holds the
executor generation and is what every tool and budget call goes through:

```python
from contextos.client import Client

client = Client("https://contextos.internal", token=os.environ["CONTEXTOS_TOKEN"])
run = client.admit(admission_body)        # run_context, contract, request: see GUIDE.md section 3
```

## 3. Governed tools as CrewAI tools

Declare each capability with `governed_tool`. The body never runs; the call goes to the
gateway, which authorizes, dispatches, records and audits it:

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
    """Issue a refund for an order to its customer, in minor units of the order's currency."""
```

`crewai.tools.tool` builds a tool's `args_schema` from `inspect.signature` and its
description from `__doc__`. `governed_tool` uses `functools.wraps`, so both survive:
`tool("issue_refund")(issue_refund)` produces the schema `order_id: str, customer_id: str,
amount_minor: int`. Do not register the governed function directly, though. Wrap it so a
call the gateway did not complete is *returned*, not raised:

```python
import functools, json
from crewai.tools import tool
from crewai.tools.tool_failure import ToolFailure
from contextos.client import ToolOutcome, ToolPaused

def refusal(outcome: ToolOutcome) -> str:
    reasons = ", ".join(outcome.reason_codes) or outcome.status
    kind = outcome.kind if isinstance(outcome, ToolPaused) else None
    if kind == "duplicate":
        return f"ALREADY REQUESTED ({reasons}): this exact action was submitted before and was not repeated."
    if kind == "unknown_outcome":
        return f"OUTCOME UNKNOWN ({reasons}): the action may have happened and is being reconciled; do not retry it."
    return f"NOT DONE ({outcome.status}: {reasons}). The action did not take effect; do not retry it."

def crew_tool(function, on_outcome=lambda outcome: None):
    @functools.wraps(function)
    def call(**arguments):
        try:
            return json.dumps(function(**arguments))
        except ToolOutcome as outcome:
            on_outcome(outcome)                       # section 5: stop the crew on a pause
            return ToolFailure(message=refusal(outcome), code=outcome.status, retryable=False,
                               details={"reason_codes": outcome.reason_codes,
                                        "obligations": outcome.obligations})
    call.__annotations__ = {**function.__annotations__, "return": str}
    governed = tool(function.__name__)(call)
    governed.cache_function = lambda _arguments, _result: False   # never replay a cached result
    return governed
```

Why not raise: CrewAI's text (ReAct) loop catches a tool exception and calls the tool
again, two or three times, before telling the model to move on; its native tool-calling
loop turns it into `Error executing tool: paused: ...`, which a model reads as a
transient error. A `ToolFailure` reaches the model as its message (with `(code: ...)`),
and CrewAI records it as a failed call: on `TaskOutput.tool_failures`, as a tool-usage
event, and, under `tool_failure_policy=ToolFailurePolicy.RAISE`, by stopping the agent
with `ToolExecutionFailedError`.

The `cache_function` matters: with `Crew(cache=True)`, CrewAI answers a repeated call
with identical arguments from its cache without running the tool. The second refund would
never reach the gateway, and the model would be told it succeeded again. Keep crews at the
default `cache=False` and set `cache_function` on every governed tool so a crew that turns
caching on cannot bypass the gateway.

A `BaseTool` subclass works the same way: call the governed function from `_run`, return
a `ToolFailure` on `ToolOutcome`, and set `cache_function` on the instance.

## 4. Budget every model call

Tool calls spend the run's budget at the gateway. Model calls must spend it too, before
they happen. CrewAI runs `before_llm_call` hooks before every model call an agent makes,
and its providers run them for model calls made outside the agent loop (the
max-iterations summary, guardrails, memory analysis, planning). Reserve there; settle when
the event bus reports the call finished:

```python
import contextlib
from collections import deque
from crewai.events import LLMCallCompletedEvent, LLMCallFailedEvent, crewai_event_bus
from crewai.hooks import HookAborted, register_before_llm_call_hook

reservations = deque()

def reserve(context):
    try:
        reservations.append(run.reserve_usage("model_call", tokens=4000))
    except Exception as refused:               # budget_exhausted, or contextosd unreachable
        raise HookAborted(f"model call not reserved: {refused}") from refused

def settle(_source, _event):
    if reservations:
        run.settle_usage(reservations.popleft())

register_before_llm_call_hook(reserve)         # before kickoff(): executors snapshot the hooks
crewai_event_bus.on(LLMCallCompletedEvent)(settle)
crewai_event_bus.on(LLMCallFailedEvent)(settle)
```

Three CrewAI behaviors shape this:

- **Hooks fail open.** Any exception a hook raises except `HookAborted` is logged and
  swallowed, and the model call goes ahead. Convert every reservation failure into
  `HookAborted`; it propagates out of `crew.kickoff()`, so the crew stops when the
  budget is spent, whatever the model wants.
- **`after_llm_call` is not a settlement point.** It is skipped when the model answers
  with native tool calls, and it does not run when the call fails. `LLMCallCompletedEvent`
  and `LLMCallFailedEvent` are emitted for every call that started, including one a hook
  denied.
- **Listeners run on a thread pool.** Call `crewai_event_bus.flush()` after `kickoff()`
  and before recording the decision, so every reservation is settled.

The executor settling is charged the whole reservation. To charge measured usage, pass
the reservation id to an LLM gateway that holds the `meter` scope (for example a proxy
at the `LLM`'s `base_url` that reads it from a request header) and let it settle
(GUIDE.md section 6). A custom `BaseLLM` must do what providers do: call
`self._invoke_before_llm_call_hooks(messages, from_agent)` and emit the call's
started and completed or failed events inside `llm_call_context()`, or its calls outside
the agent loop are neither budgeted nor settled.

## 5. Map outcomes to CrewAI behavior

| Gateway result | Exception | What the crew does |
| --- | --- | --- |
| `ok` / `completed` | none | JSON output returned to the model |
| `blocked` (authority, policy, constraints, budget) | `ToolBlocked` | `ToolFailure` with `refusal()`; the model must change course |
| `rejected` (malformed, unsurfaced, key reuse) | `ToolRejected` | `ToolFailure`; fix the call, not retry it |
| `failed` (provider did not apply it) | `ToolFailed` | `ToolFailure`; a different action may be tried |
| `paused`, `kind == "duplicate"` (`retry_unsafe`) | `ToolPaused` | `ToolFailure`; the operation already exists |
| `paused`, `kind == "approval"` | `ToolPaused` | `ToolFailure` "awaiting approval"; the reviewer decides at CrewAI's human input step |
| `paused`, `kind == "input"` | `ToolPaused` | stop the crew; answer with `run.provide_input` |
| `paused`, `kind == "unknown_outcome"` | `ToolPaused` | stop the crew; `run.reconcile(operation_id)` |
| `paused`, `kind == "other"` (e.g. `operation_in_flight`) | `ToolPaused` | `ToolFailure`; not done |

A pause for input or reconciliation must stop the crew, not become another turn the
model can talk its way through. Record it from the tool and abort the next model call:

```python
STOP = {"input", "unknown_outcome"}
stopped = []

def on_outcome(outcome):
    if isinstance(outcome, ToolPaused) and outcome.kind in STOP:
        stopped.append(outcome)

def stop_on_pause(context):                    # register before `reserve`
    if stopped:
        raise HookAborted(f"paused ({stopped[0].kind}): {', '.join(stopped[0].obligations)}")

try:
    result = crew.kickoff()
except HookAborted:
    pause = stopped[0]
    ...                                         # checkpoint (section 6), wait, then resume
```

An approval pause goes through CrewAI's human input instead, so the crew keeps its
conversation. Give the task `human_input=True` and install a `HumanInputProvider`: after
the agent answers that the call awaits approval, CrewAI calls the provider, which waits
for the decision of record and appends it as feedback; CrewAI runs the agent loop again
and the model re-sends the same call with the same idempotency key, which the gateway
redeems once. `run.sh crewai --approval` exercises this:

```python
from crewai.core.providers.human_input import SyncHumanInputProvider, set_provider

awaiting = []                                  # the tool appends each approval pause here

class Reviewer(SyncHumanInputProvider):
    def handle_feedback(self, answer, context):
        while awaiting:
            paused = awaiting.pop()
            wait_for_decision(paused.report["approval_request_id"])   # your approval service
            context.messages.append(context._format_feedback_message(
                "Approved. Re-send the call that was awaiting approval, unchanged."))
            answer = context._invoke_loop()
        context.ask_for_human_input = False
        return answer

set_provider(Reviewer())
task = Task(description=goal, expected_output="...", agent=agent, human_input=True)
```

The approval itself is granted in your approval service, bound to the action digest;
the feedback only lets the model re-send. Never retry it blindly in a loop. For an
unknown outcome, ask the provider (`run.reconcile(pause.operation_id)`) or have an
operator assert it with evidence; the operation's budget stays reserved and retries are refused until it is
resolved.

A `duplicate` pause (`retry_unsafe`) means the operation was requested earlier. The
refusal text says it was already requested and not repeated; the run's evidence says
what the original did.

## 6. Checkpoint and resume

CrewAI's checkpoints (`Crew(checkpoint=CheckpointConfig(...))`, `kickoff(from_checkpoint=...)`)
and Flow persistence (`@persist`, `kickoff(restore_from_state_id=...)`) store the crew's
own state on the executor's disk. ContextOS checkpoints store the orchestrator's state
with the run, fenced by executor generation and audited by digest, so whichever executor
holds the run reads the same state. Use CrewAI's to skip completed tasks; use the run's to
know where the run is. Save after every task:

```python
revision = {"value": 0}

def checkpoint(task_output):
    revision["value"] = run.checkpoint(
        {"task": task_output.name or task_output.description[:80], "summary": task_output.raw[:2000]},
        revision["value"])["revision"]

crew = Crew(agents=[agent], tasks=tasks, task_callback=checkpoint)
```

In a Flow, keep the run's identity in the persisted state and take the run over on resume:

```python
from crewai.flow.flow import Flow, FlowState, start
from crewai.flow.persistence import persist

class RefundState(FlowState):
    run_id: str = ""
    trace_id: str = ""

@persist()
class RefundFlow(Flow[RefundState]):
    @start()
    def act(self):
        if self.state.run_id:                  # resumed: fence the old executor
            run = client.attach(self.state.run_id, self.state.trace_id, principal_chain).take_over()
            saved = run.latest_checkpoint()
        else:
            run = client.admit(admission_body)
            self.state.run_id, self.state.trace_id = run.run_id, run.trace_id
        return build_crew(run).kickoff()       # tools and hooks bound to *this* run

RefundFlow().kickoff(restore_from_state_id=previous_state_id)
```

Bind tools and hooks to the taken-over `run`: from the takeover on, the old executor's
requests are refused with `executor_stale`. A tool call that was in flight when the old
executor died comes back paused with `reconcile_effect_before_retry`, and a completed one
with `retry_unsafe`; neither is applied again.

## 7. Multi-agent crews: delegate to child runs

Give each agent that does not need the parent's full authority its own child run in a
narrowed lane. A read-only researcher is the common case: its tools are bound to a child
admitted with an `AgentDelegationEnvelope` (`effect_policy: "read_only"`, its own
`sub_budget`), so the gateway, not the prompt, keeps it from acting:

```python
lane = run.delegate(child_admission, research_envelope)       # built as in examples/agent-loop

@governed_tool(lane, "adp_orders.lookup", approval_mode="read_only")
def lookup(order_id: str) -> dict:
    """Look up an order's status, amount and refund eligibility."""

researcher = Agent(role="Order researcher", goal="Report the order's facts.", backstory="...",
                   llm=llm, tools=[crew_tool(lookup)], allow_delegation=False)
support = Agent(role="Support agent", goal=GOAL, backstory=INSTRUCTIONS, llm=llm,
                tools=[crew_tool(issue_refund)], allow_delegation=True)
runs = {researcher.role: lane, support.role: run}
```

Route each model call to its agent's run: the hook context carries `context.agent`, and
the completed and failed events carry `event.from_agent`, so keep one reservation queue
per run and pick it by role. Delegation then works as CrewAI intends, with
`Process.sequential` and `context=[research_task]` or with `allow_delegation=True` (the
"Delegate work to coworker" tool) and `Process.hierarchical` (`manager_llm=...`): the
researcher's tool calls and model calls spend the lane's sub-budget, which was reserved
from the parent. The manager agent of a hierarchical crew has no tools of its own; budget
its calls against the parent run.

Close the lane after the crew finishes: `run.close_child(lane, "accept")` settles its
spend into the parent, and the parent cannot complete while a child is open
(`children_unsettled`). A lane whose envelope names an output schema must record a
conforming decision before it can be accepted.

## 8. The MCP alternative

Every run is also an MCP server at `POST /v1/runs/{run_id}/mcp`. CrewAI agents connect to
it through `mcps=`:

```python
from crewai.mcp import MCPServerHTTP

contextos = MCPServerHTTP(
    url=f"{base_url}/v1/runs/{run.run_id}/mcp",
    headers={"Authorization": f"Bearer {token}",
             "ContextOS-Executor-Generation": str(run.executor_generation)},
)
agent = Agent(role="Support agent", goal=GOAL, backstory=INSTRUCTIONS, llm=llm, mcps=[contextos])
```

The agent sees only the run's surfaced capabilities, with their reviewed input schemas,
named after the server and the sanitized capability id (`adp_orders.lookup` becomes
`..._adp_orders_lookup`). Refusals come back with `isError: true`, which CrewAI turns
into a `ToolFailure`, so the model reads the gateway's reason and CrewAI records the
failure. Operation keys are derived from capability and arguments, so a repeated call
cannot apply twice. Every result carries `_meta["io.contextos/toolCallId"]` and
`_meta["io.contextos/operationId"]`, which a DecisionRecord can cite. CrewAI does not
send per-call `_meta`, so it cannot set `io.contextos/idempotencyKey` or
`io.contextos/toolCallId`, or cite `io.contextos/evidenceRefs`; use `governed_tool` for
effects that must cite evidence or use a key of your choosing, and keep each effect on
one route (a keyed call and a derived-key call are two operations). After a takeover,
rebuild the server config with the new generation. If you manage the connection
yourself with `MCPServerAdapter` (`crewai-tools[mcp]`), give it the same URL and both
headers; the refusal and key behavior is the server's, so it is the same. The budget hook of section 4 applies unchanged.

## 9. Record the decision and complete

The DecisionRecord cites ContextOS tool-call ids and operation ids, which you derived in
section 3, not anything CrewAI generated:

```python
crewai_event_bus.flush()
decision = run.record_decision("support.refund.execute", "DECIDED", outcome="refund_issued",
                               tool_calls=[{"tool_call_id": "tc_refund_ord_881", "operation_id": "refund:ord_881"}],
                               rationale={"strategy": result.raw[:500]})
run.complete()
```

`complete` is refused while an effect is unknown or partial, a child is open, or anything
is in flight. Decide from what the gateway completed (your adapter saw the result), not
from the crew's final answer.

## 10. Pitfalls

- **Tool result caching.** `Crew(cache=True)` replays identical calls without running
  them. Leave it off, and set `cache_function` returning `False` on governed tools.
- **Raised tool errors are retried.** The ReAct loop re-runs a raising tool two or three
  times. Return a `ToolFailure`; never let `ToolOutcome` escape a CrewAI tool.
- **Repeated-call short-circuit.** In the ReAct loop, CrewAI refuses a call identical to
  the previous one ("I tried reusing the same input") without running it. It is a
  convenience, not a guarantee: the operation key is.
- **Hooks fail open.** Only `HookAborted` stops a model call. A hook that raises anything
  else is ignored.
- **Register hooks first.** Each agent executor copies the global hook lists when
  `kickoff()` creates it; a hook registered later misses that executor's calls.
- **`max_iter`.** When an agent reaches `max_iter` (default 25), CrewAI makes one more
  model call to force a final answer. It is budgeted (providers run the hooks), but set
  `max_iter` well below the run's budget so the crew ends by its own rule first.
- **Local limits are not the budget.** `max_iter`, `max_rpm` and `max_usage_count` count
  per process and reset with it. The run's budget ledger survives restarts, takeovers and
  child lanes.
- **Async kickoffs.** `kickoff_async` and `akickoff` run tools and hooks on other threads.
  The `Run` is safe to share; keep reservation queues per run and per agent.
- **Telemetry.** Disable it (section 1) before importing `crewai`.

## References

- Agents: https://docs.crewai.com/en/concepts/agents
- Tools and custom tools: https://docs.crewai.com/en/concepts/tools, https://docs.crewai.com/en/learn/create-custom-tools
- LLM call hooks: https://docs.crewai.com/en/learn/llm-hooks
- Tool call hooks: https://docs.crewai.com/en/learn/tool-hooks
- Event listeners: https://docs.crewai.com/en/concepts/event-listener
- Custom LLMs (`BaseLLM`): https://docs.crewai.com/en/learn/custom-llm
- LLMs and model ids: https://docs.crewai.com/en/concepts/llms
- Checkpointing: https://docs.crewai.com/en/concepts/checkpointing
- Flow state and persistence: https://docs.crewai.com/en/guides/flows/mastering-flow-state
- Hierarchical process: https://docs.crewai.com/en/learn/hierarchical-process
- Human input: https://docs.crewai.com/en/learn/human-input-on-execution
- MCP (`mcps=`, `MCPServerAdapter`): https://docs.crewai.com/en/mcp/overview, https://docs.crewai.com/en/mcp/dsl-integration
- Telemetry: https://docs.crewai.com/en/telemetry
- ContextOS: [GUIDE.md](../GUIDE.md) sections 2 (HTTP client, MCP), 3 (delegation, input,
  reconciliation) and 6 (budgets, checkpoints)
