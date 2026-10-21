# Agent framework integrations

ContextOS does not replace your agent framework. The framework keeps the model loop,
prompting, memory and orchestration; `contextosd` decides and records every effect the
agent has on the world, and meters what the run spends. Integrating means wiring a
handful of seams the framework already has to the run the agent was admitted under.

| Framework | Language | Guide | Example |
|---|---|---|---|
| LangGraph / LangChain | Python | [langgraph.md](langgraph.md) | [examples/frameworks/langgraph](../../examples/frameworks/langgraph) |
| OpenAI Agents SDK | Python, TypeScript | [openai-agents.md](openai-agents.md) | [openai-agents](../../examples/frameworks/openai-agents), [openai-agents-js](../../examples/frameworks/openai-agents-js) |
| Google ADK | Python | [google-adk.md](google-adk.md) | [google-adk](../../examples/frameworks/google-adk) |
| Claude Agent SDK | Python (TypeScript in the guide) | [claude-agent-sdk.md](claude-agent-sdk.md) | [claude-agent-sdk](../../examples/frameworks/claude-agent-sdk) |
| CrewAI | Python | [crewai.md](crewai.md) | [crewai](../../examples/frameworks/crewai) |
| Pydantic AI | Python | [pydantic-ai.md](pydantic-ai.md) | [pydantic-ai](../../examples/frameworks/pydantic-ai) |
| LlamaIndex | Python | [llamaindex.md](llamaindex.md) | [llamaindex](../../examples/frameworks/llamaindex) |
| Microsoft Agent Framework | Python | [microsoft-agent-framework.md](microsoft-agent-framework.md) | [microsoft-agent-framework](../../examples/frameworks/microsoft-agent-framework) |
| Vercel AI SDK | TypeScript | [vercel-ai-sdk.md](vercel-ai-sdk.md) | [vercel-ai-sdk](../../examples/frameworks/vercel-ai-sdk) |
| Mastra | TypeScript | [mastra.md](mastra.md) | [mastra](../../examples/frameworks/mastra) |

Any other framework that accepts plain functions as tools, or speaks MCP, integrates the
same way.

## Run the examples

Every example governs the same task as the quickstart, the refund of a damaged order,
through the framework's own agent loop:

```sh
./examples/frameworks/run.sh langgraph      # or any directory name above
```

The runner builds and starts `contextosd` with the quickstart's development services,
creates the example's environment on first use (a uv virtualenv for Python, `npm
install` for TypeScript) and runs it. Without a provider API key, each example drives
the framework with its own scripted or fake model, so the governed path runs anywhere;
the example's README names the key that switches it to a real model. The scripted model
deliberately asks for the refund twice, so every run shows the gateway refusing the
repeat and the model being told so:

```text
admitted run_langgraph_… (executor generation 2)
checkpoint revision 1: thread run_langgraph_…
  lookup_order -> {"amount_minor": 120000, … "refundable": true, "status": "delivered_damaged"}
  issue_refund -> {"refund_id": "rf_ord_881"}
  issue_refund -> ALREADY REQUESTED (retry_unsafe): this exact action was submitted before and was not repeated.
decision decision_… (refunded)
run completed
evidence: budget used {… 'tokens': 4000, 'tool_calls': 2}, 11 signed audit entries
```

With `--approval`, the run is admitted for a refund above the pack's 3,000 threshold,
so its calls wait for an exact approval. Each example surfaces the pause through the
framework's human-in-the-loop mechanism, a scripted reviewer approves the bound action
in the development approval service, and the framework re-sends the identical call,
which redeems the approval once:

```sh
./examples/frameworks/run.sh langgraph --approval
```

The pack's rule applies to the run's intent, so in such a run every governed call,
the read-only lookup included, needs its own approval. An approval binds one
operation, so a call that will be re-sent after approval needs a stable operation key
(the examples key the lookup in this mode); an unkeyed read is a new operation on every
call and would open a new request each time.

The shared setup (admission, the two governed tools, the model-call budget, the
refusal text, the scripted reviewer and the closing decision) is in
[`examples/frameworks/_shared`](../../examples/frameworks/_shared), so each example
shows only what its framework adds.

## The seams

| Seam | What to wire | Why |
|---|---|---|
| **Admission** | `client.admit(body)` before the agent starts; keep the `Run` | The run fixes the compiled context, pinned policy, budget and executor generation that every later call is checked against. |
| **Tools** | Register governed tools: `governed_tool(run, capability_id, …)` (Python) or `governedTool(run, …)` (TypeScript), or point the framework's MCP client at the run's endpoint | The tool body never runs in the agent process: the gateway authorizes, binds, dispatches, records and audits each call. The agent holds no credentials for the systems it acts on. |
| **Model calls** | Wrap every model request in `run.budgeted_model_call(tokens=…)` (TypeScript `run.budgetedModelCall`) in the framework's lowest model seam; stop on `BudgetExhausted` | Model calls spend the same conserved budget as tools, so a looping agent stops at `budget_exhausted`, across lanes and failover. |
| **Outcomes** | Map `ToolPaused`, `ToolBlocked`, `ToolRejected`, `ToolFailed` to framework behavior (below) | The model must see that a refused action did not happen, and a pause must reach a person or a reconciler, never a blind retry. |
| **Checkpoint** | `run.checkpoint(state, revision)` after each verdict; `client.attach(…).take_over()` and `latest_checkpoint()` to resume | Another executor can resume the run; the old one is fenced (`executor_stale`). Keep the framework's own checkpointer for its loop state, and store its thread or state id in the ContextOS checkpoint. |
| **Subagents** | Run a subagent or handoff as a delegated child run (`run.delegate(child, envelope)`, `close_child`) | The child gets a narrowed lane (for example `read_only`) and a sub-budget reserved from the parent; it cannot do what its lane does not allow. |
| **Decision** | `run.record_decision(…, tool_calls=[{tool_call_id, operation_id}])`, then `run.complete()` | The DecisionRecord's lineage is verified against the gateway's own ledgers and signed into the audit chain with a replay packet. |

### Two ways to expose tools

- **In process** (`governed_tool`): the framework calls a typed function; the function
  sends a `contextos.tool_call.v1` envelope. You control the idempotency key, evidence
  references and tool call id per call, so this is the route for effects a decision
  cites. Every framework here builds the tool schema from the function's signature and
  docstring.
- **MCP** (`POST /v1/runs/{run_id}/mcp`, headers `Authorization` and
  `ContextOS-Executor-Generation`): the framework's MCP client lists the run's surfaced
  capabilities with their reviewed schemas. Effectful calls derive their operation key
  from the capability and arguments unless `_meta["io.contextos/idempotencyKey"]` is
  set; evidence goes in `_meta["io.contextos/evidenceRefs"]`. Every result carries
  `_meta["io.contextos/toolCallId"]` and `_meta["io.contextos/operationId"]` for the
  decision. Many MCP clients cannot set per-call `_meta`; the guides say which can.

Do not send one effect through both routes: an explicitly keyed call and a call keyed
by derivation are different operations. After a takeover, rebuild any MCP transport
that carries the old generation header.

### Outcomes

| Outcome | Meaning | What the integration does |
|---|---|---|
| success | The gateway dispatched it and the provider confirmed | Return the output to the model |
| `ToolBlocked` | Authority, policy, constraints or budget refused it | Return the refusal to the model as a tool result; do not retry |
| `ToolRejected` | Malformed, not surfaced to this run, or incompatible reuse of a key | Same |
| `ToolFailed` | The provider definitively did not apply the effect | Same; a new attempt needs a new decision, not a retry |
| `ToolPaused`, `kind == "approval"` | Waiting for an exact approval | Suspend through the framework's human-in-the-loop mechanism; once approved, re-send the identical call |
| `ToolPaused`, `kind == "input"` | The tool asked for input | Collect it and continue with `run.provide_input(...)` |
| `ToolPaused`, `kind == "unknown_outcome"` | The effect may have happened | Tell the model it is unresolved; reconcile (`run.reconcile`) before anything else |
| `ToolPaused`, `kind == "duplicate"` | This operation was already requested | Tell the model it was not repeated |

`refusal()` in the shared helpers is the model-facing text the examples use: it says
plainly whether anything happened.

## Pitfalls that apply to most frameworks

- **Tool errors become "please try again".** Several frameworks turn a tool exception
  into text that invites a retry (the OpenAI Agents SDK's default failure handler),
  retry it themselves (CrewAI's text loop, LangChain's tool retry middleware, Pydantic
  AI's MCP `tool_error_behavior="retry"`), or reduce it to "Function failed" (Microsoft
  Agent Framework without middleware). Catch the outcome in the tool seam and return
  the refusal as a normal tool result.
- **Caching and duplicate suppression hide calls.** A cached tool result (CrewAI with
  `cache=True`) or a loop that drops an identical repeated call never reaches the
  gateway, so the model can be told an effect happened twice. Disable caching for
  effectful tools.
- **Hooks that fail open.** Some callback and instrumentation layers swallow
  exceptions (CrewAI hooks other than `HookAborted`, LlamaIndex instrumentation
  handlers), so a refused budget reservation would not stop the call. Put the budget in
  a seam that can refuse: a model wrapper or middleware.
- **Retries below the hook.** SDK-level model retries can happen between "before" and
  "after" callbacks. Budget at the lowest layer that sees each attempt.
- **Tool names.** Capability ids contain dots (`adp_payments.issue_refund`), which some
  model APIs reject in tool names. In-process tools use the function name; MCP clients
  need their prefixing or renaming option.
- **Async frameworks.** Use `contextos.aio` (`AsyncClient`, `AsyncRun`): the same
  methods as coroutines, and `governed_tool` on an `AsyncRun` makes async tools.
  Calling the synchronous client from async code blocks the event loop.
- **Parallel tool calls** are each governed independently, which is safe, but a step
  that depends on another call's result should run sequentially.
- **Every model call has a floor.** A model call reserves at least
  `[guards] model_call_min_tokens` (1,000 by default); size the run budget for the
  number of turns you expect.
- **Measured usage needs a metering gateway.** An executor settling its own reservation
  is charged the whole reservation. To charge measured usage, pass the reservation id
  to your LLM gateway, which settles it with the `meter` scope (see
  [GUIDE.md §6](../GUIDE.md#6-budget-model-calls-and-replans)).
