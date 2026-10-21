# Claude Agent SDK under ContextOS

This guide puts a Claude Agent SDK agent under `contextosd`. Every effect the agent has
goes through the gateway, every model turn spends the run's budget, refusals and pauses
reach the model as tool errors and never as silent retries, and the run ends with a
signed DecisionRecord. It targets the Python `claude-agent-sdk` 0.2.169, which bundles
Claude Code 2.1.305, and notes the TypeScript `@anthropic-ai/claude-agent-sdk`
equivalents. The runnable version is
[examples/frameworks/claude-agent-sdk](../../examples/frameworks/claude-agent-sdk/README.md).

The SDK runs the whole agent loop inside a Claude Code subprocess: model calls, tool
dispatch, permissions, subagents and sessions. You do not wrap the model call. You give
the agent tools that are governed, take every other tool away, and use the SDK's hooks
at the points where the loop would otherwise run unbudgeted.

## 1. Install

```sh
pip install "claude-agent-sdk==0.2.169"        # Python 3.10+; the wheel bundles the Claude Code CLI
npm install @anthropic-ai/claude-agent-sdk      # TypeScript; also ships the CLI
```

No separate Claude Code install is needed. Set `cli_path` (TypeScript:
`pathToClaudeCodeExecutable`) only to pin a CLI you manage yourself. Authenticate the
model with `ANTHROPIC_API_KEY`, or route the model through a gateway with
`ANTHROPIC_BASE_URL` (section 6). `contextos.client` uses the standard library only:
vendor `bindings/python/contextos`. Tool handlers and hooks are async, so use
`contextos.aio`: `AsyncClient` and `AsyncRun` have the client's methods as coroutines,
each request running in a worker thread, so they never block the event loop.

## 2. Admit a run

Admit one ContextOS run per agent task before you build the agent's options. The run
handle holds the executor generation that every governed call carries:

```python
from contextos.aio import AsyncClient
client = AsyncClient("https://contextos.internal", token=os.environ["CONTEXTOS_TOKEN"])
run = await client.admit(admission_body)  # POST /v1/runs; an AsyncRun
```

## 3. Route A: governed tools in an in-process SDK MCP server (recommended)

Use `create_sdk_mcp_server` with handlers that call the run's governed functions. With
`governed_tool`, the client sets each call's operation key, `tool_call_id` and cited
evidence. A retried refund therefore maps to the same operation, and the
DecisionRecord can cite the call by a known id. On an `AsyncRun` the governed function
is a coroutine the handler awaits:

```python
from claude_agent_sdk import create_sdk_mcp_server, tool
from contextos.client import ToolOutcome, governed_tool
from demo import refusal                 # examples/frameworks/_shared/demo.py

@governed_tool(run, "adp_payments.issue_refund", approval_mode="destructive",
               idempotency_key=lambda order_id, **_: f"refund:{order_id}",
               tool_call_id=lambda order_id, **_: f"tc_refund_{order_id}",
               evidence_refs=["kg:order:ord_881#snapshot_kg_2026_05_03_T0930"])
async def issue_refund(order_id: str, customer_id: str, amount_minor: int) -> dict:
    """Issue a refund for an order to its customer, in minor units."""

@tool("issue_refund", issue_refund.__doc__, {"order_id": str, "customer_id": str, "amount_minor": int})
async def refund(args):
    try:
        output = await issue_refund(**args)
    except ToolOutcome as outcome:                              # refusal(): worded by outcome.kind
        return {"content": [{"type": "text", "text": refusal(outcome)}], "is_error": True}
    return {"content": [{"type": "text", "text": json.dumps(output)}]}

server = create_sdk_mcp_server("contextos", tools=[lookup, refund])
```

The model sees these tools as `mcp__contextos__lookup_order` and
`mcp__contextos__issue_refund`. Return `is_error: True` for every outcome that is not
plain success. Claude Code passes it to the model as `is_error: true` on the
`tool_result`. If a handler raises, the SDK reports the exception text as an error
result, so catch `ToolOutcome` yourself and say plainly what happened. The example's
`refusal()` (`examples/frameworks/_shared/demo.py`) answers "NOT DONE (…). The action
did not take effect; do not retry it." for a refusal, and for a repeat of an operation
that already exists (`ToolPaused.kind == "duplicate"`) "ALREADY REQUESTED
(retry_unsafe): this exact action was submitted before and was not repeated."
In TypeScript, use `createSdkMcpServer({name, tools: [tool(name, description, zodShape,
handler)]})` and return `{content, isError: true}`.

## 4. Route B: the run's MCP endpoint

Every admitted run is also a Streamable HTTP MCP server, and Claude Code connects to it
directly:

```python
mcp_servers={"contextos": {
    "type": "http", "url": f"{CONTEXTOS_URL}/v1/runs/{run.run_id}/mcp",
    "headers": {"Authorization": f"Bearer {token}",
                "ContextOS-Executor-Generation": str(run.executor_generation)}}}
```

We checked this route against `contextosd` with Claude Code 2.1.305. Here is what works
and what does not:

- The server reports `connected`. Tool names are normalized: `adp_orders.lookup`
  becomes `mcp__contextos__adp_orders_lookup` and `adp_payments.issue_refund` becomes
  `mcp__contextos__adp_payments_issue_refund`. Read the real names from the `init`
  message's `tools` before you write allow rules or hook matchers.
- Each `tools/call` runs the full governed pipeline. A repeated refund comes back with
  `isError: true` and the text `ContextOS paused: retry_unsafe. This call had no
  effect; do not retry it unchanged. ...` (an unknown outcome reads "The outcome is
  unknown and must be reconciled; do not retry it."). The model sees only the text.
  `structuredContent` (status, reason codes, `operation_id`) does not reach it.
- The SDK cannot set `_meta` on a tool call. So `io.contextos/idempotencyKey`,
  `io.contextos/toolCallId` and `io.contextos/evidenceRefs` are never sent. The operation key is derived from the
  capability and arguments (`mcp:` followed by 32 hex characters of the SHA-256 of the
  canonical `{"capability", "arguments"}`). A retry with the same arguments is
  therefore refused (`retry_unsafe`), but a call with different arguments is a new
  operation. The refund cites no evidence. That is accepted only while the pack does
  not require it.
- Every result, success or refusal, names the call and its operation in `_meta`
  (`io.contextos/toolCallId`, a random `mcp_…`, and `io.contextos/operationId`). Claude
  Code does not give `_meta` to the model, but passes it to the SDK on the
  `UserMessage` that carries the tool result: read
  `message.tool_use_result["_meta"]["io.contextos/operationId"]` and cite both ids in
  the DecisionRecord. We read that from the stream schema bundled with Claude Code
  2.1.305 (`tool_use_result` spreads the MCP result's `_meta`, minus keys under
  `com.anthropic/`); we have not exercised it against a live model, nor
  checked whether `PostToolUse`'s `tool_response` carries it.
- The generation header is fixed when the client connects. After a takeover, rebuild
  the options with the new generation, or every call is refused as `executor_stale`.
- Do not mix routes for one effect. A call keyed `refund:ord_881` and the derived
  `mcp:…` key are two operations.

Use this route for read-only tools, for prototyping, or when the agent must not hold
`dispatch` credentials in process. Use route A for effects that must cite evidence or
carry an operation key you choose.

## 5. Lock the agent to the governed tools

An SDK agent has Claude Code's tools by default: Bash, Read, Edit, WebFetch, Agent and
more. A shell is an ungoverned effect. Take them all away and approve only the governed
server:

```python
options = ClaudeAgentOptions(
    model="claude-sonnet-5-5", system_prompt=INSTRUCTIONS, max_turns=6,
    mcp_servers={"contextos": server}, strict_mcp_config=True,
    setting_sources=[],                          # no user/project settings, hooks, MCP or agents from disk
    tools=[],                                    # no built-in tools at all
    allowed_tools=["mcp__contextos__*"],         # the governed tools run without a prompt
    permission_mode="dontAsk",                   # anything unlisted is denied, never asked
    hooks={"PreToolUse": [HookMatcher(hooks=[turns.pre_tool_use])]},
    env={"CLAUDE_CODE_DISABLE_TERMINAL_TITLE": "1"},
)
```

`allowed_tools` on its own does not restrict anything. It only pre-approves the tools
you list. `tools=[]` (`--tools ""`) removes the built-ins, and `dontAsk` turns every
remaining permission prompt into a denial. Never use `bypassPermissions`: it approves
every tool, whatever `allowed_tools` says. Check the `init` system message: fail closed
unless your server's status is `connected`. If a server is unavailable, the model can
fall back to whatever other tools it still has. In TypeScript, use `tools: []`,
`allowedTools`, `permissionMode: "dontAsk"`, `settingSources: []` and
`strictMcpConfig: true`. Note that the TypeScript `env` *replaces* the subprocess
environment, so spread `process.env` into it. The Python `env` is merged.

## 6. Budget model turns

The SDK makes the model calls itself, so there is no call to wrap. It has no
pre-model-call hook either. The seam is the tool boundary: every tool result is read by
exactly one more model turn. Reserve the first turn before `query()`, and reserve each
following turn in `PreToolUse`, before the tool runs:

```python
from contextos.client import BudgetExhausted

class Turns:
    def __init__(self, run): self.run = run              # an AsyncRun
    async def reserve(self):                             # raises BudgetExhausted when it cannot fit
        async with self.run.budgeted_model_call(tokens=1000):
            pass
    async def pre_tool_use(self, input_data, tool_use_id, context):
        try:
            await self.reserve()
        except BudgetExhausted as refused:
            return {"continue_": False, "stopReason": f"ContextOS: {refused.code}",
                    "hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                           "permissionDecisionReason": f"NOT DONE (budget): {refused.code}."}}
        return {}
```

When the run cannot afford a turn, the hook denies the tool and `continue_: False` ends
the query before the next model request. We verified that only two model requests were
made when the second reservation was the last one that fit. Limits to know:

- Parallel tool calls in one assistant turn fire `PreToolUse` once each, so they
  over-reserve. The TypeScript SDK has `PostToolBatch` (once per batch, before the next
  model call), which is the exact per-turn seam there. Python has no equivalent.
- Claude Code makes model requests that no hook sees. Session-title generation is one,
  and setting `CLAUDE_CODE_DISABLE_TERMINAL_TITLE=1` removes it. Compaction, and
  `auto`-mode classifier calls, are others. Keep `permission_mode` off `auto`.
- Inside a subagent, `PreToolUse` carries `agent_id` and `agent_type`. Reserve against
  that subagent's child run (section 9).
- `max_turns` and `max_budget_usd` are useful backstops, but they are the SDK's own
  accounting, not evidence.

The executor settling its own reservation is charged the whole reservation. To charge
measured usage, route the model through an LLM gateway that holds the `meter` scope:
`ANTHROPIC_BASE_URL=https://llm-gateway.internal`. The SDK cannot put a header on each
model request. `ANTHROPIC_CUSTOM_HEADERS` is fixed for the CLI process, and each
request carries `X-Claude-Code-Session-Id`. So hand the gateway the reservation another
way: register the pending reservation id under the session id or run id, or reserve one
block per `query()` and pass it in `ANTHROPIC_CUSTOM_HEADERS`. The gateway then settles
what it measured. `ResultMessage.usage` (main loop) and `model_usage` (whole tree,
subagents included) are for reports and reconciliation. The gateway's settlement is
what counts.

## 7. Map refusals and pauses

| Outcome | What the model gets | What the executor does |
| --- | --- | --- |
| `ToolBlocked`, `ToolRejected`, `ToolFailed` | `is_error` text: not done, why, do not retry | nothing; the model explains |
| `ToolPaused`, `kind == "duplicate"` | `is_error` text: already requested, not repeated | nothing; the earlier call stands |
| `ToolPaused`, `kind == "unknown_outcome"` | `is_error` text: outcome unknown, do not retry | reconcile the operation (`await run.reconcile`), never resend it |
| `ToolPaused`, `kind == "approval"` | nothing yet: the call waits in the handler | a reviewer decides, then the handler re-sends the same call |

For an approval, the handler is the human-in-the-loop seam. The agent loop awaits the
handler, so the tool call simply waits while a reviewer decides in your approval
service. Then the handler re-sends the identical call (same arguments, same operation
key), which redeems that exact approval and returns the real result. This is what the
example does, exercised end to end by
`./examples/frameworks/run.sh claude-agent-sdk --approval`:

```python
try:
    output = await issue_refund(**args)
except ToolPaused as paused:
    if paused.kind != "approval":
        raise                                         # mapped by the table above
    await wait_for_reviewer(paused.report["approval_request_id"])
    output = await issue_refund(**args)               # the same call, redeemed
```

If the wait can outlast the MCP tool timeout (`MCP_TOOL_TIMEOUT`) or the process,
return `is_error` text ("awaiting approval") instead, stop the agent with a
`PostToolUse` hook (`{"continue_": False, "stopReason": "awaiting approval"}`),
checkpoint the session id (section 8), and once approved resume the session
(`resume=session_id`) with "approved, continue"; the re-issued call redeems the
approval the same way. That route is not exercised by the example. Do not use
`can_use_tool` or a `PreToolUse` `ask` as the approval: they run before the call
reaches the gateway, which has not decided yet, and they are a UI confirmation, not
authority. A `PreToolUse` `permissionDecision: "defer"` (the turn ends with
`stop_reason: "tool_deferred"`) is the SDK's way to hold a call for later, before it is
sent.

## 8. Checkpoint and resume

ContextOS checkpoints the orchestrator's state, and SDK sessions hold the conversation.
Keep both. After each query, or at each approval pause, save the session id with your
own state:

```python
revision = (await run.checkpoint({"session_id": result.session_id, "step": "refunded"}, revision))["revision"]
```

A replacement executor awaits `run.take_over()`, reads `run.latest_checkpoint()`, and
starts a new query with `resume=state["session_id"]`. Session transcripts live on the
local disk (`~/.claude/projects/...`). For another host, configure the SDK's
`session_store` or copy the `.jsonl` file. Otherwise, start a fresh session from the
checkpointed state. Resuming never repeats an effect, because the governed calls the
model re-issues map to the same operation keys and the gateway answers from its
ledger. With route B, rebuild the MCP headers with the new generation.

## 9. Subagents: delegate to child runs

SDK subagents (`agents={...}`, invoked through the `Agent` tool) run in the same CLI
process and use the parent's tools. To ContextOS they would be the parent run. Give each
lane its own child run instead, narrowed by an `AgentDelegationEnvelope` (GUIDE
section 3, "Delegating to child runs"), and its own server:

```python
lane = await run.delegate(child_admission, envelope)      # effect_policy "read_only", sub_budget
research = create_sdk_mcp_server("research", tools=[lookup_for(lane)])
options = ClaudeAgentOptions(
    tools=["Agent"], allowed_tools=["mcp__contextos__*", "mcp__research__*"],
    mcp_servers={"contextos": server, "research": research},
    agents={"researcher": AgentDefinition(description="Looks orders up. Cannot act.",
                                          prompt="Look the order up and report it.",
                                          tools=["mcp__research__lookup_order"], model="haiku")},
    env={"CLAUDE_CODE_MAX_SUBAGENT_SPAWN_DEPTH": "1"}, disallowed_tools=["Agent(fork)"], ...)
# after the query
await run.close_child(lane, "accept")                     # settles the lane's spend into the parent
```

The lane cannot act even if the subagent tries, because the gateway gives a `read_only`
child no effectful capabilities. `AgentDefinition.tools` only keeps the subagent
focused. Re-enabling `Agent` for subagents also lets Claude start the built-in
`general-purpose` agent, which inherits the parent's tools. Set
`CLAUDE_AGENT_SDK_DISABLE_BUILTIN_AGENTS=1`. Deny forks with `Agent(fork)`, since a
fork copies the parent's conversation. Budget the subagent's turns against the lane: a
`SubagentStart` hook reserves its first turn, and `PreToolUse` with `agent_id` reserves
the rest. Close every child before `complete()`, or completion fails with
`children_unsettled`.

## 10. Record the decision and complete

```python
decision = await run.record_decision("support.refund.execute", "DECIDED", outcome="refund_issued",
                                     tool_calls=[{"tool_call_id": "tc_refund_ord_881", "operation_id": "refund:ord_881"}],
                                     rationale={"strategy": result.result[:500]})
await run.complete()
```

The gateway checks each cited `operation_id` against the run's ledger: it must exist
and its effect must be confirmed (`lineage_unverified` otherwise). Route A sets the
key; on route B, cite the ids from the result's `_meta` (section 4). Then call `GET /v1/runs/{id}/evidence` and page the signed audit chain.

## 11. Pitfalls

- **`allowed_tools` is not an allowlist.** Pair it with `tools=[]` and `dontAsk`. Never
  use `bypassPermissions`.
- **Settings leak in.** Without `setting_sources=[]` and `strict_mcp_config=True`,
  `.claude/settings.json`, `.mcp.json`, filesystem agents and hooks can add tools.
- **Blocking calls in async handlers.** `contextos.client` is synchronous. Use
  `contextos.aio` (`AsyncClient`, `AsyncRun`) in handlers and hooks.
- **Raising from a handler.** The SDK turns the exception text into an error result
  the model may read as "try again". Return explicit refusal text.
- **Retries.** Claude may retry a tool that failed. The operation key makes that safe
  for the same arguments only. Tell the model in the instructions not to retry a
  refusal.
- **Unhooked model calls.** These are title generation, compaction and the `auto`
  classifier. Disable what you can, and meter the rest at the gateway.
- **MCP route identity.** The SDK sends no `_meta`, so you get no explicit key and no
  evidence. The ids to cite come back in each result's `_meta` (section 4).

## References

- Agent SDK overview and Python reference: <https://code.claude.com/docs/en/agent-sdk/overview>,
  <https://code.claude.com/docs/en/agent-sdk/python>, <https://code.claude.com/docs/en/agent-sdk/typescript>
- MCP (HTTP servers, tool naming): <https://code.claude.com/docs/en/agent-sdk/mcp>
- Custom tools: <https://code.claude.com/docs/en/agent-sdk/custom-tools>
- Permissions: <https://code.claude.com/docs/en/agent-sdk/permissions>
- Hooks: <https://code.claude.com/docs/en/agent-sdk/hooks>
- Subagents: <https://code.claude.com/docs/en/agent-sdk/subagents>
- Sessions: <https://code.claude.com/docs/en/agent-sdk/sessions>
- Environment variables: <https://code.claude.com/docs/en/env-vars>
- Models: <https://platform.claude.com/docs/en/about-claude/models/overview>
- ContextOS: [GUIDE.md](../GUIDE.md) sections 2 ("Or connect any MCP host"), 3 and 6
