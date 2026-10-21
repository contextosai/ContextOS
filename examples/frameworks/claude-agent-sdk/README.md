# Claude Agent SDK under ContextOS

A Claude Agent SDK agent (Python `claude-agent-sdk` 0.2.169, which bundles Claude Code
2.1.305) that refunds the quickstart's damaged order through `contextosd`. The agent
loop is the SDK's own. ContextOS comes in at two points: the agent's only tools are an
in-process SDK MCP server whose handlers call the run's governed functions, and a
`PreToolUse` hook reserves budget for each model turn.

```sh
./examples/frameworks/run.sh claude-agent-sdk
```

The SDK cannot run its loop without a model. So without `ANTHROPIC_API_KEY`, a
scripted path calls the same hook and the same registered tool handlers in the order
the model would: it looks the order up, refunds it, then asks for the refund again.
The gateway refuses the repeat, and the handler tells the model it was already
requested and not repeated:

```
admitted run_claude_agent_sdk_1792550737911 (executor generation 2)
no ANTHROPIC_API_KEY: scripted path, the same hook and tool handlers without a model
model turn 1 calls mcp__contextos__lookup_order {"order_id": "ord_881"}
  result: {"amount_minor": 120000, "currency": "INR", "customer_id": "cus_77", "order_id": "ord_881", "refundable": true, "status": "delivered_damaged"}
model turn 2 calls mcp__contextos__issue_refund {"order_id": "ord_881", "customer_id": "cus_77", "amount_minor": 120000}
  result: {"refund_id": "rf_ord_881"}
model turn 3 calls mcp__contextos__issue_refund {"order_id": "ord_881", "customer_id": "cus_77", "amount_minor": 120000}
  error: ALREADY REQUESTED (retry_unsafe): this exact action was submitted before and was not repeated.
model turn 4: Refunded ord_881 in full; the repeated refund was refused, so it was not issued twice.
model turns reserved: 4
decision decision_01a15c59981c7311986dc6b621c24068 (refunded)
run completed
evidence: budget used {'cost_units': 100, 'replans': 0, 'tokens': 4000, 'tool_calls': 2}, 10 signed audit entries
```

## What is governed

- **Tools.** `create_sdk_mcp_server` exposes `lookup_order` and `issue_refund`. Their
  handlers call the shared `governed_tool` functions, so each call goes to
  `contextosd`, which authorizes, dispatches, records and audits it. The refund is
  keyed `refund:ord_881` and cites the order snapshot as evidence, so the second call
  cannot apply twice.
- **Nothing else.** `tools=[]` removes every built-in tool (Bash, Edit, Agent and the
  rest). `allowed_tools=["mcp__contextos__*"]` approves the governed tools,
  `permission_mode="dontAsk"` denies anything else, and `setting_sources=[]` and
  `strict_mcp_config=True` stop settings files from adding tools. The live path stops
  if the server is not `connected` in the init message.
- **Model turns.** One model turn is reserved (1,000 tokens) before the query starts.
  The `PreToolUse` hook then reserves the turn that will read each tool's result. That
  makes four turns and 4,000 tokens here. When the run cannot afford a turn, the hook
  denies the tool and returns `continue_: False`, which stops the agent. Claude Code's
  background session-title request is turned off (`CLAUDE_CODE_DISABLE_TERMINAL_TITLE`),
  because no hook sees it.
- **Outcomes.** A `ToolOutcome` becomes `is_error: True` with `refusal()` text. A pause
  for approval (`paused.kind == "approval"`) is also kept for a human, never retried.
- **Decision.** `finish()` records the DecisionRecord (the gateway verifies its tool
  lineage), completes the run and reads its evidence.

## With a real model

```sh
ANTHROPIC_API_KEY=... ./examples/frameworks/run.sh claude-agent-sdk
```

This runs `ClaudeSDKClient` with `claude-sonnet-5-5` and the shared `GOAL` and
`INSTRUCTIONS`. Set `CLAUDE_MODEL` to choose another model, for example
`claude-opus-5-5`. The CLI is bundled in the wheel, so you need no separate Claude
Code install. The live path was checked end to end against a local stand-in for the
Messages API (`ANTHROPIC_BASE_URL`): it made 4 model requests, reserved 4 turns, got the
refusal as `is_error: true` and stopped on budget exhaustion. It has not been run
against the real API here.

To use the run's MCP endpoint (`/v1/runs/{id}/mcp`) in place of the in-process server,
and for subagents, approvals, checkpoints and metering, see
[docs/integrations/claude-agent-sdk.md](../../../docs/integrations/claude-agent-sdk.md).
