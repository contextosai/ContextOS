"""A Claude Agent SDK agent under ContextOS.

The agent loop is the SDK's own (Claude Code, driven by ``ClaudeSDKClient``). ContextOS
enters at two seams:

- the agent's only tools are an in-process SDK MCP server whose handlers call the
  run's governed functions (``tools(run)``), so every effect goes through
  ``contextosd``; built-in tools are removed and anything unlisted is denied;
- a ``PreToolUse`` hook reserves the run's budget for the model turn that will read
  the tool's result, and stops the agent when the run cannot afford it. The first
  turn is reserved before the query starts, so no model turn is unbudgeted.

A refusal comes back as a tool error (``is_error``) with ``refusal()`` text the model
reads as "not done" or "already requested", and "do not retry". A pause for approval
holds the tool call open: the handler waits for the reviewer (``approve``), then
re-sends the identical call, which redeems that exact approval (``--approval``). The
run's MCP endpoint (``/v1/runs/{id}/mcp``) is the other route; see
docs/integrations/claude-agent-sdk.md.

Without ANTHROPIC_API_KEY there is no model to run the SDK's loop, so a scripted path
calls the same hook and the same registered tool handlers in the order the model would:
look the order up, refund it, then try the refund again, which the gateway refuses.

Run with: ./examples/frameworks/run.sh claude-agent-sdk [--approval]
"""
import asyncio
import json
import os
import sys

from claude_agent_sdk import (AssistantMessage, ClaudeAgentOptions, ClaudeSDKClient, HookMatcher, ResultMessage,
                              SystemMessage, TextBlock, ToolUseBlock, create_sdk_mcp_server, tool)
from contextos.client import ContextOSHTTPError

from demo import GOAL, INSTRUCTIONS, ToolOutcome, ToolPaused, admit, approve, budgeted, finish, offline, refusal, tools

MODEL = os.environ.get("CLAUDE_MODEL", "claude-sonnet-5-5")
SERVER = "contextos"


class Turns:
    """Reserves the run's budget for each model turn before it starts."""

    def __init__(self, run):
        self.run = run
        self.count = 0

    def reserve(self) -> None:
        # The executor settles its own reservation, so all of it is charged. A metering
        # LLM gateway (`meter` scope) would settle the measured usage instead.
        with budgeted(self.run):
            self.count += 1

    async def pre_tool_use(self, input_data, tool_use_id, context):
        """Every tool result is read by one more model turn: reserve it now, or refuse
        the tool and stop the agent."""
        try:
            await asyncio.to_thread(self.reserve)
        except ContextOSHTTPError as refused:
            return {"continue_": False, "stopReason": f"ContextOS: {refused.code}",
                    "hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                           "permissionDecisionReason": f"NOT DONE (budget): {refused.code}."}}
        return {}


def governed_server(run):
    """The run's governed tools as an in-process MCP server, and what they did."""
    lookup_order, issue_refund = tools(run)
    state = {"refunded": False}

    async def call(function, args: dict) -> dict:
        try:
            try:
                output = await asyncio.to_thread(function, **args)
            except ToolPaused as paused:
                if paused.kind != "approval":
                    raise
                # The agent loop awaits this handler, so the call waits here while a
                # reviewer decides; then the identical call (same arguments, same
                # idempotency key) is re-sent and redeems that exact approval.
                print(f"  paused for approval: {paused.report['approval_request_id']}")
                await asyncio.to_thread(approve, paused)
                print("  resumed: re-sending the same call")
                output = await asyncio.to_thread(function, **args)
        except ToolOutcome as outcome:
            return {"content": [{"type": "text", "text": refusal(outcome)}], "is_error": True}
        return {"content": [{"type": "text", "text": json.dumps(output)}]}

    @tool("lookup_order", lookup_order.__doc__, {"order_id": str})
    async def lookup(args):
        return await call(lookup_order, args)

    @tool("issue_refund", issue_refund.__doc__, {"order_id": str, "customer_id": str, "amount_minor": int})
    async def refund(args):
        result = await call(issue_refund, args)
        state["refunded"] = state["refunded"] or not result.get("is_error")
        return result

    return create_sdk_mcp_server(SERVER, tools=[lookup, refund]), {t.name: t for t in (lookup, refund)}, state


async def live(server, turns: Turns) -> str:
    options = ClaudeAgentOptions(
        model=MODEL, system_prompt=INSTRUCTIONS, max_turns=6,
        mcp_servers={SERVER: server}, strict_mcp_config=True, setting_sources=[],
        tools=[],                                   # no built-in tools: no Bash, Edit, Agent, ...
        allowed_tools=[f"mcp__{SERVER}__*"],        # the governed tools run without a prompt
        permission_mode="dontAsk",                  # anything else is denied, never asked
        hooks={"PreToolUse": [HookMatcher(hooks=[turns.pre_tool_use])]},
        # Claude Code also names the session with a background model request; skip it,
        # since no hook sees it and it would be the one model call outside the budget.
        env={"CLAUDE_CODE_DISABLE_TERMINAL_TITLE": "1"},
    )
    summary = ""
    turns.reserve()  # the query's first model turn
    async with ClaudeSDKClient(options=options) as agent:
        await agent.query(GOAL)
        async for message in agent.receive_response():
            if isinstance(message, SystemMessage) and message.subtype == "init":
                status = {s["name"]: s["status"] for s in message.data.get("mcp_servers", [])}
                if status.get(SERVER) != "connected":
                    raise RuntimeError(f"governed tools unavailable: {status}")
            elif isinstance(message, AssistantMessage):
                for block in message.content:
                    if isinstance(block, ToolUseBlock):
                        print(f"model calls {block.name} {json.dumps(block.input)}")
                    elif isinstance(block, TextBlock) and block.text.strip():
                        print(f"model: {block.text.strip()}")
            elif isinstance(message, ResultMessage):
                summary = message.result or message.subtype
                print(f"result: {message.subtype}, {message.num_turns} turns, usage {message.usage}")
    return summary


async def scripted(handlers: dict, turns: Turns) -> str:
    """The calls the model would make, through the same hook and handlers."""
    print("no ANTHROPIC_API_KEY: scripted path, the same hook and tool handlers without a model")
    refund = {"order_id": "ord_881", "customer_id": "cus_77"}
    turns.reserve()  # the first model turn
    order = None
    for name, args in [("lookup_order", {"order_id": "ord_881"}), ("issue_refund", refund),
                       ("issue_refund", refund)]:
        if name == "issue_refund":
            args = dict(args, amount_minor=order["amount_minor"])
        print(f"model turn {turns.count} calls mcp__{SERVER}__{name} {json.dumps(args)}")
        if (await turns.pre_tool_use({"tool_name": name, "tool_input": args}, None, None)).get("continue_") is False:
            return "stopped: the run's budget cannot fit another model turn"
        result = await handlers[name].handler(args)
        text = result["content"][0]["text"]
        print(f"  {'error' if result.get('is_error') else 'result'}: {text}")
        order = order or json.loads(text)
    summary = "Refunded ord_881 in full; the repeated refund was refused, so it was not issued twice."
    print(f"model turn {turns.count}: {summary}")
    return summary


def main() -> int:
    client, run = admit("claude_agent_sdk")
    server, handlers, state = governed_server(run)
    turns = Turns(run)
    if offline("ANTHROPIC_API_KEY"):
        summary = asyncio.run(scripted(handlers, turns))
    else:
        summary = asyncio.run(live(server, turns))
    print(f"model turns reserved: {turns.count}")
    finish(client, run, state["refunded"], summary)
    return 0


if __name__ == "__main__":
    sys.exit(main())
