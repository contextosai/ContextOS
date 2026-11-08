"""The OpenAI Agents SDK's own agent loop (``Runner``), governed by ContextOS.

- The run's governed functions become SDK function tools; their bodies never run
  locally, so every call is authorized, dispatched and audited by ``contextosd``.
- Every model call reserves budget first: ``BudgetedProvider``
  (``contextos.integrations.openai_agents``) wraps each model the runner asks for, so
  reservation and settlement bracket the call even if it raises.
- A refusal reaches the model as text ("NOT DONE", or "ALREADY REQUESTED" for a
  repeat) through ``failure``; the SDK's default would tell the model "Please try
  again". A pause for input or an unknown outcome is not text: it stops the run.
- When the gateway needs an exact approval for a call (``--approval``),
  ``GatewayApprovals`` opens the gateway's request from ``needs_approval`` and the SDK
  interrupts the run. A reviewer decides (``approve``), the ``RunState`` is
  checkpointed in ContextOS, and the resumed tool call redeems that approval once.

Without OPENAI_API_KEY a scripted model (the SDK's ``agents.testing.ScriptedModel``)
drives the same loop: look up, refund, refund again (refused), answer.

Run with: ./examples/frameworks/run.sh openai-agents [--approval]
"""
import ast
import asyncio
import json
import os
import sys

from agents import Agent, ModelProvider, ModelSettings, RunConfig, RunHooks, Runner, UserError, function_tool
from agents.models.multi_provider import MultiProvider
from agents.testing import ModelStep, ScriptedModel, assistant_message, function_call

from contextos.aio import AsyncRun
from contextos.integrations.openai_agents import BudgetedProvider, GatewayApprovals, failure
from demo import APPROVAL, EVIDENCE, GOAL, INSTRUCTIONS, MODEL_CALL_TOKENS, ToolPaused, admit, approve, finish, offline, tools

MODEL = os.environ.get("OPENAI_MODEL", "gpt-6.1-sol")


class Script(ModelProvider):
    """The offline stand-in for a model: the steps a model would take, reading the
    lookup's output from the conversation the runner sends it."""

    def __init__(self):
        self.model = ScriptedModel([
            [function_call("lookup_order", {"order_id": "ord_881"}, call_id="call_lookup")],
            ModelStep.respond(lambda call: [function_call("issue_refund", refund_args(call), call_id="call_refund")]),
            # A confused model repeating the effect: the gateway refuses it.
            ModelStep.respond(lambda call: [function_call("issue_refund", refund_args(call), call_id="call_refund_again")]),
            ModelStep.respond(lambda call: [assistant_message(
                f"Refunded ord_881 in full. The repeat refund was refused: {output_of(call, 'call_refund_again')}")]),
        ])

    def get_model(self, model_name):
        return self.model


def output_of(call, call_id: str) -> str:
    return next(item["output"] for item in call.input
                if isinstance(item, dict) and item.get("type") == "function_call_output" and item["call_id"] == call_id)


def refund_args(call) -> dict:
    output = output_of(call, "call_lookup")
    order = json.loads(output) if output.startswith("{\"") else ast.literal_eval(output)
    return {"order_id": "ord_881", "customer_id": "cus_77", "amount_minor": order["amount_minor"]}


class Trace(RunHooks):
    """Prints each governed result and notes whether the refund happened."""

    refunded = False

    async def on_tool_end(self, context, agent, tool, result):
        print(f"tool {tool.name} -> {result}")
        if tool.name == "issue_refund" and isinstance(result, dict) and "refund_id" in result:
            self.refunded = True


async def main() -> int:
    client, run = admit("openai_agents")
    lookup_order, issue_refund = tools(run)  # sync: the SDK runs them in a worker thread
    arun = AsyncRun(run)  # the same run, as coroutines, for calls made on the event loop
    # The gateway decides which calls need an exact approval; the SDK's interruption is
    # how the run waits for it. The keys are the ones the governed tools use.
    approvals = GatewayApprovals(run)
    lookup_key = (lambda order_id: f"lookup:{order_id}") if APPROVAL else None
    agent = Agent(
        name="support",
        instructions=INSTRUCTIONS,
        model=MODEL,  # a name, so the run config's provider resolves (and budgets) it
        model_settings=ModelSettings(parallel_tool_calls=False),  # look up before acting
        tools=[function_tool(lookup_order, failure_error_function=failure,
                             needs_approval=approvals.needs("adp_orders.lookup", "read_only",
                                                            idempotency_key=lookup_key)),
               function_tool(issue_refund, failure_error_function=failure,
                             needs_approval=approvals.needs("adp_payments.issue_refund", "destructive",
                                                            idempotency_key=lambda order_id, **_: f"refund:{order_id}",
                                                            evidence_refs=EVIDENCE))],
    )
    scripted = offline("OPENAI_API_KEY")
    config = RunConfig(model_provider=BudgetedProvider(arun, Script() if scripted else MultiProvider(), MODEL_CALL_TOKENS),
                       tracing_disabled=scripted, trace_include_sensitive_data=False)
    hooks = Trace()
    revision = 0
    try:
        result = await Runner.run(agent, GOAL, run_config=config, hooks=hooks, max_turns=8)
        while result.interruptions:
            state = result.to_state()
            for item in result.interruptions:
                paused = approvals.pending(item.call_id)
                print(f"paused for approval: {paused.report['approval_request_id']} ({item.tool_name} {item.arguments})")
                approve(paused)  # a reviewer decides in your approval service
                state.approve(item)
            # Save the state with the run: another executor can resume it, and the
            # resumed tool call redeems the gateway's approval once.
            revision = (await arun.checkpoint({"sdk_run_state": state.to_json()}, revision))["revision"]
            print(f"approved; checkpoint revision {revision}")
            result = await Runner.run(agent, state, run_config=config, hooks=hooks, max_turns=8)
    except UserError as error:
        if not isinstance(error.__cause__, ToolPaused):  # the SDK wraps what a tool raised
            raise
        paused = error.__cause__
        print(f"paused ({paused.kind}): {paused.reason_codes} {paused.obligations}; "
              "answer input or reconcile, never retry")
        return 1
    print(f"agent: {result.final_output}")
    finish(client, run, hooks.refunded, str(result.final_output))
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
