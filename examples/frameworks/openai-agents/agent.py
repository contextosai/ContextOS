"""The OpenAI Agents SDK's own agent loop (``Runner``), governed by ContextOS.

- The run's governed functions become SDK function tools; their bodies never run
  locally, so every call is authorized, dispatched and audited by ``contextosd``.
- Every model call reserves budget first: a ``ModelProvider`` wraps each model the
  runner asks for, so reservation and settlement bracket the call even if it raises.
- A refusal reaches the model as ``refusal()`` text ("NOT DONE", or "ALREADY
  REQUESTED" for a repeat) through ``failure_error_function``; the SDK's default would
  tell the model "Please try again". A pause for approval, input or an unknown outcome
  is not text: it stops the run, to wait for approval or reconcile.
- The refund needs a human's approval in the SDK too (``needs_approval``); the paused
  ``RunState`` is checkpointed in ContextOS before the run resumes.

Without OPENAI_API_KEY a scripted model (the SDK's ``agents.testing.ScriptedModel``)
drives the same loop: look up, refund, refund again (refused), answer.

Run with: ./examples/frameworks/run.sh openai-agents
"""
import ast
import asyncio
import json
import os
import sys

from agents import Agent, Model, ModelProvider, ModelSettings, RunConfig, RunHooks, Runner, UserError, function_tool
from agents.models.multi_provider import MultiProvider
from agents.testing import ModelStep, ScriptedModel, assistant_message, function_call

from demo import GOAL, INSTRUCTIONS, ToolOutcome, ToolPaused, admit, budgeted, finish, offline, refusal, tools

MODEL = os.environ.get("OPENAI_MODEL", "gpt-6.1-sol")


class BudgetedModel(Model):
    """Reserves run budget before each model call and settles it after, success or not."""

    def __init__(self, run, inner: Model):
        self.run, self.inner = run, inner

    async def get_response(self, *args, **kwargs):
        with budgeted(self.run):
            return await self.inner.get_response(*args, **kwargs)

    async def stream_response(self, *args, **kwargs):
        with budgeted(self.run):
            async for event in self.inner.stream_response(*args, **kwargs):
                yield event

    def get_retry_advice(self, request):
        return self.inner.get_retry_advice(request)

    async def close(self):
        await self.inner.close()


class BudgetedProvider(ModelProvider):
    """Every agent the runner drives (handoffs included) gets a budgeted model."""

    def __init__(self, run, inner: ModelProvider):
        self.run, self.inner = run, inner

    def get_model(self, model_name):
        return BudgetedModel(self.run, self.inner.get_model(model_name))


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


def governed_failure(ctx, error: Exception) -> str:
    """What the model sees when a governed call did not complete."""
    if isinstance(error, ToolOutcome) and not (
            isinstance(error, ToolPaused) and error.kind in ("approval", "input", "unknown_outcome")):
        # Refused, or a repeat of an operation that already exists (kind "duplicate"):
        # it did not happen now, and the model is told so.
        return refusal(error)
    # Approval pending, input required, an unknown outcome or a transport error: the
    # model cannot fix these and must not retry them, so the run stops.
    raise error


class Trace(RunHooks):
    """Prints each governed result and notes whether the refund happened."""

    refunded = False

    async def on_tool_end(self, context, agent, tool, result):
        print(f"tool {tool.name} -> {result}")
        if tool.name == "issue_refund" and isinstance(result, dict) and "refund_id" in result:
            self.refunded = True


async def needs_approval(ctx, params: dict, call_id: str) -> bool:
    return True  # every refund is shown to a human first; the gateway still decides


async def main() -> int:
    client, run = admit("openai_agents")
    lookup_order, issue_refund = tools(run)
    agent = Agent(
        name="support",
        instructions=INSTRUCTIONS,
        model=MODEL,  # a name, so the run config's provider resolves (and budgets) it
        model_settings=ModelSettings(parallel_tool_calls=False),  # look up before acting
        tools=[function_tool(lookup_order, failure_error_function=governed_failure),
               function_tool(issue_refund, failure_error_function=governed_failure, needs_approval=needs_approval)],
    )
    scripted = offline("OPENAI_API_KEY")
    config = RunConfig(model_provider=BudgetedProvider(run, Script() if scripted else MultiProvider()),
                       tracing_disabled=scripted, trace_include_sensitive_data=False)
    hooks = Trace()
    revision = 0
    try:
        result = await Runner.run(agent, GOAL, run_config=config, hooks=hooks, max_turns=8)
        while result.interruptions:
            state = result.to_state()
            for item in result.interruptions:
                print(f"approval requested: {item.tool_name}({item.arguments})")
                state.approve(item)  # a real reviewer decides here
            # Save the approved state with the run: another executor, or this one after a
            # gateway pause, resumes from it and re-sends the same governed call.
            revision = run.checkpoint({"sdk_run_state": state.to_json()}, revision)["revision"]
            print(f"approved; checkpoint revision {revision}")
            result = await Runner.run(agent, state, run_config=config, hooks=hooks, max_turns=8)
    except UserError as error:
        if not isinstance(error.__cause__, ToolPaused):  # the SDK wraps what a tool raised
            raise
        paused = error.__cause__
        print(f"paused ({paused.kind}): {paused.reason_codes} {paused.obligations}; "
              "wait for approval, answer input or reconcile, never retry")
        return 1
    print(f"agent: {result.final_output}")
    finish(client, run, hooks.refunded, str(result.final_output))
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
