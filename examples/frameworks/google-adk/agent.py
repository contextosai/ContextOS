"""Google ADK agent governed by ContextOS.

ADK's own Runner drives the agent loop; ContextOS governs what the loop does:

- the two tools are ``governed_tool`` functions wrapped in ADK ``FunctionTool``s, so
  ADK builds their declarations from the signatures and docstrings while every call
  is authorized, dispatched and audited by contextosd;
- ``before_model_callback`` reserves budget for each model call (and answers in the
  model's place when the run cannot afford it); ``after_model_callback`` settles it;
- ``on_tool_error_callback`` turns a governed refusal into a tool result that tells
  the model the action did not happen, and an approval pause into ADK's tool
  confirmation, never a retry.

Without GOOGLE_API_KEY (or Vertex AI settings) a scripted ``BaseLlm`` plays the model,
including a second refund attempt that the gateway refuses.

Run with: ./examples/frameworks/run.sh google-adk
"""
import asyncio
import json
import os
import warnings

from google.adk.agents import LlmAgent
from google.adk.models import BaseLlm, LlmRequest, LlmResponse
from google.adk.runners import InMemoryRunner
from google.adk.tools import FunctionTool
from google.genai import types

from contextos.client import ContextOSHTTPError
from demo import (GOAL, INSTRUCTIONS, ToolOutcome, ToolPaused, admit, finish, offline, refusal, tools)

MODEL_CALL_TOKENS = 1000
warnings.filterwarnings("ignore", message=r"\[EXPERIMENTAL\]")
GEMINI_MODEL = os.environ.get("GEMINI_MODEL", "gemini-3.8-flash")


class ScriptedLlm(BaseLlm):
    """Stands in for Gemini offline: decides the next step from the tool results so
    far, exactly where a real model would."""

    model: str = "scripted"

    async def generate_content_async(self, llm_request: LlmRequest, stream: bool = False):
        results = [part.function_response for content in llm_request.contents for part in content.parts or []
                   if part.function_response]
        if not results:
            yield _call("lookup_order", order_id="ord_881")
        elif len(results) == 1:
            order = results[0].response
            yield _call("issue_refund", order_id="ord_881", customer_id="cus_77", amount_minor=order["amount_minor"])
        elif len(results) == 2:
            # A model that retries what already succeeded; the gateway refuses it.
            yield _call("issue_refund", order_id="ord_881", customer_id="cus_77",
                        amount_minor=results[0].response["amount_minor"])
        else:
            yield LlmResponse(usage_metadata=USAGE, content=types.Content(role="model", parts=[types.Part(
                text="Refunded order ord_881 in full; the repeated refund was refused, so it was issued once.")]))


# Token counts a real model reports; ADK's telemetry expects them.
USAGE = types.GenerateContentResponseUsageMetadata(prompt_token_count=600, candidates_token_count=40,
                                                   total_token_count=640)


def _call(name: str, **args) -> LlmResponse:
    return LlmResponse(usage_metadata=USAGE, content=types.Content(role="model", parts=[
        types.Part(function_call=types.FunctionCall(name=name, args=args))]))


def budget_callbacks(run):
    """One reservation per model call, keyed by invocation and agent: an agent makes
    one model call at a time, and sub-agents get their own key."""
    open_reservations: dict = {}

    async def before_model(callback_context, llm_request):
        key = (callback_context.invocation_id, callback_context.agent_name)
        try:
            # The client is synchronous; keep it off the event loop.
            open_reservations[key] = await asyncio.to_thread(run.reserve_usage, "model_call",
                                                             tokens=MODEL_CALL_TOKENS)
        except ContextOSHTTPError as refused:
            # Answering here skips the model call: no budget, no call.
            return LlmResponse(content=types.Content(role="model", parts=[types.Part(
                text=f"Stopping: the run's budget refused another model call ({refused.code}).")]))
        return None

    async def settle(callback_context):
        reservation = open_reservations.pop((callback_context.invocation_id, callback_context.agent_name), None)
        if reservation:
            await asyncio.to_thread(run.settle_usage, reservation)

    async def after_model(callback_context, llm_response):
        # Streaming calls this per chunk; settle once, on the final response.
        if not llm_response.partial:
            await settle(callback_context)
        return None

    async def on_model_error(callback_context, llm_request, error):
        await settle(callback_context)
        return None  # let ADK raise the model error as usual

    return before_model, after_model, on_model_error


UNKNOWN: list = []  # operations whose effect must be reconciled before the run completes


def on_tool_error(tool, args, tool_context, error):
    """What the model sees when the gateway did not complete a call."""
    if not isinstance(error, ToolOutcome):
        return None
    kind = error.kind if isinstance(error, ToolPaused) else None
    if kind == "unknown_outcome":
        # The effect may have happened: neither "done" nor "not done" is true yet, and
        # refusal() says so.
        UNKNOWN.append(error.operation_id)
    elif kind == "approval":
        # Hand the pause to ADK's confirmation flow. The approval itself is decided by
        # the approval service; when the confirmation returns, ADK runs the same call
        # again with the same operation key and the gateway checks that approval.
        tool_context.request_confirmation(hint=f"{tool.name} is waiting for approval in ContextOS.",
                                          payload={"approval_request_id": error.report.get("approval_request_id")})
    result = {"error": refusal(error)}
    print(f"tool {tool.name}: {result['error']}")
    return result


SUCCEEDED: set = set()  # tools the gateway reported done


def after_tool(tool, args, tool_context, tool_response):
    if "error" not in tool_response:
        SUCCEEDED.add(tool.name)
        print(f"tool {tool.name}: {json.dumps(tool_response)}")
    return None


async def main() -> None:
    client, run = admit("google_adk")
    lookup_order, issue_refund = tools(run)
    before_model, after_model, on_model_error = budget_callbacks(run)
    scripted = offline("GOOGLE_API_KEY", "GEMINI_API_KEY", "GOOGLE_GENAI_USE_VERTEXAI", "GOOGLE_GENAI_USE_ENTERPRISE")
    agent = LlmAgent(
        name="support_agent",
        model=ScriptedLlm() if scripted else GEMINI_MODEL,
        instruction=INSTRUCTIONS,
        tools=[FunctionTool(lookup_order), FunctionTool(issue_refund)],
        before_model_callback=before_model,
        after_model_callback=after_model,
        on_model_error_callback=on_model_error,
        after_tool_callback=after_tool,
        on_tool_error_callback=on_tool_error,
    )
    print(f"model: {'scripted (set GOOGLE_API_KEY for Gemini)' if scripted else GEMINI_MODEL}")

    runner = InMemoryRunner(agent=agent, app_name="contextos_support")
    session = await runner.session_service.create_session(app_name="contextos_support", user_id="cus_77")
    summary = ""
    async for event in runner.run_async(user_id="cus_77", session_id=session.id,
                                        new_message=types.Content(role="user", parts=[types.Part(text=GOAL)])):
        if event.is_final_response() and event.content and event.content.parts:
            summary = "".join(part.text or "" for part in event.content.parts)
    print(f"agent: {summary}")
    await runner.close()
    for operation_id in UNKNOWN:
        print(f"reconcile {operation_id}: {run.reconcile(operation_id)['status']}")

    # Whether the refund happened comes from the gateway's result, not the model's account.
    finish(client, run, "issue_refund" in SUCCEEDED, summary)


if __name__ == "__main__":
    asyncio.run(main())
