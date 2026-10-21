"""A LlamaIndex FunctionAgent whose tool calls and model calls are governed by ContextOS.

- The tools are the run's governed functions (``tools(run)``): their bodies never run
  locally, contextosd authorizes, dispatches, records and audits each call.
- A governed call that did not complete comes back to the model as a tool result that
  says so (``refusal``); an approval pause becomes the workflow's
  human-in-the-loop (``InputRequiredEvent`` / ``HumanResponseEvent``).
- ``BudgetedLLM`` wraps the agent's LLM, so every model call reserves the run's budget
  first and a call the run cannot afford is refused before it reaches the provider.

Without OPENAI_API_KEY the agent runs on a scripted ``MockFunctionCallingLLM`` that
emits the tool calls a model would, including a repeated refund the gateway refuses.

Run with: ./examples/frameworks/run.sh llamaindex
"""
import asyncio
import json
import os
from typing import Any, Sequence

from llama_index.core.agent.workflow import FunctionAgent, ToolCallResult
from llama_index.core.base.llms.types import ChatMessage, MessageRole, ToolCallBlock
from llama_index.core.bridge.pydantic import PrivateAttr
from llama_index.core.llms import LLM
from llama_index.core.llms.function_calling import FunctionCallingLLM
from llama_index.core.llms.mock import MockFunctionCallingLLM
from llama_index.core.tools import FunctionTool
from llama_index.core.workflow import Context, HumanResponseEvent, InputRequiredEvent

from demo import (GOAL, INSTRUCTIONS, ToolOutcome, ToolPaused, admit, budgeted, finish, offline, refusal,
                  tools)


class BudgetedLLM(FunctionCallingLLM):
    """Delegates to ``inner``; every chat or completion reserves the run's budget first."""

    inner: LLM
    _run: Any = PrivateAttr()

    def __init__(self, inner: LLM, run: Any, **kwargs: Any) -> None:
        super().__init__(inner=inner, **kwargs)
        self._run = run

    @property
    def metadata(self):
        return self.inner.metadata

    def chat(self, messages, **kwargs):
        with budgeted(self._run):
            return self.inner.chat(messages, **kwargs)

    async def achat(self, messages, **kwargs):
        with budgeted(self._run):
            return await self.inner.achat(messages, **kwargs)

    def stream_chat(self, messages, **kwargs):
        with budgeted(self._run):  # settled when the stream is exhausted
            yield from self.inner.stream_chat(messages, **kwargs)

    async def astream_chat(self, messages, **kwargs):
        reservation = budgeted(self._run)
        reservation.__enter__()  # reserve now: an unaffordable call fails before streaming

        async def stream():
            try:
                async for chunk in await self.inner.astream_chat(messages, **kwargs):
                    yield chunk
            finally:
                reservation.__exit__(None, None, None)

        return stream()

    def complete(self, prompt, formatted=False, **kwargs):
        with budgeted(self._run):
            return self.inner.complete(prompt, formatted=formatted, **kwargs)

    async def acomplete(self, prompt, formatted=False, **kwargs):
        with budgeted(self._run):
            return await self.inner.acomplete(prompt, formatted=formatted, **kwargs)

    def stream_complete(self, prompt, formatted=False, **kwargs):
        with budgeted(self._run):
            yield from self.inner.stream_complete(prompt, formatted=formatted, **kwargs)

    async def astream_complete(self, prompt, formatted=False, **kwargs):
        raise NotImplementedError("not used by FunctionAgent")

    def _prepare_chat_with_tools(self, tools, user_msg=None, chat_history=None, verbose=False,
                                 allow_parallel_tool_calls=False, tool_required=False, **kwargs):
        return self.inner._prepare_chat_with_tools_compat(
            tools, user_msg=user_msg, chat_history=chat_history, verbose=verbose,
            allow_parallel_tool_calls=allow_parallel_tool_calls, tool_required=tool_required, **kwargs)

    def _validate_chat_with_tools_response(self, response, tools, allow_parallel_tool_calls=False, **kwargs):
        return self.inner._validate_chat_with_tools_response(response, tools, allow_parallel_tool_calls, **kwargs)

    def get_tool_calls_from_response(self, response, error_on_no_tool_call=True, **kwargs):
        return self.inner.get_tool_calls_from_response(response, error_on_no_tool_call=error_on_no_tool_call,
                                                       **kwargs)


def scripted(messages: Sequence[ChatMessage], **_: Any) -> ChatMessage:
    """Stands in for the model: look up, refund the order's amount, try the refund again
    (the gateway refuses it), then answer from what the tools reported."""
    results = [m.content or "" for m in messages if m.role == MessageRole.TOOL]

    def call(name: str, **kwargs: Any) -> ChatMessage:
        block = ToolCallBlock(tool_call_id=f"call_{len(results)}", tool_name=name, tool_kwargs=kwargs)
        return ChatMessage(role=MessageRole.ASSISTANT, blocks=[block])

    if not results:
        return call("lookup_order", order_id="ord_881")
    if len(results) in (1, 2):
        order = json.loads(results[0])
        return call("issue_refund", order_id="ord_881", customer_id="cus_77", amount_minor=order["amount_minor"])
    return ChatMessage(role=MessageRole.ASSISTANT,
                       content=f"Refunded ord_881 in full. The repeated refund was refused: {results[-1]}")


def governed_tools(run, state: dict) -> list:
    """The governed functions as LlamaIndex tools. Each runs off the event loop (the
    client is synchronous) and turns every outcome into what the model should see."""
    lookup, refund = tools(run)

    async def governed(ctx: Context, fn, **args: Any) -> str:
        try:
            return json.dumps(await asyncio.to_thread(fn, **args))
        except ToolPaused as paused:
            if paused.kind != "approval":
                # An unknown outcome, input request or duplicate: never retry blindly.
                return refusal(paused)
            # Approval pending: hand it to a human through the workflow. The step is
            # replayed when the answer arrives, and the same idempotency key makes the
            # re-sent call the same operation, governed again.
            answer = await ctx.wait_for_event(
                HumanResponseEvent, waiter_id=paused.operation_id,
                waiter_event=InputRequiredEvent(prefix=f"approve {fn.__name__}{args}?",
                                                operation_id=paused.operation_id))
            if answer.response != "approved":
                return refusal(paused)
            try:
                return json.dumps(await asyncio.to_thread(fn, **args))
            except ToolOutcome as outcome:
                return refusal(outcome)
        except ToolOutcome as outcome:
            return refusal(outcome)

    async def lookup_order(ctx: Context, order_id: str) -> str:
        return await governed(ctx, lookup, order_id=order_id)

    async def issue_refund(ctx: Context, order_id: str, customer_id: str, amount_minor: int) -> str:
        result = await governed(ctx, refund, order_id=order_id, customer_id=customer_id, amount_minor=amount_minor)
        state["refunded"] = state["refunded"] or result.startswith('{"refund_id"')
        return result

    return [FunctionTool.from_defaults(async_fn=lookup_order, name="lookup_order", description=lookup.__doc__),
            FunctionTool.from_defaults(async_fn=issue_refund, name="issue_refund", description=refund.__doc__)]


async def main() -> None:
    client, run = admit("llamaindex")
    if offline("OPENAI_API_KEY"):
        model = MockFunctionCallingLLM(response_generator=scripted)
    else:
        from llama_index.llms.openai import OpenAI
        model = OpenAI(model=os.environ.get("OPENAI_MODEL", "gpt-6.1-sol"))
    state = {"refunded": False}
    agent = FunctionAgent(tools=governed_tools(run, state), llm=BudgetedLLM(model, run),
                          system_prompt=INSTRUCTIONS, allow_parallel_tool_calls=False)

    handler = agent.run(user_msg=GOAL)
    async for event in handler.stream_events():
        if isinstance(event, ToolCallResult):
            print(f"{event.tool_name}({event.tool_kwargs}) -> {event.tool_output.content}")
        elif isinstance(event, InputRequiredEvent):
            # A real deployment shows this to a reviewer; the decision itself is made in
            # ContextOS's approval service, and the re-sent call is governed again.
            print(f"approval needed: {event.prefix}")
            handler.ctx.send_event(HumanResponseEvent(response=os.environ.get("APPROVAL", "denied")))
    response = await handler
    print(f"agent: {response}")
    finish(client, run, state["refunded"], str(response))


if __name__ == "__main__":
    asyncio.run(main())
