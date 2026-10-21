"""A Microsoft Agent Framework agent whose tool calls and model calls are governed by ContextOS.

- The tools are the run's governed functions (``tools(run)``) registered with ``tool``:
  their bodies never run locally; contextosd authorizes, dispatches, records and audits
  each call. The framework runs these synchronous functions in a worker thread.
- Function middleware turns a call that did not complete into a tool result that says
  so (``refusal``); a ContextOS approval pause becomes the framework's
  own approval request, answered with a function approval response.
- Chat middleware reserves the run's budget before every model call and settles it
  after; a call the run cannot afford ends the run's model loop (``budget_exhausted``).

Without OPENAI_API_KEY the agent runs on a scripted chat client built on
``BaseChatClient`` that emits the tool calls a model would, including a repeated
refund the gateway refuses.

Run with: ./examples/frameworks/run.sh microsoft-agent-framework [--approval]
(``--approval``: each call pauses for an exact approval; a scripted reviewer grants it
and the session is resumed with the framework's function approval response.)
"""
import asyncio
import json
import os

from agent_framework import (Agent, BaseChatClient, ChatContext, ChatMiddlewareLayer, ChatResponse, Content,
                             FunctionInvocationContext, FunctionInvocationLayer, Message,
                             chat_middleware, function_middleware, tool)
from contextos.client import ContextOSHTTPError

from demo import (GOAL, INSTRUCTIONS, MODEL_CALL_TOKENS, ToolOutcome, ToolPaused, admit, approve, finish, offline,
                  refusal, tools)


class ScriptedChatClient(FunctionInvocationLayer, ChatMiddlewareLayer, BaseChatClient):
    """Stands in for the model: look up, refund the order's amount, try the refund again
    (the gateway refuses it), then answer from what the tools reported. The framework's
    layers add function invocation and middleware, as they do for the provider clients."""

    async def _inner_get_response(self, *, messages, stream, options, **kwargs):
        if stream:
            raise NotImplementedError("the scripted client does not stream")
        results = [c.result for m in messages for c in m.contents if c.type == "function_result"]

        def call(name: str, **arguments) -> ChatResponse:
            content = Content.from_function_call(call_id=f"call_{len(results)}", name=name, arguments=arguments)
            return ChatResponse(messages=[Message(role="assistant", contents=[content])])

        if not results:
            return call("lookup_order", order_id="ord_881")
        if len(results) in (1, 2):
            order = json.loads(results[0])
            return call("issue_refund", order_id="ord_881", customer_id="cus_77", amount_minor=order["amount_minor"])
        return ChatResponse(messages=[Message(role="assistant", contents=[
            f"Refunded ord_881 in full. The repeated refund was refused: {results[-1]}"])])


def budget(run):
    """Chat middleware: reserve before every model call, settle after (for a stream,
    once it has been consumed), stop the loop when the run cannot afford the call."""

    @chat_middleware
    async def reserve_model_call(context: ChatContext, call_next) -> None:
        try:
            reservation = await asyncio.to_thread(run.reserve_usage, "model_call", tokens=MODEL_CALL_TOKENS)
        except ContextOSHTTPError as refused:
            if refused.code != "budget_exhausted" or context.stream:
                raise
            # Answer in place of the model, without tool calls: the loop ends here.
            context.result = ChatResponse(messages=[Message(role="assistant", contents=[
                "Stopping: the run's budget is exhausted."])])
            return

        async def settle() -> None:
            await asyncio.to_thread(run.settle_usage, reservation)

        if context.stream:
            context.stream_cleanup_hooks.append(settle)
            await call_next()
            return
        try:
            await call_next()
        finally:
            await settle()

    return reserve_model_call


PENDING: dict = {}  # approval request id (framework) -> the ContextOS pause it stands for


@function_middleware
async def governed_outcomes(context: FunctionInvocationContext, call_next) -> None:
    """What the model sees when the gateway did not complete a call."""
    try:
        await call_next()
    except ToolPaused as paused:
        if paused.kind == "approval" and "approval_response" not in context.metadata:
            # Surface the pause as the framework's approval request. When the caller
            # approves, the framework re-invokes this call through the middleware with
            # the same arguments and idempotency key, which redeems the exact approval.
            call_id = context.metadata["call_id"]
            occurrence = context.metadata.get("function_call_occurrence_id") or call_id
            call = Content.from_function_call(call_id=call_id, name=context.function.name,
                                              arguments=dict(context.arguments), id=occurrence)
            PENDING[occurrence] = paused
            context.result = Content.from_function_approval_request(
                id=occurrence, function_call=call, additional_properties={"operation_id": paused.operation_id})
        else:
            # An unknown outcome, input request or duplicate: never retry blindly.
            context.result = refusal(paused)
    except ToolOutcome as outcome:
        context.result = refusal(outcome)


async def main() -> None:
    client, run = admit("maf")
    lookup_order, issue_refund = tools(run)
    if offline("OPENAI_API_KEY"):
        chat_client = ScriptedChatClient()
    else:
        from agent_framework.openai import OpenAIChatClient
        chat_client = OpenAIChatClient(model=os.environ.get("OPENAI_MODEL", "gpt-6.1-sol"))
    agent = Agent(client=chat_client, name="support", instructions=INSTRUCTIONS,
                  tools=[tool(lookup_order), tool(issue_refund)], middleware=[budget(run), governed_outcomes])

    session = agent.create_session()
    calls, refunded = {}, False

    def show(response) -> None:
        """Prints each completed call as its result arrives; tracks a successful refund."""
        nonlocal refunded
        for message in response.messages:
            for content in message.contents:
                if content.type == "function_call":
                    calls[content.call_id] = content
                elif content.type == "function_result":
                    call = calls[content.call_id]
                    print(f"{call.name}({call.arguments}) -> {content.result}")
                    refunded = refunded or str(content.result).startswith('{"refund_id"')

    response = await agent.run(GOAL, session=session)
    show(response)
    while response.user_input_requests:
        # The framework's approval requests. A real deployment shows the bound action to
        # a reviewer, who decides in ContextOS's approval service; `approve` plays them.
        answers = []
        for request in response.user_input_requests:
            paused = PENDING.pop(request.id)
            print(f"paused for approval: {paused.report['approval_request_id']} ({request.function_call.name})")
            approve(paused)
            answers.append(request.to_function_approval_response(True))
        print("resuming the session with the approval response")
        response = await agent.run(Message(role="user", contents=answers), session=session)
        show(response)

    print(f"agent: {response.text}")
    finish(client, run, refunded, response.text)


if __name__ == "__main__":
    asyncio.run(main())
