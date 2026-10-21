"""A LangGraph agent (LangChain ``create_agent``) under ContextOS.

The agent loop is LangGraph's own; ContextOS enters through one middleware:

- ``wrap_model_call`` reserves the run's budget around every model call, so the loop
  cannot call the model past the budget;
- ``wrap_tool_call`` turns a refusal into a tool error the model reads as "not done",
  and a pause for approval into a LangGraph ``interrupt``, never a retry.

Without ANTHROPIC_API_KEY a scripted fake chat model drives the same loop: it looks
the order up, refunds it, then tries the refund again, which the gateway refuses.

With ``--approval`` the refund needs an exact approval: the run stops at the interrupt,
``approve`` plays the reviewer, and ``Command(resume=...)`` on the same thread re-sends
the identical call, which the gateway now lets through once.

Run with: ./examples/frameworks/run.sh langgraph [--approval]
"""
import ast
import json
import os
import sys
from typing import Any

from langchain.agents import create_agent
from langchain.agents.middleware import AgentMiddleware
from langchain.messages import AIMessage, ToolMessage
from langchain_core.language_models.fake_chat_models import GenericFakeChatModel
from langchain_core.outputs import ChatGeneration, ChatResult
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.types import Command, interrupt

from demo import (GOAL, INSTRUCTIONS, ToolBlocked, ToolFailed, ToolPaused, ToolRejected, admit, approve,
                  budgeted, finish, offline, refusal, tools)

MODEL = os.environ.get("LANGGRAPH_MODEL", "anthropic:claude-sonnet-5-5")


class ContextOS(AgentMiddleware):
    def __init__(self, run):
        super().__init__()
        self.run = run
        self.paused = {}  # approval_request_id -> the pause, for the reviewer

    def wrap_model_call(self, request, handler):
        with budgeted(self.run):
            return handler(request)

    def wrap_tool_call(self, request, handler):
        call = request.tool_call
        try:
            return handler(request)
        except ToolPaused as paused:
            if paused.kind != "approval":
                # A duplicate, an unknown outcome or another pause: retrying cannot change
                # it, so the model is told what happened and to stop.
                return self._error(call, refusal(paused))
            # On resume LangGraph re-runs this node, which re-sends the same governed call
            # (same operation key): approved, it runs once; still pending, we get here again.
            request_id = paused.report["approval_request_id"]
            self.paused[request_id] = paused
            answer = interrupt({"approval_request_id": request_id, "tool": call["name"], "args": call["args"],
                                "reason_codes": paused.reason_codes})
            return self._error(call, f"{refusal(paused)} Reviewer: {answer}")
        except (ToolBlocked, ToolRejected, ToolFailed) as outcome:
            return self._error(call, refusal(outcome))

    @staticmethod
    def _error(call, text: str) -> ToolMessage:
        return ToolMessage(text, tool_call_id=call["id"], name=call["name"], status="error")


class ScriptedModel(GenericFakeChatModel):
    """LangChain's fake chat model, given tools and a script that reads the conversation."""
    messages: Any = iter(())

    def bind_tools(self, tools, **kwargs):
        return self

    def _generate(self, messages, stop=None, run_manager=None, **kwargs):
        return ChatResult(generations=[ChatGeneration(message=script(messages))])


def script(messages) -> AIMessage:
    results = [m for m in messages if isinstance(m, ToolMessage)]
    refund = {"order_id": "ord_881", "customer_id": "cus_77"}
    if not results:
        return calling("lookup_order", {"order_id": "ord_881"}, 1)
    if len(results) < 3:
        order = parse(results[0].content)
        # The second refund repeats the first: the gateway, not the model, stops it.
        return calling("issue_refund", dict(refund, amount_minor=order["amount_minor"]), len(results) + 1)
    return AIMessage("Order ord_881 was refundable; I refunded it once. A repeat refund was refused and did not happen.")


def calling(name: str, args: dict, n: int) -> AIMessage:
    return AIMessage("", tool_calls=[{"name": name, "args": args, "id": f"call_{n}", "type": "tool_call"}])


def parse(content: str) -> dict:
    try:
        return json.loads(content)
    except ValueError:
        return ast.literal_eval(content)


def main() -> int:
    client, run = admit("langgraph")
    model = ScriptedModel() if offline("ANTHROPIC_API_KEY") else MODEL
    contextos = ContextOS(run)
    agent = create_agent(model, tools=list(tools(run)), system_prompt=INSTRUCTIONS, middleware=[contextos],
                         checkpointer=InMemorySaver())
    config = {"configurable": {"thread_id": run.run_id}}
    # LangGraph's checkpointer holds the conversation; the ContextOS checkpoint holds what
    # an executor taking the run over needs to find it again.
    revision = run.checkpoint({"thread_id": run.run_id}, 0)["revision"]
    print(f"checkpoint revision {revision}: thread {run.run_id}")
    state = agent.invoke({"messages": [{"role": "user", "content": GOAL}]}, config)
    while state.get("__interrupt__"):
        # The graph is checkpointed at the interrupt. A real deployment shows the request to
        # a reviewer and resumes the same thread once the approval service has decided.
        request = state["__interrupt__"][0].value
        print(f"paused for approval: {request['approval_request_id']} ({request['tool']} {request['args']})")
        approve(contextos.paused.pop(request["approval_request_id"]))
        print(f"resuming thread {run.run_id}")
        state = agent.invoke(Command(resume="approved"), config)
    refunded = False
    for message in state["messages"]:
        if isinstance(message, ToolMessage):
            print(f"  {message.name} -> {message.content}")
            refunded |= message.name == "issue_refund" and message.status != "error"
    answer = state["messages"][-1].text
    print(f"agent: {answer}")
    finish(client, run, refunded, answer)
    return 0


if __name__ == "__main__":
    sys.exit(main())
