"""Pydantic AI agent governed by ContextOS: the quickstart's refund of order ord_881.

Pydantic AI runs its own agent loop; ContextOS governs what the loop can do:

- ``ContextOSToolset`` wraps the run's governed tools. Every call goes through
  ``contextosd`` (the tool bodies never run locally), and an outcome that is not plain
  success becomes something the model can read: a refusal is a failed tool result that
  says the action did not happen (``ToolFailed``, not ``ModelRetry``), an approval pause
  is a deferred approval (``ApprovalRequired``), and an unknown effect is deferred to
  reconciliation (``CallDeferred``), never retried.
- ``BudgetedModel`` wraps the model: each request reserves tokens from the run's budget
  first and is refused when the run cannot afford it.

Without OPENAI_API_KEY or ANTHROPIC_API_KEY a scripted ``FunctionModel`` drives the real
loop: it looks the order up, refunds it, then tries the refund again, which the gateway
refuses. Run with ``./examples/frameworks/run.sh pydantic-ai``.
"""
import os

os.environ.setdefault("PYDANTIC_AI_NO_BANNER", "1")

from contextlib import ExitStack, asynccontextmanager, contextmanager
from dataclasses import dataclass, field
from typing import Any

from contextos.client import ContextOSHTTPError
from demo import (GOAL, INSTRUCTIONS, ToolOutcome, ToolPaused, admit, budgeted, finish, offline, refusal,
                  tools)
from pydantic_ai import (Agent, ApprovalRequired, CallDeferred, DeferredToolRequests, FunctionToolset,
                         ModelResponse, TextPart, ToolCallPart, ToolFailed, ToolReturnPart, UsageLimits,
                         WrapperToolset)
from pydantic_ai.exceptions import UsageLimitExceeded
from pydantic_ai.models.function import AgentInfo, FunctionModel
from pydantic_ai.models.wrapper import WrapperModel


@dataclass
class ContextOSToolset(WrapperToolset):
    """Maps every governed call's outcome onto Pydantic AI's tool semantics."""

    completed: set = field(default_factory=set)

    async def call_tool(self, name, tool_args, ctx, tool):
        try:
            result = await super().call_tool(name, tool_args, ctx, tool)
        except ToolPaused as paused:
            meta = {"operation_id": paused.operation_id, "reason_codes": paused.reason_codes}
            if paused.kind == "approval":
                print(f"tool {name}: awaiting approval")
                raise ApprovalRequired(metadata=meta)  # a human decides; resume with DeferredToolResults
            if paused.kind in ("unknown_outcome", "input"):
                print(f"tool {name}: deferred ({paused.kind})")
                raise CallDeferred(metadata=meta)  # reconcile or answer, then resume; never retry
            print(f"tool {name}: {refusal(paused)}")  # e.g. a duplicate: already requested, not repeated
            raise ToolFailed(refusal(paused))
        except ToolOutcome as outcome:  # blocked, rejected, failed: the action did not happen
            print(f"tool {name}: {refusal(outcome)}")
            raise ToolFailed(refusal(outcome))
        print(f"tool {name}: {result}")
        self.completed.add(name)
        return result


class BudgetedModel(WrapperModel):
    """Reserves from the run's budget before every model request and settles after it."""

    def __init__(self, wrapped, run):
        super().__init__(wrapped)
        self.run = run

    async def request(self, messages, model_settings, model_request_parameters):
        with self._budget():
            return await super().request(messages, model_settings, model_request_parameters)

    @asynccontextmanager
    async def request_stream(self, messages, model_settings, model_request_parameters, run_context=None):
        with self._budget():
            async with super().request_stream(messages, model_settings, model_request_parameters,
                                              run_context) as stream:
                yield stream

    @contextmanager
    def _budget(self):
        with ExitStack() as stack:
            try:
                stack.enter_context(budgeted(self.run))  # reserve now, settle on exit
            except ContextOSHTTPError as refused:
                if refused.code == "budget_exhausted":  # no request is sent: the run cannot afford it
                    raise UsageLimitExceeded(f"ContextOS run budget exhausted: {refused.detail}") from None
                raise
            yield


def scripted(messages: list, info: AgentInfo) -> ModelResponse:
    """The offline model: look up, refund the order's amount, refund again, then answer."""
    returns = [part for message in messages for part in getattr(message, "parts", [])
               if isinstance(part, ToolReturnPart)]
    if not returns:
        return ModelResponse(parts=[ToolCallPart("lookup_order", {"order_id": "ord_881"})])
    if len(returns) < 3:
        order = returns[0].content
        refund = {"order_id": "ord_881", "customer_id": "cus_77", "amount_minor": order["amount_minor"]}
        return ModelResponse(parts=[ToolCallPart("issue_refund", refund)])
    return ModelResponse(parts=[TextPart(f"Refunded ord_881 ({returns[1].content}). The repeated refund "
                                         f"was refused by the gateway: {returns[2].content}")])


def model() -> Any:
    if offline("OPENAI_API_KEY", "ANTHROPIC_API_KEY"):
        return FunctionModel(scripted, model_name="scripted")
    if os.environ.get("ANTHROPIC_API_KEY"):
        return os.environ.get("PYDANTIC_AI_MODEL", "anthropic:claude-sonnet-5-5")
    return os.environ.get("PYDANTIC_AI_MODEL", "openai:gpt-6.1-sol")


def main() -> None:
    client, run = admit("pydantic_ai")
    lookup_order, issue_refund = tools(run)
    toolset = ContextOSToolset(FunctionToolset([lookup_order, issue_refund], sequential=True))
    agent = Agent(BudgetedModel(model(), run), instructions=INSTRUCTIONS, toolsets=[toolset],
                  output_type=[str, DeferredToolRequests])
    # A local backstop only; the run's budget in contextosd is the limit that holds.
    result = agent.run_sync(GOAL, usage_limits=UsageLimits(request_limit=8))
    if isinstance(result.output, DeferredToolRequests):
        # In production: persist result.all_messages(), wait for the approval or the
        # reconciliation, then resume with message_history= and deferred_tool_results=.
        print(f"paused for a human: {result.output.metadata}")
        return
    print(f"agent: {result.output}")
    finish(client, run, "issue_refund" in toolset.completed, result.output)


if __name__ == "__main__":
    main()
