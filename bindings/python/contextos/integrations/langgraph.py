"""ContextOS middleware for LangChain ``create_agent`` (LangGraph).

::

    from contextos.integrations.langgraph import ContextOSMiddleware

    contextos = ContextOSMiddleware(run)
    agent = create_agent(model, tools=governed_tools, middleware=[contextos],
                         checkpointer=saver)
    state = agent.invoke({"messages": [...]}, config)
    while state.get("__interrupt__"):
        request = state["__interrupt__"][0].value   # approval_request_id, tool, args
        ...                                          # a person decides in your approval service
        state = agent.invoke(Command(resume="approved"), config)

- Every model call reserves the run's budget first (``Run.budgeted_model_call``), so
  the loop cannot call the model past the budget.
- A refusal, a duplicate or an unknown outcome reaches the model as a tool error that
  says it did not happen (or may have), never "please try again".
- A pause for an exact approval becomes a LangGraph ``interrupt``. On resume LangGraph
  re-runs the tool node, which re-sends the identical call. A call that changes
  something gets its operation key from its capability and arguments
  (``contextos.envelope.operation_key``) unless the tool names one, so the re-sent call
  is the same operation: approved, it runs once; still pending, it interrupts again.
  This holds across a process restart, since the key is not kept in memory.

Governed tools whose approval gates a read (``approval_mode="read_only"``) need an
``idempotency_key`` of their own: reads otherwise get a fresh operation per call.
"""
from typing import Any, Callable, Dict

from langchain.agents.middleware import AgentMiddleware
from langchain.messages import ToolMessage
from langgraph.types import interrupt

from ..errors import ToolOutcome, ToolPaused
from . import describe

__all__ = ["ContextOSMiddleware"]


class ContextOSMiddleware(AgentMiddleware):
    """Budgets model calls and governs tool outcomes for one ``Run``.

    ``model_call_tokens`` is what each model call reserves. ``describe`` turns an
    outcome into the text the model reads. ``paused`` holds each pending approval's
    ``ToolPaused`` by ``approval_request_id``, for code that shows it to a reviewer."""

    def __init__(self, run: Any, *, model_call_tokens: int = 1000,
                 describe: Callable[[ToolOutcome], str] = describe):
        super().__init__()
        self.run = run
        self.model_call_tokens = model_call_tokens
        self.describe = describe
        self.paused: Dict[str, ToolPaused] = {}

    def wrap_model_call(self, request, handler):
        with self.run.budgeted_model_call(tokens=self.model_call_tokens):
            return handler(request)

    def wrap_tool_call(self, request, handler):
        call = request.tool_call
        try:
            return handler(request)
        except ToolPaused as paused:
            if paused.kind != "approval":
                # A duplicate, an unknown outcome or input: retrying cannot change it.
                return self._error(call, self.describe(paused))
            request_id = paused.report["approval_request_id"]
            self.paused[request_id] = paused
            answer = interrupt({"approval_request_id": request_id, "tool": call["name"], "args": call["args"],
                                "reason_codes": paused.reason_codes})
            # Reached only when the resumed call is still not approved.
            return self._error(call, f"{self.describe(paused)} Reviewer: {answer}")
        except ToolOutcome as outcome:
            return self._error(call, self.describe(outcome))

    @staticmethod
    def _error(call: dict, text: str) -> ToolMessage:
        return ToolMessage(text, tool_call_id=call["id"], name=call["name"], status="error")
