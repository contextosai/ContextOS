"""CrewAI crew whose tool calls and model calls are governed by ContextOS.

The crew is CrewAI's own: an Agent with a Task in a sequential Crew, running CrewAI's
native tool-calling loop. ContextOS adds three things:

- Tools: the governed ``lookup_order`` / ``issue_refund`` become CrewAI tools. A call
  the gateway does not complete is returned to the model as ``refusal()`` text instead
  of raised, because CrewAI turns tool exceptions into retries; result caching is off,
  so a repeated call reaches the gateway instead of replaying a cached result. A pause
  for input or reconciliation stops the crew at its next model call; a pause for
  approval goes to CrewAI's human input (``Task(human_input=True)``), where the reviewer
  decides and the agent, told it was approved, re-sends the identical call.
- Budget: a ``before_llm_call`` hook reserves budget for every model call and aborts
  the crew (``HookAborted``) when the run cannot afford it; the reservation is settled
  when CrewAI reports the call completed or failed on its event bus.
- Evidence: the run ends with a DecisionRecord, completion and its audit evidence.

Without OPENAI_API_KEY a scripted model drives the same loop: it looks the order up,
refunds it, tries the refund again (the gateway refuses it) and reports.

With ``--approval`` the refund needs an exact approval, which ``approve`` grants as the
reviewer when CrewAI asks for human input.

Run with: ./examples/frameworks/run.sh crewai [--approval]
"""
import contextlib
import functools
import json
import os
import sys
import uuid
from collections import deque

# CrewAI sends anonymous telemetry and may offer trace upload; neither belongs in a
# governed run (and the example must work offline). Set before importing crewai.
os.environ.setdefault("CREWAI_DISABLE_TELEMETRY", "true")
os.environ.setdefault("OTEL_SDK_DISABLED", "true")
os.environ.setdefault("CREWAI_TRACING_ENABLED", "false")

from crewai import LLM, Agent, Crew, Process, Task  # noqa: E402
from crewai.core.providers.human_input import SyncHumanInputProvider, set_provider  # noqa: E402
from crewai.events import LLMCallCompletedEvent, LLMCallFailedEvent, crewai_event_bus  # noqa: E402
from crewai.events.types.llm_events import LLMCallType  # noqa: E402
from crewai.hooks import HookAborted, register_before_llm_call_hook  # noqa: E402
from crewai.llms.base_llm import BaseLLM, llm_call_context  # noqa: E402
from crewai.tools import tool  # noqa: E402
from crewai.tools.tool_failure import ToolFailure  # noqa: E402

from demo import (GOAL, INSTRUCTIONS, ToolOutcome, ToolPaused, admit, approve, budgeted, finish,  # noqa: E402
                  offline, refusal, tools)


# Pauses the crew must not talk its way past: a human answers or reconciles. A pause for
# approval waits for the reviewer at CrewAI's human input step instead (Reviewer below).
STOP_KINDS = {"input", "unknown_outcome"}
AWAITING = "AWAITING APPROVAL"


class Governance:
    """The run's governed tools and model-call budget, wired into CrewAI."""

    def __init__(self, run):
        self.run = run
        self.calls: list = []        # (tool name, None) or (tool name, ToolOutcome), in order
        self.stopped = None          # the pause that stops the crew, if any
        self.awaiting = None         # the approval pause the reviewer decides, if any
        self._reservations: deque = deque()
        register_before_llm_call_hook(self._reserve)
        crewai_event_bus.on(LLMCallCompletedEvent)(self._settle)
        crewai_event_bus.on(LLMCallFailedEvent)(self._settle)

    def tool(self, function):
        """A governed function as a CrewAI tool. CrewAI builds the schema from the
        signature and docstring, which ``governed_tool`` preserves. A call the gateway
        did not complete is returned as a ``ToolFailure`` carrying ``refusal()`` text,
        never raised: CrewAI would retry a raised call or hand the model a bare error
        string."""

        @functools.wraps(function)
        def call(**arguments):
            try:
                output = function(**arguments)
            except ToolOutcome as outcome:
                self.calls.append((function.__name__, outcome))
                if isinstance(outcome, ToolPaused) and outcome.kind == "approval":
                    self.awaiting = outcome
                    request_id = outcome.report["approval_request_id"]
                    print(f"{function.__name__}({arguments}) -> awaiting approval {request_id}")
                    return ToolFailure(message=f"{AWAITING} ({request_id}): the call has not run; a reviewer "
                                               f"decides, then it is re-sent unchanged.",
                                       code=outcome.status, retryable=False,
                                       details={"approval_request_id": request_id})
                if isinstance(outcome, ToolPaused) and outcome.kind in STOP_KINDS:
                    self.stopped = outcome
                print(f"{function.__name__}({arguments}) -> {refusal(outcome)}")
                # A ToolFailure reaches the model as its message and is recorded by CrewAI
                # (TaskOutput.tool_failures, ToolUsage events) as a failed call.
                return ToolFailure(message=refusal(outcome), code=outcome.status, retryable=False,
                                   details={"reason_codes": outcome.reason_codes,
                                            "obligations": outcome.obligations})
            self.calls.append((function.__name__, None))
            print(f"{function.__name__}({arguments}) -> {output}")
            return json.dumps(output)

        call.__annotations__ = {**function.__annotations__, "return": str}  # JSON text or a ToolFailure
        governed = tool(function.__name__)(call)
        governed.cache_function = lambda _arguments, _result: False  # never replay a cached result
        return governed

    def _reserve(self, context) -> None:
        """before_llm_call: every model call reserves budget first. Hooks fail open on
        any exception except HookAborted, so every refusal is raised as HookAborted."""
        if self.stopped is not None:
            raise HookAborted(f"paused ({self.stopped.kind}): {', '.join(self.stopped.obligations)}")
        stack = contextlib.ExitStack()
        try:
            stack.enter_context(budgeted(self.run))
        except Exception as refused:  # BudgetExhausted, or contextosd unreachable
            raise HookAborted(f"model call not reserved: {refused}") from refused
        self._reservations.append(stack)

    def _settle(self, _source, _event) -> None:
        """LLMCallCompleted/Failed: settles the oldest open reservation (calls of one
        agent are sequential). The after_llm_call hook would miss tool-call responses
        and failed calls, so the event bus settles instead."""
        if self._reservations:
            self._reservations.popleft().close()


class Reviewer(SyncHumanInputProvider):
    """CrewAI's human input step, given to the reviewer. With ``Task(human_input=True)``
    CrewAI asks for feedback after the agent's answer and, given some, appends it and runs
    the agent loop again on the same conversation. When a call awaits approval the
    reviewer decides it here; otherwise there is nothing to add and the answer stands."""

    def __init__(self, governance):
        self.governance = governance

    def handle_feedback(self, answer, context):
        while (paused := self.governance.awaiting) is not None:
            self.governance.awaiting = None
            request_id = paused.report["approval_request_id"]
            print(f"paused for approval: {request_id}")
            approve(paused)  # in production: wait for the approval service's decision
            print("resuming the agent loop with the reviewer's decision")
            context.messages.append(context._format_feedback_message(
                f"Approved ({request_id}). Re-send the call that was awaiting approval, unchanged."))
            answer = context._invoke_loop()
        context.ask_for_human_input = False
        return answer


class ScriptedLLM(BaseLLM):
    """A stand-in for a model with native tool calling, so the crew runs offline. Like
    CrewAI's providers, it runs the model-call hooks and reports each call on the event
    bus."""

    def supports_function_calling(self) -> bool:
        return True

    def call(self, messages, tools=None, callbacks=None, available_functions=None, from_task=None,
             from_agent=None, response_model=None):
        with llm_call_context():
            self._emit_call_started_event(messages=messages, tools=tools, from_task=from_task, from_agent=from_agent)
            messages = self._format_messages(messages)
            # Run the model-call hooks when CrewAI calls the model outside the agent loop
            # (no-op inside it, where the executor already ran them), as providers do.
            self._invoke_before_llm_call_hooks(messages, from_agent)
            response = self._next(messages)
            kind = LLMCallType.TOOL_CALL if isinstance(response, list) else LLMCallType.LLM_CALL
            self._emit_call_completed_event(response=response, call_type=kind, from_task=from_task,
                                            from_agent=from_agent, messages=messages)
            return response

    @staticmethod
    def _next(messages):
        results = [m["content"] for m in messages if m.get("role") == "tool"]
        if messages[-1].get("role") == "tool" and results[-1].startswith(AWAITING):
            return f"Waiting for a reviewer: {results[-1]}"
        results = [r for r in results if not r.startswith(AWAITING)]  # re-sent once approved
        if not results:
            return [_tool_call("lookup_order", order_id="ord_881")]
        if len(results) in (1, 2):  # refund, then (wrongly) the same refund again
            order = json.loads(results[0])
            return [_tool_call("issue_refund", order_id="ord_881", customer_id="cus_77",
                               amount_minor=order["amount_minor"])]
        return (f"Refunded order ord_881 ({json.loads(results[0])['amount_minor']} minor units) to cus_77. "
                f"A repeated refund was refused by the gateway: {results[2]}")


def _tool_call(name: str, **arguments) -> dict:
    return {"id": f"call_{uuid.uuid4().hex[:12]}", "type": "function",
            "function": {"name": name, "arguments": json.dumps(arguments)}}


def main() -> int:
    client, run = admit("crewai")
    governance = Governance(run)
    set_provider(Reviewer(governance))
    lookup_order, issue_refund = (governance.tool(function) for function in tools(run))
    llm = ScriptedLLM(model="scripted") if offline("OPENAI_API_KEY") else \
        LLM(model=os.environ.get("MODEL", "openai/gpt-6.1-sol"))
    print(f"model: {llm.model}")

    agent = Agent(role="Support agent", goal=GOAL, backstory=INSTRUCTIONS, llm=llm,
                  tools=[lookup_order, issue_refund], allow_delegation=False, max_iter=6, verbose=False)
    task = Task(description=GOAL, expected_output="What was done for the customer, and anything refused.",
                agent=agent, human_input=True)
    crew = Crew(agents=[agent], tasks=[task], process=Process.sequential, cache=False, verbose=False)
    try:
        result = crew.kickoff()
    except HookAborted as stopped:
        # A pause stays open for a human (approve, answer, reconcile); then a new kickoff
        # re-sends the same governed call. A refused reservation means the budget is spent.
        print(f"crew stopped: {stopped.reason}")
        return 0 if governance.stopped is not None else 1
    finally:
        crewai_event_bus.flush()  # settle reservations whose events are still in flight

    print(f"crew answer: {result.raw}")
    for failure in result.tasks_output[0].tool_failures:
        print(f"crewai recorded a failed call: {failure.tool_name} {failure.tool_args} ({failure.failure.code})")
    refunded = ("issue_refund", None) in governance.calls  # the gateway completed a refund
    finish(client, run, refunded=refunded, summary=result.raw)
    return 0


if __name__ == "__main__":
    sys.exit(main())
