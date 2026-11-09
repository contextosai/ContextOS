"""ContextOS for the OpenAI Agents SDK (``Runner``).

::

    from contextos.integrations.openai_agents import BudgetedProvider, GatewayApprovals, failure

    approvals = GatewayApprovals(run)
    refund = function_tool(issue_refund, failure_error_function=failure,
                           needs_approval=approvals.needs("adp_payments.issue_refund", "destructive"))
    config = RunConfig(model_provider=BudgetedProvider(async_run, MultiProvider()))
    result = await Runner.run(agent, goal, run_config=config)
    while result.interruptions:
        state = result.to_state()
        for item in result.interruptions:
            pending = approvals.pending(item.call_id)   # the gateway's approval request
            ...                                          # a person decides in your approval service
            state.approve(item)
        result = await Runner.run(agent, state, run_config=config)

- ``GatewayApprovals.needs`` is a ``needs_approval`` callable that asks the gateway.
  When the call needs an exact approval, it sends the call once, which opens the
  gateway's approval request and applies nothing, and returns ``True``, so the SDK
  interrupts the run. There is one approval, the gateway's, and the SDK's
  interruption is how the run waits for it. Once the reviewer has decided and the
  run resumes, the tool sends the identical call (same operation key, see
  ``contextos.envelope.operation_key``), which redeems that approval exactly once.
  The ``RunState`` can be checkpointed and resumed by another process.
- ``failure`` is a ``failure_error_function``: a refusal or a duplicate reaches the
  model as text that says it did not happen. A pause for approval or input, an
  unknown outcome or a transport fault stops the run instead.
- ``BudgetedProvider`` reserves the run's budget around every model call the runner
  makes, handoffs included.
"""
import asyncio
from typing import Any, Callable, Dict, Optional

from agents import Model, ModelProvider

from ..errors import ToolPaused
from . import describe, stops_the_run

__all__ = ["BudgetedModel", "BudgetedProvider", "GatewayApprovals", "failure"]


def failure(ctx: Any, error: Exception) -> str:
    """What the model sees when a governed call did not complete."""
    if stops_the_run(error):
        raise error
    return describe(error)


class GatewayApprovals:
    """``needs_approval`` callables that defer to the gateway, for one synchronous ``Run``."""

    def __init__(self, run: Any):
        self.run = run
        self._pending: Dict[str, ToolPaused] = {}

    def pending(self, call_id: str) -> Optional[ToolPaused]:
        """The gateway's pause for an interrupted call (its ``approval_request_id`` is in
        ``report``), or ``None`` after a restart: the request stays open in the
        approval service either way."""
        return self._pending.get(call_id)

    def needs(self, capability_id: str, approval_mode: str, *,
              idempotency_key: Optional[Callable[..., str]] = None,
              evidence_refs: Optional[list] = None) -> Callable[..., Any]:
        """The ``needs_approval`` callable for one governed tool. ``idempotency_key``
        must be the one the tool itself uses, if it names one."""

        def ask(params: dict, call_id: str) -> bool:
            key = idempotency_key(**params) if idempotency_key else None
            check = self.run.check_tool_call(capability_id, params, approval_mode=approval_mode,
                                             idempotency_key=key, evidence_refs=evidence_refs)
            if check.get("status") != "approval_required":
                return False
            try:
                # Opens the gateway's request for this exact call; nothing is applied.
                self.run.call_tool(capability_id, params, approval_mode=approval_mode, idempotency_key=key,
                                   evidence_refs=evidence_refs)
            except ToolPaused as paused:
                if paused.kind != "approval":
                    raise
                self._pending[call_id] = paused
                return True
            # Already approved (a resumed process): the call just ran. It is the same
            # operation the tool will send, so the tool gets its recorded result.
            return False

        async def needs_approval(ctx: Any, params: dict, call_id: str) -> bool:
            return await asyncio.to_thread(ask, params, call_id)

        return needs_approval


class BudgetedModel(Model):
    """Reserves run budget before each model call and settles it after, success or not."""

    def __init__(self, run: Any, inner: Model, tokens: int = 1000):
        self.run, self.inner, self.tokens = run, inner, tokens

    async def get_response(self, *args, **kwargs):
        async with self.run.budgeted_model_call(tokens=self.tokens):
            return await self.inner.get_response(*args, **kwargs)

    async def stream_response(self, *args, **kwargs):
        async with self.run.budgeted_model_call(tokens=self.tokens):
            async for event in self.inner.stream_response(*args, **kwargs):
                yield event

    def get_retry_advice(self, request):
        return self.inner.get_retry_advice(request)

    async def close(self):
        await self.inner.close()


class BudgetedProvider(ModelProvider):
    """Every agent the runner drives (handoffs included) gets a budgeted model. ``run``
    is a ``contextos.aio.AsyncRun``."""

    def __init__(self, run: Any, inner: ModelProvider, tokens: int = 1000):
        self.run, self.inner, self.tokens = run, inner, tokens

    def get_model(self, model_name):
        return BudgetedModel(self.run, self.inner.get_model(model_name), self.tokens)
