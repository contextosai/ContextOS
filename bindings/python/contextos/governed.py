"""``governed_tool``: turns a tool's signature into a call governed by a ContextOS run."""

from __future__ import annotations

import functools
import inspect
from typing import TYPE_CHECKING, Any, Callable, List, Optional

if TYPE_CHECKING:
    from .client import Run


def governed_tool(run: "Run", capability_id: str, *, approval_mode: str = "read_only",
                  idempotency_key: Optional[Callable[..., str]] = None,
                  evidence_refs: Optional[List[str]] = None,
                  tool_call_id: Optional[Callable[..., str]] = None) -> Callable[[Callable[..., Any]], Callable[..., dict]]:
    """Turns a tool's signature into a governed call: arguments are bound by name and
    sent through the gateway; the decorated body never runs locally.

    ``idempotency_key`` derives the operation key from the call's arguments, so a
    retried agent step maps to the same operation and cannot apply twice.
    ``tool_call_id`` derives the call's id the same way, so a DecisionRecord can cite it.
    With an ``AsyncRun`` (``contextos.aio``) the governed function is a coroutine.
    """

    def wrap(function: Callable[..., Any]) -> Callable[..., Any]:
        signature = inspect.signature(function)

        def dispatch(args: Any, kwargs: Any) -> Any:
            bound = signature.bind(*args, **kwargs)
            bound.apply_defaults()
            arguments = dict(bound.arguments)
            key = idempotency_key(**arguments) if idempotency_key else None
            call_id = tool_call_id(**arguments) if tool_call_id else None
            return run.call_tool(capability_id, arguments, approval_mode=approval_mode, idempotency_key=key,
                                 evidence_refs=evidence_refs, tool_call_id=call_id)

        if inspect.iscoroutinefunction(run.call_tool):
            @functools.wraps(function)
            async def call_async(*args: Any, **kwargs: Any) -> dict:
                return await dispatch(args, kwargs)

            return call_async

        @functools.wraps(function)
        def call(*args: Any, **kwargs: Any) -> dict:
            return dispatch(args, kwargs)

        return call

    return wrap
