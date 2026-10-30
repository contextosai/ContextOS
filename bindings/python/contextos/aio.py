"""The ``contextosd`` client for asyncio agents (ADK, the OpenAI Agents SDK, LlamaIndex,
Microsoft Agent Framework, Pydantic AI and other async frameworks).

``AsyncClient`` and ``AsyncRun`` have the methods of ``Client`` and ``Run`` as
coroutines. The client stays standard-library only: each request runs the synchronous
client in a worker thread (``asyncio.to_thread``), so the event loop never blocks on
the network while urllib keeps handling TLS, proxies and retries. Outcomes raise the
same exceptions (``ToolPaused``, ``BudgetExhausted``, ...)::

    from contextos.aio import AsyncClient
    from contextos.client import governed_tool

    client = AsyncClient("https://contextos.internal", token=os.environ["CONTEXTOS_TOKEN"])
    run = await client.admit(admission_body)

    @governed_tool(run, "adp_orders.lookup")     # an async tool, since run is an AsyncRun
    async def lookup_order(order_id: str) -> dict: ...

    async with run.budgeted_model_call(tokens=2000):
        response = await model.generate(...)

Concurrent calls share the default thread pool; pass ``executor`` to bound them
separately.
"""
import asyncio
import contextlib
import functools
from concurrent.futures import Executor
from typing import Any, AsyncIterator, List, Optional

from .client import Client, Run

__all__ = ["AsyncClient", "AsyncRun"]


class _Async:
    """Exposes a synchronous object's methods as coroutines run in a worker thread;
    plain attributes read through. A returned ``Run`` comes back as an ``AsyncRun``."""

    def __init__(self, target: Any, executor: Optional[Executor]):
        self._target = target
        self._executor = executor

    async def _call(self, function, *args: Any, **kwargs: Any) -> Any:
        args = tuple(a._target if isinstance(a, AsyncRun) else a for a in args)
        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(self._executor, functools.partial(function, *args, **kwargs))
        if isinstance(result, Run):
            return self if result is self._target else AsyncRun(result, self._executor)
        return result

    def __getattr__(self, name: str) -> Any:
        attribute = getattr(self._target, name)
        if not callable(attribute):
            return attribute

        @functools.wraps(attribute)
        async def method(*args: Any, **kwargs: Any) -> Any:
            return await self._call(attribute, *args, **kwargs)

        return method


class AsyncClient(_Async):
    """``Client`` for asyncio; see the module docstring."""

    def __init__(self, base_url: str, token: str, timeout: float = 30.0, max_retries: int = 3,
                 executor: Optional[Executor] = None, *, allow_http: bool = False):
        super().__init__(Client(base_url, token, timeout, max_retries, allow_http=allow_http), executor)

    def __repr__(self) -> str:
        return f"Async{self._target!r}"

    async def admit(self, body: dict, principal_chain: Optional[List[dict]] = None) -> "AsyncRun":
        return await self._call(self._target.admit, body, principal_chain)

    async def attach(self, run_id: str, trace_id: str, principal_chain: List[dict]) -> "AsyncRun":
        return await self._call(self._target.attach, run_id, trace_id, principal_chain)

    async def audit_entries(self, start: int = 1, page: int = 500) -> AsyncIterator[dict]:
        """Yields the tenant's signed audit entries in order, a page per request."""
        cursor: Optional[int] = start
        while cursor is not None:
            batch = await self._call(self._target.request, "GET", "/v1/audit/entries",
                                     query={"from": cursor, "limit": page})
            for entry in batch["entries"]:
                yield entry
            cursor = batch.get("next")


class AsyncRun(_Async):
    """``Run`` for asyncio; see the module docstring."""

    def __init__(self, run: Run, executor: Optional[Executor] = None):
        super().__init__(run, executor)

    def __repr__(self) -> str:
        return f"Async{self._target!r}"

    async def call_tool(self, capability_id: str, args: dict, **options: Any) -> dict:
        return await self._call(self._target.call_tool, capability_id, args, **options)

    def metering_headers(self, reservation_id: str) -> dict:
        return self._target.metering_headers(reservation_id)

    @contextlib.asynccontextmanager
    async def budgeted_model_call(self, *, tokens: int, cost_cents: int = 0,
                                  metered: bool = False) -> AsyncIterator[str]:
        """As ``Run.budgeted_model_call``: reserves before one model call and settles
        after it; ``metered=True`` leaves settlement to a metering LLM gateway."""
        reservation = await self._call(self._target.reserve_usage, "model_call", tokens=tokens, cost_cents=cost_cents)
        settle = self._target._settle_open if metered else self._target.settle_usage
        try:
            yield reservation
        except BaseException:
            await self._call(settle, reservation)
            raise
        if not metered:
            await self._call(settle, reservation)
