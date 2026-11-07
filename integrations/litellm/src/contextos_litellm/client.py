"""contextosd's metering endpoints, and the queue that delivers settlements."""
from __future__ import annotations

import asyncio
import logging
import random
import urllib.parse
from collections import Counter
from dataclasses import dataclass
from typing import Any, Dict, Optional

import httpx

from .config import Settings

log = logging.getLogger("contextos_litellm")

# Statuses a settlement is retried on: contextosd or the network may recover.
_RETRY = {429, 500, 502, 503, 504}


class ContextOSRefused(Exception):
    """contextosd refused the request; ``code`` is its error code."""

    def __init__(self, status: int, code: str, message: str):
        super().__init__(f"{status} {code}: {message}")
        self.status, self.code, self.message = status, code, message


class ContextOSUnavailable(Exception):
    """contextosd could not be reached or failed."""


@dataclass(frozen=True)
class Claim:
    """A reservation this proxy claimed for one model call."""

    run_id: str
    reservation_id: str
    tokens: int
    cost_cents: int
    model: Optional[str]


@dataclass(frozen=True)
class Settlement:
    run_id: str
    reservation_id: str
    tokens: int
    cost_cents: int
    model: Optional[str]


def _refusal(response: httpx.Response) -> ContextOSRefused:
    try:
        error = response.json().get("error") or {}
    except ValueError:
        error = {}
    return ContextOSRefused(response.status_code, str(error.get("code") or "http_error"),
                            str(error.get("message") or response.reason_phrase))


class ContextOSClient:
    """One pooled HTTP client per event loop, authenticated with the meter token."""

    def __init__(self, settings: Settings, transport: Optional[httpx.AsyncBaseTransport] = None):
        self._settings = settings
        self._transport = transport
        self._client: Optional[httpx.AsyncClient] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    def _http(self) -> httpx.AsyncClient:
        loop = asyncio.get_running_loop()
        if self._client is None or self._loop is not loop:
            self._client = httpx.AsyncClient(
                base_url=self._settings.base_url,
                timeout=self._settings.timeout,
                headers={"Authorization": f"Bearer {self._settings.meter_token}",
                         "User-Agent": "contextos-litellm"},
                transport=self._transport,
                follow_redirects=False,
            )
            self._loop = loop
        return self._client

    @staticmethod
    def _path(run_id: str, action: str) -> str:
        return f"/v1/runs/{urllib.parse.quote(run_id, safe='')}/usage/{action}"

    async def _post(self, path: str, body: Dict[str, Any]) -> httpx.Response:
        try:
            return await self._http().post(path, json=body)
        except httpx.HTTPError as error:
            raise ContextOSUnavailable(f"{type(error).__name__}: {error}") from error

    async def claim(self, run_id: str, reservation_id: str, model: Optional[str]) -> Claim:
        """Claims the reservation for one call; raises ``ContextOSRefused`` (forged,
        reused, revoked) or ``ContextOSUnavailable``."""
        body: Dict[str, Any] = {"reservation_id": reservation_id}
        if model:
            body["model"] = model
        response = await self._post(self._path(run_id, "claim"), body)
        if response.status_code >= 500:
            raise ContextOSUnavailable(f"claim failed with {response.status_code}")
        if response.status_code != 200:
            raise _refusal(response)
        try:
            claimed = response.json()
            return Claim(run_id, reservation_id, int(claimed["tokens"]), int(claimed["cost_cents"]), model)
        except (ValueError, KeyError, TypeError) as error:
            raise ContextOSUnavailable(f"unreadable claim response: {error}") from error

    async def settle(self, settlement: Settlement) -> httpx.Response:
        body: Dict[str, Any] = {"reservation_id": settlement.reservation_id, "tokens": settlement.tokens,
                                "cost_cents": settlement.cost_cents}
        if settlement.model:
            body["model"] = settlement.model
        return await self._post(self._path(settlement.run_id, "settle"), body)

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None


class Settler:
    """Delivers settlements off the request path, retrying what may succeed later.

    A settlement that cannot be delivered (queue full, retries exhausted, refused)
    leaves its reservation reserved, so the run is charged the whole reservation when
    its executor settles: unknown usage is never free.
    """

    def __init__(self, client: ContextOSClient, settings: Settings, stats: Counter):
        self._client = client
        self._settings = settings
        self._stats = stats
        self._queue: Optional[asyncio.Queue] = None
        self._workers: list = []
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    def _ensure_workers(self) -> asyncio.Queue:
        loop = asyncio.get_running_loop()
        if self._queue is None or self._loop is not loop:
            self._queue = asyncio.Queue(maxsize=self._settings.queue_size)
            self._loop = loop
            self._workers = [loop.create_task(self._work(), name=f"contextos-settler-{i}")
                             for i in range(self._settings.workers)]
        return self._queue

    def submit(self, settlement: Settlement) -> bool:
        queue = self._ensure_workers()
        try:
            queue.put_nowait(settlement)
        except asyncio.QueueFull:
            self._stats["settle_dropped"] += 1
            log.error("contextos_settle_dropped run_id=%s reservation_id=%s reason=queue_full; the reservation "
                      "stays reserved", settlement.run_id, settlement.reservation_id)
            return False
        return True

    @property
    def pending(self) -> int:
        """Settlements queued and not yet picked up by a worker."""
        return 0 if self._queue is None else self._queue.qsize()

    async def drain(self, timeout: float = 30.0) -> bool:
        """Waits until queued settlements are delivered or given up; True if drained."""
        if self._queue is None:
            return True
        try:
            await asyncio.wait_for(self._queue.join(), timeout)
            return True
        except asyncio.TimeoutError:
            return False

    async def _work(self) -> None:
        assert self._queue is not None
        queue = self._queue
        while True:
            settlement = await queue.get()
            try:
                await self.deliver(settlement)
            except Exception:  # never let one settlement stop the worker
                self._stats["settle_failed"] += 1
                log.exception("contextos_settle_failed run_id=%s reservation_id=%s", settlement.run_id,
                              settlement.reservation_id)
            finally:
                queue.task_done()

    async def deliver(self, settlement: Settlement) -> bool:
        """Sends one settlement, retrying transient failures; True once settled."""
        attempts = self._settings.settle_attempts
        for attempt in range(attempts):
            if attempt:
                delay = min(self._settings.settle_backoff_max, self._settings.settle_backoff * 2 ** (attempt - 1))
                await asyncio.sleep(delay * (0.5 + random.random() / 2))
            try:
                response = await self._client.settle(settlement)
            except ContextOSUnavailable as error:
                log.warning("contextos_settle_retry run_id=%s reservation_id=%s attempt=%d error=%s",
                            settlement.run_id, settlement.reservation_id, attempt + 1, error)
                continue
            if response.status_code == 200:
                self._stats["settled"] += 1
                charged = _charged(response)
                log.info("contextos_settled run_id=%s reservation_id=%s tokens=%d cost_cents=%d charged=%s",
                         settlement.run_id, settlement.reservation_id, settlement.tokens, settlement.cost_cents,
                         charged)
                return True
            if response.status_code == 404 and attempt:
                # An earlier attempt reached contextosd but its reply was lost.
                self._stats["settled"] += 1
                return True
            if response.status_code in _RETRY:
                log.warning("contextos_settle_retry run_id=%s reservation_id=%s attempt=%d status=%d",
                            settlement.run_id, settlement.reservation_id, attempt + 1, response.status_code)
                continue
            refusal = _refusal(response)
            self._stats["settle_refused"] += 1
            log.error("contextos_settle_refused run_id=%s reservation_id=%s status=%d code=%s message=%s",
                      settlement.run_id, settlement.reservation_id, refusal.status, refusal.code, refusal.message)
            return False
        self._stats["settle_failed"] += 1
        log.error("contextos_settle_failed run_id=%s reservation_id=%s attempts=%d; the reservation stays reserved",
                  settlement.run_id, settlement.reservation_id, attempts)
        return False


def _charged(response: httpx.Response) -> Any:
    try:
        return response.json().get("charged")
    except ValueError:
        return None
