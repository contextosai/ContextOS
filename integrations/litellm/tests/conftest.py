"""A fake contextosd for the unit tests, served through httpx's mock transport."""
import json
import pathlib
import sys

import httpx
import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from contextos_litellm import ContextOSMetering, Settings  # noqa: E402


class FakeContextOS:
    """Claims and settlements by reservation; ``fail`` queues statuses to answer with."""

    def __init__(self):
        self.reservations = {"usage:r1": {"tokens": 2000, "cost_cents": 5}, "usage:r2": {"tokens": 800, "cost_cents": 0}}
        self.claimed = set()
        self.settled = {}
        self.requests = []
        self.fail = []  # statuses (or exceptions) to answer the next requests with
        self.revoked = False

    def handle(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        self.requests.append((request.url.path, body, request.headers.get("authorization")))
        if self.fail:
            failure = self.fail.pop(0)
            if isinstance(failure, Exception):
                raise failure
            return httpx.Response(failure, json={"error": {"code": "store_unavailable", "message": "down"}})
        run, action = request.url.path.split("/")[3], request.url.path.rsplit("/", 1)[1]
        reservation = body["reservation_id"]
        if run != "run_1" or reservation not in self.reservations or reservation in self.settled:
            return self._error(404, "reservation_not_found")
        if action == "claim":
            if self.revoked:
                return self._error(403, "revoked")
            if reservation in self.claimed:
                return self._error(409, "reservation_claimed")
            self.claimed.add(reservation)
            return httpx.Response(200, json={"reservation_id": reservation, **self.reservations[reservation]})
        self.settled[reservation] = body
        return httpx.Response(200, json={"reservation_id": reservation, "verified": True,
                                         "charged": {"tokens": body["tokens"]}})

    @staticmethod
    def _error(status, code):
        return httpx.Response(status, json={"error": {"code": code, "message": code}})


@pytest.fixture
def contextos():
    return FakeContextOS()


@pytest.fixture
def settings():
    return Settings(url="http://contextos.test", meter_token="meter-token", settle_backoff=0.001,
                    settle_backoff_max=0.002, settle_attempts=3)


@pytest.fixture
def handler(contextos, settings):
    return ContextOSMetering(settings, transport=httpx.MockTransport(contextos.handle))


def request_data(headers=None, model="gpt-test", **body):
    """What the LiteLLM proxy hands a pre-call hook."""
    headers = {"content-type": "application/json", **(headers or {})}
    return {"model": model, "messages": [{"role": "user", "content": "hi"}], **body,
            "proxy_server_request": {"url": "http://proxy/v1/chat/completions", "method": "POST", "headers": headers},
            "metadata": {"headers": headers, "user_api_key": "hashed"}}


def governed(reservation="usage:r1", run="run_1"):
    return {"contextos-run-id": run, "contextos-usage-reservation": reservation}
