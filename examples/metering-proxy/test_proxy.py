"""End-to-end test of the metering proxy against a live contextosd and a fake model API.
Run with ./examples/metering-proxy/run.sh."""
import json
import os
import pathlib
import socket
import sys
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading

sys.path.insert(0, str(pathlib.Path(__file__).parent))
import proxy  # noqa: E402

from contextos.client import Client  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parents[2]
METER_KEY = "dev-meter-0123456789abcdef0123456789abcd"
SEEN = []  # request bodies the fake provider received


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class FakeModelAPI(BaseHTTPRequestHandler):
    """Chat Completions, Anthropic Messages, an error and a response without usage."""

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        SEEN.append({"path": self.path, "body": body, "headers": dict(self.headers)})
        if self.path == "/v1/chat/completions" and body.get("stream"):
            events = [{"choices": [{"delta": {"content": "ok"}}]}]
            if body.get("stream_options", {}).get("include_usage"):
                events.append({"choices": [], "usage": {"prompt_tokens": 10, "completion_tokens": 5}})
            return self._events(events)
        if self.path == "/v1/chat/completions":
            return self._json(200, {"choices": [{"message": {"content": "ok"}}],
                                    "usage": {"prompt_tokens": 120, "completion_tokens": 30, "total_tokens": 150}})
        if self.path == "/v1/messages":
            return self._events([
                {"type": "message_start", "message": {"usage": {"input_tokens": 200, "cache_read_input_tokens": 50,
                                                                 "output_tokens": 1}}},
                {"type": "content_block_delta", "delta": {"text": "ok"}},
                {"type": "message_delta", "usage": {"output_tokens": 40}},
            ])
        if self.path == "/v1/overloaded":
            return self._json(529, {"error": {"type": "overloaded_error"}})
        return self._json(200, {"output": "no usage reported"})

    def _json(self, status, value):
        payload = json.dumps(value).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _events(self, events):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.end_headers()
        for event in events:
            self.wfile.write(f"data: {json.dumps(event)}\n\n".encode())
        self.wfile.write(b"data: [DONE]\n\n")

    def log_message(self, *args):
        pass


def post(url, body, headers):
    request = urllib.request.Request(url, json.dumps(body).encode(), {"Content-Type": "application/json", **headers})
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()


def main():
    upstream_port, proxy_port = free_port(), free_port()
    upstream = ThreadingHTTPServer(("127.0.0.1", upstream_port), FakeModelAPI)
    threading.Thread(target=upstream.serve_forever, daemon=True).start()
    meter = proxy.Proxy(f"http://127.0.0.1:{upstream_port}", os.environ["CONTEXTOS_URL"], METER_KEY,
                        price=(300, 1500), upstream_key="sk-provider", upstream_auth="x-api-key")
    proxy.serve(meter, "127.0.0.1", proxy_port)
    base = f"http://127.0.0.1:{proxy_port}"

    client = Client(os.environ["CONTEXTOS_URL"], token=os.environ["CONTEXTOS_TOKEN"])
    admission = json.loads((ROOT / "examples/support-refund/requests/run.json").read_text())
    run_id = f"run_meter_{int(time.time() * 1000)}"
    admission["run_context"]["run_id"] = admission["contract"]["run_id"] = run_id
    admission["contract"]["contract_id"] = f"contract_{run_id}"
    run = client.admit(admission)

    def used():
        return run.evidence()["budget_ledger"]["used"]

    def call(path, body, tokens=4000):
        with run.budgeted_model_call(tokens=tokens, metered=True) as reservation:
            status, payload = post(base + path, body, run.metering_headers(reservation))
        return reservation, status, payload

    # A call is charged what the provider reported, not the 4,000 tokens reserved.
    reservation, status, payload = call("/v1/chat/completions", {"model": "m", "messages": []})
    assert status == 200 and json.loads(payload)["usage"]["total_tokens"] == 150, payload
    assert used()["tokens"] == 150, used()
    # The proxy adds the provider key and strips the ContextOS headers.
    sent = {k.lower(): v for k, v in SEEN[-1]["headers"].items()}
    assert sent["x-api-key"] == "sk-provider" and "contextos-usage-reservation" not in sent, sent
    # 120 input at 300 and 30 output at 1,500 cents per million tokens: rounded up to a cent.
    assert used()["cost_units"] == 100, used()

    # A reservation covers one call: reusing it is refused before the provider.
    status, payload = post(base + "/v1/chat/completions", {"model": "m", "messages": []},
                           run.metering_headers(reservation))
    assert status == 409 and b"contextos_reservation_reused" in payload, payload
    # A call without a reservation is not forwarded.
    status, _ = post(base + "/v1/chat/completions", {"model": "m", "messages": []}, {})
    assert status == 403

    # Streamed Chat Completions: the proxy asks for usage, and the stream passes through.
    _, status, payload = call("/v1/chat/completions", {"model": "m", "messages": [], "stream": True})
    assert status == 200 and b"[DONE]" in payload, payload
    assert SEEN[-1]["body"]["stream_options"] == {"include_usage": True}, SEEN[-1]
    assert used()["tokens"] == 150 + 15, used()

    # Streamed Anthropic Messages: input (with prompt-cache reads) and the final output count.
    _, status, _ = call("/v1/messages", {"model": "m", "messages": [], "stream": True})
    assert status == 200 and "stream_options" not in SEEN[-1]["body"]
    assert used()["tokens"] == 165 + 250 + 40, used()

    # A provider error with no usage used nothing.
    _, status, _ = call("/v1/overloaded", {"model": "m"})
    assert status == 529 and used()["tokens"] == 455, used()

    # No usage in a successful response: the proxy leaves the reservation, which stays
    # reserved (unknown usage is never free) until the executor settles it in full.
    reservation, status, _ = call("/v1/no-usage", {"model": "m"})
    assert status == 200 and run.evidence()["budget_ledger"]["reserved"]["tokens"] >= 4000
    run.settle_usage(reservation)
    assert used()["tokens"] == 455 + 4000, used()

    # A call that fails before reaching the proxy is settled by the executor, in full.
    try:
        with run.budgeted_model_call(tokens=1000, metered=True):
            raise TimeoutError("model unreachable")
    except TimeoutError:
        pass
    assert used()["tokens"] == 4455 + 1000, used()
    assert run.complete()["status"] == "completed"
    print(f"ok: metering proxy ({used()['tokens']} tokens charged, {len(SEEN)} provider calls)")


if __name__ == "__main__":
    main()
