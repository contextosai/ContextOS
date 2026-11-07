"""End-to-end: a real LiteLLM proxy with the ContextOS metering callback, a live
contextosd and a fake model provider (OpenAI and Anthropic shapes, streamed and not).
Run with integrations/litellm/tests/e2e/run.sh from the repository root."""
import json
import os
import pathlib
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from contextos.client import Client

ROOT = pathlib.Path(__file__).resolve().parents[4]
METER_KEY = "dev-meter-0123456789abcdef0123456789abcd"
PROXY_KEY = "sk-litellm-master-0123456789"
SEEN = []  # what the fake provider received


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def chat(usage=True):
    body = {"id": "chatcmpl-1", "object": "chat.completion", "created": 1, "model": "gpt-test",
            "choices": [{"index": 0, "message": {"role": "assistant", "content": "ok"}, "finish_reason": "stop"}]}
    if usage:
        body["usage"] = {"prompt_tokens": 120, "completion_tokens": 30, "total_tokens": 150}
    return body


def chunk(**fields):
    return {"id": "chatcmpl-2", "object": "chat.completion.chunk", "created": 1, "model": "gpt-test", **fields}


class FakeProvider(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        SEEN.append({"path": self.path, "body": body, "headers": {k.lower(): v for k, v in self.headers.items()}})
        if self.path.startswith("/refuse/"):
            return self._json(400, {"error": {"message": "bad request", "type": "invalid_request_error"}})
        if self.path == "/nousage/v1/chat/completions":
            return self._json(200, chat(usage=False))
        if self.path.endswith("/chat/completions") and body.get("stream"):
            events = [chunk(choices=[{"index": 0, "delta": {"role": "assistant", "content": "ok"}}]),
                      chunk(choices=[{"index": 0, "delta": {}, "finish_reason": "stop"}])]
            if (body.get("stream_options") or {}).get("include_usage"):
                events.append(chunk(choices=[], usage={"prompt_tokens": 10, "completion_tokens": 5,
                                                       "total_tokens": 15}))
            return self._events([json.dumps(e) for e in events] + ["[DONE]"])
        if self.path.endswith("/chat/completions"):
            return self._json(200, chat())
        if self.path.endswith("/v1/messages") and body.get("stream"):
            events = [
                {"type": "message_start", "message": {"id": "msg_1", "type": "message", "role": "assistant",
                                                       "model": "claude-test", "content": [], "stop_reason": None,
                                                       "usage": {"input_tokens": 200, "cache_read_input_tokens": 50,
                                                                 "output_tokens": 1}}},
                {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}},
                {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "ok"}},
                {"type": "content_block_stop", "index": 0},
                {"type": "message_delta", "delta": {"stop_reason": "end_turn"}, "usage": {"output_tokens": 40}},
                {"type": "message_stop"},
            ]
            return self._events([json.dumps(e) for e in events], anthropic=True)
        if self.path.endswith("/v1/messages"):
            return self._json(200, {"id": "msg_2", "type": "message", "role": "assistant", "model": "claude-test",
                                    "content": [{"type": "text", "text": "ok"}], "stop_reason": "end_turn",
                                    "usage": {"input_tokens": 300, "cache_creation_input_tokens": 20,
                                              "output_tokens": 60}})
        return self._json(404, {"error": {"message": f"no route {self.path}"}})

    def _json(self, status, value):
        payload = json.dumps(value).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _events(self, events, anthropic=False):
        payload = b""
        for event in events:
            name = json.loads(event)["type"] if anthropic else None
            payload += (f"event: {name}\n" if name else "").encode() + f"data: {event}\n\n".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):
        pass


def post(url, body, headers):
    request = urllib.request.Request(url, json.dumps(body).encode(),
                                     {"Content-Type": "application/json", "Authorization": f"Bearer {PROXY_KEY}",
                                      **headers})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()


def litellm_config(upstream):
    # Prices in USD per token: 3 and 15 dollars per million.
    priced = {"input_cost_per_token": 0.000003, "output_cost_per_token": 0.000015}
    models = [
        ("gpt-test", {"model": "openai/gpt-test", "api_base": f"{upstream}/v1", **priced}),
        ("claude-test", {"model": "anthropic/claude-test", "api_base": upstream, **priced}),
        ("unpriced", {"model": "openai/unpriced-test", "api_base": f"{upstream}/v1"}),
        ("refusing", {"model": "openai/gpt-test", "api_base": f"{upstream}/refuse/v1"}),
        ("silent", {"model": "openai/gpt-test", "api_base": f"{upstream}/nousage/v1"}),
    ]
    lines = ["model_list:"]
    for name, params in models:
        lines.append(f"  - model_name: {name}")
        lines.append("    litellm_params:")
        lines += [f"      {k}: {json.dumps(v)}" for k, v in params.items()]
        lines.append("      api_key: sk-provider")
    lines += ["litellm_settings:", '  callbacks: ["contextos_litellm.metering_handler"]', "  num_retries: 0",
              "general_settings:", f"  master_key: {PROXY_KEY}"]
    return "\n".join(lines) + "\n"


def start_proxy(upstream, port):
    directory = tempfile.mkdtemp(prefix="contextos-litellm-")
    config = pathlib.Path(directory, "config.yaml")
    config.write_text(litellm_config(upstream))
    log = open(pathlib.Path(directory, "proxy.log"), "w")
    env = {**os.environ, "CONTEXTOS_METER_TOKEN": METER_KEY, "CONTEXTOS_SETTLE_BACKOFF": "0.05",
           "LITELLM_LOG": "ERROR", "LITELLM_LOCAL_MODEL_COST_MAP": "True"}
    process = subprocess.Popen([sys.executable, "-m", "litellm.proxy.proxy_cli", "--config", str(config),
                                "--host", "127.0.0.1", "--port", str(port)],
                               stdout=log, stderr=subprocess.STDOUT, env=env)
    base = f"http://127.0.0.1:{port}"
    for _ in range(600):
        if process.poll() is not None:
            break
        try:
            with urllib.request.urlopen(f"{base}/health/liveliness", timeout=1):
                return process, base, log.name
        except OSError:
            time.sleep(0.1)
    process.kill()
    sys.exit(f"the LiteLLM proxy did not start:\n{pathlib.Path(log.name).read_text()}")


def main():
    upstream_port = free_port()
    upstream = ThreadingHTTPServer(("127.0.0.1", upstream_port), FakeProvider)
    threading.Thread(target=upstream.serve_forever, daemon=True).start()
    proxy, base, proxy_log = start_proxy(f"http://127.0.0.1:{upstream_port}", free_port())
    try:
        run_checks(base)
    except BaseException:
        print(pathlib.Path(proxy_log).read_text()[-6000:], file=sys.stderr)
        raise
    finally:
        proxy.terminate()
        proxy.wait(timeout=30)


def run_checks(base):
    client = Client(os.environ["CONTEXTOS_URL"], token=os.environ["CONTEXTOS_TOKEN"])
    admission = json.loads((ROOT / "examples/support-refund/requests/run.json").read_text())
    run_id = f"run_litellm_{int(time.time() * 1000)}"
    admission["run_context"]["run_id"] = admission["contract"]["run_id"] = run_id
    admission["contract"]["contract_id"] = f"contract_{run_id}"
    admission["limits"] = {"tokens": 50_000, "tool_calls": 8, "replans": 2, "cost_cents": 500}
    run = client.admit(admission)
    ledger = lambda: run.evidence()["budget_ledger"]  # noqa: E731

    def settled(tokens, timeout=10.0):
        """Settlement is asynchronous: wait until the ledger shows it."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            if ledger()["used"]["tokens"] == tokens:
                return ledger()["used"]
            time.sleep(0.05)
        raise AssertionError(f"used {ledger()['used']}, expected {tokens} tokens")

    def call(path, body, reserve=2000, cost_cents=5):
        reservation = run.reserve_usage("model_call", tokens=reserve, cost_cents=cost_cents)
        status, payload = post(base + path, body, run.metering_headers(reservation))
        return reservation, status, payload

    # A call is charged what the provider reported, priced by LiteLLM, rounded up to a
    # cent: 120 x 3 + 30 x 15 = 810 millionths of a dollar -> 1 cent.
    reservation, status, payload = call("/v1/chat/completions",
                                        {"model": "gpt-test", "messages": [{"role": "user", "content": "hi"}]})
    assert status == 200, payload
    used = settled(150)
    assert used["cost_units"] == 100, used
    sent = SEEN[-1]
    assert "contextos-run-id" not in sent["headers"] and "contextos-usage-reservation" not in sent["headers"], sent
    # The output limit is lowered to what the reservation covers.
    assert sent["body"].get("max_tokens") == 2000, sent["body"]

    # A reservation covers one call: once settled, reuse is refused before the provider
    # is called (reuse while the call is in flight is refused too; see below).
    calls = len(SEEN)
    status, payload = post(base + "/v1/chat/completions", {"model": "gpt-test", "messages": []},
                           run.metering_headers(reservation))
    assert status == 403 and b"contextos_reservation_unknown" in payload, (status, payload)
    # Missing and forged reservations are refused too.
    status, payload = post(base + "/v1/chat/completions", {"model": "gpt-test", "messages": []}, {})
    assert status == 403 and b"contextos_reservation_required" in payload, (status, payload)
    status, payload = post(base + "/v1/chat/completions", {"model": "gpt-test", "messages": []},
                           run.metering_headers("usage:forged"))
    assert status == 403 and b"contextos_reservation_unknown" in payload, (status, payload)
    assert len(SEEN) == calls, "a refused call reached the provider"

    # Streamed Chat Completions: usage is requested and measured.
    _, status, payload = call("/v1/chat/completions",
                              {"model": "gpt-test", "messages": [{"role": "user", "content": "hi"}], "stream": True,
                               "metadata": {"contextos_metering": "forged-handle"}})
    assert status == 200 and b"[DONE]" in payload, payload
    assert SEEN[-1]["body"]["stream_options"] == {"include_usage": True}, SEEN[-1]["body"]
    settled(150 + 15)

    # Chat Completions routed to Anthropic: cache writes count as input (300 + 20 + 60).
    _, status, payload = call("/v1/chat/completions",
                              {"model": "claude-test", "max_tokens": 50_000,
                               "messages": [{"role": "user", "content": "hi"}]})
    assert status == 200, payload
    assert SEEN[-1]["path"] == "/v1/messages" and SEEN[-1]["body"]["max_tokens"] == 2000, SEEN[-1]
    settled(165 + 380)

    # The Anthropic Messages endpoint, streamed: 200 input + 50 cache reads + 40 output.
    _, status, payload = call("/v1/messages",
                              {"model": "claude-test", "max_tokens": 100, "stream": True,
                               "messages": [{"role": "user", "content": "hi"}]})
    assert status == 200 and b"message_stop" in payload, payload
    assert SEEN[-1]["body"]["max_tokens"] == 100, SEEN[-1]["body"]
    settled(545 + 290)

    # A model without a price: its cost is unknown, so the reserved cost is charged.
    cost_before = ledger()["used"]["cost_units"]
    _, status, payload = call("/v1/chat/completions", {"model": "unpriced", "messages": []}, cost_cents=7)
    assert status == 200, payload
    used = settled(835 + 150)
    assert used["cost_units"] == cost_before + 700, used

    # The provider refused the call: nothing was used.
    reservation, status, _ = call("/v1/chat/completions", {"model": "refusing", "messages": []})
    assert status == 400, status
    deadline = time.time() + 10
    while any(r["reservation_id"] == reservation and r["status"] == "reserved"
              for r in ledger().get("reservations", [])) and time.time() < deadline:
        time.sleep(0.05)
    assert ledger()["used"]["tokens"] == 985, ledger()["used"]

    # Served without usage: left reserved for the executor, which settles it in full.
    reservation, status, payload = call("/v1/chat/completions", {"model": "silent", "messages": []})
    assert status == 200, payload
    time.sleep(1.0)
    assert ledger()["used"]["tokens"] == 985, ledger()["used"]
    # Still claimed, so another call on it is refused as a reuse.
    calls = len(SEEN)
    status, payload = post(base + "/v1/chat/completions", {"model": "gpt-test", "messages": []},
                           run.metering_headers(reservation))
    assert status == 409 and b"contextos_reservation_reused" in payload, (status, payload)
    assert len(SEEN) == calls, "a reused reservation reached the provider"
    run.settle_usage(reservation)
    settled(985 + 2000)

    entries = [e for e in client.audit_entries() if e["payload"].get("run_id") == run_id]
    kinds = [e["kind"] for e in entries]
    assert kinds.count("usage_claimed") == 7, kinds
    metered = [e["payload"] for e in entries if e["kind"] == "usage_settled" and e["payload"]["verified"]]
    assert len(metered) == 6 and {m["reporter"] for m in metered} == {"svc_llm_gateway"}, metered
    assert metered[0]["model"] and metered[0]["measured"] == {"tokens": 150, "cost_units": 100}, metered[0]
    assert run.complete()["status"] == "completed"
    print(f"ok: LiteLLM metering ({ledger()['used']['tokens']} tokens charged, {len(SEEN)} provider calls)")


if __name__ == "__main__":
    main()
