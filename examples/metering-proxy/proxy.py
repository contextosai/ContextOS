#!/usr/bin/env python3
"""A metering proxy for model APIs: settles each model call's ContextOS budget
reservation with the usage the provider reported, instead of the whole reservation.

    agent ──(model request + ContextOS-Run-Id, ContextOS-Usage-Reservation)──▶ proxy
    proxy ──(request, without the ContextOS headers)──▶ model API
    proxy ◀── response (usage) ── model API
    proxy ──(POST /v1/runs/{run}/usage/settle, measured tokens and cost)──▶ contextosd

The executor reserves with ``run.budgeted_model_call(tokens=…, metered=True)`` and sends
``run.metering_headers(reservation)`` with the request; this proxy holds a token with
only the ``meter`` scope, so contextosd treats what it reports as measured usage.

It understands the usage blocks of OpenAI Chat Completions and Responses and of
Anthropic Messages, streamed (server-sent events) or not; a streamed Chat Completions
request is asked to include usage. Standard library only. A reference, not a hardened
gateway: production metering belongs in the LLM gateway you already operate, following
the same contract.

Usage:
    CONTEXTOS_METER_TOKEN=… python3 proxy.py --upstream https://api.openai.com \\
        --contextos https://contextos.internal [--listen 127.0.0.1:8090] \\
        [--price 250:1000] [--upstream-key-env OPENAI_API_KEY [--upstream-auth x-api-key]]
"""
import argparse
import json
import math
import os
import sys
import threading
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

RUN_HEADER = "ContextOS-Run-Id"
RESERVATION_HEADER = "ContextOS-Usage-Reservation"
# Not forwarded: hop-by-hop headers, the ContextOS headers, and encodings this proxy
# could not read usage from.
DROPPED = {"host", "content-length", "connection", "keep-alive", "transfer-encoding", "te", "upgrade",
           "proxy-connection", "accept-encoding", RUN_HEADER.lower(), RESERVATION_HEADER.lower()}


class Usage:
    """Token counts seen in a response; streamed events report them incrementally."""

    def __init__(self):
        self.input = self.output = None

    def observe(self, value):
        if not isinstance(value, dict):
            return
        for usage in (value.get("usage"), (value.get("response") or {}).get("usage"),
                      (value.get("message") or {}).get("usage")):
            if not isinstance(usage, dict):
                continue
            seen_input = _first_int(usage, "input_tokens", "prompt_tokens")
            if seen_input is not None:
                # Anthropic counts prompt-cache writes and reads apart from input_tokens.
                seen_input += sum(_first_int(usage, k) or 0
                                  for k in ("cache_creation_input_tokens", "cache_read_input_tokens"))
                self.input = max(self.input or 0, seen_input)
            seen_output = _first_int(usage, "output_tokens", "completion_tokens")
            if seen_output is not None:
                self.output = max(self.output or 0, seen_output)

    @property
    def known(self):
        return self.input is not None or self.output is not None


def _first_int(usage, *keys):
    for key in keys:
        if isinstance(usage.get(key), int) and not isinstance(usage.get(key), bool):
            return usage[key]
    return None


class Proxy:
    def __init__(self, upstream, contextos, meter_token, price=None, upstream_key=None, upstream_auth="bearer",
                 require_reservation=True):
        self.upstream = upstream.rstrip("/")
        self.contextos = contextos.rstrip("/")
        self.meter_token = meter_token
        self.price = price  # (input, output) cents per million tokens
        # The provider key the proxy adds, so agents need not hold it.
        self.upstream_key = upstream_key
        self.upstream_auth = upstream_auth
        self.require_reservation = require_reservation
        self._seen = set()
        self._lock = threading.Lock()

    def claim(self, reservation):
        """One reservation covers one model call: a reused one would go unmetered."""
        with self._lock:
            if reservation in self._seen:
                return False
            self._seen.add(reservation)
            return True

    def settle(self, run_id, reservation, usage, status):
        if not usage.known:
            if status >= 400:
                # The provider refused the call and reported no usage: nothing was used.
                usage.input = usage.output = 0
            else:
                # Unknown usage is never free: leave the reservation for the executor,
                # whose settlement charges all of it.
                print(f"[meter] {reservation}: no usage in the response; left unsettled", file=sys.stderr)
                return None
        tokens = (usage.input or 0) + (usage.output or 0)
        body = {"reservation_id": reservation, "tokens": tokens}
        if self.price:
            body["cost_cents"] = math.ceil(((usage.input or 0) * self.price[0] + (usage.output or 0) * self.price[1])
                                           / 1_000_000)
        request = urllib.request.Request(
            f"{self.contextos}/v1/runs/{urllib.parse.quote(run_id, safe='')}/usage/settle",
            data=json.dumps(body).encode(), method="POST",
            headers={"Authorization": f"Bearer {self.meter_token}", "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                settled = json.load(response)
        except urllib.error.HTTPError as error:
            print(f"[meter] {reservation}: settlement refused ({error.code} {error.read()[:200]!r})", file=sys.stderr)
            return None
        print(f"[meter] {reservation}: charged {settled['charged']} (verified={settled['verified']})", file=sys.stderr)
        return settled


def handler(proxy):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.0"  # the response ends when the connection closes

        def do_POST(self):
            run_id, reservation = self.headers.get(RUN_HEADER), self.headers.get(RESERVATION_HEADER)
            if not (run_id and reservation):
                if proxy.require_reservation:
                    return self._refuse(403, "contextos_reservation_required",
                                        f"Model calls need {RUN_HEADER} and {RESERVATION_HEADER}.")
            elif not proxy.claim(reservation):
                return self._refuse(409, "contextos_reservation_reused", "This reservation already covered a call.")
            body = _with_stream_usage(self.path, self.rfile.read(int(self.headers.get("Content-Length") or 0)))
            headers = {k: v for k, v in self.headers.items() if k.lower() not in DROPPED}
            if proxy.upstream_key:
                headers = {k: v for k, v in headers.items() if k.lower() not in ("authorization", "x-api-key")}
                if proxy.upstream_auth == "x-api-key":
                    headers["x-api-key"] = proxy.upstream_key
                else:
                    headers["Authorization"] = f"Bearer {proxy.upstream_key}"
            request = urllib.request.Request(proxy.upstream + self.path, data=body, method="POST", headers=headers)
            usage = Usage()
            try:
                response = urllib.request.urlopen(request, timeout=600)
            except urllib.error.HTTPError as error:
                response = error  # the provider's error, relayed as is
            except OSError as error:
                self._refuse(502, "upstream_unavailable", str(error))
                response = None
            status = response.getcode() if response is not None else 502
            if response is not None:
                self._relay(response, status, usage)
            if run_id and reservation:
                proxy.settle(run_id, reservation, usage, status)

        def _relay(self, response, status, usage):
            self.send_response(status)
            for key, value in response.headers.items():
                if key.lower() not in DROPPED:
                    self.send_header(key, value)
            self.end_headers()
            streaming = "text/event-stream" in (response.headers.get("Content-Type") or "")
            if streaming:
                # Pass each event through as it arrives, reading usage from its data line.
                for line in response:
                    self.wfile.write(line)
                    self.wfile.flush()
                    if line.startswith(b"data:"):
                        try:
                            usage.observe(json.loads(line[5:]))
                        except ValueError:
                            pass  # e.g. "[DONE]"
            else:
                payload = response.read()
                self.wfile.write(payload)
                try:
                    usage.observe(json.loads(payload))
                except ValueError:
                    pass

        def _refuse(self, status, code, message):
            payload = json.dumps({"error": {"type": code, "code": code, "message": message}}).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *args):
            pass

    return Handler


def _with_stream_usage(path, body):
    """A streamed Chat Completions request reports usage only when asked to."""
    if not path.split("?")[0].endswith("/chat/completions"):
        return body
    try:
        request = json.loads(body)
    except ValueError:
        return body
    if isinstance(request, dict) and request.get("stream") is True:
        options = request.get("stream_options")
        if not isinstance(options, dict):
            options = request["stream_options"] = {}
        if options.get("include_usage") is not True:
            options["include_usage"] = True
            return json.dumps(request).encode()
    return body


def serve(proxy, host, port):
    server = ThreadingHTTPServer((host, port), handler(proxy))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--upstream", required=True, help="model API base URL, e.g. https://api.openai.com")
    parser.add_argument("--contextos", required=True, help="contextosd base URL")
    parser.add_argument("--listen", default="127.0.0.1:8090")
    parser.add_argument("--price", help="input:output cents per million tokens, to charge cost as well")
    parser.add_argument("--upstream-key-env", help="environment variable holding the provider key the proxy adds")
    parser.add_argument("--upstream-auth", choices=["bearer", "x-api-key"], default="bearer",
                        help="how the provider takes the key (Anthropic: x-api-key)")
    parser.add_argument("--allow-unreserved", action="store_true",
                        help="forward calls without a reservation (unmetered); refused by default")
    args = parser.parse_args()
    price = tuple(float(p) for p in args.price.split(":")) if args.price else None
    proxy = Proxy(args.upstream, args.contextos, os.environ["CONTEXTOS_METER_TOKEN"], price,
                  os.environ[args.upstream_key_env] if args.upstream_key_env else None, args.upstream_auth,
                  require_reservation=not args.allow_unreserved)
    host, port = args.listen.rsplit(":", 1)
    serve(proxy, host, int(port))
    print(f"metering {args.upstream} on http://{args.listen}", file=sys.stderr, flush=True)
    threading.Event().wait()


if __name__ == "__main__":
    main()
