#!/usr/bin/env python3
"""Relays ContextOS escalation notifications to Slack and PagerDuty.

Run it where contextosd's `[[notifications]]` webhook points:

    CONTEXTOS_NOTIFY_SECRET=... SLACK_WEBHOOK_URL=https://hooks.slack.com/... \
    PAGERDUTY_ROUTING_KEY=... python3 relay.py --port 8787

It verifies each request's ContextOS-Signature (HMAC-SHA256 over "<t>.<body>",
at most five minutes old), drops event ids it has already relayed, and forwards a
short message with the link to the decision. It never approves anything: approvers
act where they sign in.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MAX_AGE_SECONDS = 300


def verify(secret: bytes, header: str, body: bytes, now: float) -> bool:
    try:
        parts = dict(p.split("=", 1) for p in header.split(","))
        timestamp = int(parts["t"])
    except (KeyError, ValueError):
        return False
    if abs(now - timestamp) > MAX_AGE_SECONDS:
        return False
    expected = hmac.new(secret, f"{timestamp}.".encode() + body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, parts.get("v1", ""))


def message(event: dict) -> str:
    data = event.get("data", {})
    if event.get("type") == "io.contextos.escalation.opened":
        text = (f"Decision needed: {data.get('capability_id')} in run {data.get('run_id')} "
                f"({', '.join(data.get('reason_codes') or [])})")
    else:
        text = f"Escalation {data.get('escalation_id')} {data.get('outcome')} by {data.get('by')}"
    return f"{text} {data['link']}" if data.get("link") else text


def pagerduty(event: dict, routing_key: str) -> dict:
    opened = event.get("type") == "io.contextos.escalation.opened"
    return {"routing_key": routing_key, "dedup_key": event["subject"],
            "event_action": "trigger" if opened else "resolve",
            "payload": {"summary": message(event), "source": "contextos", "severity": "warning"},
            "links": [{"href": event["data"]["link"]}] if event.get("data", {}).get("link") else []}


def post(url: str, payload: dict) -> None:
    request = urllib.request.Request(url, json.dumps(payload).encode(), {"content-type": "application/json"})
    urllib.request.urlopen(request, timeout=5).close()


def handler(secret: bytes, slack: str | None, routing_key: str | None):
    seen: set[str] = set()

    class Relay(BaseHTTPRequestHandler):
        def do_POST(self):
            body = self.rfile.read(int(self.headers.get("content-length", 0)))
            if not verify(secret, self.headers.get("contextos-signature", ""), body, time.time()):
                self.send_response(401)
                self.end_headers()
                return
            event = json.loads(body)
            if event["id"] not in seen:
                if slack:
                    post(slack, {"text": message(event)})
                if routing_key:
                    post("https://events.pagerduty.com/v2/enqueue", pagerduty(event, routing_key))
                seen.add(event["id"])
            self.send_response(204)
            self.end_headers()

    return Relay


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--port", type=int, default=8787)
    args = parser.parse_args()
    secret = os.environ["CONTEXTOS_NOTIFY_SECRET"].encode()
    relay = handler(secret, os.environ.get("SLACK_WEBHOOK_URL"), os.environ.get("PAGERDUTY_ROUTING_KEY"))
    ThreadingHTTPServer(("127.0.0.1", args.port), relay).serve_forever()


if __name__ == "__main__":
    main()
