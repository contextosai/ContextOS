"""End to end: a real contextosd asks the relay for approval of a high-value refund, a
finance lead approves it from Slack through a signed callback, and the retried call goes
through; a second refund is denied from Slack and refused; a forged callback is refused;
the audit chain verifies. Run from the repo root: python3 examples/approval-relay/e2e.py
"""

import hashlib
import hmac
import importlib.util
import json
import os
import sys
import threading
import time
import types
import urllib.parse
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "bindings/python"))
sys.path.insert(0, str(ROOT / "examples/replay"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from contextos.client import Client  # noqa: E402
from contextos.errors import ToolBlocked, ToolPaused  # noqa: E402
from local_gateway import free_port, local_gateway  # noqa: E402

import relay  # noqa: E402

CONFIG = {
    "trust_domain": "contextos.dev",
    # The development authority service's observers (examples/support-refund/dev_services.py).
    "observer": "dev_control_plane",
    "trusted_observers": [
        {"principal_id": "dev_control_plane", "principal_type": "workload", "trust_domain": "contextos.dev"},
        {"principal_id": "contextosd", "principal_type": "workload", "trust_domain": "contextos.dev"},
    ],
    "directory": {"slack:U_ANA": {"principal_id": "fin_lead_ana", "roles": ["finance_lead"]}},
    "tiers": [{"after_seconds": 0, "approvers": ["fin_lead_ana"]}],
    "secrets": {"slack_signing_secret": "RELAY_SLACK_SECRET", "teams_secret": "RELAY_TEAMS_SECRET",
                "email_link_secret": "RELAY_EMAIL_SECRET"},
}


def serve(handler):
    port = free_port()
    server = ThreadingHTTPServer(("127.0.0.1", port), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return f"http://127.0.0.1:{port}", server


def click(url, rid, verdict, secret=b"slack-signing-secret"):
    body = urllib.parse.urlencode({"payload": json.dumps(
        {"actions": [{"value": f"{verdict}:{rid}"}], "user": {"id": "U_ANA"}})}).encode()
    ts = str(int(time.time()))
    sig = "v0=" + hmac.new(secret, b"v0:" + ts.encode() + b":" + body, hashlib.sha256).hexdigest()
    request = urllib.request.Request(url + "/slack/actions", data=body,
                                     headers={"x-slack-request-timestamp": ts, "x-slack-signature": sig})
    try:
        with urllib.request.urlopen(request) as response:
            return response.status
    except urllib.error.HTTPError as e:
        return e.code


def main():
    os.environ.update({"RELAY_SLACK_SECRET": "slack-signing-secret", "RELAY_TEAMS_SECRET": "unused",
                       "RELAY_EMAIL_SECRET": "unused"})
    spec = importlib.util.spec_from_file_location("dev_services", ROOT / "examples/support-refund/dev_services.py")
    dev = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(dev)
    payments_port = free_port()
    dev.serve(payments_port, dev.payments)
    tools = types.SimpleNamespace(url=f"http://127.0.0.1:{payments_port}/mcp")
    the_relay = relay.Relay(CONFIG)
    relay_url, _ = serve(relay.handler(the_relay))
    with local_gateway(tools, approvals=relay_url + "/approvals") as (base, key):
        run_body = json.loads((ROOT / "examples/support-refund/requests/run.json").read_text())
        run_body["request"]["input"]["context"]["refund_amount"] = 4200
        run = Client(base, key).admit(run_body)
        args = {"order_id": "ord_881", "customer_id": "cus_77", "amount_minor": 120000}
        evidence = ["kg:order:ord_881#snapshot_kg_2026_05_03_T0930"]

        def refund(key_suffix):
            return run.call_tool("adp_payments.issue_refund", args, approval_mode="destructive",
                                 idempotency_key=f"refund:ord_881:{key_suffix}", evidence_refs=evidence,
                                 tool_call_id=f"tc_{key_suffix}")

        try:
            refund("a")
            raise SystemExit("expected the refund to wait for approval")
        except ToolPaused as paused:
            assert paused.kind == "approval", paused
        sent = the_relay.outbox.sent
        assert [(m["channel"], m["to"]) for m in sent] == [("slack", "U_ANA")], sent
        rid = sent[0]["request"]
        assert click(relay_url, rid, "approved", secret=b"forged") == 401, "a forged click is refused"
        assert click(relay_url, rid, "approved") == 200
        out = refund("a")
        print("approved from Slack:", json.dumps(out)[:120])

        args["amount_minor"] = 110000
        try:
            refund("b")
            raise SystemExit("expected the second refund to wait for approval")
        except ToolPaused:
            pass
        assert click(relay_url, the_relay.outbox.sent[-1]["request"], "denied") == 200
        try:
            refund("b")
            raise SystemExit("expected the denied refund to be refused")
        except ToolBlocked as blocked:
            assert "approval_denied" in blocked.reason_codes, blocked.reason_codes
        print("denied from Slack: refused with approval_denied")

        verify = json.loads(urllib.request.urlopen(urllib.request.Request(
            base + "/v1/audit/verify", headers={"authorization": f"Bearer {key}"})).read())
        assert verify["verified"] is True, verify
        print("audit chain verified")


if __name__ == "__main__":
    main()
