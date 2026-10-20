#!/usr/bin/env python3
"""DEVELOPMENT ONLY. Never deploy.

Stand-ins for the services a real deployment operates, so the quickstart runs on a
laptop with no dependencies beyond Python 3:

  :7701 authority   - an identity/mandate broker that grants exactly what is asked
  :7702 constraints - a control plane that attests every required control
  :7703 approvals   - an approval service with no approvals on file
  :7704 payments    - an MCP (2026-07-28, stateless) server with one tool, issue_refund

The gateway still verifies every fact it receives (currency, binding, scope, digests),
but these services vouch for anything. A real authority broker verifies the caller's
mandate; a real control plane observes enforcement.
"""

import hashlib
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TD = "contextos.dev"
WINDOW = {"observed_at": "2026-01-01T00:00:00Z", "valid_until": "2099-01-01T00:00:00Z"}


def jcs(value):
    # Sufficient RFC 8785 subset for these ASCII-keyed, integer-only payloads.
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def digest(value):
    return "sha256:" + hashlib.sha256(jcs(value).encode()).hexdigest()


def principal(pid, tenant):
    return {"principal_id": pid, "principal_type": "workload", "trust_domain": TD, "tenant_id": tenant}


def artifact(kind, aid):
    return {"artifact_type": kind, "artifact_id": aid, "version": "1", "sha256": digest({"kind": kind, "id": aid})}


def authority(req):
    run, binding = req["run"], req["binding"]
    tenant = run["tenant_id"]
    grant = {
        "grant_id": "dev_grant", "grant_revision": "1", "issuer": principal("dev_broker", tenant), "subject": run["actor"],
        "audience": "contextosd", "not_before": WINDOW["observed_at"], "expires_at": WINDOW["valid_until"],
        "delegation_depth_remaining": 1, "verification_ref": artifact("authority_grant", "dev_grant"),
        "scope": {"root_run_id": run["run_id"], "purpose_ids": [binding["purpose_id"]], "capability_ids": [binding["capability_id"]],
                  "resource_ids": binding["resource_ids"], "destination_ids": binding["destination_ids"],
                  "classification_labels": ["CONFIDENTIAL"], "argument_constraints": [],
                  **({"amount_ceiling": {"minor_units": 10_000_000, "currency": binding["amount"]["currency"]}} if "amount" in binding else {})},
    }
    observer = principal("dev_control_plane", tenant)
    return {
        "authenticated": {"principal": run["actor"], "audience": "contextosd", "root_run_id": run["run_id"], "run_id": run["run_id"],
                          "mandate_kind": "workload", "trusted_issuers": [principal("dev_broker", tenant)], "trusted_observers": [observer],
                          "verification_status": "verified", "verification_ref": artifact("authentication", "dev"), **WINDOW},
        "leaf_grant_ref": {"grant_id": "dev_grant", "grant_revision": "1"},
        "grants": [grant],
        "observations": [{"grant_id": "dev_grant", "grant_revision": "1",
                          "grant_digest": digest({"domain": "contextos.authority_grant.v1", "grant": grant}),
                          "verification_ref": grant["verification_ref"], "verification_status": "verified",
                          "revocation_status": "active", "observer": observer, **WINDOW}],
        "run_links": [],
    }


def constraints(req):
    observer = principal("dev_control_plane", req["run"]["tenant_id"])
    return {"observations": [
        {"control": c, "action_digest": req["action_digest"], "policy_refs": req["run"]["policy_refs"], "verdict": "allow",
         "verification_status": "verified", "verification_ref": artifact("control", c["control_id"]), "observer": observer, **WINDOW}
        for c in req["required_controls"]]}


def approvals(req):
    return {"approval": None} if req.get("op") == "lookup" else {"approval_request_id": "dev_approval_request"}


def payments(req):
    args = req["params"]["arguments"]
    print(f"[payments] refund {args['amount_minor']} for {args['order_id']} (operation {req['params']['_meta']['io.contextos/operationId']})")
    return {"jsonrpc": "2.0", "id": req["id"], "result": {"structuredContent": {"refund_id": "rf_" + args["order_id"]}}}


def serve(port, handler):
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            out = json.dumps(handler(body)).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(out)))
            self.end_headers()
            self.wfile.write(out)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()


if __name__ == "__main__":
    import os

    # CONTEXTOS_DEV_PORTS="a,b,c,d" moves the services (authority, constraints, approvals, payments).
    ports = [int(p) for p in os.environ.get("CONTEXTOS_DEV_PORTS", "7701,7702,7703,7704").split(",")]
    for port, handler in zip(ports, [authority, constraints, approvals, payments]):
        serve(port, handler)
    print(f"dev services on {ports} (DEVELOPMENT ONLY)", flush=True)
    threading.Event().wait()
