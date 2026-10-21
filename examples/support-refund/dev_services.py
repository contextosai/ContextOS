#!/usr/bin/env python3
"""DEVELOPMENT ONLY. Never deploy.

Stand-ins for the services a real deployment operates, so the quickstart runs on a
laptop with no dependencies beyond Python 3:

  :7701 authority   - an identity/mandate broker that grants exactly what is asked
  :7702 constraints - a control plane that attests every required control
  :7703 approvals   - an approval service: it records each request, and a reviewer grants
                      one with {"op": "approve", "approval_request_id": ...}
  :7704 tools       - an MCP (2026-07-28, stateless) server with issue_refund and lookup_order

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
    root_run_id = run.get("root_run_id", run["run_id"])
    scope = {"root_run_id": root_run_id, "purpose_ids": [binding["purpose_id"]], "capability_ids": [binding["capability_id"]],
             "resource_ids": binding["resource_ids"], "destination_ids": binding["destination_ids"],
             "classification_labels": ["CONFIDENTIAL"], "argument_constraints": [],
             **({"amount_ceiling": {"minor_units": 10_000_000, "currency": binding["amount"]["currency"]}} if "amount" in binding else {})}

    def grant(grant_id, issuer, depth, parent=None):
        g = {"grant_id": grant_id, "grant_revision": "1", "issuer": issuer, "subject": run["actor"], "audience": "contextosd",
             "not_before": WINDOW["observed_at"], "expires_at": WINDOW["valid_until"], "delegation_depth_remaining": depth,
             "verification_ref": artifact("authority_grant", grant_id), "scope": scope}
        if parent:
            g["parent_grant_ref"] = {"grant_id": parent, "grant_revision": "1"}
        return g

    if run.get("parent_run_id"):
        # A delegated run: the mandate's root grant, narrowed to the child's agent.
        # (In this example parent and child act as the same agent.)
        grants = [grant("dev_child_grant", run["actor"], 1, parent="dev_grant"), grant("dev_grant", principal("dev_broker", tenant), 2)]
    else:
        grants = [grant("dev_grant", principal("dev_broker", tenant), 1)]
    observer = principal("dev_control_plane", tenant)
    return {
        "authenticated": {"principal": run["actor"], "audience": "contextosd", "root_run_id": root_run_id, "run_id": run["run_id"],
                          "mandate_kind": "workload", "trusted_issuers": [principal("dev_broker", tenant)],
                          # The gateway attests run links for delegated runs.
                          "trusted_observers": trusted_observers(tenant),
                          "verification_status": "verified", "verification_ref": artifact("authentication", "dev"), **WINDOW},
        "leaf_grant_ref": {"grant_id": grants[0]["grant_id"], "grant_revision": "1"},
        "grants": grants,
        "observations": [{"grant_id": g["grant_id"], "grant_revision": "1",
                          "grant_digest": digest({"domain": "contextos.authority_grant.v1", "grant": g}),
                          "verification_ref": g["verification_ref"], "verification_status": "verified",
                          "revocation_status": "active", "observer": observer, **WINDOW} for g in grants],
        "run_links": [],
    }


def trusted_observers(tenant):
    # Development only: trusting the gateway as an observer lets it vouch for the
    # delegated-run facts it consumes. A production broker verifies delegation itself.
    gateway = {"principal_id": "contextosd", "principal_type": "workload", "trust_domain": TD, "tenant_id": tenant}
    return [principal("dev_control_plane", tenant), gateway]


def constraints(req):
    observer = principal("dev_control_plane", req["run"]["tenant_id"])
    return {"observations": [
        {"control": c, "action_digest": req["action_digest"], "policy_refs": req["run"]["policy_refs"], "verdict": "allow",
         "verification_status": "verified", "verification_ref": artifact("control", c["control_id"]), "observer": observer, **WINDOW}
        for c in req["required_controls"]]}


# Inside every window, and never before the decision it verifies.
DECIDED = "2026-01-02T00:00:00Z"
# action digest -> the request as opened, and the verified approval once granted.
REQUESTS, APPROVED = {}, {}


def approvals(req):
    if req["op"] == "lookup":
        return {"approval": APPROVED.get(req["action_digest"])}
    if req["op"] == "request":
        request_id = "dev_approval:" + req["action_digest"][7:19]
        REQUESTS[req["action_digest"]] = {"request_id": request_id, "run": req["run"], "binding": req["binding"]}
        print(f"[approvals] request {request_id} for {req['binding']['capability_id']}", flush=True)
        return {"approval_request_id": request_id}
    # A reviewer's decision. A real approval service authenticates the person, checks
    # their entitlement and shows them the exact binding before recording a decision.
    action_digest, opened = next((d, r) for d, r in REQUESTS.items() if r["request_id"] == req["approval_request_id"])
    APPROVED[action_digest] = approved(action_digest, opened)
    print(f"[approvals] approved {opened['request_id']}", flush=True)
    return {"approved": opened["request_id"]}


def approved(action_digest, opened):
    """The verified approval material for one exact action: request, decision, the
    observation that verified the decision, and the approver's entitlement."""
    run, binding, request_id = opened["run"], opened["binding"], opened["request_id"]
    tenant = run["tenant_id"]
    approver = {"principal_id": "dev_finance_lead", "principal_type": "person", "trust_domain": TD, "tenant_id": tenant}
    observer = principal("dev_control_plane", tenant)
    proposal = {"request_id": request_id, "proposal_id": binding["proposal_id"], "run_id": binding["run_id"],
                "tenant_id": tenant, "operation_id": binding["operation_id"], "action_digest": action_digest,
                "policy_refs": binding["policy_refs"], "authority_refs": binding["authority_refs"],
                "not_before": WINDOW["observed_at"], "expires_at": WINDOW["valid_until"]}
    request = {**proposal, "approval_request_id": request_id, "requester": run["actor"],
               "eligible_approvers": [approver], "eligible_approver_roles": ["finance_lead"], "required_approvals": 1,
               "prohibit_self_approval": True, "verification_ref": artifact("approval_request", request_id)}
    decision = {**proposal, "approval_id": f"{request_id}:1", "approval_request_id": request_id, "approver": approver,
                "decision": "approved", "decided_at": DECIDED,
                "verification_ref": artifact("approval_decision", f"{request_id}:1")}
    observation = {"approval_id": decision["approval_id"],
                   "decision_digest": digest({"domain": "contextos.approval_decision.v1", "decision": decision}),
                   "verification_ref": decision["verification_ref"], "verification_status": "verified",
                   "observer": observer, "observed_at": DECIDED, "valid_until": WINDOW["valid_until"]}
    entitlement = {"approver": approver, "role_id": "finance_lead", "approval_request_id": request_id,
                   "action_digest": action_digest, "observer": observer, "verification_status": "verified",
                   "verification_ref": artifact("entitlement", "finance_lead"), **WINDOW}
    return {"proposal": proposal, "request": request, "decisions": [decision], "verification_observations": [observation],
            "entitlements": [entitlement], "trusted_observers": trusted_observers(tenant)}


def payments(req):
    tool = req["params"]["name"]
    args = req["params"]["arguments"]
    if tool == "lookup_order":
        print(f"[orders] lookup {args['order_id']}")
        order = {"order_id": args["order_id"], "status": "delivered_damaged", "amount_minor": 120000, "currency": "INR",
                 "customer_id": "cus_77", "refundable": True}
        return {"jsonrpc": "2.0", "id": req["id"], "result": {"structuredContent": order}}
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
