#!/usr/bin/env python3
"""A support workflow that fails halfway and is compensated, newest effect first.

Synthetic and local: no model key, cloud account or payment service. The agent refunds
a damaged order, grants the customer store credit, then asks fulfilment for a
replacement; the fulfilment tool errors, so whether it shipped is unknown. The saga
refuses to undo anything while that effect is in doubt. Once on-call reconciles it
(not shipped, with evidence), the orchestrator compensates the run: each declared
compensation is a new governed operation (authority, policy, budget, claim, observation,
audit), the newest effect is undone first, and nothing is undone twice.
"""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import URLError
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "bindings/python"))
from contextos.client import Client, ToolPaused, ToolRejected  # noqa: E402

# Set by run.sh: a release archive's bin/ or a fresh cargo build.
BIN = Path(os.environ.get("CONTEXTOS_BIN", ROOT / "target/debug"))
EXAMPLE = ROOT / "examples/support-refund"
KEY = "dev-key-0123456789abcdef0123456789abcdef"
RISK = {"effect": "external_state", "authority": "service", "interaction": "api", "data_scope": "CONFIDENTIAL"}


def serve(handler):
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            try:
                request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                payload = json.dumps(handler(request)).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def capability(name, adapter, reversibility, properties, compensation=None, amount=True, resource="/order_id"):
    """A manifest in the shape of the quickstart's refund."""
    manifest = json.loads((EXAMPLE / "capabilities/issue_refund.json").read_text())
    manifest.update({
        "capability_id": f"{adapter}.{name}", "adapter_id": adapter, "protocol_tool": name,
        "desired_effect": name, "description": name.replace("_", " ").capitalize() + ".",
        "action_risk": {**RISK, "reversibility": reversibility},
        "resource_pointers": [resource], "destination_pointers": [],
        "input_schema": {"type": "object", "additionalProperties": False, "required": sorted(properties),
                         "properties": properties},
        "capability_ref": {**manifest["capability_ref"], "artifact_id": name},
    })
    if not amount:
        manifest.pop("amount")
    if compensation:
        manifest["compensation"] = compensation
    return manifest


def main():
    spec = importlib.util.spec_from_file_location("development_facts", EXAMPLE / "dev_services.py")
    facts = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(facts)
    calls, lock = [], threading.Lock()

    def provider(request):
        tool, args = request["params"]["name"], request["params"]["arguments"]
        with lock:
            calls.append(tool)
        if tool == "ship_replacement":
            return {"jsonrpc": "2.0", "id": request["id"], "result": {
                "isError": True, "content": [{"type": "text", "text": "out of stock"}]}}
        return {"jsonrpc": "2.0", "id": request["id"], "result": {"structuredContent": {"status": "done", **args}}}

    services = [serve(handler) for handler in [facts.authority, facts.constraints, facts.approvals, provider]]
    process = None
    try:
        with tempfile.TemporaryDirectory(prefix="contextos-saga-") as tmp:
            tmp = Path(tmp)
            order = {"order_id": {"type": "string"}, "amount_minor": {"type": "integer", "minimum": 1}}
            credit = {"customer_id": {"type": "string"}, "amount_minor": {"type": "integer", "minimum": 1}}
            manifests = [
                capability("issue_refund", "adp_payments", "compensatable", order, {
                    "capability_id": "adp_payments.reverse_refund",
                    "arguments": {"order_id": "/arguments/order_id", "amount_minor": "/arguments/amount_minor"}}),
                capability("reverse_refund", "adp_payments", "irreversible", order),
                capability("grant_credit", "adp_payments", "compensatable", credit, {
                    "capability_id": "adp_payments.revoke_credit",
                    "arguments": {"customer_id": "/arguments/customer_id", "amount_minor": "/arguments/amount_minor"}},
                    resource="/customer_id"),
                capability("revoke_credit", "adp_payments", "irreversible", credit, resource="/customer_id"),
                capability("ship_replacement", "adp_fulfillment", "irreversible", {"order_id": {"type": "string"}},
                           amount=False),
            ]
            paths = []
            for manifest in manifests:
                path = tmp / f"{manifest['capability_id']}.json"
                path.write_text(json.dumps(manifest))
                paths.append(str(path))

            # The pack surfaces every capability the workflow and its compensations use.
            pack = json.loads((EXAMPLE / "pack.json").read_text())
            pack["pack_meta"]["pack_version"] = "5.2.1"
            tooling = pack["tooling_layer"]
            registry = {a["adapter_id"]: a for a in tooling["adapter_registry"]}
            registry["adp_fulfillment"] = {**copy.deepcopy(registry["adp_payments"]), "adapter_id": "adp_fulfillment",
                                           "endpoint_ref": "internal://fulfillment", "capabilities": [],
                                           "capability_risks": {}}
            tooling["adapter_registry"] = list(registry.values())
            for manifest in manifests:
                adapter = registry[manifest["adapter_id"]]
                name = manifest["protocol_tool"]
                if name not in adapter["capabilities"]:
                    adapter["capabilities"].append(name)
                adapter["capability_risks"][name] = manifest["action_risk"]
                if not any(p["capability"] == name for p in tooling["permissions"]):
                    tooling["permissions"].append({"permission_id": f"p_{name}", "adapter_id": adapter["adapter_id"],
                                                   "capability": name, "allow": True})
            (tmp / "pack.json").write_text(json.dumps(pack))

            with socket.socket() as listener:
                listener.bind(("127.0.0.1", 0))
                port = listener.getsockname()[1]
            config = (EXAMPLE / "contextosd.toml").read_text()
            config = config.replace('packs = ["examples/support-refund/pack.json"]', f'packs = ["{tmp / "pack.json"}"]')
            config = config.replace(
                'capabilities = ["examples/support-refund/capabilities/issue_refund.json", '
                '"examples/support-refund/capabilities/lookup_order.json"]',
                "capabilities = " + json.dumps(paths))
            config = config.replace("127.0.0.1:8080", f"127.0.0.1:{port}")
            config = config.replace("sha256:REPLACED_BY_RUN_SH", "sha256:" + hashlib.sha256(KEY.encode()).hexdigest())
            config = config.replace('"dispatch", "audit:read"', '"dispatch", "reconcile", "audit:read"')
            for old, service in zip(range(7701, 7705), services):
                config = config.replace(f"127.0.0.1:{old}", f"127.0.0.1:{service.server_port}")
            config = config.replace('[[adapters]]\nid = "adp_orders"',
                                    f'[[adapters]]\nid = "adp_fulfillment"\nkind = "mcp"\n'
                                    f'endpoint = "http://127.0.0.1:{services[3].server_port}/mcp"\n\n'
                                    '[[adapters]]\nid = "adp_orders"')
            (tmp / "runtime.toml").write_text(config)
            base = f"http://127.0.0.1:{port}"
            with (tmp / "server.log").open("w") as log:
                process = subprocess.Popen(
                    [str(BIN / "contextosd"), "--config", str(tmp / "runtime.toml")],
                    cwd=ROOT, stdout=log, stderr=log,
                    env={**os.environ, "CONTEXTOS_AUDIT_SEED": "11" * 32, "RUST_LOG": "warn"})
                for _ in range(100):
                    if process.poll() is not None:
                        raise RuntimeError((tmp / "server.log").read_text())
                    try:
                        urlopen(base + "/readyz", timeout=1)
                        break
                    except (URLError, OSError):
                        time.sleep(0.1)
                else:
                    raise RuntimeError("Local runtime did not become ready")

                client = Client(base, token=KEY)
                body = json.loads((EXAMPLE / "requests/run.json").read_text())
                body["pack_ref"] = "ctxpack.support@5.2.1"
                body["request"]["input"]["context"]["refund_amount"] = 600
                for part in ("run_context", "contract"):
                    body[part]["run_id"] = "run_saga"
                body["contract"]["contract_id"] = "contract_saga"
                run = client.admit(body)

                def step(label, capability_id, args, key):
                    try:
                        run.call_tool(capability_id, args, approval_mode="destructive", idempotency_key=key)
                        print(f"  {label:<38} completed")
                        return True
                    except ToolPaused as paused:
                        assert "reconcile_effect_before_retry" in paused.obligations, paused.obligations
                        print(f"  {label:<38} tool error: outcome unknown")
                        return False

                print("Workflow: resolve a damaged-goods case")
                step("1. refund INR 600 for ord_881", "adp_payments.issue_refund",
                     {"order_id": "ord_881", "amount_minor": 60_000}, "refund:ord_881")
                step("2. store credit INR 250 for cus_77", "adp_payments.grant_credit",
                     {"customer_id": "cus_77", "amount_minor": 25_000}, "credit:cus_77")
                shipped = step("3. ship a replacement for ord_881", "adp_fulfillment.ship_replacement",
                               {"order_id": "ord_881"}, "ship:ord_881")
                assert not shipped

                listed = run.compensations()["effects"]
                assert [e["state"] for e in listed] == ["compensable", "compensable"], listed
                waiting = run.compensate_all()
                assert waiting["status"] == "stopped" and waiting["steps"] == [], waiting
                assert waiting["stopped_at"] == {"operation_id": "ship:ord_881", "reason": "unresolved"}, waiting
                print("Saga refused: ship:ord_881 may have shipped; nothing is undone while it is in doubt.")
                evidence = {"artifact_type": "fulfillment_ticket", "artifact_id": "FUL-4471", "version": "1",
                            "sha256": "sha256:" + hashlib.sha256(b"FUL-4471: not shipped").hexdigest()}
                resolved = run.reconcile("ship:ord_881", outcome="not_applied", evidence_ref=evidence)
                assert resolved["status"] == "resolved", resolved
                print("On-call reconciles it with ticket FUL-4471: not shipped.")
                print("The case cannot be completed; compensating its applied effects, newest first:")
                saga = run.compensate_all()
                assert saga["status"] == "compensated", saga
                for done in saga["steps"]:
                    result = done["result"]
                    print(f"  {result['capability_id']:<38} {result['status']} "
                          f"(compensates {result['metadata']['compensates_operation_id']})")
                assert calls == ["issue_refund", "grant_credit", "ship_replacement", "revoke_credit",
                                 "reverse_refund"], calls
                states = [e["state"] for e in run.compensations()["effects"]]
                assert states == ["compensated", "compensated"], states
                print("Compensation states:", ", ".join(states))

                # Compensated effects are not undone twice, whoever asks.
                try:
                    run.compensate("refund:ord_881")
                    raise AssertionError("a compensated effect must not be compensated again")
                except ToolRejected as refused:
                    assert refused.reason_codes == ["compensation_already_applied"], refused.reason_codes
                assert run.compensate_all()["steps"] == []
                assert len(calls) == 5, calls
                print("A second compensation is refused before the provider; provider calls: 5")
                run.fail()

                entries = client.request("GET", "/v1/audit/entries", query={"from": 1, "limit": 1000})
                keys = client.request("GET", "/v1/audit/keys")
                (tmp / "entries.json").write_text(json.dumps(entries))
                (tmp / "keys.json").write_text(json.dumps(keys))
                linked = [e for e in entries["entries"] if e["kind"] == "compensation_requested"]
                assert len(linked) == 2, linked
                verified = subprocess.run(
                    [str(BIN / "ctx"), "audit-verify", "--entries", str(tmp / "entries.json"),
                     "--keys", str(tmp / "keys.json")], check=True, capture_output=True, text=True)
                proof = json.loads(verified.stdout)
                assert proof["verified"] is True, proof
                print("Offline audit verification:", json.dumps(proof, sort_keys=True))
                print("saga compensated")
    finally:
        if process is not None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        for service in services:
            service.shutdown()
            service.server_close()


if __name__ == "__main__":
    main()
