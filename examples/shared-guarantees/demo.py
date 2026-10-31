#!/usr/bin/env python3
"""Synthetic local demonstration; no model key, cloud account or payment service."""
import concurrent.futures
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[2]
# Set by run.sh: a release archive's bin/ or a fresh cargo build.
BIN = Path(os.environ.get("CONTEXTOS_BIN", ROOT / "target/debug"))
KEY = "dev-key-0123456789abcdef0123456789abcdef"
# Kept after the run so the evidence can be verified again independently.
RECEIPT = Path(os.environ.get("CONTEXTOS_RECEIPT_DIR", ROOT / "receipts/shared-guarantees"))
LOST, PENDING = 10_000, 5_000


def shown(path):
    """A path relative to the working directory when it is inside it."""
    try:
        return str(Path(path).resolve().relative_to(Path.cwd()))
    except ValueError:
        return str(path)


def inr(minor):
    return f"INR {minor // 100:,}"


def show(view, note=None):
    print(f"    limit {inr(view['limit'])} | committed {inr(view['committed'])} | "
          f"held {inr(view['held'])} | available {inr(view['available'])}")
    if note:
        print(f"    next safe step: {note}")


def digest(value):
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return "sha256:" + hashlib.sha256(raw.encode()).hexdigest()


def serve(handler):
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            try:
                request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                reply = handler(request)
                if reply is None:  # the response is lost: close without answering
                    self.close_connection = True
                    return
                payload = json.dumps(reply).encode()
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


def main():
    spec = importlib.util.spec_from_file_location(
        "development_facts", ROOT / "examples/support-refund/dev_services.py")
    facts = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(facts)
    calls, ledger, lock = [], {}, threading.Lock()

    def payments(request):
        if request["method"] == "tasks/get":
            return {"jsonrpc": "2.0", "id": request["id"], "result": {"task": {
                "taskId": request["params"]["taskId"], "status": "completed",
                "result": {"structuredContent": {"refund_id": "synthetic_pending_refund"}}}}}
        arguments = request["params"]["arguments"]
        amount = arguments["amount_minor"]
        key = request["params"]["_meta"]["io.contextos/operationId"]
        with lock:
            calls.append(amount)
            ledger[key] = {"refund_id": f"synthetic_{key}", "order_id": arguments["order_id"],
                           "amount_minor": amount, "status": "succeeded"}
        if amount == LOST:
            return None
        if amount == PENDING:
            return {"jsonrpc": "2.0", "id": request["id"], "result": {
                "resultType": "task", "task": {"taskId": "pending_refund", "status": "working"}}}
        return {"jsonrpc": "2.0", "id": request["id"], "result": {
            "structuredContent": {"refund_id": "synthetic_refund"}}}

    services = [serve(handler) for handler in
                [facts.authority, facts.constraints, facts.approvals, payments]]
    process = None
    try:
        with tempfile.TemporaryDirectory(prefix="contextos-guarantees-") as tmp:
            tmp = Path(tmp)
            config = (ROOT / "examples/support-refund/contextosd.toml").read_text()
            with socket.socket() as listener:
                listener.bind(("127.0.0.1", 0))
                port = listener.getsockname()[1]
            base = f"http://127.0.0.1:{port}"
            config = config.replace("127.0.0.1:8080", f"127.0.0.1:{port}")
            config = config.replace("sha256:REPLACED_BY_RUN_SH",
                                    "sha256:" + hashlib.sha256(KEY.encode()).hexdigest())
            config = config.replace('"dispatch", "audit:read"', '"dispatch", "reconcile", "audit:read"')
            for old, service in zip(range(7701, 7705), services):
                config = config.replace(f"127.0.0.1:{old}", f"127.0.0.1:{service.server_port}")
            config += '''
[[guarantees]]
id = "refunds-per-order"
capability_ids = ["adp_payments.issue_refund"]
resource_pointer = "/order_id"
amount_pointer = "/amount_minor"
limit = 100000
unit = "INR_minor"
'''
            (tmp / "runtime.toml").write_text(config)
            with (tmp / "server.log").open("w") as log:
                process = subprocess.Popen(
                    [str(BIN / "contextosd"), "--config", str(tmp / "runtime.toml")],
                    cwd=ROOT, stdout=log, stderr=log,
                    env={**os.environ, "CONTEXTOS_AUDIT_SEED": "11" * 32, "RUST_LOG": "warn"})

                def api(path, body=None, generation=None):
                    headers = {"Authorization": f"Bearer {KEY}", "Content-Type": "application/json"}
                    if generation is not None:
                        headers["contextos-executor-generation"] = str(generation)
                    req = Request(base + path, headers=headers,
                                  data=None if body is None else json.dumps(body).encode())
                    try:
                        with urlopen(req, timeout=15) as response:
                            payload = response.read()
                            return json.loads(payload) if response.headers.get_content_type() == "application/json" else payload.decode()
                    except HTTPError as error:
                        if path == "/readyz":
                            raise
                        raise RuntimeError(f"{error.code} {path}: {error.read().decode()}") from error

                for _ in range(100):
                    if process.poll() is not None:
                        raise RuntimeError((tmp / "server.log").read_text())
                    try:
                        api("/readyz")
                        break
                    except (URLError, HTTPError):
                        time.sleep(0.1)
                else:
                    raise RuntimeError("Local runtime did not become ready")

                template = json.loads((ROOT / "examples/support-refund/requests/run.json").read_text())
                tool = json.loads((ROOT / "examples/support-refund/requests/tool_call.json").read_text())

                def admit(run, agent, amount):
                    body = copy.deepcopy(template)
                    body["run_context"]["run_id"] = run
                    body["contract"]["run_id"] = run
                    body["contract"]["contract_id"] = f"contract_{run}"
                    body["request"]["request_id"] = f"req_{run}"
                    body["request"]["input"]["context"]["refund_amount"] = amount // 100
                    for context in [body["request"], body["run_context"]]:
                        context["agent"]["agent_id"] = agent
                        context["agent"]["workload_identity"] = f"spiffe://contextos/agents/{agent}"
                    admitted = api("/v1/runs", body)
                    return admitted["executor_generation"]

                def dispatch(run, agent, amount, generation):
                    body = copy.deepcopy(tool)
                    body["run_id"] = run
                    body["tool_call_id"] = f"call_{run}"
                    body["idempotency_key"] = f"refund_{run}"
                    body["args"]["amount_minor"] = amount
                    body["principal_chain"] = [{"kind": "agent", "id": agent}]
                    return api(f"/v1/runs/{run}/tool-calls", body, generation)

                resource = digest("ord_881")
                path = f"/v1/guarantees/refunds-per-order/resources/{resource}"
                balances = []

                def balance(step, expected):
                    view = api(path)
                    assert (view["committed"], view["held"], view["available"]) == expected, view
                    balances.append({"step": step, **{k: view[k] for k in
                                     ("limit", "committed", "held", "available", "unit")}})
                    return view

                def refused(result):
                    return ", ".join(result["report"]["reason_codes"])

                print("1. Two agents each request INR 800 from order ord_881; all refunds on the")
                print("   order share one INR 1,000 ceiling.")
                a = admit("shared_a", "support_email", 80_000)
                b = admit("shared_b", "support_chat", 80_000)
                with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                    futures = [
                        pool.submit(dispatch, "shared_a", "support_email", 80_000, a),
                        pool.submit(dispatch, "shared_b", "support_chat", 80_000, b)]
                    results = [future.result() for future in futures]
                assert sum(r["result"]["status"] == "completed" for r in results) == 1, results
                assert any("shared_guarantee_exceeded" in r["report"]["reason_codes"] for r in results), results
                assert calls == [80_000], calls
                for agent, result in zip(["support_email", "support_chat"], results):
                    if result["result"]["status"] == "completed":
                        print(f"    {agent}: refunded (the provider was called once)")
                    else:
                        print(f"    {agent}: withheld before dispatch ({refused(result)})")
                show(balance("race", (80_000, 0, 20_000)))

                print(f"2. A third agent requests {inr(LOST)}. The provider applies it, but the response")
                print("   is lost, so the outcome is unknown and its reservation stays held.")
                lost_gen = admit("shared_lost", "support_voice", LOST)
                lost = dispatch("shared_lost", "support_voice", LOST, lost_gen)
                assert lost["result"]["status"] != "completed", lost
                assert calls == [80_000, LOST], calls
                print(f"    support_voice: {lost['result']['status']} ({lost['result']['error']})")
                show(balance("lost_response", (80_000, LOST, 10_000)),
                     "reconcile against the provider's records; do not retry the refund")

                print(f"3. A fourth agent's {inr(PENDING)} refund is accepted as a pending provider task;")
                print(f"   it is held too. A further {inr(10_000)} request is withheld before dispatch.")
                c = admit("shared_pending", "support_async", PENDING)
                pending = dispatch("shared_pending", "support_async", PENDING, c)
                assert pending["result"]["status"] == "paused", pending
                print("    support_async: accepted as a pending provider task, held until it resolves")
                d = admit("shared_after_pending", "support_followup", 10_000)
                blocked = dispatch("shared_after_pending", "support_followup", 10_000, d)
                assert blocked["report"]["reason_codes"] == ["shared_guarantee_exceeded"], blocked
                assert calls == [80_000, LOST, PENDING], calls
                print(f"    support_followup: withheld ({refused(blocked)})")
                show(balance("pending_and_refused", (80_000, LOST + PENDING, 5_000)),
                     "resolve the held effects; capacity returns only if they did not apply")

                print("4. Querying the provider's task confirms the pending refund.")
                resolved = api("/v1/runs/shared_pending/operations/refund_shared_pending/reconcile",
                               {"source": "provider"}, c)
                assert resolved["status"] == "resolved", resolved
                show(balance("provider_query", (80_000 + PENDING, LOST, 5_000)))

                print("5. The lost response left no task to query. An operator checks the provider's")
                print("   ledger, finds the refund and records it as confirmed, citing that export.")
                RECEIPT.mkdir(parents=True, exist_ok=True)
                entry = ledger["refund_shared_lost"]
                export = json.dumps({"provider": "synthetic_payments", "entries": [entry]}, indent=2)
                (RECEIPT / "provider-ledger.json").write_text(export)
                confirmed = api("/v1/runs/shared_lost/operations/refund_shared_lost/reconcile", {
                    "source": "operator", "outcome": "confirmed", "evidence_ref": {
                        "artifact_type": "provider_ledger", "artifact_id": "synthetic_payments_export",
                        "version": "1", "sha256": "sha256:" + hashlib.sha256(export.encode()).hexdigest()}},
                    lost_gen)
                assert confirmed["status"] == "resolved", confirmed
                show(balance("operator_confirmed", (95_000, 0, 5_000)))
                assert calls == [80_000, LOST, PENDING], calls

                entries = api("/v1/audit/entries?from=1&limit=1000")
                keys = api("/v1/audit/keys")
                (RECEIPT / "entries.json").write_text(json.dumps(entries))
                (RECEIPT / "keys.json").write_text(json.dumps(keys))
                (RECEIPT / "balances.json").write_text(json.dumps(
                    {"guarantee_id": "refunds-per-order", "resource_digest": resource,
                     "provider_calls": len(calls), "balances": balances}, indent=2))
                verify = [str(BIN / "ctx"), "audit-verify", "--entries", str(RECEIPT / "entries.json"),
                          "--keys", str(RECEIPT / "keys.json")]
                verified = subprocess.run(verify, check=True, capture_output=True, text=True)
                proof = json.loads(verified.stdout)
                assert proof["verified"] is True, proof
                print(f"6. {len(calls)} provider calls, never more than INR 1,000 committed. The audit log")
                print(f"   ({proof['entries']} signed entries) verifies offline.")
                print(f"Receipt: {shown(RECEIPT)}/ (audit entries, keys, balances, provider ledger)")
                print("Verify it yourself:")
                print("  " + " ".join(shown(Path(arg)) if "/" in arg else arg for arg in verify))
                print("Offline audit verification:", json.dumps(proof, sort_keys=True))
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
