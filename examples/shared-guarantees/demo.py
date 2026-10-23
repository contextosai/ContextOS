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


def digest(value):
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return "sha256:" + hashlib.sha256(raw.encode()).hexdigest()


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


def main():
    spec = importlib.util.spec_from_file_location(
        "development_facts", ROOT / "examples/support-refund/dev_services.py")
    facts = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(facts)
    calls, lock = [], threading.Lock()

    def payments(request):
        if request["method"] == "tasks/get":
            return {"jsonrpc": "2.0", "id": request["id"], "result": {"task": {
                "taskId": request["params"]["taskId"], "status": "completed",
                "result": {"structuredContent": {"refund_id": "synthetic_pending_refund"}}}}}
        amount = request["params"]["arguments"]["amount_minor"]
        with lock:
            calls.append(amount)
        if amount == 15_000:
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
                print("Two independent agents request INR 800 each against one INR 1,000 ceiling.")
                print("Provider effects: 1; the competing effect is withheld before dispatch.")

                resource = digest("ord_881")
                path = f"/v1/guarantees/refunds-per-order/resources/{resource}"
                view = api(path)
                assert (view["committed"], view["held"], view["available"]) == (80_000, 0, 20_000), view

                c = admit("shared_pending", "support_async", 15_000)
                pending = dispatch("shared_pending", "support_async", 15_000, c)
                assert pending["result"]["status"] == "paused", pending
                view = api(path)
                assert (view["committed"], view["held"], view["available"]) == (80_000, 15_000, 5_000), view
                d = admit("shared_after_pending", "support_followup", 10_000)
                blocked = dispatch("shared_after_pending", "support_followup", 10_000, d)
                assert blocked["report"]["reason_codes"] == ["shared_guarantee_exceeded"], blocked
                assert calls == [80_000, 15_000], calls
                print("A pending INR 150 effect holds capacity; a further INR 100 effect is withheld.")

                resolved = api("/v1/runs/shared_pending/operations/refund_shared_pending/reconcile",
                               {"source": "provider"}, c)
                assert resolved["status"] == "resolved", resolved
                view = api(path)
                assert (view["committed"], view["held"], view["available"]) == (95_000, 0, 5_000), view
                print("Provider query confirms the pending effect: INR 950 committed, INR 50 available.")

                entries = api("/v1/audit/entries?from=1&limit=1000")
                keys = api("/v1/audit/keys")
                (tmp / "entries.json").write_text(json.dumps(entries))
                (tmp / "keys.json").write_text(json.dumps(keys))
                verified = subprocess.run(
                    [str(BIN / "ctx"), "audit-verify", "--entries", str(tmp / "entries.json"),
                     "--keys", str(tmp / "keys.json")], check=True, capture_output=True, text=True)
                proof = json.loads(verified.stdout)
                assert proof["verified"] is True, proof
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
