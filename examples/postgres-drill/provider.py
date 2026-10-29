"""DEVELOPMENT ONLY. A synthetic payment provider for the PostgreSQL drill.

Its ledger is the drill's ground truth: every refund the provider applied, keyed by the
operation id the gateway sends. Faults are set per order:

  lose  apply the refund, then close the connection without answering
  hang  apply the refund, signal `arrived`, and answer only after `release` (by then
        the replica that sent it has usually been killed)
  slow  apply the refund and answer after a delay, so calls are in flight during a
        database restart
"""
import importlib.util
import json
from pathlib import Path
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = Path(__file__).resolve().parents[2]


class Server(ThreadingHTTPServer):
    # The default backlog of 5 refuses connections when many calls arrive at once,
    # which the gateway reports as a failed fact service rather than load.
    request_queue_size = 256
    daemon_threads = True


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

    server = Server(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


class Payments:
    def __init__(self, slow_seconds=1.0):
        self.lock = threading.Lock()
        self.applied = {}  # operation id -> [entry, ...]; more than one is a duplicate effect
        self.faults = {}  # order id -> "lose" | "hang" | "slow"
        self.arrived, self.release = threading.Event(), threading.Event()
        self.slow_seconds = slow_seconds
        self.slow_seen = 0

    def handle(self, request):
        if request["method"] == "tasks/get":
            return {"jsonrpc": "2.0", "id": request["id"], "error": {"code": -32602, "message": "unknown task"}}
        arguments = request["params"]["arguments"]
        operation = request["params"]["_meta"]["io.contextos/operationId"]
        order, amount = arguments["order_id"], arguments["amount_minor"]
        with self.lock:
            self.applied.setdefault(operation, []).append(
                {"operation_id": operation, "order_id": order, "amount_minor": amount,
                 "refund_id": f"synthetic_{operation}", "status": "succeeded"})
            fault = self.faults.get(order)
            if fault == "slow":
                self.slow_seen += 1
        if fault == "lose":
            return None
        if fault == "hang":
            self.arrived.set()
            self.release.wait(60)
            return None
        if fault == "slow":
            time.sleep(self.slow_seconds)
        return {"jsonrpc": "2.0", "id": request["id"], "result": {
            "structuredContent": {"refund_id": f"synthetic_{operation}"}}}

    def total(self, order):
        with self.lock:
            return sum(e["amount_minor"] for entries in self.applied.values() for e in entries
                       if e["order_id"] == order)

    def entries(self, order=None):
        with self.lock:
            return [e for entries in self.applied.values() for e in entries
                    if order is None or e["order_id"] == order]

    def duplicates(self):
        with self.lock:
            return {op: len(entries) for op, entries in self.applied.items() if len(entries) > 1}

    def has(self, operation):
        with self.lock:
            return bool(self.applied.get(operation))


def start(slow_seconds=1.0):
    """Authority, constraints, approvals (development stand-ins) and the payments
    provider, in the order of the support-refund example's ports 7701-7704."""
    spec = importlib.util.spec_from_file_location(
        "development_facts", ROOT / "examples/support-refund/dev_services.py")
    facts = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(facts)
    payments = Payments(slow_seconds)
    services = [serve(h) for h in [facts.authority, facts.constraints, facts.approvals, payments.handle]]
    return services, payments
