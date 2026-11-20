"""A synthetic card processor for the Agent Failure Lab.

It keeps its own ledger, honours idempotency keys, and refuses a refund above what is
left of the order's payment, as a real processor does. `mode` decides what happens to
the next refund: answered, or applied with the response lost. No real money is involved.
"""
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def total(entries):
    return sum(e["amount_minor"] for e in entries)


class Provider:
    def __init__(self, payments):
        """`payments` maps each order to what was paid for it, in minor units."""
        self.payments = dict(payments)
        self.mode, self.ledger, self.calls, self.keys = "answer", [], 0, {}
        self.lock = threading.Lock()
        self.server = None

    def refund(self, order_id, amount, request_key, idempotency_key=None):
        """One refund request. Returns (outcome, ledger entry or None); the outcome is
        `paid`, `paid_no_answer` (applied, response lost), `deduplicated` (the key was
        seen: the earlier refund is returned and nothing moves) or `refused_by_provider`."""
        with self.lock:
            self.calls += 1
            mode, self.mode = self.mode, "answer"
            if idempotency_key is not None and idempotency_key in self.keys:
                return "deduplicated", self.keys[idempotency_key]
            refunded = total(e for e in self.ledger if e["order_id"] == order_id)
            if refunded + amount > self.payments.get(order_id, 0):
                return "refused_by_provider", None
            entry = {"refund_id": f"re_{len(self.ledger) + 1:03d}", "order_id": order_id,
                     "amount_minor": amount, "request_key": request_key}
            self.ledger.append(entry)
            if idempotency_key is not None:
                self.keys[idempotency_key] = entry
            return ("paid_no_answer" if mode == "lose_response" else "paid"), entry

    def export(self, order_id):
        """The provider's ledger for one order, as an operator would download it."""
        return {"provider": "synthetic_payments", "order_id": order_id,
                "refunds": [e for e in self.ledger if e["order_id"] == order_id]}

    # The MCP endpoint the gateway calls.

    def serve(self):
        provider = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                try:
                    request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                    reply = provider.mcp(request)
                    if reply is None:  # the response is lost: the connection just closes
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

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        return self

    @property
    def url(self):
        return f"http://127.0.0.1:{self.server.server_port}/mcp"

    def close(self):
        if self.server is not None:
            self.server.shutdown()
            self.server.server_close()

    def mcp(self, request):
        if request.get("method") != "tools/call":
            return {"jsonrpc": "2.0", "id": request.get("id"), "error": {"code": -32601, "message": "unsupported"}}
        args = request["params"]["arguments"]
        key = request["params"].get("_meta", {}).get("io.contextos/operationId", "")
        outcome, entry = self.refund(args["order_id"], args["amount_minor"], key)
        if outcome == "refused_by_provider":
            return {"jsonrpc": "2.0", "id": request["id"], "result": {"isError": True, "content": [
                {"type": "text", "text": "amount exceeds the payment's refundable balance"}]}}
        if outcome == "paid_no_answer":
            return None
        return {"jsonrpc": "2.0", "id": request["id"], "result": {
            "structuredContent": {"refund_id": entry["refund_id"], "status": "succeeded"}}}
