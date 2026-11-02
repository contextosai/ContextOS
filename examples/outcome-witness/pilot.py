#!/usr/bin/env python3
"""A refund is done when the refund ledger says it posted, not when the payment API
accepted the call.

Synthetic and local: no model key, cloud account or payment service. The quickstart's
refund capability declares an outcome contract: the refund ledger, an evidence issuer
independent of the payment provider, must attest `refund_posted` for the order and
amount within 15 minutes. The provider confirms the refund; the run still cannot record
its decision or complete. A ledger reading for the wrong amount is refused. The
ledger's reading for the refund closes the outcome; the decision cites it, the run
completes, and the evidence bundle and audit chain carry it.

The ledger signs with `ctx attest`, the development signer for issuers and witnesses.
"""
import hashlib
import importlib.util
import json
import os
from datetime import datetime, timezone
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
from contextos.client import Client, ContextOSHTTPError  # noqa: E402

BIN = Path(os.environ.get("CONTEXTOS_BIN", ROOT / "target/debug"))
EXAMPLE = ROOT / "examples/support-refund"
KEY = "dev-key-0123456789abcdef0123456789abcdef"
LEDGER_KEY = "dev-ledger-0123456789abcdef0123456789ab"
LEDGER = "https://refund-ledger.example.test"
LEDGER_SEED = "5e" * 32


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


def at(offset_seconds=0):
    now = datetime.now(timezone.utc).timestamp() + offset_seconds
    return datetime.fromtimestamp(now, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def attest(tmp, claims):
    """The ledger signs a reading (what a real ledger service does with its own key)."""
    path = tmp / "claims.json"
    path.write_text(json.dumps(claims))
    signed = subprocess.run([str(BIN / "ctx"), "attest", "--claims", str(path), "--seed-env", "LEDGER_SEED"],
                            check=True, capture_output=True, text=True, env={**os.environ, "LEDGER_SEED": LEDGER_SEED})
    return json.loads(signed.stdout)


def posted(order, amount):
    return {"iss": LEDGER, "sub": order, "satisfies": ["refund_posted"], "observed_at": at(),
            "valid_until": at(600), "amount": {"minor_units": amount, "currency": "INR"}}


def refused(call):
    """The refusal's reason: the error code, or a lifecycle refusal's first reason code."""
    try:
        call()
    except ContextOSHTTPError as error:
        reasons = error.detail.get("reason_codes") if isinstance(error.detail, dict) else None
        return reasons[0] if reasons else error.code
    raise AssertionError("expected a refusal")


def main():
    spec = importlib.util.spec_from_file_location("development_facts", EXAMPLE / "dev_services.py")
    facts = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(facts)
    services = [serve(handler) for handler in [facts.authority, facts.constraints, facts.approvals, facts.payments]]
    process = None
    try:
        with tempfile.TemporaryDirectory(prefix="contextos-outcome-") as tmp:
            tmp = Path(tmp)
            manifest = json.loads((EXAMPLE / "capabilities/issue_refund.json").read_text())
            manifest["outcome"] = {"witness": LEDGER, "postcondition": "refund_posted", "within_seconds": 900}
            (tmp / "issue_refund.json").write_text(json.dumps(manifest))
            jwks = attest(tmp, {"iss": LEDGER})["jwks"]

            with socket.socket() as listener:
                listener.bind(("127.0.0.1", 0))
                port = listener.getsockname()[1]
            config = (EXAMPLE / "contextosd.toml").read_text()
            config = config.replace("examples/support-refund/capabilities/issue_refund.json",
                                    str(tmp / "issue_refund.json"))
            config = config.replace("127.0.0.1:8080", f"127.0.0.1:{port}")
            config = config.replace("sha256:REPLACED_BY_RUN_SH", "sha256:" + hashlib.sha256(KEY.encode()).hexdigest())
            for old, service in zip(range(7701, 7705), services):
                config = config.replace(f"127.0.0.1:{old}", f"127.0.0.1:{service.server_port}")
            config += f"""
# The refund ledger: vouches that a refund posted, independently of the payment API.
[[evidence_issuers]]
issuer = "{LEDGER}"
tenants = ["tenant_acme_prod"]
satisfies = ["refund_posted"]
max_validity_seconds = 3600
algorithm = "EdDSA"
jwks = '''{json.dumps(jwks)}'''

# The ledger's relay: may report outcome readings, nothing else.
[[api_keys]]
key_sha256 = "sha256:{hashlib.sha256(LEDGER_KEY.encode()).hexdigest()}"
tenant_id = "tenant_acme_prod"
principal_id = "svc_refund_ledger"
scopes = ["outcome:report"]
"""
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
                run = client.admit(json.loads((EXAMPLE / "requests/run.json").read_text()))
                call = json.loads((EXAMPLE / "requests/tool_call.json").read_text())
                run.call_tool(call["capability_id"], call["args"], approval_mode="destructive",
                              idempotency_key=call["idempotency_key"], evidence_refs=call["evidence_refs"],
                              tool_call_id="tc_refund")
                print("Payment API confirmed the refund of INR 1200 for ord_881.")
                cited = [{"tool_call_id": "tc_refund", "operation_id": call["idempotency_key"]}]
                decide = lambda: run.record_decision("support.refund.execute", "DECIDED",  # noqa: E731
                                                     outcome="refund_issued", tool_calls=cited)
                assert refused(decide) == "outcome_pending"
                assert refused(run.complete) == "outcome_pending"
                print("Decision and completion refused: outcome_pending (the ledger has not reported).")

                time.sleep(0.2)  # the reading is taken after the refund
                ledger = Client(base, token=LEDGER_KEY)
                operation = call["idempotency_key"]
                wrong = attest(tmp, posted("ord_881", 90_000))["attestation"]
                code = refused(lambda: ledger.report_outcome(run.run_id, operation, wrong))
                assert code == "outcome_amount_mismatch", code
                print("Ledger reading of INR 900 refused: outcome_amount_mismatch.")
                reading = attest(tmp, posted("ord_881", 120_000))["attestation"]
                closed = ledger.report_outcome(run.run_id, operation, reading)
                assert closed["state"] == "witnessed" and closed["late"] is False, closed
                print("Ledger reading of INR 1200 for ord_881 accepted: refund_posted witnessed.")

                decision = decide()
                refs = decision["record"]["tool_lineage"][0]["artifact_refs"]
                assert refs == ["outcome:" + closed["observation"]["attestation_digest"]], refs
                print(f"Decision cites the ledger's reading: {refs[0][:30]}…")
                assert run.complete()["status"] == "completed"
                print("Run completed.")

                evidence = run.evidence()
                assert [o["state"] for o in evidence["outcomes"]] == ["witnessed"], evidence["outcomes"]
                entries = client.request("GET", "/v1/audit/entries", query={"from": 1, "limit": 1000})
                kinds = [e["kind"] for e in entries["entries"]]
                assert kinds.count("outcome_pending") == 1 and kinds.count("outcome_witnessed") == 1, kinds
                keys = client.request("GET", "/v1/audit/keys")
                (tmp / "entries.json").write_text(json.dumps(entries))
                (tmp / "keys.json").write_text(json.dumps(keys))
                verified = subprocess.run(
                    [str(BIN / "ctx"), "audit-verify", "--entries", str(tmp / "entries.json"),
                     "--keys", str(tmp / "keys.json")], check=True, capture_output=True, text=True)
                proof = json.loads(verified.stdout)
                assert proof["verified"] is True, proof
                print("Offline audit verification:", json.dumps(proof, sort_keys=True))
                print("outcome witnessed")
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
