"""End-to-end test of the HTTP client against a real contextosd.

Run with: cargo build --release -p contextosd -p ctx &&
          PYTHONPATH=bindings/python python3 bindings/python/tests/test_client.py
"""
import hashlib
import importlib.util
import json
import os
import pathlib
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request

from contextos.client import Client, ContextOSHTTPError, ToolBlocked, ToolPaused, governed_tool

ROOT = pathlib.Path(__file__).resolve().parents[3]
BINARY = ROOT / "target/release/contextosd"
EXAMPLE = ROOT / "examples/support-refund"
KEY = "dev-key-0123456789abcdef0123456789abcdef"
JUDGE_KEY = "dev-judge-0123456789abcdef0123456789abcd"
OPS_KEY = "dev-ops-0123456789abcdef0123456789abcdef"


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def start_world():
    spec = importlib.util.spec_from_file_location("dev_services", EXAMPLE / "dev_services.py")
    dev = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(dev)
    ports = {name: free_port() for name in ("authority", "constraints", "approvals", "payments", "server")}
    for name, handler in (("authority", dev.authority), ("constraints", dev.constraints),
                          ("approvals", dev.approvals), ("payments", dev.payments)):
        dev.serve(ports[name], handler)
    config = (EXAMPLE / "contextosd.toml").read_text()
    config = config.replace("127.0.0.1:8080", f"127.0.0.1:{ports['server']}")
    for name, default in (("authority", 7701), ("constraints", 7702), ("approvals", 7703), ("payments", 7704)):
        config = config.replace(f"127.0.0.1:{default}", f"127.0.0.1:{ports[name]}")
    config = config.replace('"examples/', f'"{EXAMPLE.parent}/')
    config = config.replace("sha256:REPLACED_BY_RUN_SH", "sha256:" + hashlib.sha256(KEY.encode()).hexdigest())
    path = pathlib.Path(tempfile.mkdtemp()) / "contextosd.toml"
    path.write_text(config)
    server = subprocess.Popen([str(BINARY), "--config", str(path)], env={**os.environ, "CONTEXTOS_AUDIT_SEED": "11" * 32},
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    base = f"http://127.0.0.1:{ports['server']}"
    for _ in range(100):
        try:
            urllib.request.urlopen(base + "/readyz", timeout=1)
            break
        except OSError:
            time.sleep(0.05)
    return server, base


def main() -> None:
    if not BINARY.exists():
        print(f"skipped: {BINARY} not built")
        return
    server, base = start_world()
    try:
        client = Client(base, token=KEY)
        admission = json.loads((EXAMPLE / "requests/run.json").read_text())
        run = client.admit(admission)
        assert run.executor_generation == 2, run

        call = json.loads((EXAMPLE / "requests/tool_call.json").read_text())
        output = run.call_tool(call["capability_id"], call["args"], approval_mode="destructive",
                               idempotency_key=call["idempotency_key"], evidence_refs=call["evidence_refs"],
                               tool_call_id="tc_1")
        assert output["refund_id"] == "rf_ord_881", output

        # Replaying the operation is refused before the provider and raises, never returns.
        try:
            run.call_tool(call["capability_id"], call["args"], approval_mode="destructive",
                          idempotency_key=call["idempotency_key"], evidence_refs=call["evidence_refs"])
            raise AssertionError("replay must not succeed")
        except ToolPaused as paused:
            assert paused.reason_codes == ["retry_unsafe"], paused.reason_codes

        # A decorated tool: the signature becomes the governed arguments.
        @governed_tool(run, call["capability_id"], approval_mode="destructive",
                       idempotency_key=lambda **a: f"refund:{a['order_id']}:again",
                       evidence_refs=call["evidence_refs"])
        def issue_refund(order_id: str, customer_id: str, amount_minor: int):  # pragma: no cover
            raise AssertionError("never runs locally")

        try:
            issue_refund("ord_881", "cus_77", amount_minor=999_999_999)
            raise AssertionError("an amount beyond the grant must not succeed")
        except ToolBlocked as refused:
            assert refused.reason_codes == ["scope_mismatch"], refused.reason_codes

        decision = run.record_decision("support.refund.execute", "DECIDED", outcome="refund_issued",
                                       tool_calls=[{"tool_call_id": "tc_1", "operation_id": call["idempotency_key"]}])
        assert decision["record"]["tool_lineage"][0]["tool_call_id"] == "tc_1"

        # An independent evaluator scores the decision; the executor's key cannot.
        record_id = decision["record"]["record_id"]
        try:
            client.score(run.run_id, record_id, "evaluator.refund_quality@3", policy=1.0, utility=0.9, safety=1.0)
            raise AssertionError("the executor scored its own decision")
        except ContextOSHTTPError as refused:
            assert refused.status == 403, refused
        judge = Client(client.base_url, JUDGE_KEY)
        scored = judge.score(run.run_id, record_id, "evaluator.refund_quality@3", policy=1.0, utility=0.9, safety=1.0)
        assert scored["score"]["scorecard"]["latency"] == decision["record"]["budget_usage"]["wall_clock_ms"]

        # Failover: a second executor takes over; the first is fenced.
        replacement = client.attach(run.run_id, run.trace_id, run.principal_chain).take_over()
        assert replacement.executor_generation == 4
        stale = run.envelope(call["capability_id"], call["args"], approval_mode="destructive",
                             idempotency_key="refund:other", evidence_refs=call["evidence_refs"])
        response = client.request("POST", f"/v1/runs/{run.run_id}/tool-calls", stale, generation=2)
        assert response["report"]["reason_codes"] == ["executor_stale"], response

        # Kill switch: a revoked capability is blocked before it is sent; restored, it runs.
        ops = Client(client.base_url, OPS_KEY)
        ops.revoke("capability", "adp_payments.issue_refund", "incident 4711")
        assert ops.revocations()["revoked"][0]["by"] == "svc_oncall"
        try:
            replacement.call_tool(call["capability_id"], call["args"], approval_mode="destructive",
                                  idempotency_key="refund:revoked", evidence_refs=call["evidence_refs"])
            raise AssertionError("a revoked capability ran")
        except ToolBlocked as blocked:
            assert blocked.reason_codes == ["revoked_capability"], blocked.reason_codes
        assert ops.restore("capability", "adp_payments.issue_refund", "resolved")["revoked"] == []

        assert replacement.complete()["status"] == "completed"
        evidence = replacement.evidence()
        assert evidence["run_state"]["status"] == "completed"
        entries = list(client.audit_entries(page=2))
        assert [e["sequence"] for e in entries] == list(range(1, len(entries) + 1))
        print(f"ok: client end to end ({len(entries)} audit entries)")
    finally:
        server.terminate()
        server.wait(timeout=10)


if __name__ == "__main__":
    sys.exit(main())
