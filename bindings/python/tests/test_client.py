"""End-to-end test of the HTTP client against a real contextosd.

Run with: cargo build --release -p contextosd -p ctx &&
          PYTHONPATH=bindings/python python3 bindings/python/tests/test_client.py
"""
import asyncio
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

from contextos.aio import AsyncClient, AsyncRun
from contextos.client import (BudgetExhausted, Client, ContextOSHTTPError, ToolBlocked, ToolPaused, ToolRejected,
                              governed_tool, task_authorization, task_scope)

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

        # This example's refund declares no compensation: nothing is listed, and a request
        # to compensate it is refused before the provider.
        assert run.compensations() == {"run_id": run.run_id, "effects": []}
        try:
            run.compensate(call["idempotency_key"])
            raise AssertionError("an undeclared compensation must not run")
        except ToolRejected as refused:
            assert refused.reason_codes == ["compensation_not_declared"], refused.reason_codes
        assert run.compensate_all()["status"] == "compensated"


        # A run bound to what the user asked: the refund of ord_881 to cus_77, up to INR 1200.
        scoped = json.loads((EXAMPLE / "requests/run.json").read_text())
        for part in ("run_context", "contract"):
            scoped[part]["run_id"] = "run_scoped"
        scoped["contract"]["contract_id"] = "contract_scoped"
        user = {"principal_id": "usr_771", "principal_type": "person", "trust_domain": "contextos.dev",
                "tenant_id": "tenant_acme_prod"}
        scoped["task_authorization"] = task_authorization(user, [task_scope(
            "run_scoped", "support.refund", call["capability_id"], resources=["ord_881"], destinations=["cus_77"],
            amount=(120_000, "INR"))])
        scoped_run = client.admit(scoped)
        try:
            scoped_run.call_tool(call["capability_id"], {**call["args"], "amount_minor": 480_000},
                                 approval_mode="destructive", idempotency_key="refund:more",
                                 evidence_refs=call["evidence_refs"])
            raise AssertionError("a refund beyond what the user asked must not run")
        except ToolBlocked as refused:
            assert "outside_task_authorization" in refused.reason_codes, refused.reason_codes
            assert "task_scope_amount" in refused.reason_codes, refused.reason_codes
        # The executor may restrict its own task further; widening is not its call.
        lower = task_authorization(user, [task_scope(
            "run_scoped", "support.refund", call["capability_id"], resources=["ord_881"], destinations=["cus_77"],
            amount=(50_000, "INR"))], max_effects=1, amount_total=(50_000, "INR"))
        assert lower["limits"] == {"max_effects": 1, "amount_total": {"minor_units": 50_000, "currency": "INR"}}
        assert client.amend_task_authorization("run_scoped", 0, lower)["change"] == "narrowed"
        try:
            client.amend_task_authorization("run_scoped", 1, scoped["task_authorization"])
            raise AssertionError("the executor widened its own task")
        except ContextOSHTTPError as refused:
            assert refused.status == 403, refused

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

        # The orchestrator checkpoints its state after each verdict.
        assert run.checkpoint({"step": 1, "verdict": "accept"}, 0)["revision"] == 1

        # Advisory peer tasks use conditional revisions, never tool authority.
        task = run.publish_work("inspect", "Inspect the order", "Record a test report")["task"]
        assert task["revision"] == 1
        assert run.work_tasks(limit=1)["tasks"][0]["task_id"] == "inspect"
        assert run.work_task("inspect")["data_only"] is True
        claimed = run.update_work("inspect", "claim", 1, lease_seconds=30)["task"]
        assert claimed["claim"]["run_id"] == run.run_id
        proof = {"artifact_type": "test", "artifact_id": "local-report", "sha256": "sha256:" + "a" * 64}
        done = run.update_work("inspect", "complete", 2, lease_epoch=1, evidence_refs=[proof])
        assert done["task"]["status"] == "completed" and done["evidence_verified"] is False
        try:
            run.update_work("inspect", "claim", 1, lease_seconds=30)
            raise AssertionError("stale task revision was accepted")
        except ContextOSHTTPError as refused:
            assert refused.code == "work_conflict", refused

        # Model calls spend the run's budget; a self-reported settlement charges it all.
        reservation = run.reserve_usage("model_call", tokens=3000)
        assert run.settle_usage(reservation)["charged"]["tokens"] == 3000
        # A reservation the run cannot afford is refused before the model is called.
        try:
            with run.budgeted_model_call(tokens=1_000_000):
                raise AssertionError("the model call ran")
        except BudgetExhausted as exhausted:
            assert exhausted.status == 409 and exhausted.reasons, exhausted

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

        # The reviewer files a correction; an operator closes it with evidence.
        filed = judge.file_feedback(run.run_id, "correction", "policy", "Refund should have been escalated.",
                                    decision_record_id=record_id, expected_outcome="escalate")
        assert filed["replay_obligation"]["case"] == run.run_id
        assert client.open_feedback()["open"] == 1
        closed = Client(client.base_url, OPS_KEY).close_feedback(
            filed["feedback_id"], "fixed", artifact_type="gate_report", artifact_id="gate_1", sha256="sha256:" + "c" * 64)
        assert closed["status"] == "fixed"
        assert client.open_feedback()["open"] == 0

        # No escalations are open; resolving an unknown one is refused.
        assert client.open_escalations()["open"] == 0
        try:
            Client(client.base_url, OPS_KEY).resolve_escalation("esc_unknown", "handled", "n/a")
            raise AssertionError("resolved an unknown escalation")
        except ContextOSHTTPError as refused:
            assert refused.status == 404, refused

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

        assert replacement.latest_checkpoint()["state"] == {"step": 1, "verdict": "accept"}
        assert replacement.complete()["status"] == "completed"
        evidence = replacement.evidence()
        assert evidence["run_state"]["status"] == "completed"
        entries = list(client.audit_entries(page=2))
        assert [e["sequence"] for e in entries] == list(range(1, len(entries) + 1))
        print(f"ok: client end to end ({len(entries)} audit entries)")
        asyncio.run(async_client(base, admission))
    finally:
        server.terminate()
        server.wait(timeout=10)


async def async_client(base: str, admission: dict) -> None:
    """The asyncio client: the same flow as coroutines, concurrent on one event loop."""
    client = AsyncClient(base, token=KEY)
    admission = json.loads(json.dumps(admission))
    admission["run_context"]["run_id"] = admission["contract"]["run_id"] = "run_async_1"
    admission["contract"]["contract_id"] = "contract_run_async_1"
    run = await client.admit(admission)
    assert isinstance(run, AsyncRun) and run.executor_generation == 2, run
    await run.publish_work("async-task", "Inspect", "Record a report")
    assert (await run.work_tasks())["tasks"][0]["available"] is True
    await run.update_work("async-task", "claim", 1, lease_seconds=30)
    assert (await run.work_task("async-task"))["task"]["lease_epoch"] == 1
    await run.update_work("async-task", "release", 2, lease_epoch=1)

    @governed_tool(run, "adp_orders.lookup")
    async def lookup_order(order_id: str) -> dict:  # pragma: no cover
        raise AssertionError("never runs locally")

    async with run.budgeted_model_call(tokens=1000) as reservation:
        assert reservation.startswith("usage:"), reservation
    orders = await asyncio.gather(lookup_order("ord_881"), lookup_order(order_id="ord_881"))
    assert [o["order_id"] for o in orders] == ["ord_881", "ord_881"], orders
    try:
        async with run.budgeted_model_call(tokens=1_000_000):
            raise AssertionError("the model call ran")
    except BudgetExhausted:
        pass
    # Takeover keeps the handle; the run is fenced at the new generation.
    taken = await (await client.attach(run.run_id, run.trace_id, run.principal_chain)).take_over()
    assert isinstance(taken, AsyncRun) and taken.executor_generation == 4, taken
    assert (await taken.complete())["status"] == "completed"
    sequences = [entry["sequence"] async for entry in client.audit_entries(page=3)]
    assert sequences == list(range(1, len(sequences) + 1))
    print(f"ok: asyncio client end to end ({len(sequences)} audit entries)")


if __name__ == "__main__":
    sys.exit(main())
