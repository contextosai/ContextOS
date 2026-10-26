"""A deterministic peer cooperation loop using the existing governed HTTP client."""
import concurrent.futures
import hashlib
import json
import os
import pathlib
import threading
import time
import uuid

from contextos.client import Client, ContextOSHTTPError

ROOT = pathlib.Path(__file__).resolve().parents[2]


def admission_for(run_id):
    body = json.loads((ROOT / "examples/support-refund/requests/run.json").read_text())
    body["run_context"]["run_id"] = body["contract"]["run_id"] = run_id
    body["contract"]["contract_id"] = "contract_" + run_id
    return body


def peer(parent, parent_body, suffix):
    child_id = parent.run_id + suffix
    agent = parent_body["run_context"]["agent"]["agent_id"]
    envelope = {
        "envelope_version": "contextos.agent_delegation.v1", "delegation_id": "dlg_" + child_id,
        "parent_run_id": parent.run_id, "child_run_id": child_id, "trace_id": parent.trace_id,
        "tenant_id": parent_body["contract"]["tenant_id"], "issuer": agent, "subject": agent,
        "principal_chain": parent.principal_chain,
        "scope": {"allowed_intents": [parent_body["request"]["input"]["intent"]],
                  "allowed_capabilities": ["adp_orders.lookup"], "data_classification_ceiling": "CONFIDENTIAL",
                  "output_schema_ref": "schema://orders/refund-evidence.v1"},
        "sub_budget": {"total_tokens": 100, "bucket_tokens": {}, "max_tool_calls": 2,
                       "max_replan_attempts": 0, "wall_clock_ms": 60000, "max_cost_cents": 1},
        "effect_policy": "read_only", "issued_at": "2020-01-01T00:00:00Z", "expires_at": "2098-01-01T00:00:00Z",
        "parent_claim_hash": parent.admitted["compiled_context_hash"],
    }
    return parent.delegate(admission_for(child_id), envelope)


def report(kind, data):
    # A digest of actual local observations. This remains worker-reported evidence.
    digest = hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()
    return [{"artifact_type": "demo_observation", "artifact_id": kind, "sha256": "sha256:" + digest}]


def main():
    client = Client(os.environ["CONTEXTOS_URL"], token=os.environ["CONTEXTOS_TOKEN"])
    body = admission_for("run_peers_" + uuid.uuid4().hex[:12])
    parent = client.admit(body)
    a, b = peer(parent, body, "_a"), peer(parent, body, "_b")
    parent.publish_work("research", "Read order status", "A governed order lookup returns an observation")
    a.publish_work("summarize", "Summarize the observation", "Record the demonstration's observed status",
                   dependencies=["research"])
    try:
        b.update_work("summarize", "claim", 1, lease_seconds=30)
        raise AssertionError("a dependency was skipped")
    except ContextOSHTTPError as error:
        assert error.code == "work_not_ready", error
    print("peers discovered two tasks; dependency blocks premature work")

    barrier = threading.Barrier(2)

    def compete(run):
        barrier.wait(timeout=5)
        try:
            return run, run.update_work("research", "claim", 1, lease_seconds=1)
        except ContextOSHTTPError as error:
            assert error.code == "work_conflict", error
            return run, None

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(compete, [a, b]))
    assert sum(result is not None for _, result in results) == 1
    first = next(run for run, result in results if result is not None)
    replacement = b if first is a else a
    print("concurrent claims: exactly one winner")

    # Simulate an abandoned worker before any tool effect. In real recovery, inspect
    # the prior worker's operations and reconcile unknown effects before repeating.
    timeout = time.monotonic() + 5
    while not replacement.work_task("research")["task"]["available"]:
        if time.monotonic() >= timeout:
            raise AssertionError("lease did not expire")
        time.sleep(0.05)
    current = replacement.update_work("research", "claim", 2, lease_seconds=30)["task"]
    assert current["previous_claim"]["run_id"] == first.run_id
    assert current["lease_epoch"] == 2
    try:
        first.update_work("research", "complete", 3, lease_epoch=1, evidence_refs=report("stale", {}))
        raise AssertionError("an old lease completed current work")
    except ContextOSHTTPError as error:
        assert error.code == "work_lease_stale", error
    print("abandoned lease reclaimed; stale completion refused")

    order = replacement.call_tool("adp_orders.lookup", {"order_id": "ord_881"}, approval_mode="read_only")
    replacement.update_work("research", "complete", 3, lease_epoch=2, evidence_refs=report("order", order))
    first.update_work("summarize", "claim", 1, lease_seconds=30)
    first.update_work("summarize", "complete", 2, lease_epoch=1, evidence_refs=report("summary", order["status"]))
    tasks = parent.work_tasks()["tasks"]
    assert len(tasks) == 2 and all(t["status"] == "completed" for t in tasks)
    assert parent.work_task("research")["evidence_verified"] is False
    print("dependency chain completed; evidence remains worker-reported")

    for lane in (a, b):
        closed = parent.close_child(lane, "accept")
        assert closed["status"] == "closed", closed
    assert parent.complete()["status"] == "completed"
    print("peer coordination complete; ordinary child acceptance and run completion retained")


if __name__ == "__main__":
    main()
