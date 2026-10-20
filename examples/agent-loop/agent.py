"""A complete governed agent loop over the ContextOS HTTP client.

    plan -> delegate research (read-only lane) -> critic -> act (governed effect)
         -> decide (verified DecisionRecord) -> complete -> evidence

The planner and critic are deterministic so the example runs anywhere; each is a
single function where a model call would go. Everything that matters for safety is
enforced by contextosd, not by this script: the research lane cannot act, the refund
cannot repeat, the decision's lineage is verified, and every step is audited.

Run with: ./examples/agent-loop/run.sh
"""
import json
import os
import pathlib
import sys
import time

from contextos.client import Client, ToolBlocked, ToolPaused, ToolRejected

ROOT = pathlib.Path(__file__).resolve().parents[2]
REQUESTS = ROOT / "examples/support-refund/requests"
EVIDENCE = ["kg:order:ord_881#snapshot_kg_2026_05_03_T0930"]


def admission_for(run_id: str) -> dict:
    body = json.loads((REQUESTS / "run.json").read_text())
    body["run_context"]["run_id"] = run_id
    body["contract"]["run_id"] = run_id
    body["contract"]["contract_id"] = f"contract_{run_id}"
    return body


def plan(goal: str) -> list:
    """The planner: a model would turn the goal into steps over surfaced tools."""
    return [
        {"lane": "research", "tool": "adp_orders.lookup", "args": {"order_id": "ord_881"}},
        {"tool": "adp_payments.issue_refund", "args": {"order_id": "ord_881", "customer_id": "cus_77"}},
    ]


def critic(order: dict, refund_amount: int) -> tuple:
    """The critic: a model (or rules) judges the step against the evidence."""
    if not order.get("refundable"):
        return False, "order is not refundable"
    if refund_amount > order["amount_minor"]:
        return False, "refund exceeds the order amount"
    return True, "damaged delivery, refund within order amount"


def main() -> int:
    client = Client(os.environ.get("CONTEXTOS_URL", "http://127.0.0.1:8080"), token=os.environ["CONTEXTOS_TOKEN"])
    run_id = f"run_agent_{int(time.time() * 1000)}"
    parent_body = admission_for(run_id)
    run = client.admit(parent_body)
    print(f"admitted {run.run_id} (executor generation {run.executor_generation})")
    steps = plan("Refund the damaged order ord_881")

    # Delegate research to a read-only lane: it can read the order, never act.
    research = steps[0]
    child_id = f"{run_id}_research"
    child_body = admission_for(child_id)
    agent = parent_body["run_context"]["agent"]["agent_id"]
    envelope = {
        "envelope_version": "contextos.agent_delegation.v1", "delegation_id": f"dlg_{child_id}",
        "parent_run_id": run.run_id, "child_run_id": child_id, "trace_id": run.trace_id,
        "tenant_id": parent_body["contract"]["tenant_id"], "issuer": agent, "subject": agent,
        "principal_chain": run.principal_chain,
        "scope": {"allowed_intents": [parent_body["request"]["input"]["intent"]],
                  "allowed_capabilities": [research["tool"]], "data_classification_ceiling": "CONFIDENTIAL",
                  "output_schema_ref": "schema://orders/refund-evidence.v1"},
        "sub_budget": {"total_tokens": 1000, "bucket_tokens": {}, "max_tool_calls": 2, "max_replan_attempts": 0,
                       "wall_clock_ms": 60000, "max_cost_cents": 1},
        "effect_policy": "read_only", "issued_at": "2020-01-01T00:00:00Z", "expires_at": "2098-01-01T00:00:00Z",
        "parent_claim_hash": run.admitted["compiled_context_hash"],
    }
    lane = run.delegate(child_body, envelope)
    order = lane.call_tool(research["tool"], research["args"], approval_mode="read_only")
    print(f"research lane {lane.run_id} found: {order}")
    try:
        lane.call_tool("adp_payments.issue_refund", {"order_id": "ord_881", "customer_id": "cus_77", "amount_minor": 1},
                       approval_mode="destructive", idempotency_key="lane:refund", evidence_refs=EVIDENCE)
        print("UNEXPECTED: the read-only lane acted")
        return 1
    except (ToolRejected, ToolBlocked, ToolPaused) as refused:
        print(f"research lane cannot act: {refused.reason_codes}")
    settled = run.close_child(lane, "accept")
    print(f"closed research lane; usage settled into the parent: tool_calls={settled['usage']['tool_calls']}")

    # Critic, then the governed effect.
    refund = steps[1]
    amount = order["amount_minor"]
    ok, why = critic(order, amount)
    if not ok:
        run.record_decision("support.refund.execute", "REJECTED", rationale={"strategy": why})
        run.complete()
        return 0
    args = dict(refund["args"], amount_minor=amount)
    try:
        output = run.call_tool(refund["tool"], args, approval_mode="destructive", idempotency_key="refund:ord_881",
                               evidence_refs=EVIDENCE, tool_call_id="tc_refund")
    except ToolPaused as paused:
        print(f"paused: {paused.reason_codes} {paused.obligations}; a real agent waits or reconciles here")
        return 0
    print(f"refund issued: {output}")

    decision = run.record_decision(
        "support.refund.execute", "DECIDED", outcome="refund_issued",
        tool_calls=[{"tool_call_id": "tc_refund", "operation_id": "refund:ord_881"}],
        rationale={"strategy": why},
    )
    print(f"decision {decision['record']['record_id']} signed at audit hash {decision['record']['audit']['record_hash'][:23]}…")
    print(f"run {run.complete()['status']}")

    evidence = run.evidence()
    entries = list(client.audit_entries())
    print(f"evidence: {len(evidence['decisions'])} decision(s), budget used {evidence['budget_ledger']['used']}, "
          f"{len(entries)} signed audit entries")
    return 0


if __name__ == "__main__":
    sys.exit(main())
