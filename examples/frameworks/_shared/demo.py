"""Shared setup for the framework examples: one admitted run, its governed tools, and
the model-call budget, so each example shows only what its framework adds.

Every example governs the same task, the quickstart's refund of order ord_881:

- ``lookup_order`` is read-only; ``issue_refund`` is an external effect that must cite
  the order snapshot as evidence and is keyed so it can never apply twice.
- The tool bodies never run locally: ``governed_tool`` sends each call through
  ``contextosd``, which authorizes, dispatches, records and audits it.
- Each model call reserves tokens from the run's budget first (``budgeted``), the same
  ledger tool calls spend, so the agent cannot loop past its budget.

Run an example with ``./examples/frameworks/run.sh <framework>``. With ``--approval``
the run is admitted for a refund above the pack's 3,000 threshold, so the refund pauses
for an exact approval: the example surfaces it through the framework's human-in-the-loop
mechanism, ``approve`` plays the reviewer, and the framework re-sends the same call.
"""
import contextlib
import json
import os
import pathlib
import sys
import time
import urllib.request
from typing import Iterator, Tuple

from contextos.client import Client, Run, ToolBlocked, ToolFailed, ToolOutcome, ToolPaused, ToolRejected, governed_tool

ROOT = pathlib.Path(__file__).resolve().parents[3]
REQUESTS = ROOT / "examples/support-refund/requests"
EVIDENCE = ["kg:order:ord_881#snapshot_kg_2026_05_03_T0930"]
GOAL = "Customer cus_77 reports order ord_881 arrived damaged. Check the order and refund it if it is refundable."
INSTRUCTIONS = (
    "You are a support agent. Look the order up before acting. Refund only a refundable order, "
    "for at most its amount_minor. If a tool reports that an action was refused or paused, "
    "do not retry it: explain what happened."
)
# `--approval`: the pack's high-value rule requires an approval above 3,000.
APPROVAL = "--approval" in sys.argv[1:]
# A model call reserves at least `[guards] model_call_min_tokens` (1,000 by default).
MODEL_CALL_TOKENS = 1000

__all__ = ["GOAL", "INSTRUCTIONS", "EVIDENCE", "APPROVAL", "admit", "tools", "budgeted", "refusal", "approve", "finish",
           "offline",
           "ToolOutcome", "ToolPaused", "ToolBlocked", "ToolRejected", "ToolFailed"]


def offline(*env_keys: str) -> bool:
    """True when none of the provider keys is set: the example then uses a scripted model."""
    return not any(os.environ.get(key) for key in env_keys)


def admit(name: str) -> Tuple[Client, Run]:
    """Admits a fresh run of the quickstart's support pack for this example."""
    client = Client(os.environ.get("CONTEXTOS_URL", "http://127.0.0.1:8080"), token=os.environ["CONTEXTOS_TOKEN"])
    run_id = f"run_{name}_{int(time.time() * 1000)}"
    body = json.loads((REQUESTS / "run.json").read_text())
    body["run_context"]["run_id"] = body["contract"]["run_id"] = run_id
    body["contract"]["contract_id"] = f"contract_{run_id}"
    if APPROVAL:
        body["request"]["input"]["context"]["refund_amount"] = 5000
    run = client.admit(body)
    print(f"admitted {run.run_id} (executor generation {run.executor_generation})")
    return client, run


def tools(run: Run):
    """The run's two governed tools as plain typed functions, for any framework that
    builds tool schemas from signatures and docstrings."""

    # The pack's high-value rule gates every call of the run, reads included. An approval
    # binds one operation, so with --approval the lookup is keyed too: the re-sent call
    # is the same operation and redeems it. Otherwise each read is its own operation.
    keyed = {"idempotency_key": lambda order_id: f"lookup:{order_id}",
             "tool_call_id": lambda order_id: f"tc_lookup_{order_id}"} if APPROVAL else {}

    @governed_tool(run, "adp_orders.lookup", approval_mode="read_only", **keyed)
    def lookup_order(order_id: str) -> dict:
        """Look up an order's status, amount (amount_minor) and refund eligibility."""

    @governed_tool(run, "adp_payments.issue_refund", approval_mode="destructive",
                   idempotency_key=lambda order_id, **_: f"refund:{order_id}",
                   tool_call_id=lambda order_id, **_: f"tc_refund_{order_id}", evidence_refs=EVIDENCE)
    def issue_refund(order_id: str, customer_id: str, amount_minor: int) -> dict:
        """Issue a refund for an order to its customer, in minor units of the order's currency."""

    return lookup_order, issue_refund


@contextlib.contextmanager
def budgeted(run: Run, tokens: int = MODEL_CALL_TOKENS) -> Iterator[str]:
    """Reserves budget for one model call; refused with ``budget_exhausted`` when the run
    cannot afford it. In production pass the reservation id to your LLM gateway, which
    meters the call with the ``meter`` scope; settling it here charges all of it."""
    reservation = run.reserve_usage("model_call", tokens=tokens)
    try:
        yield reservation
    finally:
        run.settle_usage(reservation)


def refusal(outcome: ToolOutcome) -> str:
    """What the model is told when the gateway did not complete a call: whether anything
    happened, why, and that retrying will not change it. Approval and input pauses are
    for the framework's human-in-the-loop path; this text is for everything else."""
    reasons = ", ".join(outcome.reason_codes) or outcome.status
    kind = outcome.kind if isinstance(outcome, ToolPaused) else None
    if kind == "duplicate":
        return f"ALREADY REQUESTED ({reasons}): this exact action was submitted before and was not repeated."
    if kind == "unknown_outcome":
        return f"OUTCOME UNKNOWN ({reasons}): the action may have happened and is being reconciled; do not retry it."
    return f"NOT DONE ({outcome.status}: {reasons}). The action did not take effect; do not retry it."


def approve(paused: ToolPaused) -> None:
    """Plays the reviewer: approves the paused call's exact action in the development
    approval service. In production a person decides in your approval service, which
    shows them the bound action; the agent never approves its own calls."""
    request_id = paused.report["approval_request_id"]
    port = os.environ["CONTEXTOS_DEV_PORTS"].split(",")[2]
    body = json.dumps({"op": "approve", "approval_request_id": request_id}).encode()
    urllib.request.urlopen(urllib.request.Request(f"http://127.0.0.1:{port}/", body,
                                                  {"Content-Type": "application/json"}), timeout=5).read()
    print(f"reviewer approved {request_id}")


def finish(client: Client, run: Run, refunded: bool, summary: str) -> None:
    """Records the decision (its tool lineage is verified by the gateway), completes the
    run and prints its evidence."""
    calls = [{"tool_call_id": "tc_refund_ord_881", "operation_id": "refund:ord_881"}] if refunded else []
    decision = run.record_decision("support.refund.execute", "DECIDED" if refunded else "REJECTED",
                                   outcome="refund_issued" if refunded else None, tool_calls=calls,
                                   rationale={"strategy": summary[:500]})
    print(f"decision {decision['record']['record_id']} ({'refunded' if refunded else 'not refunded'})")
    print(f"run {run.complete()['status']}")
    evidence = run.evidence()
    entries = sum(1 for _ in client.audit_entries())
    print(f"evidence: budget used {evidence['budget_ledger']['used']}, {entries} signed audit entries")
