#!/usr/bin/env python3
"""Replays a staging support agent's recorded refunds through a staging gateway set up
like deploy/profiles/consequential-tools.toml.

The recording (traffic.jsonl) is what the agent did in staging without ContextOS: a
test refund, a refund on a live order (its staging credential reached production), the
same test refund again from a new run, and refunds past what one agent should commit in
a day."""
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "bindings/python"))
sys.path.insert(0, str(ROOT / "examples/replay"))
from contextos.client import Client  # noqa: E402
from contextos.replay import ToolServer, load_traffic, markdown, replay  # noqa: E402
from local_gateway import local_gateway  # noqa: E402

HERE = Path(__file__).resolve().parent
OUT = Path(os.environ.get("CONTEXTOS_RECEIPT_DIR", ROOT / "receipts/consequential-tools"))
GUARDS = '''
# This gateway serves staging: refunds on live orders are not its to send.
[guards.environments]
current = "staging"
[[guards.environments.targets]]
capabilities = ["adp_payments.issue_refund"]
pointer = "/order_id"
prefixes = { "ord_" = "production", "test_ord_" = "staging" }

# Each agent may refund INR 1,500 a day, across all its runs.
[[guarantees]]
id = "refunds-per-agent-day"
capability_ids = ["adp_payments.issue_refund"]
resource_from = "actor"
amount_pointer = "/amount_minor"
limit = 150000
unit = "INR_minor"
window_seconds = 86400
'''


def main() -> None:
    tools = ToolServer()
    try:
        # The refund manifest names its intent: one refund per order, whichever run sends it.
        with local_gateway(tools, GUARDS, {"issue_refund.json": HERE / "issue_refund.json"}) as (base, key):
            with (HERE / "traffic.jsonl").open() as f:
                records = load_traffic(f)
            template = json.loads((ROOT / "examples/replay/admission.json").read_text())
            report = replay(Client(base, key), records, template, tools)
    finally:
        tools.close()
    print(markdown(report))
    reasons = report["reasons"]
    assert reasons.get("environment_mismatch") == 1, report["entries"]
    print("prod refund refused: the staging gateway does not send effects to production")
    assert reasons.get("effect_repeated_across_runs") == 1, report["entries"]
    print("duplicate refused: the same refund from a second run")
    assert reasons.get("shared_guarantee_exceeded") == 1, report["entries"]
    print("cost cap held: the agent's daily refund cap")
    expected = {"recorded_effects": 5, "effects_sent": 2, "effects_prevented": 2,
                "duplicates_refused": 1, "limits_held": 1}
    assert {k: report[k] for k in expected} == expected, ({k: report[k] for k in expected}, report["entries"])
    # The recording shows the live refund succeeding, so the report asks a person to
    # review its refusal; here the review confirms it: staging had no business sending it.
    assert [c["line"] for c in report["false_block_candidates"]] == [3], report["false_block_candidates"]
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "replay-report.json").write_text(json.dumps(report, indent=2))
    (OUT / "replay-report.md").write_text(markdown(report))
    print(f"consequential-tools report written: {OUT / 'replay-report.md'}")


if __name__ == "__main__":
    main()
