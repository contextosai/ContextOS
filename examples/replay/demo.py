#!/usr/bin/env python3
"""Replays a morning of recorded support-agent tool calls through a local gateway.

The recording (traffic.jsonl) is what the agents really did without ContextOS: one
refund sent twice after a client timeout, a second channel refunding the same order,
a refund whose response was lost, and a refund above the approval threshold. Every
call goes to the replay's own tool server, which answers with the recorded outcome."""
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "bindings/python"))
from contextos.client import Client  # noqa: E402
from contextos.replay import ToolServer, load_traffic, markdown, replay  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parent))
from local_gateway import local_gateway  # noqa: E402

HERE = Path(__file__).resolve().parent
OUT = Path(os.environ.get("CONTEXTOS_RECEIPT_DIR", ROOT / "receipts/replay"))
GUARANTEE = '''
[[guarantees]]
id = "refunds-per-order"
capability_ids = ["adp_payments.issue_refund"]
resource_pointer = "/order_id"
amount_pointer = "/amount_minor"
limit = 100000
unit = "INR_minor"
'''


def main() -> None:
    tools = ToolServer()
    try:
        with local_gateway(tools, GUARANTEE) as (base, key):
            with (HERE / "traffic.jsonl").open() as f:
                records = load_traffic(f)
            template = json.loads((HERE / "admission.json").read_text())
            report = replay(Client(base, key), records, template, tools)
    finally:
        tools.close()
    print(markdown(report))
    expected = {"duplicates_refused": 1, "limits_held": 1, "held_unknown": 1, "approvals_required": 1,
                "effects_sent": 2, "recorded_effects": 5, "effects_prevented": 2}
    actual = {k: report[k] for k in expected}
    assert actual == expected, (actual, report["entries"])
    assert not report["false_block_candidates"], report["false_block_candidates"]
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "replay-report.json").write_text(json.dumps(report, indent=2))
    (OUT / "replay-report.md").write_text(markdown(report))
    print(f"replay report written: {OUT / 'replay-report.md'}")


if __name__ == "__main__":
    main()
