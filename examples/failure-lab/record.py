#!/usr/bin/env python3
"""Records the Agent Failure Lab's story from a real ContextOS gateway.

Each scenario (scenarios.py) runs against its own contextosd (in-memory store,
development fact services, the support-refund pack) and a synthetic card processor.
Every request the agent or a person sends, the gateway's answer, the money each world
paid and the signed audit entries are written to lab/story.js, which the static lab
page plays back. The same attempts sent without a gateway are recorded beside them.

    ./examples/failure-lab/run.sh            # re-record lab/story.js
    ./examples/failure-lab/run.sh --check    # fail if the runtime's behaviour drifted
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "examples/replay"))
from local_gateway import local_gateway  # noqa: E402

from provider import Provider  # noqa: E402
from scenarios import APPROVAL_LINE, INTENT, RECOVERY, SCENARIOS  # noqa: E402
from session import SUPPORT, Session  # noqa: E402
from worlds import Baseline, Money  # noqa: E402

BIN = Path(os.environ.get("CONTEXTOS_BIN", ROOT / "target/debug"))
STORY = ROOT / "lab/story.js"
VERSION = "contextos.failure_lab.v2"


def approval_rule():
    """The support-refund pack's rule that sends a large refund for approval."""
    pack = json.loads((SUPPORT / "pack.json").read_text())
    for bundle in pack["policy_layer"]["policy_bundles"]:
        for rule in bundle["policy_dsl"]["rules"]:
            if rule.get("then", {}).get("requires_approval_gate"):
                return rule
    raise SystemExit("the support-refund pack has no approval rule")


def configuration(scenario, session):
    """What was declared to get this scenario's behaviour, for the page to show."""
    spec = next(iter(scenario.get("runs", {}).items()), None)
    parts = {
        "intent": INTENT, "recovery": RECOVERY, "gateway_toml": scenario.get("gateway_toml", "").strip(),
        "task_authorization": spec and "task" in spec[1] and session.task_authorization(spec[0], spec[1]["task"]),
        "pack_rule": approval_rule(),
    }
    return {name: parts[name] for name in scenario["config"]}


def wait_for_window(seconds):
    """Rate windows are aligned to the clock; a recording that straddles two of them
    would count differently, so start well inside one."""
    left = seconds - time.time() % seconds
    if left < 20:
        time.sleep(left + 1)


def record_scenario(name):
    scenario = SCENARIOS[name]
    provider = Provider(scenario["orders"]).serve()
    baselines = {kind: Baseline(kind, scenario["orders"]) for kind in scenario["worlds"]}
    money = {world: Money(scenario["rightful"]) for world in ("gated", *baselines)}
    manifest = json.loads((SUPPORT / "capabilities/issue_refund.json").read_text())
    manifest.update(intent=INTENT, recovery=RECOVERY)
    if "window_seconds" in scenario:
        wait_for_window(scenario["window_seconds"])
    try:
        with tempfile.TemporaryDirectory(prefix="contextos-lab-") as tmp:
            path, services = Path(tmp) / "issue_refund.json", {}
            path.write_text(json.dumps(manifest, indent=2))
            with local_gateway(provider, scenario.get("gateway_toml", ""), {"issue_refund.json": path},
                               services=services) as (base, key):
                session = Session(scenario, base, key, services, provider, baselines, money)
                for step in scenario["steps"]:
                    getattr(session, "step_" + step["kind"])(step)
                return {"orders": scenario["orders"], "worlds": ["gated", *scenario["worlds"]],
                        "rightful": scenario["rightful"], "config": configuration(scenario, session),
                        "steps": session.steps, "receipt": session.receipt()}
    finally:
        provider.close()


def projection(story):
    """The parts of the story that must not change unless the runtime's behaviour does:
    identifiers, times, digests and signatures vary from run to run."""
    def step(scenario, s):
        kinds = {e["sequence"]: e["kind"] for e in scenario["receipt"]["entries"]["entries"]}
        return {
            "step": s["step"], "http_status": s["response"]["http_status"],
            "summary": {k: v for k, v in s["summary"].items() if k in ("status", "reason_codes", "obligations", "outcome")},
            "worlds": {name: {"paid": w["paid"], "excess": w["excess"], "provider_calls": w["provider_calls"],
                              "balance": w.get("balance"), "attempt": (w.get("attempt") or {}).get("outcome")}
                       for name, w in s["worlds"].items()},
            "audit_kinds": [kinds[n] for n in s["audit"]],
        }
    return {name: {"config": scenario["config"], "steps": [step(scenario, s) for s in scenario["steps"]]}
            for name, scenario in story["scenarios"].items()}


def verify_receipts(story):
    """Each scenario's receipt must verify offline, as the page tells visitors it will."""
    with tempfile.TemporaryDirectory(prefix="contextos-lab-receipt-") as tmp:
        for name, scenario in story["scenarios"].items():
            entries, keys = Path(tmp) / f"{name}-entries.json", Path(tmp) / f"{name}-keys.json"
            entries.write_text(json.dumps(scenario["receipt"]["entries"]))
            keys.write_text(json.dumps(scenario["receipt"]["keys"]))
            out = subprocess.run([str(BIN / "ctx"), "audit-verify", "--entries", str(entries), "--keys", str(keys)],
                                 capture_output=True, text=True)
            if out.returncode != 0 or json.loads(out.stdout).get("verified") is not True:
                raise SystemExit(f"{name}: the receipt does not verify: {out.stdout or out.stderr}")


def version():
    out = subprocess.run([str(BIN / "contextosd"), "--version"], capture_output=True, text=True, check=True)
    return out.stdout.strip()


def outline(story):
    """One line per step, for whoever re-records."""
    for name, scenario in projection(story).items():
        print(name)
        for s in scenario["steps"]:
            worlds = "  ".join(f"{w}: paid {v['paid']} excess {v['excess']}" for w, v in s["worlds"].items())
            print(f"  {s['step']:<13} {s['summary'].get('status', ''):<10} "
                  f"{','.join(s['summary'].get('reason_codes', [])):<60} {worlds}")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--check", action="store_true", help="compare with lab/story.js instead of writing it")
    parser.add_argument("--out", type=Path, default=STORY)
    args = parser.parse_args(argv)
    story = {"story_version": VERSION, "recorded_with": version(), "currency": "INR",
             "approval_line_minor": APPROVAL_LINE,
             "scenarios": {name: record_scenario(name) for name in SCENARIOS}}
    if args.check:
        text = args.out.read_text()
        committed = json.loads(text[text.index("{"):text.rindex("}") + 1])
        verify_receipts(committed)
        if projection(committed) != projection(story):
            print(json.dumps({"committed": projection(committed), "now": projection(story)}, indent=1))
            print("failure lab story drifted: re-record with ./examples/failure-lab/run.sh", file=sys.stderr)
            return 1
        print("failure lab story matches the runtime")
        return 0
    verify_receipts(story)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text("// Generated by examples/failure-lab/record.py from a real contextosd run. Do not edit.\n"
                        "window.LAB_STORY = " + json.dumps(story, indent=1, sort_keys=True) + ";\n")
    outline(story)
    print(f"failure lab story written: {os.path.relpath(args.out)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
