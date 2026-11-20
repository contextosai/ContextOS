"""The Agent Failure Lab page and the refund replay: offline checks.

The lab's recording is checked against a live gateway by examples/failure-lab/check.sh;
these tests cover what needs no gateway: the page has words for every recorded step,
states only amounts that are in the recording, links only to files that exist, and the
refund replay parses, maps and totals calls.
"""

from decimal import Decimal
import importlib.util
import json
from pathlib import Path
import re
import shutil
import subprocess
import unittest

ROOT = Path(__file__).resolve().parent.parent
REPO = "https://github.com/contextosai/ContextOS"


def story():
    text = (ROOT / "lab/story.js").read_text()
    return json.loads(text[text.index("{"):text.rindex("}") + 1])


def replay_refunds():
    spec = importlib.util.spec_from_file_location(
        "replay_refunds", ROOT / "examples/replay-refunds/replay_refunds.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def words():
    """The page's words, read with Node when it is installed (CI has it)."""
    node = shutil.which("node")
    if node is None:
        raise unittest.SkipTest("node is not installed")
    script = "global.window = {}; require(process.argv[1]); console.log(JSON.stringify(window.LAB_WORDS));"
    out = subprocess.run([node, "-e", script, str(ROOT / "lab/words.js")], capture_output=True, text=True, check=True)
    return json.loads(out.stdout)


def strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from strings(item)


def last(scenario):
    return scenario["steps"][-1]["worlds"]


class LabPageTests(unittest.TestCase):
    def test_every_recorded_step_has_words(self):
        script = (ROOT / "lab/words.js").read_text()
        for name, scenario in story()["scenarios"].items():
            section = script[script.index(f'key: "{name}"'):]
            for step in scenario["steps"]:
                self.assertRegex(section, rf"\b{step['step']}: {{", f"{name}/{step['step']}")

    def test_words_cover_the_recording(self):
        text, recorded = words(), story()
        self.assertEqual(sorted(s["key"] for s in text["scenarios"]), sorted(recorded["scenarios"]))
        for scenario in text["scenarios"]:
            steps = [s["step"] for s in recorded["scenarios"][scenario["key"]]["steps"]]
            self.assertEqual(sorted(scenario["steps"]), sorted(steps), scenario["key"])
        for scenario in recorded["scenarios"].values():
            for world in scenario["worlds"]:
                self.assertIn(world, text["worlds"])
            for key in scenario["config"]:
                self.assertIn(key, text["config"])
            for step in scenario["steps"]:
                for code in step["summary"].get("reason_codes", []):
                    if code.startswith(("task_scope", "shared_", "effect_", "retry_", "circuit_", "revoked_")):
                        self.assertIn(code, text["refused"])

    def test_amounts_in_the_words_are_recorded(self):
        """Every "INR n" the page's words state is an amount in that scenario's
        recording: a request, a ledger, a balance, a limit or an order's payment."""
        text, recorded = words(), story()
        line = recorded["approval_line_minor"]
        for scenario in text["scenarios"]:
            data = recorded["scenarios"][scenario["key"]]
            numbers = {int(n) for n in re.findall(r"\d+", json.dumps({k: v for k, v in data.items() if k != "receipt"}))}
            numbers.add(line)
            for sentence in strings(scenario):
                for amount in re.findall(r"INR ([\d,]+)", sentence):
                    self.assertIn(int(amount.replace(",", "")) * 100, numbers, f"{scenario['key']}: {sentence}")
        for sentence in strings(text["worlds"]):
            for amount in re.findall(r"INR ([\d,]+)", sentence):
                self.assertEqual(int(amount.replace(",", "")) * 100, line)

    def test_story_has_no_local_paths(self):
        text = (ROOT / "lab/story.js").read_text()
        for marker in ("/Users/", "/opt/", "/private/", "/tmp/", "/home/", "127.0.0.1", "localhost"):
            self.assertNotIn(marker, text)

    def test_money_adds_up(self):
        for name, scenario in story()["scenarios"].items():
            self.assertEqual(scenario["worlds"][0], "gated")
            sequences = {e["sequence"] for e in scenario["receipt"]["entries"]["entries"]}
            for step in scenario["steps"]:
                self.assertLessEqual(set(step["audit"]), sequences)
                for world in step["worlds"].values():
                    self.assertEqual(world["paid"], sum(e["amount_minor"] for e in world["ledger"]))
                    self.assertEqual(world["excess"], sum(e["excess_minor"] for e in world["ledger"]))
                    for entry in world["ledger"]:
                        self.assertLessEqual(entry["amount_minor"], scenario["orders"][entry["order_id"]])

    def test_every_scenario_shows_a_difference(self):
        """The page's point: behind the gateway nothing unauthorised is paid, and the
        strongest baseline recorded for each failure pays some."""
        for name, scenario in story()["scenarios"].items():
            end = last(scenario)
            self.assertEqual(end["gated"]["excess"], 0, name)
            self.assertGreater(end[scenario["worlds"][-1]]["excess"], 0, name)
            self.assertGreater(end["gated"]["paid"], 0, name)  # it is not an off switch

    def test_lost_response(self):
        end = last(story()["scenarios"]["lost_response"])
        self.assertEqual((end["gated"]["paid"], end["gated"]["balance"]["held"]), (80_000, 0))
        # A key per run stops the retry and not the redelivered ticket.
        self.assertEqual((end["direct"]["excess"], end["keyed"]["excess"]), (160_000, 80_000))

    def test_repository_links_resolve(self):
        script = (ROOT / "lab/lab.js").read_text()
        links = re.findall(r"\$\{REPO\}/(tree|blob)/main/([^\"`#]+)", script)
        self.assertTrue(links)
        for kind, path in links:
            target = ROOT / path
            self.assertTrue(target.is_dir() if kind == "tree" else target.is_file(), path)

    def test_page_loads_only_its_own_files(self):
        page = (ROOT / "lab/index.html").read_text()
        for source in re.findall(r"(?:src|href)=\"([^\"]+)\"", page):
            self.assertTrue((ROOT / "lab" / source).is_file(), source)
        for name in ("index.html", "lab.css", "lab.js", "words.js"):
            self.assertNotRegex((ROOT / "lab" / name).read_text(), r"@import|url\(|<link[^>]+https?:|src=\"https?:")


class RefundReplayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rr = replay_refunds()

    def test_reads_common_log_shapes(self):
        lines = [
            '{"ts": "2026-11-03T10:00:00Z", "session_id": "s1", "name": "refund", '
            '"arguments": "{\\"order\\": \\"A\\", \\"amount\\": 2.5}", "outcome": "ok"}',
            "",
            '{"ts": "2026-11-03T09:00:00Z", "run_id": "r0", "tool": "lookup", "input": {"order": "A"}, '
            '"outcome": "ok"}',
        ]
        calls = self.rr.read_calls(lines)
        self.assertEqual([c["line"] for c in calls], [3, 1])  # time order
        self.assertEqual(calls[1]["run"], "s1")
        self.assertEqual(calls[1]["args"], {"order": "A", "amount": 2.5})

    def test_refuses_malformed_lines_by_number(self):
        with self.assertRaisesRegex(self.rr.InputError, "line 2: outcome"):
            self.rr.read_calls(['{"tool": "t", "args": {}, "outcome": "ok"}',
                                '{"tool": "t", "args": {}, "outcome": "maybe"}'])
        with self.assertRaisesRegex(self.rr.InputError, "line 1: needs a tool"):
            self.rr.read_calls(['{"args": {}, "outcome": "ok"}'])

    def test_pointer(self):
        value = {"a/b": {"items": [{"x": 1}]}, "m~n": 2}
        self.assertEqual(self.rr.pointer(value, "/a~1b/items/0/x"), 1)
        self.assertEqual(self.rr.pointer(value, "/m~0n"), 2)
        self.assertIsNone(self.rr.pointer(value, "/missing"))

    def test_minor_units(self):
        self.assertEqual(self.rr.minor_units(25.5, "major", 1), 2550)
        self.assertEqual(self.rr.minor_units("2550", "minor", 1), 2550)
        for bad, unit in ((25.555, "major"), (0, "minor"), ("x", "minor"), (12.5, "minor")):
            with self.assertRaises(self.rr.InputError):
                self.rr.minor_units(bad, unit, 1)

    def test_maps_refunds_and_skips_other_tools(self):
        calls = self.rr.read_calls([
            '{"ts": "1", "run_id": "r", "tool": "refund_payment", "args": {"o": "A", "amt": 10}, "outcome": "timeout"}',
            '{"ts": "2", "run_id": "r", "tool": "send_email", "args": {}, "outcome": "ok"}',
        ])
        self.assertEqual(self.rr.guess_tool(calls), "refund_payment")
        mapping = {"tool": "refund_payment", "order": "/o", "amount": "/amt", "customer": None, "unit": "major"}
        records, skipped = self.rr.to_records(calls, mapping)
        self.assertEqual(skipped, {"send_email": 1})
        self.assertEqual(records[0]["args"], {"order_id": "A", "customer_id": "customer", "amount_minor": 1000})
        self.assertNotIn("output", records[0])
        with self.assertRaisesRegex(self.rr.InputError, "no order at /order"):
            self.rr.to_records(calls, {**mapping, "order": "/order"})

    def test_money_buckets(self):
        def record(line, ts, run, order, amount, outcome):
            return {"line": line, "ts": ts, "run_id": run, "outcome": outcome,
                    "args": {"order_id": order, "amount_minor": amount}}

        records = [
            record(1, "2026-11-01T00:00:00Z", "r1", "A", 500, "ok"),
            record(2, "2026-11-01T00:01:00Z", "r1", "A", 500, "ok"),
            record(3, "2026-11-01T00:02:00Z", "r2", "B", 300, "timeout"),
            record(4, "2026-11-03T00:00:00Z", "r3", "A", 500, "ok"),
            record(5, "2026-11-03T00:05:00Z", "r4", "C", 700, "ok"),
        ]
        entries = [
            {"line": 1, "recorded": "ok", "result": "allowed", "reason_codes": []},
            {"line": 2, "recorded": "ok", "result": "duplicate_refused", "reason_codes": ["retry_unsafe"]},
            {"line": 3, "recorded": "timeout", "result": "held_unknown", "reason_codes": []},
            {"line": 4, "recorded": "ok", "result": "duplicate_refused",
             "reason_codes": ["effect_repeated_across_runs"]},
            {"line": 5, "recorded": "ok", "result": "blocked", "reason_codes": ["policy_denied"]},
        ]
        money = self.rr.money_report(records, {"entries": entries}, {1, 3}, "USD", None)
        t = money["totals"]
        self.assertEqual((t["recorded_paid"], t["recorded_unknown"]), (2200, 300))
        self.assertEqual((t["sent_paid"], t["held"], t["repeats_refused"], t["needs_review"]), (500, 300, 500, 500))
        self.assertEqual([r["line"] for r in money["review"]], [4])
        self.assertEqual([r["line"] for r in money["false_block_candidates"]], [5])
        text = self.rr.markdown(money, {})
        self.assertIn("USD 22.00", text)
        self.assertIn("line 5", text)
        self.assertEqual(self.rr.fmt(123456, "INR"), "INR 1,234.56")
        self.assertEqual(Decimal(money["by_order"]["A"]["recorded_paid"]), 1500)


if __name__ == "__main__":
    unittest.main()
