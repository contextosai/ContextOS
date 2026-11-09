"""Unit tests for contextos.replay that need no server: traffic parsing, admission
templates, the tool server's recorded answers and the report.

Run with: PYTHONPATH=bindings/python python3 -m unittest bindings/python/tests/test_replay.py
"""
import json
import unittest
import urllib.request

from contextos.replay import ToolServer, admission_for, load_traffic, markdown, summarize


def line(**fields):
    record = {"ts": "2026-11-01T09:00:00Z", "run_id": "r1", "capability_id": "a.b", "args": {}, "outcome": "ok"}
    record.update(fields)
    return json.dumps(record)


class TrafficTest(unittest.TestCase):
    def test_sorted_by_time_then_line(self):
        records = load_traffic([line(ts="2026-11-01T10:00:00Z", run_id="late"), "",
                                line(run_id="first"), line(run_id="second")])
        self.assertEqual([r["run_id"] for r in records], ["first", "second", "late"])
        self.assertEqual([r["line"] for r in records], [3, 4, 1])

    def test_refuses_bad_lines_by_number(self):
        with self.assertRaisesRegex(ValueError, "line 2: missing outcome"):
            load_traffic([line(), json.dumps({"ts": "t", "run_id": "r", "capability_id": "c", "args": {}})])
        with self.assertRaisesRegex(ValueError, "line 1: outcome must be"):
            load_traffic([line(outcome="maybe")])
        with self.assertRaisesRegex(ValueError, "line 1: not JSON"):
            load_traffic(["{"])


class AdmissionTest(unittest.TestCase):
    def test_fills_placeholders_with_their_types(self):
        template = {"run_id": "$RUN_ID", "contract": "contract_$RUN_ID", "amount": "$AMOUNT",
                    "message": "Refund $ORDER for INR $AMOUNT", "agents": ["$AGENT"], "fixed": 3}
        record = {"run_id": "r1", "agent": "agt", "vars": {"AMOUNT": 4500, "ORDER": "ord_1", "RUN": "x"}}
        self.assertEqual(admission_for(template, record), {
            "run_id": "r1", "contract": "contract_r1", "amount": 4500,
            "message": "Refund ord_1 for INR 4500", "agents": ["agt"], "fixed": 3})
        self.assertEqual(template["run_id"], "$RUN_ID")  # the template is not changed


class ToolServerTest(unittest.TestCase):
    def call(self, server):
        body = json.dumps({"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {}}).encode()
        request = urllib.request.Request(server.url, data=body, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(request, timeout=5) as response:
            return json.loads(response.read())

    def test_answers_with_the_recorded_outcome(self):
        server = ToolServer()
        try:
            server.current = {"line": 4, "outcome": "ok", "output": {"refund_id": "rf_1"}}
            self.assertEqual(self.call(server)["result"], {"structuredContent": {"refund_id": "rf_1"}})
            server.current = {"line": 5, "outcome": "error", "error": "card expired"}
            self.assertTrue(self.call(server)["result"]["isError"])
            server.current = {"line": 6, "outcome": "timeout"}
            with self.assertRaises(Exception):
                self.call(server)
            server.current = None
            self.assertIn("error", self.call(server))
            self.assertEqual(server.reached, [4, 5, 6])
        finally:
            server.close()


class ReportTest(unittest.TestCase):
    def test_counts_and_false_block_candidates(self):
        def entry(n, result, recorded="ok", effect=True, reasons=()):
            return {"line": n, "run_id": f"r{n % 2}", "capability_id": "pay.refund", "effect": effect,
                    "recorded": recorded, "result": result, "reason_codes": list(reasons)}
        calls = [entry(1, "allowed", effect=False), entry(2, "allowed"),
                 entry(3, "duplicate_refused", reasons=["effect_repeated"]),
                 entry(4, "limit_refused", reasons=["shared_guarantee_exceeded"]),
                 entry(5, "held_unknown", recorded="timeout"),
                 entry(6, "blocked", reasons=["policy_denied"]),
                 entry(7, "blocked", recorded="error", reasons=["policy_denied"])]
        report = summarize(calls, reached=[1, 2, 5, 5])
        self.assertEqual((report["calls"], report["runs"]), (7, 2))
        self.assertEqual((report["recorded_effects"], report["effects_sent"], report["effects_prevented"]), (5, 2, 2))
        self.assertEqual((report["duplicates_refused"], report["limits_held"], report["held_unknown"]), (1, 1, 1))
        self.assertEqual([c["line"] for c in report["false_block_candidates"]], [6])
        self.assertEqual(report["reasons"]["policy_denied"], 2)
        text = markdown(report)
        self.assertIn("2 reached the tool", text)
        self.assertIn("line 6 (`pay.refund`", text)


if __name__ == "__main__":
    unittest.main()
