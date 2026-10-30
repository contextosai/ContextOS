import hashlib
import hmac
import importlib.util
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location(
    "relay", Path(__file__).resolve().parent.parent / "examples/notify/relay.py")
relay = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(relay)

SECRET = b"notify-secret-0123456789abcdef0123456789"
OPENED = {"id": "t1:42", "type": "io.contextos.escalation.opened", "subject": "esc_1",
          "data": {"escalation_id": "esc_1", "run_id": "run_1", "capability_id": "adp_payments.issue_refund",
                   "reason_codes": ["policy_escalation"], "link": "https://tower.example/escalations/esc_1"}}


def signed(body: bytes, t: int) -> str:
    return f"t={t},v1=" + hmac.new(SECRET, f"{t}.".encode() + body, hashlib.sha256).hexdigest()


class RelayTests(unittest.TestCase):
    def test_signatures_are_checked_and_must_be_fresh(self):
        body = b'{"id":"t1:42"}'
        self.assertTrue(relay.verify(SECRET, signed(body, 1000), body, 1000))
        self.assertFalse(relay.verify(SECRET, signed(body, 1000), body + b" ", 1000))
        self.assertFalse(relay.verify(SECRET, signed(body, 1000), body, 1000 + 301))
        self.assertFalse(relay.verify(SECRET, "garbage", body, 1000))

    def test_messages_link_the_decision_and_pagerduty_resolves_by_escalation(self):
        self.assertIn("https://tower.example/escalations/esc_1", relay.message(OPENED))
        self.assertEqual(relay.pagerduty(OPENED, "rk")["event_action"], "trigger")
        resolved = {"id": "t1:43", "type": "io.contextos.escalation.resolved", "subject": "esc_1",
                    "data": {"escalation_id": "esc_1", "outcome": "handled", "by": "ops"}}
        event = relay.pagerduty(resolved, "rk")
        self.assertEqual((event["event_action"], event["dedup_key"]), ("resolve", "esc_1"))


if __name__ == "__main__":
    unittest.main()
