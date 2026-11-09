"""Unit tests for the default operation key (contextos.envelope.operation_key).

Run with: PYTHONPATH=bindings/python python3 -m unittest bindings/python/tests/test_envelope.py
"""
import unittest

from contextos.client import Client, Run
from contextos.envelope import operation_key


class OperationKeyTest(unittest.TestCase):
    def test_same_call_same_key(self):
        a = operation_key("pay.refund", {"order_id": "o1", "amount": 600, "tags": ["x", "é"]})
        b = operation_key("pay.refund", {"tags": ["x", "é"], "amount": 600, "order_id": "o1"})
        self.assertEqual(a, b)
        self.assertRegex(a, r"^call:[0-9a-f]{32}$")
        self.assertNotEqual(a, operation_key("pay.refund", {"order_id": "o1", "amount": 601, "tags": ["x", "é"]}))
        self.assertNotEqual(a, operation_key("pay.credit", {"order_id": "o1", "amount": 600, "tags": ["x", "é"]}))
        # The Node client derives the same key (bindings/node/client.mjs operationKey).
        self.assertEqual(operation_key("a.b", {"y": 1, "x": [1, "é"]}), "call:6cdf3bfbe73e5ecc093a0c96a5f53b78")

    def test_envelope_defaults_only_for_effects(self):
        run = Run(Client("http://127.0.0.1:1", "t"), "run_1", "trace", 2, [])
        effect = run.envelope("pay.refund", {"order_id": "o1"}, approval_mode="destructive")
        self.assertEqual(effect["idempotency_key"], operation_key("pay.refund", {"order_id": "o1"}))
        named = run.envelope("pay.refund", {"order_id": "o1"}, approval_mode="destructive", idempotency_key="k")
        self.assertEqual(named["idempotency_key"], "k")
        read = run.envelope("orders.lookup", {"order_id": "o1"}, approval_mode="read_only")
        self.assertIsNone(read["idempotency_key"])


if __name__ == "__main__":
    unittest.main()
