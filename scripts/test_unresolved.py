"""examples/ops/unresolved.py finds effects whose latest outcome is unknown, partial or
missing, and nothing once they are reconciled."""

import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "examples/ops/unresolved.py"


def entry(kind, **payload):
    return {"kind": kind, "payload": payload}


def run(chain):
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump({"entries": chain}, f)
    return subprocess.run([sys.executable, str(SCRIPT), "--entries", f.name],
                          capture_output=True, text=True, check=True).stdout


class Unresolved(unittest.TestCase):
    def test_lists_unknown_partial_and_unobserved_until_reconciled(self):
        chain = [
            entry("operation_claim", run_id="r1", operation_id="op_lost", attempt_id="a1", capability_id="c"),
            entry("effect_observation", attempt_id="a1", outcome="unknown"),
            entry("operation_claim", run_id="r1", operation_id="op_done", attempt_id="a2", capability_id="c"),
            entry("effect_observation", attempt_id="a2", outcome="confirmed"),
            entry("operation_claim", run_id="r2", operation_id="op_inflight", attempt_id="a3", capability_id="c"),
        ]
        out = run(chain)
        self.assertIn("unknown: run r1 operation op_lost", out)
        self.assertIn("no outcome yet: run r2 operation op_inflight", out)
        self.assertNotIn("op_done", out)
        chain += [entry("effect_reconciliation", attempt_id="a1", outcome="not_applied"),
                  entry("effect_observation", attempt_id="a3", outcome="confirmed")]
        self.assertEqual(run(chain).strip(), "no unresolved effects")


if __name__ == "__main__":
    unittest.main()
