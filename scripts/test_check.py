"""Exercise the real commit gate without running external build tools."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


class CheckScriptTests(unittest.TestCase):
    def run_gate(self, *, agent_exit=0, tower_exit=0, guarantee_exit=0, archive_exit=0, marker=True,
                 large_output=False, peer_exit=0, compensation_exit=0):
        with tempfile.TemporaryDirectory(prefix="contextos-check-") as directory:
            root = Path(directory)
            (root / "scripts").mkdir()
            shutil.copyfile(Path(__file__).with_name("check.sh"), root / "scripts/check.sh")
            (root / "scripts/check-archive.sh").write_text(
                f"#!/usr/bin/env bash\necho 'Offline audit verification:'\nexit {archive_exit}\n"
            )
            (root / "tower").mkdir()
            tools = root / "bin"
            tools.mkdir()
            for name in ("cargo", "npm", "node", "python3"):
                tool = tools / name
                tool.write_text("#!/bin/sh\nexit 0\n")
                tool.chmod(0o755)
            for name in ("support-refund", "shared-guarantees", "metering-proxy", "agent-loop", "peer-coordination",
                         "compensation", "why-not-a-row-lock", "tower"):
                example = root / "examples" / name
                example.mkdir(parents=True)
                text = "#!/usr/bin/env bash\n"
                if name == "shared-guarantees":
                    text += f"echo 'Offline audit verification:'\nexit {guarantee_exit}\n"
                if name == "peer-coordination":
                    text += f"echo 'peer coordination complete'\nexit {peer_exit}\n"
                if name == "compensation":
                    text += f"echo 'saga compensated'\nexit {compensation_exit}\n"
                if name == "why-not-a-row-lock":
                    text += "echo 'row lock comparison complete'\n"
                if name in ("agent-loop", "tower"):
                    if marker:
                        text += "echo 'run completed'\n" if name == "agent-loop" else "echo 'tower sees the fleet'\n"
                    if large_output:
                        text += "for ((i=0; i<10000; i++)); do echo 'additional example output'; done\n"
                    text += f"exit {agent_exit if name == 'agent-loop' else tower_exit}\n"
                (example / "run.sh").write_text(text)
            return subprocess.run(
                ["bash", str(root / "scripts/check.sh")],
                env={**os.environ, "PATH": f"{tools}:{os.environ['PATH']}"},
                capture_output=True,
                text=True,
                timeout=15,
            )

    def test_agent_failure_after_success_message_fails_gate(self):
        result = self.run_gate(agent_exit=7)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("FAILED: agent loop", result.stdout)
        self.assertNotIn("ALL CHECKS PASSED", result.stdout)

    def test_guarantee_failure_after_verification_message_fails_gate(self):
        result = self.run_gate(guarantee_exit=7)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("FAILED: shared guarantees", result.stdout)
        self.assertNotIn("ALL CHECKS PASSED", result.stdout)

    def test_tower_failure_after_success_message_fails_gate(self):
        result = self.run_gate(tower_exit=9)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("FAILED: tower example", result.stdout)
        self.assertNotIn("ALL CHECKS PASSED", result.stdout)

    def test_archive_failure_fails_gate(self):
        result = self.run_gate(archive_exit=3)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("FAILED: release archive", result.stdout)
        self.assertNotIn("ALL CHECKS PASSED", result.stdout)

    def test_peer_failure_after_success_message_fails_gate(self):
        result = self.run_gate(peer_exit=8)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("FAILED: peer coordination", result.stdout)

    def test_compensation_failure_after_success_message_fails_gate(self):
        result = self.run_gate(compensation_exit=4)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("FAILED: compensation", result.stdout)

    def test_missing_success_message_fails_gate(self):
        result = self.run_gate(marker=False)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("FAILED: agent loop", result.stdout)

    def test_success_consumes_output_after_marker(self):
        result = self.run_gate(large_output=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("ALL CHECKS PASSED", result.stdout)


if __name__ == "__main__":
    unittest.main()
