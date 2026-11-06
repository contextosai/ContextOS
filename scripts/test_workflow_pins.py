"""Every GitHub Action is pinned to a full commit SHA, with its tag in a comment.

A tag can be moved to other code after review; a SHA cannot. The comment lets
Dependabot propose updates and lets reviewers see the version.
"""

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parent.parent
USES = re.compile(r"^\s*-?\s*uses:\s*(\S+)(.*)$")
PINNED = re.compile(r"^[\w.-]+/[\w./-]+@[0-9a-f]{40}$")


class WorkflowPinTests(unittest.TestCase):
    def test_actions_are_pinned_to_commits(self):
        unpinned = []
        for workflow in sorted((ROOT / ".github/workflows").glob("*.y*ml")):
            for number, line in enumerate(workflow.read_text().splitlines(), 1):
                match = USES.match(line)
                if not match or match.group(1).startswith("./"):
                    continue
                if not PINNED.match(match.group(1)) or not match.group(2).strip().startswith("#"):
                    unpinned.append(f"{workflow.name}:{number}: {line.strip()}")
        self.assertEqual(unpinned, [], "pin each action as owner/repo@<sha> # <tag>")


if __name__ == "__main__":
    unittest.main()
