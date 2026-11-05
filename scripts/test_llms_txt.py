"""llms.txt names only files that exist in this repository."""

from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parent.parent
REPO = "https://github.com/contextosai/ContextOS/"


class LlmsTxtTests(unittest.TestCase):
    def test_every_repository_link_resolves(self):
        text = (ROOT / "llms.txt").read_text()
        self.assertTrue(text.startswith("# ContextOS\n"))
        links = re.findall(r"\]\((https://[^)]+)\)", text)
        self.assertGreater(len(links), 10)
        for link in links:
            if not link.startswith(REPO):
                continue
            kind, _, path = link[len(REPO):].partition("/main/")
            self.assertIn(kind, ("blob", "tree"), link)
            target = ROOT / path
            self.assertTrue(target.is_file() if kind == "blob" else target.is_dir(), link)


if __name__ == "__main__":
    unittest.main()
