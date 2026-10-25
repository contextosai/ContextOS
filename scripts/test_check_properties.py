"""The property catalog check fails on drift in either direction."""

from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).parent))
from check_properties import problems  # noqa: E402

HEADER = "| ID | Property | Source | Level | Check | Status |\n|---|---|---|---|---|---|\n"


class CatalogTests(unittest.TestCase):
    def check(self, rows: str, test: str) -> list:
        with tempfile.TemporaryDirectory(prefix="contextos-properties-") as directory:
            root = Path(directory)
            (root / "docs/verification").mkdir(parents=True)
            (root / "docs/verification/PROPERTIES.md").write_text(HEADER + rows)
            (root / "tests").mkdir()
            (root / "tests/p.rs").write_text(test)
            return problems(root)

    def test_a_catalogued_property_with_its_check_passes(self):
        row = "| AUTH-1 | p | s | L2 | `holds` in `tests/p.rs` | Holds |\n"
        self.assertEqual(self.check(row, "/// AUTH-1: p\nfn holds() {}\n"), [])

    def test_a_missing_check_fails(self):
        row = "| AUTH-1 | p | s | L2 | `holds` in `tests/p.rs` | Holds |\n"
        self.assertEqual(self.check(row, "/// AUTH-1: p\nfn other() {}\n"), ["AUTH-1: no fn holds in tests/p.rs"])

    def test_a_check_must_name_its_property(self):
        row = "| AUTH-1 | p | s | L2 | `holds` in `tests/p.rs` | Holds |\n"
        self.assertEqual(self.check(row, "fn holds() {}\n"), ["AUTH-1: tests/p.rs does not mention it"])

    def test_an_uncatalogued_property_fails(self):
        row = "| AUTH-1 | p | s | L2 | `holds` in `tests/p.rs` | Holds |\n"
        found = self.check(row, "/// AUTH-1: p\nfn holds() {}\n/// AUTH-2: q\nfn more() {}\n")
        self.assertEqual(found, ["AUTH-2: named in tests/p.rs but not catalogued"])


if __name__ == "__main__":
    unittest.main()
