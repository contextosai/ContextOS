"""Checks docs/verification/PROPERTIES.md against the tests it cites.

Every catalogued property must name a check that exists (`fn <name>` in the file) and
that file must mention the property's identifier; every identifier those files mention
must be catalogued. Run from the repo root, or pass the root as the only argument.
"""
import re
import sys
from pathlib import Path

ROW = re.compile(r"^\| ([A-Z]+-\d+) \|.*\| `(\w+)` in `([^`]+)` \|")
IDENTIFIER = re.compile(r"\b(?:AUTH|POLICY|RUN|BUDGET|TASK|SPEC)-\d+\b")


def problems(root: Path) -> list:
    catalog = root / "docs/verification/PROPERTIES.md"
    rows = [m.groups() for m in map(ROW.match, catalog.read_text().splitlines()) if m]
    if not rows:
        return [f"{catalog}: no properties listed"]
    found = []
    listed = {identifier for identifier, _, _ in rows}
    files = {}
    for identifier, check, path in rows:
        source = root / path
        if not source.is_file():
            found.append(f"{identifier}: {path} does not exist")
            continue
        text = files.setdefault(path, source.read_text())
        if not re.search(rf"\bfn {re.escape(check)}\b", text):
            found.append(f"{identifier}: no fn {check} in {path}")
        if identifier not in text:
            found.append(f"{identifier}: {path} does not mention it")
    for path, text in files.items():
        for identifier in sorted(set(IDENTIFIER.findall(text)) - listed):
            found.append(f"{identifier}: named in {path} but not catalogued")
    return found


if __name__ == "__main__":
    found = problems(Path(sys.argv[1] if len(sys.argv) > 1 else "."))
    for problem in found:
        print(problem, file=sys.stderr)
    sys.exit(1 if found else 0)
