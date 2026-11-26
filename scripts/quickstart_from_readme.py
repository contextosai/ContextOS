"""Runs README.md's Quickstart exactly as written, from a fresh checkout, and fails if
it fails or takes longer than the ten minutes the README promises. The `git clone` and
`cd` lines are skipped: CI has already checked out the commit under test."""

import re
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BUDGET_SECONDS = 600


def commands(readme: str) -> list:
    section = readme.split("## Quickstart", 1)[1]
    block = re.search(r"```sh\n(.*?)```", section, re.S).group(1)
    return [line for line in block.splitlines()
            if line.strip() and not line.startswith(("git clone", "cd ContextOS"))]


def main() -> int:
    steps = commands((ROOT / "README.md").read_text())
    if not steps:
        print("README Quickstart has no commands", file=sys.stderr)
        return 1
    started = time.monotonic()
    for step in steps:
        print(f"$ {step}", flush=True)
        if subprocess.run(["bash", "-c", step], cwd=ROOT).returncode != 0:
            print(f"QUICKSTART FAILED at: {step}", file=sys.stderr)
            return 1
    took = time.monotonic() - started
    print(f"quickstart finished in {took:.0f} s (budget {BUDGET_SECONDS} s)")
    return 0 if took <= BUDGET_SECONDS else 1


if __name__ == "__main__":
    sys.exit(main())
