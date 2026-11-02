#!/usr/bin/env python3
"""Imports exposure created outside ContextOS into a shared guarantee, from a CSV file.

    CONTEXTOS_URL=https://contextos.internal IMPORT_TOKEN=... \\
        python3 examples/ops/import_exposure.py refunds-per-order prior.csv

The CSV has a header row with import_id, resource, amount, source, as_of and
evidence_ref. `resource` is the canonical resource id; `as_of` is a contract timestamp
(for example 2026-10-01T00:00:00Z). The token needs `exposure:import` and selects the
tenant. Standard library only.

Rows go up in pages of 1,000. Every row is idempotent per import_id, so an interrupted
import is resumed by running the same command again: rows already imported answer
`duplicate`. Exits non-zero when any row was refused, and prints each refusal.
"""
import csv
import json
import os
import sys
import urllib.error
import urllib.request

PAGE = 1000
FIELDS = ["import_id", "resource", "amount", "source", "as_of", "evidence_ref"]


def rows(path):
    with open(path, newline="") as f:
        reader = csv.DictReader(f)
        missing = [name for name in FIELDS if name not in (reader.fieldnames or [])]
        if missing:
            sys.exit(f"{path}: missing columns {', '.join(missing)}")
        for line, row in enumerate(reader, start=2):
            try:
                amount = int(row["amount"])
            except ValueError:
                sys.exit(f"{path}:{line}: amount must be a whole number of the guarantee's unit")
            yield {**{name: row[name] for name in FIELDS}, "amount": amount}


def post(url, token, guarantee, page):
    request = urllib.request.Request(
        f"{url}/v1/guarantees/{guarantee}/imports",
        data=json.dumps({"rows": page}).encode(),
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=120) as response:
            return json.load(response)["results"]
    except urllib.error.HTTPError as error:
        sys.exit(f"import refused ({error.code}): {error.read().decode(errors='replace')}; run again to resume")


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    guarantee, path = sys.argv[1:]
    url = os.environ.get("CONTEXTOS_URL", "http://127.0.0.1:8080").rstrip("/")
    token = os.environ.get("IMPORT_TOKEN") or sys.exit("set IMPORT_TOKEN (a credential with exposure:import)")
    counts = {"imported": 0, "duplicate": 0, "refused": 0}
    over_limit = set()
    pending = list(rows(path))
    for start in range(0, len(pending), PAGE):
        page = pending[start:start + PAGE]
        for result in post(url, token, guarantee, page):
            counts[result["status"]] += 1
            if result["status"] == "refused":
                print(f"refused {result.get('import_id')}: {result['reason']}", file=sys.stderr)
            elif result.get("over_limit"):
                over_limit.add(result["resource_digest"])
    print(json.dumps({"guarantee": guarantee, **counts, "over_limit_resources": sorted(over_limit)}))
    return 1 if counts["refused"] else 0


if __name__ == "__main__":
    sys.exit(main())
