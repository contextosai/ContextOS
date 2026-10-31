#!/usr/bin/env python3
"""Lists a tenant's effects whose outcome is still unknown or partial, from its audit
chain, with the call that reconciles each. For on-call: no run id needed.

    CONTEXTOS_URL=https://contextos.internal AUDIT_TOKEN=... python3 examples/ops/unresolved.py
    python3 examples/ops/unresolved.py --entries export.json    # an exported chain

The token needs `audit:read` and selects the tenant. Standard library only. Reconcile
by querying the provider first; never re-run an effect to find out whether it happened.
"""
import json
import os
import sys
import urllib.request


def entries(url, token):
    sequence = 1
    while sequence:
        request = urllib.request.Request(f"{url}/v1/audit/entries?from={sequence}&limit=1000",
                                         headers={"Authorization": f"Bearer {token}"})
        with urllib.request.urlopen(request, timeout=30) as response:
            page = json.load(response)
        yield from page["entries"]
        sequence = page.get("next")


def main():
    if sys.argv[1:2] == ["--entries"] and len(sys.argv) == 3:
        with open(sys.argv[2]) as f:
            chain = json.load(f)
        chain = chain["entries"] if isinstance(chain, dict) else chain
    else:
        url = os.environ.get("CONTEXTOS_URL", "http://127.0.0.1:8080").rstrip("/")
        token = os.environ.get("AUDIT_TOKEN") or sys.exit("set AUDIT_TOKEN (a credential with audit:read)")
        chain = entries(url, token)
    claims, latest = {}, {}
    for entry in chain:
        payload, kind = entry["payload"], entry["kind"]
        attempt = payload.get("attempt_id")
        if not attempt:
            continue
        if kind == "operation_claim":
            claims[attempt] = payload
        elif kind in ("effect_observation", "effect_reconciliation"):
            latest[attempt] = payload.get("outcome")
    # Unresolved: the latest outcome is unknown or partial, or there is none yet (in
    # flight, or orphaned by a crash).
    unresolved = [(claim, latest.get(attempt)) for attempt, claim in claims.items()
                  if latest.get(attempt) in (None, "unknown", "partial")]
    if not unresolved:
        print("no unresolved effects")
        return
    for claim, outcome in unresolved:
        run, operation = claim["run_id"], claim["operation_id"]
        print(f"{outcome or 'no outcome yet'}: run {run} operation {operation} ({claim.get('capability_id')})")
        print(f"  curl -X POST \"$CONTEXTOS/v1/runs/{run}/operations/{operation}/reconcile\" "
              f"-H \"Authorization: Bearer $OPS_TOKEN\" -H 'Content-Type: application/json' "
              f"-d '{{\"source\": \"provider\"}}'")


if __name__ == "__main__":
    main()
