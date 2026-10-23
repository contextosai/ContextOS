#!/usr/bin/env bash
# Quickstart: admit a run and dispatch one governed refund. Run from the repo root.
set -euo pipefail
source examples/dev-env.sh

api() { curl -sS -H "authorization: Bearer $KEY" -H 'content-type: application/json' "$@"; }
# What the user asked for ("Refund order ord_881 for INR 1200"), fixed before the agent
# acts: the refund of that order to that customer, up to that amount.
RUN="$(python3 -c '
import json
run = json.load(open("examples/support-refund/requests/run.json"))
run["task_authorization"] = {
    "issued_by": {"principal_id": "usr_771", "principal_type": "person", "trust_domain": "contextos.dev",
                  "tenant_id": "tenant_acme_prod"},
    "scopes": [{"root_run_id": "run_demo_1", "purpose_ids": ["support.refund"],
                "capability_ids": ["adp_payments.issue_refund"], "resource_ids": ["ord_881"],
                "destination_ids": ["cus_77"], "classification_labels": ["CONFIDENTIAL"], "argument_constraints": [],
                "amount_ceiling": {"minor_units": 120000, "currency": "INR"}}]}
print(json.dumps(run))')"
echo "== admit run"
ADMITTED="$(api -X POST $CONTEXTOS_URL/v1/runs --data "$RUN")"
echo "$ADMITTED" | python3 -c 'import json,sys;r=json.load(sys.stdin);print({k:r[k] for k in ("run_id","executor_generation","features")})'
# The executor presents its generation with every effectful request; a takeover by
# another executor makes it stale.
GENERATION="$(echo "$ADMITTED" | python3 -c 'import json,sys;print(json.load(sys.stdin)["executor_generation"])')"
exe() { api -H "contextos-executor-generation: $GENERATION" "$@"; }
echo "== dispatch refund"
exe -X POST $CONTEXTOS_URL/v1/runs/run_demo_1/tool-calls --data @examples/support-refund/requests/tool_call.json \
  | python3 -c 'import json,sys;r=json.load(sys.stdin);print({"status":r["result"]["status"],"output":r["result"]["output"],"audit":r["report"]["audit_sequences"]})'
echo "== replay the same operation (must not refund twice)"
exe -X POST $CONTEXTOS_URL/v1/runs/run_demo_1/tool-calls --data @examples/support-refund/requests/tool_call.json \
  | python3 -c 'import json,sys;r=json.load(sys.stdin);print({"status":r["result"]["status"],"reasons":r["report"]["reason_codes"]})'
echo "== refund four times what the user asked (must not run)"
exe -X POST $CONTEXTOS_URL/v1/runs/run_demo_1/tool-calls --data "$(python3 -c '
import json
c = json.load(open("examples/support-refund/requests/tool_call.json"))
c.update(tool_call_id="tc_demo_2", idempotency_key="refund:ord_881:more")
c["args"]["amount_minor"] = 480000
print(json.dumps(c))')" \
  | python3 -c 'import json,sys;r=json.load(sys.stdin);print({"status":r["result"]["status"],"reasons":r["report"]["reason_codes"]})'
echo "== verify audit chain"
api $CONTEXTOS_URL/v1/audit/verify; echo
