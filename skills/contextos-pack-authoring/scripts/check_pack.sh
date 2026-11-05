#!/usr/bin/env bash
# Checks a Context Pack the way a release would: schema, references that must resolve,
# pack tests, a decision plan per role, and the release gate against a baseline.
#
#   check_pack.sh --pack PACK [--tests SUITE]... [--run RUN [--roles r1,r2] [--intent I]]
#                 [--baseline OLD --cases CASES [--acknowledge ACK]]
#
# Uses `ctx` from $CTX, else PATH, else this checkout's target/release/ctx. Exits
# non-zero on the first failing check; prints each plan for a person to read.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../../.." && pwd)"
if [[ -n "${CTX:-}" ]]; then ctx="$CTX"
elif command -v ctx >/dev/null 2>&1; then ctx="$(command -v ctx)"
else ctx="$repo/target/release/ctx"; fi
[[ -x "$ctx" ]] || { echo "ctx not found: set CTX or build it (cargo build --release -p ctx)" >&2; exit 2; }

pack="" run="" roles="" intent="" baseline="" cases="" ack=""
tests=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --pack) pack="$2"; shift 2 ;;
        --tests) tests+=("$2"); shift 2 ;;
        --run) run="$2"; shift 2 ;;
        --roles) roles="$2"; shift 2 ;;
        --intent) intent="$2"; shift 2 ;;
        --baseline) baseline="$2"; shift 2 ;;
        --cases) cases="$2"; shift 2 ;;
        --acknowledge) ack="$2"; shift 2 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done
[[ -n "$pack" ]] || { echo "--pack is required" >&2; exit 2; }
if [[ -n "$baseline" && -z "$cases" ]]; then echo "--baseline needs --cases" >&2; exit 2; fi

scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT

echo "== schema"
"$ctx" validate context-pack "$pack" >/dev/null || { "$ctx" validate context-pack "$pack"; exit 1; }
echo "ok: conforms to context-pack.v2"

echo "== references"
python3 -I - "$pack" <<'PY'
import json, sys
pack = json.load(open(sys.argv[1]))
policy, tooling = pack["policy_layer"], pack["tooling_layer"]
gates = {g["gate_id"] for g in policy.get("approval_gates", [])}
specs = {s["decision_key"] for s in pack["decision_layer"]["decision_specs"]}
caps = {f'{a["adapter_id"]}.{c}' for a in tooling["adapter_registry"] for c in a["capabilities"]}
problems, rule_ids = [], set()
for bundle in policy["policy_bundles"]:
    for rule in bundle["policy_dsl"]["rules"]:
        rid = f'{bundle["bundle_id"]}/{rule["rule_id"]}'
        if rule["rule_id"] in rule_ids:
            problems.append(f"{rid}: rule_id appears more than once")
        rule_ids.add(rule["rule_id"])
        then = rule["then"]
        gate = then.get("requires_approval_gate")
        if gate and gate not in gates:
            problems.append(f"{rid}: requires_approval_gate {gate} is not an approval_gates gate_id")
        binding = rule.get("decision_binding")
        if binding and binding not in specs:
            problems.append(f"{rid}: decision_binding {binding} has no decision_specs entry")
        for cap in then.get("prohibits") or []:
            if cap not in caps:
                problems.append(f"{rid}: prohibits {cap}, which no adapter declares")
        if not rule.get("rationale"):
            problems.append(f"{rid}: no rationale")
for p in tooling.get("permissions", []):
    cap = f'{p["adapter_id"]}.{p["capability"]}'
    if cap not in caps:
        problems.append(f'permission {p["permission_id"]}: {cap} is not a declared capability')
for problem in problems:
    print("problem:", problem)
if problems:
    sys.exit(1)
print(f"ok: {len(rule_ids)} rule(s); gates, decision bindings, prohibitions and permissions resolve")
PY

if [[ ${#tests[@]} -gt 0 ]]; then
    echo "== tests"
    if ! "$ctx" test --pack "$pack" "${tests[@]}" >"$scratch/tests.json"; then
        python3 -I - "$scratch/tests.json" <<'PY'
import json, sys
report = json.load(open(sys.argv[1]))
for suite in report["suites"]:
    for test in suite["tests"]:
        if test["status"] != "pass":
            print(f'{test["status"]}: {suite["suite"]}: {test["name"]}: {"; ".join(test["failures"])}')
PY
        exit 1
    fi
    python3 -I - "$scratch/tests.json" <<'PY'
import json, sys
print(f'ok: {json.load(open(sys.argv[1]))["passed"]} test(s) pass')
PY
fi

if [[ -n "$run" ]]; then
    echo "== plans"
    IFS=',' read -r -a role_list <<<"${roles:-}"
    [[ ${#role_list[@]} -gt 0 ]] || role_list=("")
    for role in "${role_list[@]}"; do
        file="$run"
        if [[ -n "$role" ]]; then
            file="$scratch/run-$role.json"
            python3 -I - "$run" "$role" "$file" <<'PY'
import json, sys
body = json.load(open(sys.argv[1]))
run_context = body.get("run_context", body)
run_context.setdefault("user", {})["role"] = sys.argv[2]
json.dump(body, open(sys.argv[3], "w"))
PY
        fi
        args=(plan --pack "$pack" --run "$file")
        [[ -n "$intent" ]] && args+=(--intent "$intent")
        "$ctx" "${args[@]}" >"$scratch/plan.json"
        python3 -I - "$scratch/plan.json" "$role" <<'PY'
import json, sys
plan = json.load(open(sys.argv[1]))
role = sys.argv[2] or "(as in the run)"
print(f'role {role}, intent {plan["intent"]}: verdict {plan["verdict"]}, possible {plan["possible_verdicts"]}')
for rule in plan["rules"]:
    condition = "" if rule["applies"] == "always" else " " + json.dumps(rule["condition"], separators=(",", ":"))
    print(f'  {rule["effect"]:<16} {rule["rule_id"]} ({rule["branch"]}) {rule["applies"]}{condition}')
PY
    done
fi

if [[ -n "$baseline" ]]; then
    echo "== release gate"
    args=(gate --baseline "$baseline" --candidate "$pack" --cases "$cases")
    [[ -n "$ack" ]] && args+=(--acknowledge "$ack")
    if ! "$ctx" "${args[@]}" >"$scratch/gate.json"; then
        cat "$scratch/gate.json"
        echo "release gate failed: report the widenings above to the release owner" >&2
        exit 1
    fi
    echo "ok: no unacknowledged widening"
fi
echo "pack checks passed"
