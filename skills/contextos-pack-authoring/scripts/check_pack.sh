#!/usr/bin/env bash
# Checks a Context Pack the way a release would: schema, references that must resolve,
# pack tests, a decision plan per role, and the release gate against a baseline.
#
#   check_pack.sh --pack PACK [--tests SUITE]... [--run RUN [--roles r1,r2] [--intent I]]
#                 [--baseline OLD --cases CASES [--acknowledge ACK]]
#
# Uses `ctx` from $CTX, else PATH, else $CONTEXTOS_BIN, else a release archive's bin/,
# else this checkout's target/release or target/debug. Exits non-zero on the first
# failing check; prints each plan for a person to read.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../../.." && pwd)"
ctx=""
if [[ -n "${CTX:-}" ]]; then ctx="$CTX"
elif command -v ctx >/dev/null 2>&1; then ctx="$(command -v ctx)"
else
    for candidate in "${CONTEXTOS_BIN:+$CONTEXTOS_BIN/ctx}" "$repo/bin/ctx" "$repo/target/release/ctx" "$repo/target/debug/ctx"; do
        if [[ -n "$candidate" && -x "$candidate" ]]; then ctx="$candidate"; break; fi
    done
fi
[[ -n "$ctx" && -x "$ctx" ]] || {
    echo "ctx not found: run from a release archive, build it (cargo build -p ctx) or set CTX" >&2
    exit 2
}

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
"$ctx" inspect "$pack" >"$scratch/inspect.json"
python3 -I - "$scratch/inspect.json" <<'PY'
import json, sys
summary = json.load(open(sys.argv[1]))
for problem in summary["problems"]:
    print("problem:", problem)
if summary["problems"]:
    sys.exit(1)
rules = sum(len(r) for r in summary["intents"].values())
print(f"ok: {rules} rule(s) over {len(summary['intents'])} intent(s); every name resolves")
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
