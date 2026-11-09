"""Replay recorded tool-call traffic through a ContextOS gateway and report what it
would have done: duplicates refused, limits held, approvals required, outcomes left
in doubt, and refusals worth reviewing as possible false blocks.

The gateway under test sends every effect to the replay's own tool server, which
answers each call with the recorded outcome, so no real system is touched. Point the
gateway's adapters at :attr:`ToolServer.url` (``kind = "mcp"``) before replaying.

Traffic is JSON Lines, one tool call per line::

    {"ts": "2026-11-01T09:30:00Z", "run_id": "run_1", "agent": "agt_support",
     "capability_id": "adp_payments.issue_refund", "args": {...},
     "approval_mode": "destructive", "outcome": "ok", "output": {...}}

``outcome`` is ``ok`` (the tool applied the call and answered ``output``), ``error``
(the tool refused it) or ``timeout`` (no answer arrived: the effect may have happened).
``idempotency_key``, ``evidence_refs`` and ``vars`` are optional. Without a key each
call is a fresh operation, as most agent code sends them today. ``vars`` fill the
admission template's ``$NAME`` placeholders for the call's run, beside ``$RUN_ID`` and
``$AGENT``.

Run it as ``python -m contextos.replay --help``.
"""
import argparse
import copy
import json
import os
import sys
import threading
from collections import Counter, defaultdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Iterable, List, Optional

from .client import Client
from .errors import ToolBlocked, ToolFailed, ToolOutcome, ToolPaused, ToolRejected

OUTCOMES = ("ok", "error", "timeout")
# Refusals that are the point of the gateway: the recorded call repeated or overran.
DUPLICATE_REASONS = ("effect_repeated", "effect_repeated_across_runs", "retry_unsafe")
LIMIT_PREFIX = "shared_guarantee_"


def load_traffic(lines: Iterable[str]) -> List[dict]:
    """Recorded calls in time order; malformed lines are refused with their number."""
    records = []
    for number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as error:
            raise ValueError(f"line {number}: not JSON ({error})") from error
        for field in ("ts", "run_id", "capability_id", "args", "outcome"):
            if field not in record:
                raise ValueError(f"line {number}: missing {field}")
        if record["outcome"] not in OUTCOMES:
            raise ValueError(f"line {number}: outcome must be one of {', '.join(OUTCOMES)}")
        record["line"] = number
        records.append(record)
    return sorted(records, key=lambda r: (r["ts"], r["line"]))


class ToolServer:
    """An MCP tool server that answers each call with the recorded outcome of the call
    being replayed, and counts the effects that reached it."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0):
        self.current: Optional[dict] = None
        self.reached: List[int] = []
        self._lock = threading.Lock()
        server = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                try:
                    request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                    reply = server._answer(request)
                    if reply is None:  # a recorded timeout: the response is lost
                        self.close_connection = True
                        return
                    payload = json.dumps(reply).encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(payload)))
                    self.end_headers()
                    self.wfile.write(payload)
                except (BrokenPipeError, ConnectionResetError):
                    pass

            def log_message(self, *args):
                pass

        self._server = ThreadingHTTPServer((host, port), Handler)
        threading.Thread(target=self._server.serve_forever, daemon=True).start()

    @property
    def url(self) -> str:
        host, port = self._server.server_address[:2]
        return f"http://{host}:{port}/mcp"

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()

    def _answer(self, request: dict) -> Optional[dict]:
        rid = request.get("id")
        if request.get("method") != "tools/call":
            return {"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": "not recorded"}}
        with self._lock:
            record = self.current
            if record is not None:
                self.reached.append(record["line"])
        if record is None:
            return {"jsonrpc": "2.0", "id": rid, "error": {"code": -32603, "message": "no call is being replayed"}}
        if record["outcome"] == "timeout":
            return None
        if record["outcome"] == "error":
            return {"jsonrpc": "2.0", "id": rid, "result": {
                "isError": True, "content": [{"type": "text", "text": record.get("error", "recorded error")}]}}
        return {"jsonrpc": "2.0", "id": rid, "result": {"structuredContent": record.get("output") or {}}}


def admission_for(template: dict, record: dict) -> dict:
    """The template with ``$RUN_ID``, ``$AGENT`` and each ``$NAME`` of the record's
    ``vars`` filled in. A string that is exactly one placeholder takes the variable's
    own JSON type, so ``"$AMOUNT"`` can become a number."""
    values = {"RUN_ID": record["run_id"], "AGENT": record.get("agent", ""), **record.get("vars", {})}
    names = sorted(values, key=len, reverse=True)  # $RUN_ID before $RUN

    def fill(value: Any) -> Any:
        if isinstance(value, str):
            if value.startswith("$") and value[1:] in values:
                return values[value[1:]]
            for name in names:
                value = value.replace("$" + name, str(values[name]))
            return value
        if isinstance(value, list):
            return [fill(v) for v in value]
        if isinstance(value, dict):
            return {k: fill(v) for k, v in value.items()}
        return value

    return fill(copy.deepcopy(template))


def _classify(error: ToolOutcome) -> str:
    if isinstance(error, ToolPaused):
        return {"approval": "approval_required", "unknown_outcome": "held_unknown",
                "duplicate": "duplicate_refused", "input": "input_required"}.get(error.kind, "paused")
    if any(code in DUPLICATE_REASONS for code in error.reason_codes):
        return "duplicate_refused"
    if any(code.startswith(LIMIT_PREFIX) for code in error.reason_codes):
        return "limit_refused"
    if isinstance(error, ToolFailed):
        return "tool_failed"
    if isinstance(error, (ToolBlocked, ToolRejected)):
        return "blocked"
    return "other"


def replay(client: Client, records: List[dict], template: dict, tools: ToolServer,
           approval_modes: Optional[Dict[str, str]] = None) -> dict:
    """Admit one run per recorded run and dispatch every call in time order. Returns the
    report: one entry per call and the totals."""
    approval_modes = approval_modes or {}
    runs: Dict[str, Any] = {}
    calls = []
    for record in records:
        mode = record.get("approval_mode") or approval_modes.get(record["capability_id"], "read_only")
        entry = {"line": record["line"], "run_id": record["run_id"], "capability_id": record["capability_id"],
                 "effect": mode != "read_only", "recorded": record["outcome"], "reason_codes": [], "result": None}
        try:
            run = runs.get(record["run_id"])
            if run is None:
                principal = [{"kind": "agent", "id": record["agent"]}] if record.get("agent") else None
                run = runs[record["run_id"]] = client.admit(admission_for(template, record), principal)
            tools.current = record
            try:
                run.call_tool(record["capability_id"], record["args"], approval_mode=mode,
                              idempotency_key=record.get("idempotency_key"),
                              evidence_refs=record.get("evidence_refs"), tool_call_id=record.get("tool_call_id"))
                entry["result"] = "allowed"
            finally:
                tools.current = None
        except ToolOutcome as error:
            entry["result"] = _classify(error)
            entry["reason_codes"] = error.reason_codes
        except Exception as error:  # an admission refusal or a transport fault: report, go on
            entry["result"] = "error"
            entry["reason_codes"] = [type(error).__name__ + ": " + str(error)[:200]]
        calls.append(entry)
    return summarize(calls, tools.reached)


def summarize(calls: List[dict], reached: List[int]) -> dict:
    results = Counter(c["result"] for c in calls)
    reasons = Counter(code for c in calls if c["result"] != "allowed" for code in c["reason_codes"])
    by_capability: Dict[str, Counter] = defaultdict(Counter)
    for c in calls:
        by_capability[c["capability_id"]][c["result"]] += 1
    effects = [c for c in calls if c["effect"]]
    sent = set(reached)
    recorded_effects = sum(1 for c in effects if c["recorded"] in ("ok", "timeout"))
    # Effects the recording shows applied that the gateway refused as a repeat or over a limit.
    prevented = sum(1 for c in effects if c["recorded"] == "ok" and c["result"] in ("duplicate_refused", "limit_refused"))
    # A refusal of a call that really succeeded, for a reason other than a repeat or a
    # limit, is a candidate false block: review the rule that refused it.
    candidates = [c for c in calls if c["recorded"] == "ok"
                  and c["result"] in ("blocked", "tool_failed", "other", "error")]
    return {
        "report_version": "contextos.replay_report.v1",
        "calls": len(calls),
        "runs": len({c["run_id"] for c in calls}),
        "recorded_effects": recorded_effects,
        "effects_sent": sum(1 for c in effects if c["line"] in sent),
        "effects_prevented": prevented,
        "results": dict(sorted(results.items())),
        "duplicates_refused": results["duplicate_refused"],
        "limits_held": results["limit_refused"],
        "approvals_required": results["approval_required"],
        "held_unknown": results["held_unknown"],
        "reasons": dict(reasons.most_common()),
        "by_capability": {k: dict(sorted(v.items())) for k, v in sorted(by_capability.items())},
        "false_block_candidates": candidates[:50],
        "entries": calls,
    }


def markdown(report: dict) -> str:
    lines = [
        "# Replay report", "",
        f"{report['calls']} recorded calls in {report['runs']} runs. The recording shows "
        f"{report['recorded_effects']} effects applied or in doubt; through ContextOS, "
        f"{report['effects_sent']} reached the tool, and {report['effects_prevented']} that the "
        "recording shows applied were refused as a repeat or over a limit.", "",
        "| Outcome | Calls |", "|---|---|",
    ]
    lines += [f"| {k} | {v} |" for k, v in report["results"].items()]
    lines += ["", "## Refusal reasons", "", "| Reason | Calls |", "|---|---|"]
    lines += [f"| `{k}` | {v} |" for k, v in report["reasons"].items()] or ["| none | 0 |"]
    lines += ["", "## By capability", "", "| Capability | Outcomes |", "|---|---|"]
    lines += [f"| `{k}` | {', '.join(f'{r} {n}' for r, n in v.items())} |"
              for k, v in report["by_capability"].items()]
    lines += ["", "## Possible false blocks", ""]
    if report["false_block_candidates"]:
        lines += [f"- line {c['line']} (`{c['capability_id']}`, run `{c['run_id']}`): "
                  f"{', '.join(c['reason_codes']) or c['result']}" for c in report["false_block_candidates"]]
    else:
        lines.append("None: every call the recording shows as successful was allowed, "
                     "or refused as a repeat or over a limit.")
    return "\n".join(lines) + "\n"


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m contextos.replay", description=__doc__.split("\n\n")[0])
    parser.add_argument("traffic", help="recorded tool calls, JSON Lines")
    parser.add_argument("--url", required=True, help="the gateway under test")
    parser.add_argument("--token-env", default="CONTEXTOS_TOKEN", help="environment variable holding the API key")
    parser.add_argument("--admission", required=True, help="admission template with $RUN_ID and $AGENT")
    parser.add_argument("--approval-modes", help="JSON object: capability id to approval mode")
    parser.add_argument("--tools-port", type=int, default=0, help="port for the replay tool server")
    parser.add_argument("--wait", action="store_true",
                        help="print the tool server URL and wait for Enter before replaying")
    parser.add_argument("--out", default="replay-report", help="report path prefix (.json and .md)")
    args = parser.parse_args(argv)
    token = os.environ.get(args.token_env)
    if not token:
        parser.error(f"set {args.token_env} to the gateway API key")
    with open(args.traffic) as f:
        records = load_traffic(f)
    with open(args.admission) as f:
        template = json.load(f)
    modes = json.loads(args.approval_modes) if args.approval_modes else {}
    tools = ToolServer(port=args.tools_port)
    try:
        if args.wait:
            print(f"replay tool server: {tools.url}", flush=True)
            input("point the gateway's adapters here, then press Enter ")
        report = replay(Client(args.url, token), records, template, tools, modes)
    finally:
        tools.close()
    with open(args.out + ".json", "w") as f:
        json.dump(report, f, indent=2)
    with open(args.out + ".md", "w") as f:
        f.write(markdown(report))
    print(f"replay report written: {args.out}.md and {args.out}.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
