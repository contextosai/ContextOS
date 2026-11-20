#!/usr/bin/env python3
"""Replay your agent's refund tool calls through a local ContextOS gateway.

One supported workflow: refunds. Give it your agent's tool calls as JSON Lines, say
which tool issues refunds and where the order and amount are in its arguments, and it
replays every refund, in time order, through contextosd on this machine. Each call is
answered with the outcome you recorded, so no payment system is called. The report
says, in money, what the gateway would have sent, refused as a repeat, held because
the outcome was unknown, stopped at an order's ceiling or sent for approval, and lists
every refund of a call that really succeeded that it would have blocked for another
reason (possible false blocks).

One call per line; field names follow common agent logs:

    {"ts": "2026-11-03T09:14:05Z", "run_id": "conv_8812", "tool": "refund_payment",
     "args": {"order": "A-1042", "amount": 25.0}, "outcome": "ok", "output": {...}}

  ts        ISO 8601 time of the call (optional: file order is used without it)
  run_id    the agent run, conversation or session (also: session_id, conversation_id, trace_id)
  tool      the tool name (also: name, tool_name)
  args      the tool's arguments, an object or a JSON string (also: arguments, input)
  outcome   ok (the provider applied it), error (it refused) or timeout (no answer arrived)
  output    optional: what the tool returned
  agent     optional: which agent made the call

Calls to other tools are counted and skipped.
"""
import argparse
import contextlib
import copy
from collections import defaultdict
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
import io
import json
import os
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "bindings/python"))
sys.path.insert(0, str(ROOT / "examples/replay"))
from contextos.client import Client  # noqa: E402
from contextos.replay import ToolServer, replay  # noqa: E402
from local_gateway import local_gateway  # noqa: E402

REFUND = "adp_payments.issue_refund"
OUTCOMES = ("ok", "error", "timeout")
RUN_FIELDS = ("run_id", "session_id", "conversation_id", "trace_id")
TOOL_FIELDS = ("tool", "name", "tool_name")
ARG_FIELDS = ("args", "arguments", "input")
# A repeat across runs inside this window is the same request (the intent key's window).
WINDOW_SECONDS = 86_400
NO_APPROVALS = 10 ** 12


class InputError(ValueError):
    """A line of the input that cannot be replayed, with its line number."""


def first(record, fields):
    return next((record[f] for f in fields if f in record and record[f] is not None), None)


def pointer(value, path):
    """Resolves a JSON Pointer (RFC 6901) inside `value`; None when absent."""
    if path in ("", "/"):
        return value
    for raw in path.lstrip("/").split("/"):
        part = raw.replace("~1", "/").replace("~0", "~")
        if isinstance(value, dict) and part in value:
            value = value[part]
        elif isinstance(value, list) and part.isdigit() and int(part) < len(value):
            value = value[int(part)]
        else:
            return None
    return value


def read_calls(lines):
    """Every tool call of the log, normalized; malformed lines are refused by number."""
    calls = []
    for number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as error:
            raise InputError(f"line {number}: not JSON ({error})") from error
        tool, args = first(record, TOOL_FIELDS), first(record, ARG_FIELDS)
        if isinstance(args, str):
            try:
                args = json.loads(args)
            except json.JSONDecodeError as error:
                raise InputError(f"line {number}: arguments are not JSON ({error})") from error
        if not tool or not isinstance(args, dict):
            raise InputError(f"line {number}: needs a tool name and an arguments object")
        outcome = record.get("outcome")
        if outcome not in OUTCOMES:
            raise InputError(f"line {number}: outcome must be one of {', '.join(OUTCOMES)}")
        calls.append({"line": number, "ts": record.get("ts"), "run": str(first(record, RUN_FIELDS) or "run"),
                      "agent": str(record.get("agent") or "agent"), "tool": tool, "args": args,
                      "outcome": outcome, "output": record.get("output"), "error": record.get("error")})
    return sorted(calls, key=lambda c: (c["ts"] or "", c["line"]))


def minor_units(value, unit, line):
    try:
        amount = Decimal(str(value))
    except (InvalidOperation, ValueError) as error:
        raise InputError(f"line {line}: amount {value!r} is not a number") from error
    minor = amount * 100 if unit == "major" else amount
    if minor != minor.to_integral_value() or minor <= 0:
        raise InputError(f"line {line}: amount {value!r} is not a positive whole number of minor units")
    return int(minor)


def to_records(calls, mapping):
    """The refund calls as replay records for the gateway's refund capability."""
    records, skipped = [], defaultdict(int)
    for call in calls:
        if call["tool"] != mapping["tool"]:
            skipped[call["tool"]] += 1
            continue
        order = pointer(call["args"], mapping["order"])
        amount = pointer(call["args"], mapping["amount"])
        if order is None or amount is None:
            raise InputError(f"line {call['line']}: no order at {mapping['order']} or amount at {mapping['amount']}"
                             " (set --order and --amount to JSON Pointers into the arguments)")
        customer = pointer(call["args"], mapping["customer"]) if mapping["customer"] else None
        minor = minor_units(amount, mapping["unit"], call["line"])
        args = {"order_id": str(order), "customer_id": str(customer or "customer"), "amount_minor": minor}
        record = {"line": call["line"], "ts": call["ts"] or "", "run_id": call["run"], "agent": call["agent"],
                  "capability_id": REFUND, "args": args, "approval_mode": "destructive", "outcome": call["outcome"],
                  "evidence_refs": [f"kg:order:{args['order_id']}#snapshot_kg_2026_05_03_T0930"],
                  "vars": {"ORDER": args["order_id"], "CUSTOMER": args["customer_id"], "AMOUNT": minor // 100}}
        if call["outcome"] == "ok":
            record["output"] = call["output"] if isinstance(call["output"], dict) else {"result": call["output"]}
        if call["error"]:
            record["error"] = str(call["error"])
        records.append(record)
    return records, dict(skipped)


def guess_tool(calls):
    names = sorted({c["tool"] for c in calls if "refund" in c["tool"].lower()})
    return names[0] if len(names) == 1 else None


def parse_ts(value):
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    except (AttributeError, ValueError):
        return None


def money_report(records, report, reached, currency, ceiling):
    """The replay's results, in money, per order and in total."""
    by_line = {r["line"]: r for r in records}
    rows = []
    for entry in report["entries"]:
        record = by_line[entry["line"]]
        rows.append({"line": entry["line"], "ts": record["ts"], "run_id": record["run_id"],
                     "order_id": record["args"]["order_id"], "amount_minor": record["args"]["amount_minor"],
                     "recorded": entry["recorded"], "result": entry["result"],
                     "reason_codes": entry["reason_codes"], "sent": entry["line"] in reached})
    review = review_items(rows)
    review_lines = {r["line"] for r in review}
    false_blocks = [r for r in rows if r["recorded"] == "ok" and r["line"] not in review_lines
                    and r["result"] in ("blocked", "tool_failed", "other", "error")]
    orders = defaultdict(lambda: defaultdict(int))
    for row in rows:
        totals, amount = orders[row["order_id"]], row["amount_minor"]
        if row["recorded"] == "ok":
            totals["recorded_paid"] += amount
        if row["recorded"] == "timeout":
            totals["recorded_unknown"] += amount
        if row["line"] in review_lines:
            totals["needs_review"] += amount
        elif row["sent"] and row["result"] == "allowed":
            totals["sent_paid"] += amount
        elif row["sent"] and row["result"] == "held_unknown":
            totals["held"] += amount
        elif row["result"] == "duplicate_refused":
            totals["repeats_refused"] += amount
        elif row["result"] == "limit_refused":
            totals["over_ceiling"] += amount
        elif row["result"] == "approval_required":
            totals["awaiting_approval"] += amount
    keys = ("recorded_paid", "recorded_unknown", "sent_paid", "held", "repeats_refused", "over_ceiling",
            "awaiting_approval", "needs_review")
    return {
        "report_version": "contextos.refund_replay.v1", "currency": currency, "order_ceiling_minor": ceiling,
        "refund_calls": len(rows), "runs": len({r["run_id"] for r in rows}), "orders": len(orders),
        "totals": {k: sum(o[k] for o in orders.values()) for k in keys},
        "by_order": {order: {k: o[k] for k in keys} for order, o in sorted(orders.items())},
        "review": review, "false_block_candidates": false_blocks, "calls": rows,
    }


def review_items(rows):
    """Repeats the gateway refused that your recording spaced further apart than the
    intent window: the replay runs in minutes, so it cannot tell these from retries."""
    items = []
    for i, row in enumerate(rows):
        if "effect_repeated_across_runs" not in row["reason_codes"]:
            continue
        earlier = [r for r in rows[:i] if r["order_id"] == row["order_id"] and r["amount_minor"] == row["amount_minor"]]
        start, end = parse_ts(earlier[-1]["ts"]) if earlier else None, parse_ts(row["ts"])
        if start and end and (end - start).total_seconds() > WINDOW_SECONDS:
            items.append({**row, "why": "refused as a repeat, but recorded more than a day after the same refund"})
    return items


def fmt(minor, currency):
    return f"{currency} {Decimal(minor) / 100:,.2f}"


def markdown(money, skipped):
    c, t = money["currency"], money["totals"]
    f = lambda v: fmt(v, c)  # noqa: E731
    lines = ["# Refund replay", "",
             f"{money['refund_calls']} refund calls in {money['runs']} runs on {money['orders']} orders"
             + (f"; {sum(skipped.values())} calls to other tools skipped." if skipped else "."), "",
             f"Your recording paid {f(t['recorded_paid'])}"
             + (f", plus {f(t['recorded_unknown'])} that got no answer" if t["recorded_unknown"] else "")
             + f". Through ContextOS, {f(t['sent_paid'])} would have been paid, {f(t['held'])} held until someone "
             f"checked the provider, and {f(t['repeats_refused'])} of repeated refunds not sent.", "",
             "| | Amount |", "|---|---|",
             f"| Refunded in your recording | {f(t['recorded_paid'])} |",
             f"| Recorded with no answer (may have been paid) | {f(t['recorded_unknown'])} |",
             f"| Sent through ContextOS and paid | {f(t['sent_paid'])} |",
             f"| Sent through ContextOS, outcome unknown: held until reconciled | {f(t['held'])} |",
             f"| Not sent: repeat of a refund already sent or in doubt | {f(t['repeats_refused'])} |",
             f"| Not sent: over the order's ceiling | {f(t['over_ceiling'])} |",
             f"| Waiting for a person's approval | {f(t['awaiting_approval'])} |",
             f"| Refused as a repeat, needs your review (below) | {f(t['needs_review'])} |", ""]
    if money["order_ceiling_minor"] is None:
        lines += ["No per-order ceiling was set (`--order-limit`).", ""]
    lines += ["## By order", "", "| Order | Recorded paid | Through ContextOS: paid | Held | Repeats not sent |",
              "|---|---|---|---|---|"]
    lines += [f"| `{o}` | {f(v['recorded_paid'])} | {f(v['sent_paid'])} | {f(v['held'])} | {f(v['repeats_refused'])} |"
              for o, v in money["by_order"].items()]
    lines += ["", "## Review these", ""]
    if money["review"]:
        lines += [f"- line {r['line']} (`{r['order_id']}`, {f(r['amount_minor'])}): {r['why']}. If it was a new "
                  "refund, it was a false block in this replay." for r in money["review"]]
    if money["false_block_candidates"]:
        lines += [f"- line {r['line']} (`{r['order_id']}`, {f(r['amount_minor'])}, run `{r['run_id']}`): the call "
                  f"succeeded in your recording but was refused: {', '.join(r['reason_codes']) or r['result']}"
                  for r in money["false_block_candidates"]]
    if not money["review"] and not money["false_block_candidates"]:
        lines.append("Nothing: every refund your recording shows as successful was sent, or refused as a repeat, "
                     "over the ceiling or for approval.")
    lines += ["", "## Every refund call", "", "| Line | Run | Order | Amount | Recorded | Through ContextOS | Reasons |",
              "|---|---|---|---|---|---|---|"]
    lines += [f"| {r['line']} | `{r['run_id']}` | `{r['order_id']}` | {f(r['amount_minor'])} | {r['recorded']} | "
              f"{r['result']}{'' if r['sent'] else ' (not sent)'} | {', '.join(r['reason_codes'])} |"
              for r in money["calls"]]
    return "\n".join(lines) + "\n"


def gateway_files(tmp, currency, approval_above):
    """The refund capability and pack, adjusted for this replay."""
    manifest = json.loads((ROOT / "examples/support-refund/capabilities/issue_refund.json").read_text())
    manifest["amount"]["currency"] = currency
    # One business request is one refund of one amount on one order, across runs.
    manifest["intent"] = {"key_pointers": ["/order_id", "/amount_minor"], "window_seconds": WINDOW_SECONDS}
    # Never retried blind; once proven not applied, a refund may be sent once more.
    manifest["recovery"] = {"strategy": "manual_reconcile", "max_attempts": 2, "retry_delays_seconds": [0]}
    manifest_path = Path(tmp) / "issue_refund.json"
    manifest_path.write_text(json.dumps(manifest, indent=2))
    pack = json.loads((ROOT / "examples/support-refund/pack.json").read_text())
    threshold = NO_APPROVALS if approval_above is None else approval_above

    def retune(node):
        if isinstance(node, dict):
            if ">" in node and isinstance(node[">"], list) and node[">"][0] == {"var": "request.context.refund_amount"}:
                node[">"][1] = threshold
            for value in node.values():
                retune(value)
        elif isinstance(node, list):
            for value in node:
                retune(value)

    retune(pack)
    pack_path = Path(tmp) / "pack.json"
    pack_path.write_text(json.dumps(pack, indent=2))
    return manifest_path, pack_path


def admission_template(currency):
    """The replay example's admission, in this replay's currency. Its task scope is
    not what is under test, so its amount ceiling does not bind."""
    template = json.loads((ROOT / "examples/replay/admission.json").read_text())

    def walk(node):
        if isinstance(node, dict):
            if isinstance(node.get("amount_ceiling"), dict):
                node["amount_ceiling"] = {"minor_units": NO_APPROVALS, "currency": currency}
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    walk(template)
    template["request"]["input"]["message"] = f"Refund order $ORDER for {currency} $AMOUNT."
    return template


def run(records, *, currency, ceiling, approval_above):
    guarantee = "" if ceiling is None else f'''
[[guarantees]]
id = "refunds-per-order"
capability_ids = ["{REFUND}"]
resource_pointer = "/order_id"
amount_pointer = "/amount_minor"
limit = {ceiling}
unit = "{currency}_minor"
'''
    template = admission_template(currency)
    tools = ToolServer()
    try:
        with tempfile.TemporaryDirectory(prefix="contextos-refund-replay-") as tmp:
            manifest, pack = gateway_files(tmp, currency, approval_above)
            with local_gateway(tools, guarantee, {"issue_refund.json": manifest}, pack=pack) as (base, key):
                # The development approval service prints each request; the report counts them.
                with contextlib.redirect_stdout(io.StringIO()):
                    report = replay(Client(base, key), copy.deepcopy(records), template, tools)
                return report, list(tools.reached)
    finally:
        tools.close()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0], epilog=__doc__.split("\n\n", 1)[1],
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("calls", type=Path, help="your agent's tool calls, JSON Lines")
    parser.add_argument("--refund-tool", help="the tool that issues refunds (default: the only tool named *refund*)")
    parser.add_argument("--order", default="/order_id", help="JSON Pointer to the order in its arguments")
    parser.add_argument("--amount", default="/amount", help="JSON Pointer to the amount in its arguments")
    parser.add_argument("--customer", help="JSON Pointer to the customer in its arguments (optional)")
    parser.add_argument("--amount-unit", choices=("minor", "major"), default="minor",
                        help="minor: cents, paise (2500 = 25.00); major: 25.00 (default: minor)")
    parser.add_argument("--currency", default="USD", help="three-letter currency code for the report")
    parser.add_argument("--order-limit", type=Decimal, help="cap all refunds of one order at this amount (major units)")
    parser.add_argument("--approval-above", type=int,
                        help="ask a person to approve a run whose first refund is above this (whole major units)")
    parser.add_argument("--out", type=Path, default=ROOT / "receipts/replay-refunds/report",
                        help="report path prefix: writes .md and .json")
    args = parser.parse_args(argv)
    currency = args.currency.upper()
    if len(currency) != 3 or not currency.isalpha():
        parser.error("--currency must be a three-letter code such as USD")
    try:
        with args.calls.open() as f:
            calls = read_calls(f)
        tool = args.refund_tool or guess_tool(calls)
        if not tool:
            parser.error("name the refund tool with --refund-tool; tools in the log: "
                         + ", ".join(sorted({c["tool"] for c in calls})))
        mapping = {"tool": tool, "order": args.order, "amount": args.amount, "customer": args.customer,
                   "unit": args.amount_unit}
        records, skipped = to_records(calls, mapping)
    except InputError as error:
        print(f"{args.calls}: {error}", file=sys.stderr)
        return 2
    if not records:
        print(f"{args.calls}: no calls to {tool}", file=sys.stderr)
        return 2
    ceiling = None if args.order_limit is None else int(args.order_limit * 100)
    report, reached = run(records, currency=currency, ceiling=ceiling, approval_above=args.approval_above)
    money = money_report(records, report, set(reached), currency, ceiling)
    money["skipped_tools"] = skipped
    text = markdown(money, skipped)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.with_suffix(".json").write_text(json.dumps(money, indent=2))
    args.out.with_suffix(".md").write_text(text)
    print(text)
    print(f"refund replay report written: {os.path.relpath(args.out.with_suffix('.md'))} and .json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
