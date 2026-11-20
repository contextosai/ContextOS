"""The lab's baselines and its money accounting.

A baseline world sends the agent's attempts straight to its own provider, the way an
agent without a gateway would. `Money` then splits what any world's provider paid into
what somebody authorised and the excess, by the scenario's `rightful` rule.
"""
from provider import Provider, total
from scenarios import APPROVAL_LINE


class Baseline:
    """One baseline: `direct`, `keyed` or `checked` (see scenarios.py)."""

    def __init__(self, kind, payments):
        self.kind, self.provider = kind, Provider(payments)

    def refund(self, step, approved):
        """Sends one attempt; returns what the agent's code would see."""
        order, amount, run = step["order"], step["amount"], step["run"]
        attempt = {"order_id": order, "amount_minor": amount}
        if self.kind == "checked" and amount > APPROVAL_LINE and (order, amount) not in approved:
            return {**attempt, "outcome": "waiting_for_approval"}
        key = None
        if self.kind == "keyed":
            # One key per refund per run: a retry inside the run reuses it, a new run
            # cannot know it.
            key = attempt["idempotency_key"] = f"{run}:{order}:{amount}"
        self.provider.mode = step.get("mode", "answer")
        outcome, entry = self.provider.refund(order, amount, f"{run}/{step.get('call', 'call_1')}", key)
        self.provider.mode = "answer"
        attempt["outcome"] = outcome
        if entry is not None:
            attempt["refund_id"] = entry["refund_id"]
        return attempt


class Money:
    """Marks each ledger entry with how much of it nobody authorised."""

    def __init__(self, rule):
        self.rule, self.excess = rule, {}

    def account(self, ledger, approved):
        """Returns the ledger with `excess_minor` on every entry. An entry is judged
        once, when it first appears, against the entries before it."""
        out = []
        for index, entry in enumerate(ledger):
            if entry["refund_id"] not in self.excess:
                self.excess[entry["refund_id"]] = self.judge(entry, ledger[:index], approved)
            out.append({**{k: entry[k] for k in ("refund_id", "order_id", "amount_minor")},
                        "excess_minor": self.excess[entry["refund_id"]]})
        return out

    def judge(self, entry, before, approved):
        rule, amount = self.rule, entry["amount_minor"]
        if rule["rule"] == "owed":
            # What the customer is owed on each order; anything else is excess.
            owed = rule["owed"].get(entry["order_id"], 0)
            paid = total(e for e in before if e["order_id"] == entry["order_id"])
            return amount - max(0, min(amount, owed - paid))
        if rule["rule"] == "cap":
            return amount - max(0, min(amount, rule["limit"] - total(before)))
        if rule["rule"] == "first":
            return amount if len(before) >= rule["count"] else 0
        if rule["rule"] == "approved":
            return 0 if (entry["order_id"], amount) in approved else amount
        raise ValueError(rule)


def view(ledger, calls, money, approved):
    entries = money.account(ledger, approved)
    return {"ledger": entries, "provider_calls": calls, "paid": total(entries),
            "excess": sum(e["excess_minor"] for e in entries)}
