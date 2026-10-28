"""The textbook answer: a refund service that guards its ceiling with a row lock.

This is the design a skeptical reviewer proposes first, written carefully. SQLite's
BEGIN IMMEDIATE takes the database write lock, which plays the role of
SELECT ... FOR UPDATE on the order's row: concurrent refunds on one order serialize,
and the check and the update are atomic. The provider is reached over the network,
exactly as a payment service provider is.

Two placements of the provider call are shown, because both appear in production:

- LockAroundCall holds the lock across the provider call and commits after it.
- ReserveThenCall commits the reservation first, calls the provider, and gives the
  amount back if the call fails. This is the usual fix for holding locks across I/O.
  With release_on_failure=False it keeps the amount instead, the usual fix for that.

Both are correct while the provider answers. The demo shows what each does when it
does not, and when one business limit spans two services with separate databases.
"""
import json
import sqlite3
from urllib.request import Request, urlopen


class ProviderUnavailable(Exception):
    """No answer arrived: the effect may or may not have been applied."""


def call_tool(endpoint, tool, arguments, timeout):
    """One MCP tools/call. Any transport failure surfaces as ProviderUnavailable."""
    body = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": tool, "arguments": arguments}}
    request = Request(endpoint, data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
    try:
        with urlopen(request, timeout=timeout) as response:
            return json.loads(response.read())["result"]
    except OSError as error:
        raise ProviderUnavailable(str(error)) from error


class LedgerService:
    """One service, one database, one per-order ceiling on its own column."""

    tool = "issue_refund"

    def __init__(self, path, endpoint, ceiling, timeout=0.5):
        self.path, self.endpoint, self.ceiling, self.timeout = path, endpoint, ceiling, timeout
        with self.connect() as db:
            db.execute("CREATE TABLE IF NOT EXISTS orders (order_id TEXT PRIMARY KEY, used INTEGER NOT NULL)")

    def connect(self):
        return sqlite3.connect(self.path, timeout=10, isolation_level=None)

    def used(self, order_id):
        with self.connect() as db:
            row = db.execute("SELECT used FROM orders WHERE order_id = ?", (order_id,)).fetchone()
        return row[0] if row else 0

    def provider(self, order_id, amount):
        return call_tool(self.endpoint, self.tool, {"order_id": order_id, "amount_minor": amount}, self.timeout)


class LockAroundCall(LedgerService):
    def refund(self, order_id, amount):
        db = self.connect()
        try:
            db.execute("BEGIN IMMEDIATE")  # the row lock
            row = db.execute("SELECT used FROM orders WHERE order_id = ?", (order_id,)).fetchone()
            used = row[0] if row else 0
            if used + amount > self.ceiling:
                db.execute("ROLLBACK")
                return "exceeded"
            self.provider(order_id, amount)  # inside the transaction
            db.execute("INSERT INTO orders VALUES (?, ?) ON CONFLICT(order_id) DO UPDATE SET used = ?",
                       (order_id, used + amount, used + amount))
            db.execute("COMMIT")
            return "refunded"
        except ProviderUnavailable:
            db.execute("ROLLBACK")  # undoes our row, not the provider's
            return "failed"
        finally:
            db.close()


class ReserveThenCall(LedgerService):
    def __init__(self, *args, release_on_failure=True, **kwargs):
        super().__init__(*args, **kwargs)
        self.release_on_failure = release_on_failure

    def refund(self, order_id, amount):
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT used FROM orders WHERE order_id = ?", (order_id,)).fetchone()
            used = row[0] if row else 0
            if used + amount > self.ceiling:
                db.execute("ROLLBACK")
                return "exceeded"
            db.execute("INSERT INTO orders VALUES (?, ?) ON CONFLICT(order_id) DO UPDATE SET used = ?",
                       (order_id, used + amount, used + amount))
            db.execute("COMMIT")
        try:
            self.provider(order_id, amount)
            return "refunded"
        except ProviderUnavailable:
            if self.release_on_failure:  # so a failed call does not strand capacity
                with self.connect() as db:
                    db.execute("UPDATE orders SET used = used - ? WHERE order_id = ?", (amount, order_id))
            return "failed"


class StoreCreditService(ReserveThenCall):
    """A second team's service: its own database, its own ceiling, same order."""

    tool = "grant_store_credit"
