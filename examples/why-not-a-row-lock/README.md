# Why not a row lock?

Run from the repository root:

```sh
./examples/why-not-a-row-lock/run.sh
```

Prerequisites: the pinned Rust toolchain and Python 3.9+. The script builds debug
binaries and uses synthetic loopback services, SQLite from the Python standard
library, temporary development credentials and an in-memory store. No model key,
cloud account or payment account is needed.

One synthetic provider applies refunds and store credit. It can lose a response after
applying the effect, or stall and never apply it; the caller sees the same timeout
either way. Each order has an INR 1,000 limit.

**Part 1** drives [refund_service.py](refund_service.py), a refund service that guards
the limit with a database write lock (the role of `SELECT ... FOR UPDATE`):

- Two concurrent INR 800 refunds: one applies. The lock is correct for the race.
- A lost response, with the lock held across the call or with reserve-then-release:
  the ledger forgets an applied refund and the provider pays INR 1,600.
- A stalled call with reserve-and-keep: nothing was refunded, but further refunds are
  refused until someone edits the row.
- Refund and store credit in two services: each stays within its own ceiling, and
  the customer receives INR 1,600.

**Part 2** sends the same faults through ContextOS with one guarantee covering
`adp_payments.issue_refund` and `adp_loyalty.grant_store_credit`:

- The lost response is held as unknown. A second agent's refund and a third agent's
  store credit are withheld before dispatch.
- An operator reconciles it as confirmed, citing the provider's ledger.
- The stalled call is held, reconciled as not applied, released once and retried.
- The remaining INR 200 goes out as store credit: exactly INR 1,000 in total.

The example asserts every balance and the provider's own totals, so a broken
invariant exits nonzero. It exports the audit and verifies it offline; output ends
with `row lock comparison complete`.

The reasoning, including when to keep the transaction and build this in your service,
is in [Why not a database transaction?](../../docs/WHY_NOT_A_TRANSACTION.md). The
operator assertions here cite synthetic evidence; ContextOS records cited evidence
and does not fetch it.
