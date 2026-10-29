# Why not a database transaction?

The objection: *two agents refunding one order is a race condition. Put
`SELECT ... FOR UPDATE` on the order row in the refund service, check the ceiling,
write, commit. Why put a gateway in front of it?*

## Short answer

If the effect is a write to a database you own, and every caller goes through that
one service, use the transaction. It is simpler, faster and stronger than anything
placed in front of the service. ContextOS does not replace it, and you should keep it
when you deploy ContextOS.

A row lock makes a check against your database atomic with a write to your database.
A refund is not a write to your database: the money moves at the payment provider,
in a database you cannot enlist. The lock solves the race completely. It does not
solve three other problems, and agents make all three common:

1. The effect happens outside the transaction, so a timeout leaves it unknown.
2. One business limit spans several systems, each with its own database.
3. The tool belongs to someone else, so there is no row to lock.

Run both designs against the same faults:

```sh
./examples/why-not-a-row-lock/run.sh
```

```text
Part 1: a refund service with a row lock (refund_service.py), ceiling INR 1,000 per order
  race: two agents, INR 800 each                     1 applied, 1 refused. Correct.
  lost response, lock held across the call           ledger INR 800, provider refunded INR 1,600. Over the limit.
  lost response, reserve, call, release on failure   ledger INR 800, provider refunded INR 1,600. Over the limit.
  stalled call, reserve and keep on failure          ledger INR 800, provider refunded INR 0. Owed refunds refused until someone edits the row.
  refund + store credit, two databases               each within its own ceiling; customer paid INR 1,600. Over the limit.

Part 2: the same faults through ContextOS, one guarantee over both tools
  lost response, ord_881                             unknown: INR 800 held, INR 200 available
  second agent, refund INR 800                       withheld before dispatch (shared_guarantee_exceeded)
  third agent, store credit INR 800                  withheld before dispatch: another system, one limit
  reconciled from the provider ledger                confirmed: INR 800 committed
  stalled call, ord_882                              held; reconciled not applied, released; retry refunds INR 500
  store credit INR 200                               applied; customer paid INR 1,000 of INR 1,000
```

The baseline in [refund_service.py](../examples/why-not-a-row-lock/refund_service.py)
is the textbook design, written carefully, and it wins the race. Every row it
locks stays consistent. The order's limit is broken anyway, because the limit is
about money at the provider, not about the row.

## 1. The effect is outside the transaction

Your database and the payment provider cannot commit atomically. No payment
provider joins an XA or two-phase commit with your database. Every design therefore
chooses an order of operations, and a timeout tests that choice. A timeout means the
caller does not know whether the effect was applied:

| Design | Lost response: applied, no answer | Stalled call: not applied, no answer |
|---|---|---|
| Lock across the call, roll back on error | Rollback forgets an applied refund; the next one passes. **Over the limit.** | Correct |
| Reserve and commit, call, release on error | Same. **Over the limit.** | Correct |
| Reserve and commit, call, keep on error | Correct | Capacity stranded; refunds the customer is owed are refused **indefinitely** |

The caller cannot tell the two columns apart. Any design that resolves a timeout by
itself is wrong in one of them. Holding the lock across the call also turns provider
latency into database contention: a connection and a lock stay held for the
provider's timeout, on every refund.

The correct design adds a third state: *held until evidence resolves it*. Building that
state well requires more than one extra column:

- **Attempt identity.** A retry must be either the same attempt or a deliberately new
  one, never an accidental new one. The operation's identity is separate from
  transport attempts.
- **No retry of an unknown before reconciliation.** Otherwise the retry *is* the
  double refund. This still applies when the provider supports idempotency keys:
  the retry may come from another agent or run, with a different key.
- **Fencing.** A worker that pauses (GC, partition, a slow pod) after reserving must
  not dispatch after recovery has given up on its attempt. ContextOS requires a
  one-time activation of the exact attempt before the adapter runs. Recovery can
  close an unstarted attempt with a tombstone, so a delayed worker cannot revive it.
- **Reconciliation that never re-sends.** Resolve by querying the provider or by an
  attributed operator assertion that cites its evidence.
- **Sealing.** The first accepted definitive fact settles an attempt. A contradictory
  report later is an incident with evidence, not an edit to the balance.
- **No TTL.** The passage of time does not prove an effect was not applied, so
  restarts, expiry and run completion do not release capacity.
- **Evidence.** Record who reserved, who asserted the outcome, on what evidence, and
  why a later call was refused.

This is a reservation (escrow) ledger, the structure behind card authorization
holds. It is what the ContextOS gateway runs in front of every governed effect. The
real question is therefore not "row lock or ContextOS". It is *build this ledger into
every service that triggers an external effect, or run it once at the tool
boundary.* For one service and one provider, building it yourself is reasonable.

ContextOS does not avoid transactions. Its ledger is a compare-and-swap on a protected
store, PostgreSQL in production, so it is a transaction too. It sits in front of the
dispatch and records the dispatch's state in that transaction.

## 2. One limit spans several systems

"Total compensation on an order may not exceed INR 1,000" covers refunds at the
payment provider, store credit in the loyalty system and vouchers in the CRM. Each
team can lock its own row. None of them can see the others' rows. The options are:

- A new compensation service that every team calls first, holding reservations for
  effects that happen elsewhere. That is the ledger from section 1, now shared by
  several teams.
- A distributed transaction across three teams' databases and a provider. In
  practice this is not available.
- One ContextOS guarantee listing both capabilities:

```toml
[[guarantees]]
id = "compensation-per-order"
capability_ids = ["adp_payments.issue_refund", "adp_loyalty.grant_store_credit"]
resource_pointer = "/order_id"
amount_pointer = "/amount_minor"
limit = 100000
unit = "INR_minor"
```

The capabilities must share the resource and amount shape and the unit. The demo's
second part enforces this one limit across two adapters.

## 3. The tool is not yours

Agents increasingly call third-party tools directly, through MCP servers or SaaS APIs.
There is no row to lock in someone else's database. The provider still enforces its own
invariants: a payment provider refuses refunds above the captured amount. Keep that;
it is the strongest backstop. But *agents may refund at most INR 1,000 per order
without a human* is your policy, not the provider's. The only place it can be
enforced is the call path.

## 4. Agents change the retry model

Idempotency keys deduplicate *the same request*. After a timeout, an agent often
rephrases the call, starts a new run, or hands the ticket to another agent. The
result is a new key with the same business intent, so the key does not help. A
ceiling helps only if it counts unknown outcomes (section 1). ContextOS charges
capacity to the business resource, not to the run or key, so new run IDs, new keys
and other replicas sharing the store do not reset it.

## Which to use

| Situation | Use |
|---|---|
| The effect is a write to a database you own, and every caller goes through one service | The transaction. ContextOS adds nothing to this limit. |
| One service you own calls one external provider, and you will build attempts, fencing and reconciliation | Build it in the service. ContextOS is optional. |
| One limit spans several services or teams | A ContextOS guarantee over all of their capabilities |
| Agents call third-party tools directly | ContextOS on the call path; keep the provider's own checks |
| Several agent frameworks or runtimes call the same tools | ContextOS, so the rule lives in one place, not in each framework |

Run both when they apply. A service's own invariant stays authoritative for its own
data. ContextOS adds the cross-system limit that counts unknown outcomes.

## What ContextOS does not solve

- **Bypass.** Calls that do not pass through the gateway are not counted. For its own
  data, a service-side transaction that callers cannot bypass is strictly stronger.
- **Static ceilings.** The limit is configured. It does not read captured or already
  refunded amounts from the system of record, and it does not count exposure that
  existed before deployment.
- **Hot resources serialize.** Each tenant, guarantee and resource has one ledger,
  updated by compare-and-swap. Concurrent effects on one order contend the way they
  would on a row lock. A [failure drill](research/2026-10-29-postgres-shared-limit-drill.md)
  raced twelve agents per order across three processes on PostgreSQL; contention at
  hundreds of writers per resource has not been measured.
- **One store is one enforcement domain.** There is no cross-region escrow
  allocation. A replica on another store, or missing the guarantee, escapes the limit.
- **Finality is a trust assumption.** Reconciliation trusts the provider's answer or
  an authorized operator's attributed assertion. The cited evidence is recorded, not
  independently fetched and checked.
- **Orphaned dispatches stay held until attested.** If a worker disappears after its
  dispatch started and before it recorded an observation, reconciliation cannot
  release the reservation on an assertion of absence. A separate `attest` principal
  can, after a quiet window and citing the provider's records; nothing releases it by
  time alone.
- **Ledger size.** Each resource keeps at most 1,024 receipts, and there is no
  rollover yet.

[Shared guarantees](SHARED_GUARANTEES.md) has configuration, recovery and the full
state table. [ADR-0005](adr/0005-shared-business-exposure.md) records the decision and
the alternatives.

## Prior art

None of the techniques are new. ContextOS packages them at the tool boundary for
agents that already exist:

- P. O'Neil, *The Escrow Transactional Method*, ACM TODS 11(4), 1986: reserving
  quantities against a shared total, without long locks.
- H. Garcia-Molina and K. Salem, *Sagas*, SIGMOD 1987. Undoing completed effects is
  covered in the [compensation guide](COMPENSATION.md).
- Fencing tokens, which stop a paused lock holder from acting after its lease has
  passed to another.
- Card authorization holds: the same states as held, captured and released.
