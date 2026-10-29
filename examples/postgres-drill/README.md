# Shared-limit failure drill on PostgreSQL

The [shared-guarantees demo](../shared-guarantees) shows one INR 1,000 ceiling per
order holding across agents, in one process on an in-memory store. This drill runs
the same rule on the deployment you would trust: separate `contextosd` processes
sharing one PostgreSQL store and audit log, a real `SIGKILL` and restart, and
optionally a database restart under load. The synthetic payment provider keeps its own
ledger of every refund it applied; the drill checks the runtime's protected balances
against that ledger, not against HTTP status codes.

```sh
# A disposable database (or any PostgreSQL the drill may write to):
docker run -d --name contextos-drill-pg -e POSTGRES_USER=contextos -e POSTGRES_PASSWORD=contextos \
  -e POSTGRES_DB=contextos_drill -p 127.0.0.1:55433:5432 postgres:18
export CONTEXTOS_DRILL_DATABASE_URL=postgres://contextos:contextos@127.0.0.1:55433/contextos_drill
# Optional: restart the database mid-drill. Without it, phase 5 is skipped.
export CONTEXTOS_DRILL_PG_RESTART="docker restart -t 0 contextos-drill-pg"
./examples/postgres-drill/run.sh
docker rm -f contextos-drill-pg
```

Prerequisites: Python 3.9+, Bash and a PostgreSQL the drill may write to. Each run
uses a fresh guarantee id and fresh order ids, so a database can be reused. In a
source checkout the script builds release binaries; a release archive uses its `bin/`.
Synthetic, loopback services only: no model key, cloud account or payment account.
`CONTEXTOS_DRILL_REPLICAS` (3), `CONTEXTOS_DRILL_AGENTS` (12) and
`CONTEXTOS_DRILL_ROUNDS` (10) size it.

## What it does

1. **Contention.** For each of ten orders, twelve agents race INR 300 refunds,
   admitted on one process and sent through another. Exactly three fit; the rest are
   withheld before dispatch with `shared_guarantee_exceeded`.
2. **Spread.** Sixty refunds on sixty different orders at once, for comparison.
3. **`SIGKILL` after send.** The provider applies an INR 400 refund and the sending
   process is killed before it records any answer, then restarted on the same store.
   The inspection API shows the hold as `dispatch_active`, next safe step
   `confirm_with_evidence_only`. A fresh run asking INR 700 is withheld, INR 600 fits.
   A new executor takes the run over; asserting `not_applied` is refused
   (`shared_guarantee_dispatch_active`), confirming from the provider ledger resolves
   it.
4. **Lost reply.** The provider applies INR 600 and drops the connection. The same
   refund requested again under a fresh run and idempotency key is withheld; the ledger
   counts the unknown outcome against the order, not against the key.
5. **Database restart** (with `CONTEXTOS_DRILL_PG_RESTART`). PostgreSQL is restarted
   while 24 slow refunds are in flight and 12 more arrive. Every failed call is then
   resent unchanged, as an agent that treats `503` as retryable would.
6. **Resolve every hold** found through `GET /v1/guarantees/{id}/holds`, from the
   provider ledger alone: confirmed when the provider has the refund, not applied only
   when the attempt never started. A started attempt with no provider record stays
   held.
7. **Invariants** for every order: the provider never paid more than the limit, the
   ledger never committed plus held more than the limit, every applied refund is
   committed (or still held), and no operation reached the provider twice.
8. **Audit:** the chain written by all processes exports and verifies offline.

The run ends with `No violations:` and writes `receipts/postgres-drill/report.json`
(outcome counts, p50/p95/p99 latency per phase, holds resolved and kept, the audit
verification). Any violation exits non-zero.

## Reading the database-restart phase

What a resend does depends on where the outage met the call:

| First answer | Meaning | Resent unchanged |
|---|---|---|
| `503 store_unavailable` | refused before anything was claimed | an ordinary first attempt |
| `503 dispatch_unavailable` | claimed, and possibly sent | `paused: operation_in_flight` or `retry_unsafe`; never sent again |

A claimed attempt holds its capacity until it is reconciled. Phase 6 does that from the
provider's records.

## What this does not show

- Laptop loopback latency, with Python fact services and a synthetic provider. It is
  not a capacity measurement; do not compare it with production figures.
- One PostgreSQL instance. No failover, replication lag, backup or restore.
- No targeted fault inside the audit append or between two particular store writes; the in-process
  [crash-point tests](../../crates/contextos-gateway/tests/pipeline.rs) enumerate those.
- All processes run the same configuration. Configuration drift across replicas, and
  calls that bypass the gateway, escape the limit as documented in
  [shared guarantees](../../docs/SHARED_GUARANTEES.md).

The [validation record](../../docs/research/2026-10-29-postgres-shared-limit-drill.md)
gives measured results and one stranded-hold case the drill found.
