# Shared limit on PostgreSQL: failure drill record

Date: 29 October 2026. Runtime `main` at `46a7048` plus the drill in
[`examples/postgres-drill`](../../examples/postgres-drill). Supersedes the "not
exercised" limitation of the [22 October validation record](2026-10-22-shared-guarantees-validation.md)
for multi-process operation on PostgreSQL; its other limits stand.

## Question

Does one shared business limit hold across separate `contextosd` processes on one
PostgreSQL store when processes are killed mid-dispatch, provider replies are lost
and the database restarts under load? "Holds" means, checked against the provider's
own ledger rather than HTTP status codes:

- the provider never paid more than the limit on any order;
- every refund the provider applied is committed, or still held, in the protected ledger;
- no operation reached the provider twice;
- every hold that remains can be explained, and resolved from evidence without
  re-sending anything.

## Setup

- Three `contextosd` release processes (`0.1.0-alpha.2` on `main`), one PostgreSQL 18.6
  container, shared store and audit log. Apple M4 Pro, 14 cores, macOS 26.6.
- Development fact services and a synthetic MCP payment provider on loopback.
- One guarantee: INR 1,000 per order over `adp_payments.issue_refund`.
- Database restart by `docker restart -t 0` (SIGKILL of the server, then crash recovery).

## Results

Fourteen full runs with a database restart while developing the drill. In none did
the limit break, an applied refund go unaccounted or an operation reach the provider
twice. One run reported a violation that was the drill's own fault: the synthetic fact
services' listen backlog refused connections under 60 concurrent calls, and the
gateway failed those calls closed (`authority_unavailable`, nothing sent). The
backlog was raised. The figures below are from the last run (`examples/postgres-drill/run.sh`,
default sizes).

| Phase | Calls | Outcome |
|---|---|---|
| Contention: 10 orders x 12 agents, INR 300 each, across 3 processes | 120 | 30 completed, 90 `shared_guarantee_exceeded`; every order at exactly INR 900 |
| Spread: 60 orders, one refund each | 60 | 60 completed |
| SIGKILL after the provider applied INR 400 | 1 | held as `dispatch_active` after restart; `not_applied` refused; confirmed from the provider ledger |
| Lost reply, then the same refund under a fresh run and key | 3 | first held, repeat withheld, a fitting INR 400 completed |
| Refunds in flight when PostgreSQL restarted | 24 | 24 `503 dispatch_unavailable`, all applied at the provider, all held |
| Identical resend of those 24 | 24 | 24 `operation_in_flight`; no provider call |
| Refunds sent during the outage | 12 | 12 `503 store_unavailable`; resent after recovery, 12 completed |
| Holds left, resolved from the provider ledger | 24 | 24 `dispatch_active` confirmed; none kept |
| Invariants over 108 orders | | 130 provider effects, 0 duplicates, 0 violations |
| Audit chain written by 3 processes | | verified offline with `ctx audit-verify` |

Across runs, the outage met calls at different points. Calls sent during the restart
were variously refused before any claim (`store_unavailable`), completed after the
database returned, or claimed and then failed (`dispatch_unavailable`); resending a
claimed call returned `operation_in_flight` or `retry_unsafe` and never reached the
provider. `dispatch_unavailable` covers any store failure inside governed dispatch,
including one before the attempt is claimed: in the first CI run on a slower Linux
runner, 7 of 24 such calls had not reached the provider, and their unchanged resend
sent each exactly once. The drill's first version wrongly required no provider call at
all for those resends; it now checks that no refund the provider already applied is
sent again.

Loopback latency per tool call, last run (includes the synthetic fact services each
dispatch consults; not a capacity figure):

| Phase | p50 | p95 | p99 |
|---|---|---|---|
| Contention, one hot order per round (completed and withheld alike) | 68 ms | 97 ms | 100 ms |
| Spread, 60 concurrent | 180 ms | 191 ms | 193 ms |

Latency varied by more than 2x between runs on the same laptop (contention p50 from 68
to 160 ms); treat these as an order of magnitude only. Withheld calls took about as
long as completed ones.

## Finding: an outage can strand a hold that was never sent

In one of the fourteen runs, one hold remained `dispatch_active` with no provider
record. Reading the dispatch path explains it: the gateway marks the shared receipt
`dispatch_started`, then creates the attempt's dispatch gate, then sends. When the
store fails between the first two writes, nothing is sent, but the receipt records
that the attempt may have been, and reconciliation correctly refuses an assertion of
absence for a started dispatch. The capacity stays held until someone can show it was
not applied, which this provider cannot do for a call it never received.

This is over-holding, not a conservation failure, and it is the documented behavior
for orphaned dispatches. It is also avoidable for this window: the dispatch gate is
the gateway's own fence. Creating the gate before marking the receipt started would
leave a receipt that a store failure interrupts in the not-started state, which
reconciliation can already release safely; the receipt's own start transition still
fences a racing reconciliation. That change touches the enumerated crash-point
ordering and is proposed separately rather than made here.

## Limits of this evidence

- One laptop, one PostgreSQL instance, loopback services. No failover, replication,
  backup or restore, and no network partition between processes and database.
- Faults are process kills, a lost reply and a whole-database restart. Faults between
  two particular store writes, or inside the audit append, are covered by the
  in-process crash-point tests, not by this drill.
- All replicas share one configuration. Drift across replicas and bypassing calls are
  documented escape risks and were not exercised.
- Twelve agents per hot order. Contention at hundreds of concurrent writers per
  resource was not measured.
- A synthetic provider that applies every refund it receives and keeps a perfect
  ledger. Real providers' finality and reconciliation evidence are deployment-owned.

The drill runs in CI on every change (the `rust` job, with a database restart of the
service container), so a regression in these behaviors fails the build.
