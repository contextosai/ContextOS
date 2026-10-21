# Performance

Numbers are from Criterion on a developer laptop (Apple Silicon, `--release`, single
thread per benchmark). They show relative cost and regressions, not production
capacity. Reproduce:

```sh
cargo bench -p contextos-kernel --bench kernel
cargo bench -p contextos-gateway --bench dispatch
```

## End to end over HTTP, several replicas

`load_across_replicas` (an opt-in test) starts replicas sharing one store and one
audit log, plus fake fact providers and an MCP tool server, and drives concurrent
agents that each admit a run on one replica and dispatch its governed effect on
another:

```sh
CONTEXTOS_LOAD_REPLICAS=3 CONTEXTOS_LOAD_AGENTS=64 CONTEXTOS_LOAD_RUNS=40 \
  cargo test --release -p contextosd --test dispatch load_across -- --ignored --nocapture
```

| Setup (one laptop, everything in one process) | Result |
|---|---|
| 3 replicas, 64 agents | ~2,600 runs/s (admission + effect), ~5,200 requests/s, p50 9–10 ms, p99 47 ms; admission p50 5.1–5.3 ms (2026-10-21, after the envelope, schema, escalation, metrics and memory-verification checks; ~2,300 before them, within run-to-run variance) |
| PostgreSQL (local socket), 1 replica, 64 agents | ~1,750 runs/s, ~3,500 requests/s, p50 17 ms, p99 51 ms; admission p50 14 ms |
| PostgreSQL (local socket), 3 replicas, 64 agents | ~1,530 runs/s, ~3,060 requests/s, p50 16 ms, p99 71 ms |

The test asserts what matters at scale: every effect reaches the provider exactly
once, and one tenant's audit chain written by every replica verifies end to end. The
throughput figures are a floor, not capacity: the load generator, the fake providers
(which compute real authority facts) and every replica share one machine's cores, so
adding replicas here adds no CPU. Admission (compile, negotiate, pin policy, open
ledgers, keep the replay case) is the heavier request.

Set `CONTEXTOS_TEST_DATABASE_URL` to run it on PostgreSQL; the replicas then share the
database, and the test verifies this execution's segment of the tenant's audit chain
from the entry before it (as `ctx audit-verify --continues` does).

On one machine, one tenant on three replicas is slower than on one. A tenant's audit
chain is a serialization point: group commit batches a tenant's appends within a
process, but replicas appending to the same chain contend on its head. Replicas add
throughput across tenants (whose chains are independent) and add availability; a single
very hot tenant scales with one replica's group commit, so route a tenant's traffic
with affinity when it dominates load ([ADR-0004](adr/0004-partitioned-audit-chains.md)
proposes partitioned chains if one tenant must exceed a single writer). Losing writers back off on the database's scale
(jittered, 0.4 to 3.4 ms) rather than in milliseconds-doubling steps; that raised
three-replica throughput on one tenant from ~1,380 to ~1,530 runs/s and cut p99 from
~95 to ~71 ms.

Profiling this test first showed the load generator itself dominating: each request
body was built by re-reading and re-parsing a 1.3 MB vector file. Parsing it once
doubled measured throughput (~1,150 → ~2,300 runs/s) without any server change. The
remaining profile is spread across idle waits, socket I/O, allocation, and canonical
JSON encoding and hashing for signed audit entries, with no single dominant hot spot.

## Kernel (pure, in-process)

| Operation | When | Latency |
|---|---|---|
| JsonLogic predicate | per policy rule | 0.9 µs |
| Action-binding digest (RFC 8785 + SHA-256) | per effect | 8.6 µs |
| Canonicalize a compiled context | per run | 13 µs |
| Authorization (authority chain + policy + constraints + approval) | per effect | 63 µs |
| Context Pack compilation | per run | 97 µs |
| Contract negotiation (high-assurance profile) | per run | 275 µs |

History: authorization 161 → 63 µs and canonicalization 39 → 13 µs by replacing
check-only canonicalization with an allocation-free limit walk, comparing canonical
equality structurally, writing JCS output in place and sorting keys by bytes when that
equals UTF-16 order.

## Gateway (governed dispatch, in-memory store, signed audit, instant fake providers)

| Measure | Result |
|---|---|
| One run, sequential effects (average over 50 effects) | ~0.36 ms per effect |
| 32 runs of one tenant in parallel, 50 effects each | ~98 µs per effect (~10,200 effects/s) |

The benchmark runs with contextosd's default guards (loop guard, repeated-effect
guard), and each effect of a run is a distinct refund. The repeated-effect guard claims
each new effect's signature with one compare-and-swap before dispatch, which costs
~4% (`CONTEXTOS_BENCH_GUARDS=off`: ~0.35 ms sequential, ~95 µs per effect in parallel).

Every effect appends three signed entries to its tenant's hash chain, so a tenant's
chain is the one serial point in the pipeline. The audit writer uses **group commit**:
appenders encode and hash their payloads in parallel, queue them, and whichever
appender holds the chain links the whole queue and writes it in one atomic batch.
Before group commit, single-tenant throughput was flat at ~1,500–2,000 effects/s no
matter how many runs were active: the cost was not the 12 µs of linking and signing
but waking the next waiter for every entry. With group commit, throughput scales with
parallelism and the process is CPU-bound (~6.7 cores busy at 32 runs). Tenants never
share a chain, so throughput across tenants scales with cores and replicas.

History: 1.2 ms → 0.74 ms per sequential effect from one ledger document per
operation; → ~0.66 ms with mimalloc (the server's default allocator); → ~0.59 ms by
removing a quadratic receipt-to-reservation check from budget-ledger validation and
computing canonical string and integer lengths without encoding them; → ~0.37 ms by
compacting the budget ledger every 16 effects (ADR-0003), which keeps it small.
Single-tenant parallel throughput: ~1,900 → ~7,200 effects/s (group commit) →
~10,400 effects/s (compaction). Single-tenant
parallel throughput ~1,900 → ~7,200 effects/s from group commit.

With PostgreSQL, a batch is one `INSERT … SELECT unnest(…)` round trip, so per-tenant
audit throughput is bounded by batch size over round-trip time rather than by entries
over round-trip time. Run the PostgreSQL benchmarks with
`CONTEXTOS_BENCH_DATABASE_URL=postgres://… cargo bench -p contextos-gateway --bench dispatch -- postgres`
(CI runs them on every push).

Remaining per-effect CPU: canonical encoding and hashing of audit payloads and ledgers,
authorization, and re-validation of the (now bounded) budget ledger. The kernel
deliberately re-validates every ledger it is given rather than trusting stored state.

Store reads per dispatch are kept to what correctness needs: one run-state read serves
ownership, status and the unresolved-effect count; compaction works from the state
the reservation just wrote (copied only when compaction is due); the duplicate
fast path's operation-ledger read also decides whether the ledger must be created;
and unresolved outcomes are recorded from the adapter response rather than re-read.
The ownership re-check immediately before the claim is deliberate (it is the fencing
linearization point). On PostgreSQL every removed read is a round trip.

## PostgreSQL

Measured against PostgreSQL 16 on the same laptop (`scripts/dev-postgres.sh`), with
`synchronous_commit` on:

| Measure | Over a Unix socket | Over loopback TCP |
|---|---|---|
| One run, sequential effects | ~1.4 ms per effect | ~4.0 ms per effect |
| 32 runs of one tenant in parallel | ~194 µs per effect (~5,100 effects/s) | ~0.89 ms per effect |

The TCP column is bounded by this machine's loopback, not the runtime: plain
concurrent reads through the same pool top out at ~9,400/s over TCP against ~124,000/s
over the socket. In production, throughput per tenant is round trips per effect times
network latency, so the runtime keeps round trips low:

- about 8 statements per effect (from 13): one run-state read, policy, constraint and
  approval facts fetched concurrently with the operation-ledger read, transactions
  seeded from state the dispatch already holds (claim from the fast-path read,
  observation from the claim, settlement from the reservation) on stores where reads
  are not free, and the observation's audit entry written concurrently with the
  settlement;
- no ping before every pooled connection use (sqlx's default doubled round trips);
- audit appends batched per tenant (group commit), one statement per batch.

Under load the audit phases dominate: each tenant's chain is serial, so the next step
for very hot tenants is per-run audit streams anchored to the tenant chain.

## Known limits

- A single budget ledger holds at most 128 mutation receipts (spec bound). The gateway
  compacts it every 16 effects (ADR-0003), so a run is limited by its budget, not by
  receipt slots. At most 64 reservations can be open at once.
- Each audit-chain batch holds at most 256 entries.
