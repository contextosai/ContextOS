# Performance

Numbers are from Criterion on a developer laptop (Apple Silicon, `--release`, single
thread per benchmark). They show relative cost and regressions, not production
capacity. Reproduce:

```sh
cargo bench -p contextos-kernel --bench kernel
cargo bench -p contextos-gateway --bench dispatch
```

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
| One run, sequential effects (average over 50 effects) | ~0.59 ms per effect |
| 32 runs of one tenant in parallel, 50 effects each | ~138 µs per effect (~7,200 effects/s) |

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
computing canonical string and integer lengths without encoding them. Single-tenant
parallel throughput ~1,900 → ~7,200 effects/s from group commit.

With PostgreSQL, a batch is one `INSERT … SELECT unnest(…)` round trip, so per-tenant
audit throughput is bounded by batch size over round-trip time rather than by entries
over round-trip time. Run the PostgreSQL benchmarks with
`CONTEXTOS_BENCH_DATABASE_URL=postgres://… cargo bench -p contextos-gateway --bench dispatch -- postgres`
(CI runs them on every push).

Remaining per-effect CPU: the run's budget ledger (reserve and settle each re-validate
and re-encode it; about half of a sequential effect, growing with its receipts),
canonical encoding and hashing of audit payloads, and authorization. The kernel
deliberately re-validates every ledger it is given rather than trusting stored state.

## Known limits

- One budget ledger holds at most 128 mutation receipts (spec bound), so a run supports
  ~64 governed effects before its ledger must roll over.

Open design decision: safely rolling a run's budget into a new ledger segment needs a
fence that retires the old segment for new reservations while still accepting its
settlements. The spec's executor generation fences stale executors, and overloading it
for this would weaken that guarantee, so rollover waits for a spec-level design (or
long runs delegate work to child runs with their own reserved budgets).
