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

| Measure | Latency |
|---|---|
| Full dispatch, average over the first 50 effects of a run | ~0.74 ms |

History: 1.2 ms → 0.74 ms by moving from one run-wide operation ledger to one ledger
document per operation (the kernel evaluates the single-operation projection; attempt
ids are fresh and provider keys derive from the operation id, so no cross-operation
check is lost). Operation cost no longer grows with the run, and parallel operations
in a run no longer contend.

Remaining profile per effect: the shared run budget ledger (reserve + settle, kernel
re-validation of up to 128 receipts, canonical encoding) is the largest component;
then authorization (~63 µs plus fact gathering) and three signed audit appends
(~25 µs each). With PostgreSQL, round trips to the store dominate: one dispatch makes
about nine store operations.

## Known limits

- One budget ledger holds at most 128 mutation receipts (spec bound), so a run supports
  ~64 governed effects before its ledger must roll over.

Open design decision: safely rolling a run's budget into a new ledger segment needs a
fence that retires the old segment for new reservations while still accepting its
settlements. The spec's executor generation fences stale executors, and overloading it
for this would weaken that guarantee, so rollover waits for a spec-level design (or
long runs delegate work to child runs with their own reserved budgets).
