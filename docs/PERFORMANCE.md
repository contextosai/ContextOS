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
| Full dispatch, average over the first 50 effects of a run | ~1.2 ms |

Profile per effect: four ledger transactions dominate (≈ 200 µs each), split between
kernel re-validation of the whole run ledger (≈ 100 µs), canonical encoding on commit
(≈ 55 µs) and reads. Because the run-wide operation ledger grows with every effect,
this cost is O(effects in the run).

## Known limits

- One budget ledger holds at most 128 mutation receipts (spec bound), so a run supports
  ~64 governed effects before its ledger must roll over.
- One operation ledger holds at most 128 operations per run.

Planned (next): per-operation ledger documents (constant per-effect cost, no
cross-operation contention inside a run) and budget-ledger rollover.
