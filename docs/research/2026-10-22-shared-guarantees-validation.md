# Shared business guarantees: validation record

Date: 22 October 2026. Change based on `ac345a2`, developed on
`codex/shared-business-guarantees`.

## Result

The opt-in alpha implements the scoped conservation contract in
[ADR-0005](../adr/0005-shared-business-exposure.md). The full repository gate
completed with exit status 0 and `ALL CHECKS PASSED`:

```sh
scripts/check.sh
```

| Gate | Observed result |
|---|---|
| Gate-script regressions | 5 passed, including a demo that exits unsuccessfully after printing its verification marker |
| Rust formatting | `cargo fmt --all --check` passed |
| Rust lint | `cargo clippy --workspace --all-targets -- -D warnings` passed |
| Rust workspace | 266 passed, 0 failed, 1 ignored across 58 test groups |
| Release binaries | `contextosd`, `ctx`, and the Tower example's `towerd` built |
| Tower | Dependency install, production UI build and test suite passed |
| HTTP clients | Python and Node end-to-end checks passed |
| Examples | Support refund, shared guarantees, agent loop, metering proxy and Tower passed |

No dependency, normative schema or conformance-vector change was required.

## Demonstrated outcome

The documented entry point also ran independently:

```sh
./examples/shared-guarantees/run.sh
```

Observed output, with variable hashes omitted:

```text
Two independent agents request INR 800 each against one INR 1,000 ceiling.
Provider effects: 1; the competing effect is withheld before dispatch.
A pending INR 150 effect holds capacity; a further INR 100 effect is withheld.
Provider query confirms the pending effect: INR 950 committed, INR 50 available.
Offline audit verification: {"entries": 29, "verified": true, ...}
```

The synthetic provider's actual call counter, balances and verifier result are
asserted by the demo. This tests coordinated effects without requiring model
behavior, external credentials or a payment account.

## Adversarial review and regressions

A fresh design review and an independent security review examined dispatch,
reconciliation, storage, identity, audit and recovery boundaries. Reproduced
findings were fixed and retained as deterministic regressions. The final security
review reported no remaining important finding within the documented alpha scope.

- [Kernel tests](../../crates/contextos-kernel/tests/shared_exposure.rs) cover
  conservation, exact action/attempt binding, malformed state, saturation and
  activation versus abort, including abort before reservation.
- [Gateway tests](../../crates/contextos-gateway/tests/pipeline.rs) cover competing
  independent runs, replica reconstruction, unknown/partial outcomes, definitive
  absence, definition pins, storage/audit interruptions and settlement repair.
  Pause-based tests exercise delayed dispatch versus recovery, stale contradictory
  reconciliation, an unknown outcome appearing between the initial read and the
  authoritative claim, invalid recovery evidence, and confirmation without usage.
- [HTTP tests](../../crates/contextosd/tests/dispatch/coordination.rs) cover shared capacity across
  server instances, scope and tenant isolation, read views and recovery after a run
  has failed. Configuration tests exercise weakened/changed protection review.

The independent reviewer additionally reran four isolated scratch regressions for
delayed dispatch, contradictory finality, unknown retry and conservative run-budget
charging. Those passed; the repository tests are the maintained evidence.

## Limits of this evidence

The local demo and cross-replica tests use a shared in-memory store. No PostgreSQL
server or test database URL was available, so PostgreSQL-backed contention,
multi-process crash recovery, throughput and latency were not exercised. The
workspace's existing ignored load test was not enabled. A green gate is not an
enterprise capacity measurement. (Multi-process operation on PostgreSQL was later
exercised: see the [29 October drill record](2026-10-29-postgres-shared-limit-drill.md).)

The contract requires stable resource identity, complete tool mediation, consistent
configuration and tenant identity, a protected shared store, truthful definitive
observations and accounted prior exposure. The alpha has static ceilings, a limit
of 1,024 retained receipts per resource, and no accounted rollover or migration API.
An orphaned started dispatch without a recorded observation retains capacity;
externally fenced absence recovery remains future work. See the
[operator guide](../SHARED_GUARANTEES.md).

The [market assessment](2026-10-22-value-proposition.md) establishes a differentiation
hypothesis, not worldwide uniqueness, buyer validation, external outcome proof,
regulatory certification or universal AI safety.
