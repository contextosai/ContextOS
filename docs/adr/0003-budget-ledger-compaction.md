# ADR-0003: Budget-ledger compaction

Status: accepted (runtime extension; proposed upstream to the specification)

## Context

The spec bounds a budget ledger at 128 mutation receipts. Each governed effect uses
two (reserve, settle), so one run's ledger supports at most 64 effects, after which
reservations fail with `counter_exhausted`. Long-running agents need far more. The spec
leaves this to "an explicit versioned archival/migration design that retains recovery
receipts and accounting continuity", and requires that any budget migration "retain
consumed/reserved capacity" and never "reset or enlarge the original ledger".

The ledger also grows with every effect, and the kernel re-validates the whole ledger
on every transition, so per-effect cost grew with the run.

## Decision

Before a reservation, when the run's ledger holds at least 32 receipts, the gateway
compacts it with the pure kernel transition `compact_budget_ledger`:

1. Fully settled reservations and every receipt that references them move, unchanged,
   into a write-once archive document (`budget_archive`, format
   `contextos-rs.budget_archive.v1`).
2. Their `used` counters fold into the ledger's `opening_usage`. The spec's
   conservation equation, used = opening + Σ reservations, therefore still holds, and
   `used`, `reserved` and `ceiling` are byte-for-byte unchanged.
3. `opening_usage_ref` is re-addressed: its digest is the spec's `budget_opening_digest`
   of the new ledger, its `artifact_id` names the archive, and its version is the new
   revision. The archive records the digest of the ledger it was cut from and the
   previous `opening_usage_ref`, so archives form a verifiable chain back to admission.
4. Open reservations (`reserved`, `usage_unknown`) and their receipts stay in the
   ledger, so they settle, recover and reconcile exactly as before.
5. The transition validates its input and output with the same checks as every other
   ledger transition, is fenced by expected revision and executor generation, and
   rejects any result whose counters differ.

The archive is written before the ledger. Its id derives from the ledger revision, and
a revision has exactly one state, so concurrent or retried compactions write the same
archive. Each compaction is appended to the audit chain with both digests.
`verify_compaction(previous, compacted, archive)` recomputes a compaction for auditors.

## Consequences

- A run is limited by its budget, not by receipt slots: the gateway test dispatches 150
  effects in one run, and the kernel test 300 with an unknown reservation carried
  across compactions.
- The ledger stays at 32 receipts or fewer, so per-effect cost no longer grows with
  the run: sequential dispatch fell from ~0.59 ms to ~0.37 ms.
- Idempotent replay of a mutation whose receipt was archived is no longer answered from
  the live ledger. The gateway never replays mutations of settled reservations (attempt
  ids are fresh and settlement happens once), and reconciliation skips settled
  reservations; other embedders that replay must consult the archive.
- Archives are retained with the ledger and are part of the run's evidence.
- Revision numbers advance by one per compaction.

## Alternatives considered

- **Segment ledgers funded by child reservations.** Uses spec primitives, but a
  segment's unspent allocation is locked until it drains, which either fragments the
  budget or blocks new work behind unresolved effects.
- **Reusing executor generation as a rollover fence.** Rejected: it weakens the fence
  that keeps stale executors from acting.
