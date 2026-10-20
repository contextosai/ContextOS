# Proposal to the ContextOS specification: budget-ledger compaction

Status: draft for the spec maintainers. Implemented in this runtime as a runtime
extension ([ADR-0003](../adr/0003-budget-ledger-compaction.md)).

## Problem

`execution-contract` bounds a budget ledger at 128 mutation receipts and defers longer
histories to "an explicit versioned archival/migration design that retains recovery
receipts and accounting continuity". Without one, a run supports about 64 governed
effects, and every implementation must invent its own archival scheme, so archives
are not portable across runtimes.

## Proposed normative text

> A runtime MAY compact a budget ledger. Compaction moves every reservation whose
> status is `settled`, and every mutation receipt that references one, into an archive,
> and adds each moved reservation's `used` counters to `opening_usage`. Compaction MUST
> leave `used`, `reserved`, `ceiling`, `original_limits` and `original_limits_ref`
> unchanged, MUST keep every non-settled reservation and its receipts, MUST increase
> `revision` by one, and MUST set `opening_usage_ref` to an artifact reference whose
> `sha256` is `budgetOpeningDigest` of the compacted ledger and whose `artifact_id`
> names the archive. The archive MUST record the canonical digest of the ledger it was
> cut from and that ledger's `opening_usage` and `opening_usage_ref`. Compaction is
> fenced by expected revision and executor generation like every ledger mutation.
> Recovering a mutation whose receipt was archived MUST consult the archive.

## Proposed reference API

```ts
compactBudgetLedger(ledger, { archive_id, expected_revision, executor_generation })
  : { status: "accepted", ledger, archive } | { status: "rejected", reason_code }
verifyBudgetCompaction(previous, compacted, archive): boolean
```

Reason codes: `budget_accounting_invalid`, `revision_conflict`, `executor_stale`,
`counter_exhausted`, `nothing_to_compact`.

## Conformance vectors

Generated from the reference once adopted: compaction after mixed settled, reserved and
`usage_unknown` reservations; settlement of an open reservation after compaction;
repeated compaction chains; tampered archives; stale revision and generation.

## Compatibility

Additive. A ledger that is never compacted is unchanged. A compacted ledger is a valid
ledger under the existing validation rules (conservation holds through
`opening_usage`), so existing verifiers accept it; only recovery of archived receipts
needs the archive.
