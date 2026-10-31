# Proposal to the ContextOS specification: what resume compares in the budget snapshot

Status: draft for the spec maintainers. This runtime matches the reference
`validateResume` byte for byte (the durable-execution vectors), and nothing in it calls
`validate_resume` outside the kernel and conformance tests yet, so the fix should land
in the spec before a production caller does.

## Problem

Resume requires the store's current `budget_snapshot` to equal the checkpoint's exactly
(`crates/contextos-kernel/src/run_state.rs`, the `artifact_binding_mismatch` branch).
The snapshot includes `ledger_revision`, `used` and `reserved`. A run's ledger can
legitimately change while the run is checkpointed:

- delegating reserves a child's sub-budget from the parent's ledger, and
- closing a child settles its unused allocation back into the parent's ledger.

A parent that checkpoints while its children work (the usual "wait for children"
pattern) therefore cannot resume once any child closes: the snapshot differs, and the
rejection carries no remediation obligation. If an observer instead reports the
checkpoint's own snapshot, the check is vacuous. Either reading is wrong; the spec
does not say which ledger changes a checkpoint should tolerate.

## Proposed normative text

> On resume, the store observation's `budget_snapshot` MUST equal the checkpoint's in
> `cost_unit`, `ceiling` and `deadline`, and its `ledger_revision` MUST NOT be lower.
> `used` and `reserved` MAY differ only by ledger mutations made by the run's own
> delegated children (child reservations, settlements and closures), which the store
> observation MUST list as `budget_mutations_since_checkpoint`, each with the child
> run id and its effect on `used` and `reserved`. Applying the listed mutations to the
> checkpoint's snapshot MUST yield the observed one. Any other difference is
> `artifact_binding_mismatch`.

## Conformance impact

New durable-execution vectors:

- a child closes between checkpoint and resume, the mutation is listed: accepted;
- the same difference with no listed mutation: `artifact_binding_mismatch`;
- a listed mutation from a run that is not the parent's child: rejected;
- a lower `ledger_revision`: rejected;
- a changed `ceiling` or `deadline`: rejected (unchanged behaviour).

Existing vectors, whose snapshots are unchanged between checkpoint and resume, keep
their outcomes.

## Runtime plan once accepted

Regenerate the durable vectors from the updated reference, port the comparison, and
have the gateway's store observer list the ledger mutations since the checkpoint from
the budget ledger's mutation log (and its compaction archives).
