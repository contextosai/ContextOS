# Shared business guarantees: design

Date: 2026-10-22. Decision delegated by the user: choose the strongest research opportunity and proceed. Research: [value proposition](../../research/2026-10-22-value-proposition.md).

## Intent

Turn ContextOS into an open source coordination boundary for business limits shared by independent agents. Keep the Rust kernel, existing authorization, bindings and Tower. Add one complete vertical slice: numeric exposure ceilings for a stable resource, across runs and replicas sharing a protected store.

## Contract

For every tenant, guarantee and canonical resource, `committed + held <= limit`. Reserve before the provider call. Confirmed definitive effects move held exposure to committed. Definitive not-applied or not-dispatched effects release the reservation after every potentially dispatched attempt is accounted for. Unknown, non-definitive and partial effects retain the full reservation. Time, run completion, cancellation, erasure and restart never free exposure. Reconciliation uses the existing authorized path and only changes exposure after the kernel accepts the observation. A stale attempt cannot release a newer attempt's hold. Shared attempts seal the first accepted definitive fact through the operation CAS; contradictory concurrent or later assertions produce signed refusals. Accepted finality observations remain a trusted integration boundary.

This is a configured numeric ceiling, not proof of a refund's legal validity, the order's true paid amount, or arbitrary business correctness. All calls affecting the limit must be mediated. Existing systems of record should keep their own invariants.

## Configuration and identity

Add opt-in `[[guarantees]]` to server configuration. A `SharedGuarantee` names `id`, `capability_ids`, `resource_pointer`, `amount_pointer`, `limit`, and `unit`. `limit` and extracted `amount` are positive exact JSON integers no greater than 2^53−1. Pointers use RFC 6901. Resource values must be bounded nonempty canonical identifier strings; deployments must ensure the provider uses exactly that identity. Unit is trusted metadata, not an agent-selected argument. Capabilities must exist, be effectful, and belong to at most one guarantee. One guarantee may coordinate multiple tools using the same argument shape and unit.

Each resource gets the configured ceiling. There is no caller-provided ceiling, no automatic discovery of past spend, no periodic reset and no dynamic provisioning endpoint. Start on resources with a known accounted starting point. A guarantee's semantic definition is hashed and pinned under the tenant/guarantee id before extracting any resource; changing it under an existing id fails closed even for new resource keys. Adding/removing/renaming a guarantee is a reviewed deployment change, not a migration API.

Resource ledger keys are tenant + guarantee id + hash of the canonical resource string. Reservation identity is a digest of run id and operation id. The immutable link binds the exact action, amount and resource; current attempt ownership lives in the resource receipt. It excludes agent identity so unrelated agents compete for the same ledger. Raw arguments and resource values are not copied into guarantee audit entries.

## Persistence and recovery

Use existing `DocumentStore` CAS, supported by memory and PostgreSQL. Add distinct document kinds for the resource exposure ledger and per-operation guarantee link. Create the empty resource ledger, then write the immutable link *before* reserving resource exposure. Recovery can tombstone a delayed reservation and interruption after a hold is recoverable. Link creation must compare the complete binding on reuse. The resource ledger holds bounded reservation receipts; saturation blocks visibly rather than deleting replay protection. The initial bound is 1024 receipts per resource; safe rollover is future work.

The operation claim continues to serialize an operation. Reserve shared exposure after the existing run-budget/operation/effect-guard checks and immediately before dispatch. A denied shared reservation records a definitive withheld dispatch and releases its run-budget reservation. Never call a provider without the shared reservation and its signed audit event. A crash or store/audit failure may conservatively strand a hold; it cannot create free capacity. Existing operator reconciliation can settle a recoverable hold.

Require reconciliation before any retry of a shared unknown operation, including an otherwise provider-idempotent retry. This conservative restriction avoids releasing an earlier uncertain attempt based on a later failed retry. Released exposure can be re-reserved only for a different attempt of the same action. Committed exposure cannot reopen. Settlement is idempotent; stale settlements cannot reduce exposure. Before invocation, the exact held receipt must win a one-time dispatch activation CAS. Recovery of an unstarted claim atomically aborts it or creates an exact-attempt released tombstone if reserve has not landed. Activation refuses aborted/released/already-started receipts. An active claim without recorded observations cannot release on an absence assertion; confirmed assertions may conservatively commit its full exposure. Externally fenced absence recovery of an orphaned active dispatch is future work. Settlement marks observation receipt only from persisted accepted operation evidence, signs its requested transition, then commits shared state through CAS.

## Interfaces

Kernel: a new pure module with serializable ledger/binding types and deterministic reserve/settle functions producing `TransitionResult`. Every malformed ledger or request refuses without mutation. Dispatch activation, observation receipt and abort/tombstone transitions are also pure kernel functions. Validate receipt totals and integer bounds, not only cached totals.

Gateway: configuration validation and shared reservation/settlement helpers; store the operation link and use it during reconciliation, independent of reconstructed caller arguments. Builder method validates guarantees against registered manifests. Errors use structured `shared_guarantee_*` reasons. Refusals and state changes go into the existing signed tenant audit stream.

Server: validate configuration at startup; expose effective guarantees to configuration review; `GET /v1/guarantees` and `GET /v1/guarantees/{id}/resources/{resource_digest}` require `audit:read` and derive tenant from authentication. Inspection returns limit, held, committed, available, unit and receipt count, never mutation authority. Reconciliation retains its existing scope and requires the current executor generation, including terminal runs; it creates no new provider effect. Update OpenAPI and its route conformance tests.

Clients: existing dispatch and reconciliation remain unchanged; guarantee enforcement does not depend on the agent opting in. The demo can use the existing Python client and read APIs.

## Acceptance

- Race independent runs and gateway instances against one store: at most one $80 effect under a $100 ceiling; distinct resources and tenants retain separate capacity.
- Confirmed, unknown, partial, not-dispatched and not-applied each obey the contract; changed run/operation identity cannot replenish it.
- Retry/reconciliation cannot double-charge, double-release or release a newer hold.
- A new gateway instance over existing state preserves consumed capacity. Rule mismatch, malformed input/state, safe-integer overflow, receipt saturation, unavailable store and audit failure refuse before dispatch.
- Protected routes require the right scope; no tenant/resource aliasing through path construction.
- Existing Rust suite and conformance vectors pass; format and clippy remain clean. A local model-free demo shows the collective failure and its prevention with audit verification.

## Non-goals and rollout

No identity provider, new agent framework, LLM policy judge, worldwide uniqueness claim, universal safety guarantee, UI redesign, dynamic balances, multi-rule atomicity, multi-region coordination, automatic expiry, automatic rollback, or changed normative schemas. No breaking changes to existing callers. This extension is opt-in and alpha. Tower continues to derive fleet evidence; dedicated exposure UX is future work.


## Design review rulings

- Settlements derive from the accepted whole-operation history, not a single adapter response; unknown/partial/conflicted history retains full exposure.
- Definition pins precede resource routing. Removing/renaming protection or omitting it from a replica remains an administrator-controlled boundary change.
- A durable activation/abort state machine closes both before-reservation and after-reservation recovery races. A read-only balance recheck is insufficient.
- Shared first-definitive sealing is an explicit runtime restriction beyond the normative operation kernel. Contradictory facts are retained as signed refusals for incident investigation, not accepted into a balance already released.
- Terminal-run reconciliation checks the current generation without requiring a running status.
- No new external dependencies or universal novelty/compliance claims.
