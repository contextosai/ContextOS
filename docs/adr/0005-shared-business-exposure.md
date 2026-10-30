# ADR-0005: Shared business exposure at the tool boundary

Status: implemented on this branch as an opt-in alpha runtime extension.
Date: 2026-10-22.

## Context

Run budgets coordinate one run and its delegated children. Independent agents can
each obey those budgets and authorization policies while collectively exceeding a
business-resource ceiling. Retrying under a new run must not allocate fresh business
capacity. Unknown external effects must remain accounted for.

The [research](../research/2026-10-22-value-proposition.md) recommends making this
shared boundary the first differentiated product outcome. Stateful policies,
transaction accounting, agent contracts and signed receipts already have prior art;
the decision is about packaging and enforcing a useful integration, not invention.

## Decision

Use one protected CAS ledger per tenant/guarantee/resource, alongside ordinary run
and operation ledgers. Trusted configuration supplies exact argument pointers,
unit and static ceiling. Pin the complete guarantee definition by tenant/id before
resource extraction. Persist an immutable operation link after the empty resource
ledger exists and before reserving exposure.

Conserve committed plus held exposure. A one-time activation CAS authorizes the
exact receipt to dispatch. Recovery can atomically abort an unstarted receipt or
create an exact-attempt tombstone before a delayed reservation arrives. No TTL
restores capacity. A started receipt without recorded observations refuses
absence-based release.

For shared operations, refuse unknown retries in both the early path and the
authoritative operation claim CAS. Seal an attempt's first accepted definitive
observation through that operation CAS; audit later or stale contradictory facts as
refusals. This is an explicit additional gateway restriction. Keep the normative
operation kernel and conformance vectors unchanged.

Derive settlement from protected accepted operation history. Sign the settlement
request before changing shared capacity. Retrying reconciliation repairs interrupted
settlement, including terminal runs using their current executor generation.
Confirmation before measured usage charges the original protected run-budget
allocation conservatively.

Expose read-only tenant-scoped guarantee and exposure APIs. Reuse existing audit,
storage, authentication, provider adapters, clients and independent audit verification.
No new dependency or agent framework is introduced.

## Alternatives

- A freshly fetched policy balance alone leaves a check-then-act race.
- Per-agent/run budgets do not coordinate unrelated identities.
- A common workflow/orchestrator can coordinate one resource; require no migration
  of existing agent frameworks to obtain this boundary.
- A business service's own transaction is often the strongest solution. Retain it;
  ContextOS supplies coordination at heterogeneous tool boundaries.
- Automatically expiring reservations or resolving from one retry response creates
  capacity while an earlier external effect may still apply.
- Accepting contradictory definitive observations after release can invalidate a
  conserved balance. Shared attempts therefore seal final facts and retain
  contradictions as signed incident evidence.

## Consequences and limits

The guarantee covers configured mediated tools sharing a tenant and protected store.
Resource canonicalization, prior exposure accounting and trusted finality evidence
are deployment responsibilities. Removing/renaming rules, omitting them from a
replica, changing stores or bypassing the gateway changes the enforcement domain.

The ledger keeps at most 1,024 live receipts per resource and blocks on saturation.
Settled receipts are archived an hour after they are first seen settled
(`EXPOSURE_RECEIPT_RETENTION_SECONDS`, well past the 120-second stall bound after
which a dispatch sends nothing), their committed amount kept in the total; held
receipts never are. Static ceilings, accounted migration, dynamic system-of-record balances,
externally fenced orphan recovery, PostgreSQL contention measurements and dedicated
Tower exposure views remain separate work. No worldwide novelty, universal AI
safety, external outcome proof or compliance certification is asserted.
