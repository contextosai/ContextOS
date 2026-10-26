# ADR-0006: Advisory peer task coordination

Status: implemented as an alpha runtime extension.
Date: 2026-10-25.

## Context

[The Agensh study](../research/2026-10-25-agensh.md) identifies peer work discovery
and persistent claims as a gap alongside ContextOS's existing governance. The user
prioritized decentralized task coordination. Advisory claims alone cannot prevent
two peers owning the same task; an expired claim also establishes nothing about
previous external effects.

## Decision

Use a root-owned, tenant-keyed protected WorkBoard document with immutable task
definitions, dependency readiness and conditional leased ownership. Resolve teams
from protected admission lineage, and bind the authenticated caller to the worker's
stored `admitted_by`. Revision and lease-epoch checks arbitrate concurrent workers.
Reuse the existing trusted clock, stores, signed audit and HTTP clients. Do not
change normative schemas, pure kernel semantics or provider-effect protocols.

Keep task content and completion reports advisory. Explicit task publication shares
metadata across descendants; no run context or evidence content is automatically
copied. A task result does not admit evidence, accept isolated output or widen tool
authority. Existing delegation and effect gates remain independent. Run-state
checks cannot atomically fence board writes; document already-admitted lifecycle
races instead of claiming cross-document linearizability.

Bound board content and page sizes. Audit proposed mutations by digest before CAS,
label them as attempts, and use stored revisions for committed state. Tombstone an
absent or existing board before removing the root ReplayCase retention index;
propagate failed CAS retries, so partial erasure is recoverable.

## Alternatives

- Transplant Gitea, Mattermost and the full Agensh harness: adds deployment and
  identity systems outside the selected task-coordination scope.
- Advisory text-only claims: less code, but cannot arbitrate ownership atomically.
- Per-task documents: reduce contention, but consistent discovery, dependencies
  and root erasure require a deliberate index/transaction protocol. Defer until
  coordination benchmarks justify the complexity.
- Treat task completion as verification: a well-formed evidence reference cannot
  establish truth or satisfy independent result/effect gates.

## Consequences

Peers can choose tasks without a central assignment loop. The first version caps
each board at 256 tasks/1 MiB and serializes its writes; it makes no 1,024-worker
scaling claim. Teams outside one admitted delegation tree remain separate. Roots
own shared content retention; erasing a child alone does not redact team metadata.
Lease recovery requires prior-effect inspection/reconciliation by the framework.
Typed findings, durable notices and integration/verification protocols remain
separate roadmap capabilities.
