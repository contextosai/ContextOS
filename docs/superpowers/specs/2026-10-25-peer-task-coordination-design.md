# Peer task coordination

Status: approved for end-to-end implementation in this chat. Date: 2026-10-25.
Research: [Agensh study](../../research/2026-10-25-agensh.md).

## Intent

Let admitted peers discover, claim and finish tasks without a central worker
assigning each task. Preserve ContextOS's existing authority, budget, lifecycle,
effect identity and reconciliation rules. The user selected decentralized task
coordination as the first priority; the implementation choices below are proposed
by the builder.

## Scope and invariants

- A tenant-scoped work board belongs to one admitted root run. Only that root and
  descendants with runtime-recorded delegation lineage may access it. The root is
  derived from admission, never accepted from the request body.
- Bind the authenticated caller to the worker admission's nonempty `admitted_by`.
  Knowing a run id and generation is not authorization to act for that worker.
  Legacy admissions without this binding are refused. A shared API principal is
  a shared identity; generation headers are fencing tokens, not credentials.
- Reuse `dispatch` permission and the current executor generation for reads and
  mutations, as with checkpoints. Check worker/root lifecycle and both deadlines
  on entry and each CAS retry. These checks are not atomic with board writes:
  a request admitted before a concurrent stop/takeover can still commit. Board
  revision/epoch fencing is atomic; do not describe separate RunState checks as
  linearizable task fencing. A task claim never changes capabilities, authority,
  task authorization, run budgets, or shared resource exposure.
- Publish only explicitly supplied task metadata. Never copy admission messages,
  compiled context, checkpoints, results or evidence contents into the board.
  Published metadata is visible to all admitted descendants, irrespective of lane.
  Text, evidence references and status remain untrusted coordination data. They
  neither become admitted evidence nor accept an isolated child's output; existing
  schema, parent acceptance, data-flow and effect gates still apply.
- A task has a stable caller-chosen identifier, bounded title and acceptance
  criteria, creator run, optional dependencies, status, revision, and lease epoch.
  Identifiers use 1..64 ASCII alphanumeric/underscore/hyphen characters; title is
  1..256 bytes and acceptance criteria 1..4096 bytes, both nonblank. Definitions
  are immutable. Dependencies must already exist, so cycles cannot be created.
  Claiming requires every dependency to be completed. Dependency readiness is
  scheduling metadata, not permission to import or merge results.
- States: `pending`, `claimed`, `completed`. An expired claim is discoverable as
  available without requiring a sweeper. Release returns it to pending. Completion
  is terminal and requires a bounded nonempty list of well-formed evidence refs.
  The evidence is attributed to the worker; it is not independently verified.
- Claim/renew use a server-clock lease of 1..3600 seconds, bounded by both run
  deadlines. Claim, renew, release and complete require the task's expected revision.
  Renew/release/complete also require its current lease epoch and matching worker
  run and executor generation. Every new claim increments the epoch. An executor
  taking over the same worker may replace its predecessor's lease immediately.
- Return predecessor worker/generation/epoch metadata when work is reclaimed.
  Expiry or release never establishes that prior effects did not apply. Workers
  must inspect and reconcile prior-work effects before retrying any consequential
  operation, using the existing operation ledgers/provider recovery. The board is
  not a complete effect-history ledger and does not promise cross-run exactly-once
  effects. Completing a run does not implicitly complete its board tasks.
- Lost responses are safe: a repeated conditional mutation conflicts, and the
  caller reads the current task. An identical task-creation retry returns the
  existing task; different content under the same id conflicts.
- Board writes use protected-store CAS with bounded retries. Concurrent claims
  have exactly one winner. Failed dependencies, stale revisions, expired leases,
  store failure and audit failure return stable non-success reason codes.

## API and storage

Add an alpha runtime extension, not a change to normative schemas or kernel
semantics. Gateway coordination methods back these routes:

| Route | Operation |
|---|---|
| `GET /v1/runs/{run_id}/work` | Bounded task discovery with explicit cursor and status/availability metadata |
| `POST /v1/runs/{run_id}/work` | Publish an immutable task definition |
| `GET /v1/runs/{run_id}/work/{task_id}` | Inspect a task, its revision and current ownership |
| `POST /v1/runs/{run_id}/work/{task_id}` | Conditional `claim`, `renew`, `release`, or `complete` |

Use a dedicated `DocKind::WorkBoard`, keyed by the trusted root run. Keep at most
256 tasks, 16 dependencies per task, 16 evidence references per completion, and
1 MiB canonical board content. Page at most 100 tasks; cursors are stable task ids
in lexicographic order, with documented live-view behavior under concurrent
publication. This bounds state and request work, but serializes writes within a
board. It is an explicit first-version tradeoff, not a large-team scaling claim.

Audit each mutation attempt before CAS by root/run/task ids, operation, revision,
epoch and content digest, excluding free text. The stored revision is the source
of truth for whether an attempt committed. Audit failures prevent writes; CAS
losers may leave audited attempts. Board content is root-owned team content and
is tombstoned when the root run is erased or retained out; erasing an individual
child does not erase the team's board. Create a board tombstone even if no board
exists, and commit it before the root ReplayCase tombstone. This prevents both
late initial publication and retention losing its retry index after a partial
erasure. Refuse exhausted erasure CAS retries visibly. Tombstones cannot be
overwritten. A board digest in audit identifies an attempted mutation, not proof
that it committed or that the worker's claimed evidence is true.

Python sync/async and Node clients expose task discovery, publication, inspection
and commands. A deterministic local example races peer claims, recovers an expired
lease, refuses stale completion, and reports a completed dependency chain without
model keys or external services.

## Build and quality bar

Rust workspace and existing Python/Node HTTP client conventions. No new external
dependencies. Keep the kernel pure and preserve the normative conformance vectors.
Use typed request structs with unknown-field rejection and strict JSON ingress.
Public methods document conditional retry behavior and worker-reported evidence.

Test first: claim contention across gateway instances on one protected store;
dependencies; takeover and lease expiry; revision/epoch fencing; retries; tenant
and unrelated-root isolation; same-tenant principal impersonation; limits and
malformed input; creation after erasure; partial erasure retry; audit/store failure.
Test the HTTP routes and all three clients, then the local example. Test board
ownership fencing separately from lifecycle races so no stronger guarantee is
accidentally asserted.

Commands:

```sh
rtk cargo test -p contextos-gateway --test coordination
rtk cargo test -p contextosd --test dispatch
rtk cargo test -p contextosd --test openapi
rtk cargo fmt --all --check
rtk cargo clippy --workspace --all-targets -- -D warnings
rtk cargo test --workspace
```

Update the API description, threat model, user guide, changelog and ADR alongside
behavior. Preserve the checkout's pre-existing changes. No deployment or merge is
part of this work.

## Not included in this increment

Typed findings, peer messages, automatic model/session launching, Git hosting,
automatic merging, independent task-quality verification, dynamic team membership
outside an admitted delegation tree, and claims of 1,024-agent scaling. These are
separate capabilities in the research roadmap, not unfinished stubs in this API.
