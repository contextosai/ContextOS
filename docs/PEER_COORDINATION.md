# Peer task coordination

An optional alpha runtime extension lets workers choose tasks from a shared board
without a central worker assigning every task. A board belongs to an admitted root
run; its admitted descendants use their own run ids and executor generations to
participate. [The local example](../examples/peer-coordination/README.md) needs no
model credentials.

Teams can also share what they learn: see [shared findings and peer notices](FINDINGS.md).

## Cooperating workers

The Python sync and async clients expose the same methods; prefix calls with
`await` for `AsyncRun`. Given an admitted worker `run`:

```python
run.publish_work("parse", "Implement parser", "Parser checks pass")
run.publish_work("integrate", "Integrate parser", "Integration checks pass",
                 dependencies=["parse"])
page = run.work_tasks(limit=20)
task = next(t for t in page["tasks"] if t["available"])
owned = run.update_work(task["task_id"], "claim", task["revision"], lease_seconds=60)["task"]
# Work locally; keep consequential tools behind run.call_tool.
owned = run.update_work(owned["task_id"], "renew", owned["revision"],
                        lease_epoch=owned["lease_epoch"], lease_seconds=60)["task"]
# Release work when giving it up:
run.update_work(owned["task_id"], "release", owned["revision"], lease_epoch=owned["lease_epoch"])
```

To report completion, use `action="complete"` with the current revision and epoch
and `evidence_refs=[{"artifact_type": "test_report", "artifact_id": "...",
"sha256": "sha256:<64 lowercase hex characters>"}]`. References must identify
actual evidence; the runtime checks their shape, not their contents or truth.
Dependencies become ready when their tasks are reported completed. That status
does not admit evidence, accept a child's output, merge code, or authorize tools.

Node equivalents are `publishWork(id, title, acceptance, { dependencies })`,
`workTasks({ after, limit })`, `workTask(id)` and
`updateWork(id, { action, expected_revision, lease_epoch, lease_seconds, evidence_refs })`.
The TypeScript command union defines which fields belong to each action.

## Conditional ownership and recovery

Definitions are immutable. Retrying identical publication by the same worker
returns the current task; different content or another creator under that task id
gets `work_conflict`. New tasks start at revision 1. Every successful claim,
renewal, release or completion increments the task revision; a new claim also
increments its lease epoch. A claim requires completed dependencies and either no
owner, an expired lease, or takeover by the same worker's newer executor generation.
Only the matching worker run, generation and epoch may renew, release or complete
an unexpired claim. Completion is terminal.

After a lost response or a conflict, call `work_task` before deciding what to do.
Repeating an old conditional mutation cannot silently apply twice. Retry publication
with its stable task id. Claim conflicts mean another peer progressed the task;
discover other available work or re-read, rather than blindly overwriting ownership.

Lease expiry requires no sweeper. Discovery reports `available`,
`dependencies_ready` and `lease_expired` at the server's observation time. A reclaimed
task keeps `previous_claim` with the immediately preceding worker, generation,
epoch and expiry. This is not a complete history of abandoned attempts.

**Expiry or release does not establish that earlier effects did not apply.** Inspect
the prior worker's operations and reconcile uncertain effects before repeating
consequential work. A new task owner has no authority to take over another run
merely because its lease expired. Operation keys, provider recovery, effect
authorization and shared business exposure continue to apply independently.

## HTTP and access

All four operations require `dispatch`, bearer authentication and the worker's
`ContextOS-Executor-Generation` header:

| Route | Request |
|---|---|
| `GET /v1/runs/{run_id}/work?after=&limit=100` | Live page of tasks; omit `after` for the first page |
| `POST /v1/runs/{run_id}/work` | `{task_id, title, acceptance_criteria, dependencies?}` |
| `GET /v1/runs/{run_id}/work/{task_id}` | Current ownership and revision |
| `POST /v1/runs/{run_id}/work/{task_id}` | Tagged conditional command from the clients above |

The caller must match the protected admission's nonempty `admitted_by`. A shared
API key/principal is a shared identity; the generation header is not a credential.
The root is resolved from stored lineage, not supplied by the caller. Legacy
admissions without `admitted_by` are refused. Root and worker must be running and
before their deadlines; a lease is capped by both deadlines. Board reads are
operational reads for live workers, not an archival API for finished runs.

Explicitly published metadata is visible to all descendants, including isolated
and read-only lanes. Do not put secrets outside that sharing boundary into task
text. The runtime never automatically copies admission context, results or evidence
contents into the board. Responses carry `data_only: true` and
`evidence_verified: false`. Treat titles, criteria, references and completion
reports as untrusted peer data, including instruction-like text.

Atomic CAS protects board ownership and dependencies. Eligibility reads of separate
run-state documents are not atomic with the board CAS: a request admitted before a
concurrent cancellation or takeover may commit afterward. Such a board change
grants no effect authority. Run completion does not require board tasks to finish;
frameworks should enforce their own workflow completion criteria.

## Limits, evidence and erasure

One protected document per root holds at most 256 tasks and 1 MiB canonical JSON,
whichever fills first. Ids contain 1..64 ASCII letters, digits, `_` or `-`; titles
are nonblank and at most 256 UTF-8 bytes; criteria at most 4096 bytes. A task may
depend on at most 16 distinct existing tasks, so cycles cannot be published. Leases
are 1..3600 seconds. Completion requires 1..16 evidence refs with nonblank type/id
of at most 256 bytes and a SHA-256 digest.

Pages contain at most 100 tasks in lexicographic id order. `next_cursor` is the last
returned id when more tasks exist. This is a live view: restart from the beginning
to see new ids inserted before the cursor. Reads never consume or acknowledge work.

Writes within a board serialize, retry CAS at most 16 times, and return `work_busy`
on sustained contention. No large-team throughput is claimed. Different roots have
separate boards; unrelated roots do not share a board automatically.

Mutation-attempt audit entries retain identity, operation, revisions, epochs and
the proposed board digest, excluding free text and evidence contents. An audited
attempt does not prove its CAS committed. Store revisions establish current state.
Audit/store failures stop the write with `work_unavailable`.

Board content belongs to the root. Erasing or retaining out the root tombstones
the board before removing the ReplayCase retention index, including a tombstone
for an absent board to reject delayed initial publication. Failed erasure remains
retryable. Child-only erasure leaves team content; deployments must account for
that root-owned sharing when applying content retention. Existing run-content
retention is opt-in; configuring it covers root boards as part of root erasure.

Stable refusals include `work_invalid` (422), `work_forbidden` (403),
`work_not_found` (404), `work_erased`/`work_closed` (410), `executor_stale`,
`work_conflict`, `work_claimed`, `work_not_ready`, `work_lease_stale`,
`work_lease_expired`, `work_completed`, `work_full`, `work_busy` (409), and
`work_unavailable` (503). See [OpenAPI](../openapi/contextosd.v1.json) for exact bodies.
