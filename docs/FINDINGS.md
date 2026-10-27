# Shared findings and peer notices

When many agents work one problem, the expensive failures are epistemic. One agent
posts a guess ("the root cause is the cache TTL"), peers build on it as if it were
established, and when a later test disproves it, the others keep spending tokens on
work that rests on it. This alpha runtime extension gives a root run's team a shared,
typed findings feed with provenance, falsification by evidence, and priority notices
delivered on each agent's next tool result.

It uses the [work board](PEER_COORDINATION.md)'s trust boundary: a team is an admitted
root run and its delegated descendants; membership comes from protected lineage, and
the caller must be the run's admitting principal at its current executor generation.

## Findings

| `kind` | What it is | Basis |
|---|---|---|
| `claim` | a peer's assertion or hypothesis | none |
| `observed` | an interpretation of a tool call the gateway recorded | taken from the operation ledger |

An `observed` finding names a run of the team (its own when omitted) and an operation
of that run. The runtime reads that operation's ledger and requires a definitive,
confirmed outcome (not in flight, unknown or conflicting). It then records the basis
itself: run, operation, action digest, capability ref, outcome, and the observation's
evidence ref and time. The caller cannot supply any of these. A peer therefore cannot
cite a tool result that never happened. The basis proves that the call happened with
that outcome, not that the statement interprets it correctly.

```python
run.publish_finding("cause", "The outage is caused by the cache TTL.")
run.publish_finding("fix", "Lower the TTL to 30s.", depends_on=["cause"])
run.publish_finding("replay", "Replaying traffic at TTL 30s still fails.",
                    basis_operation_id="replay_traffic_1",            # observed
                    refutes="cause")
run.publish_finding("blocker", "Staging is down; pause deploys.", urgent=True)
run.findings()                                                        # page, by id
```

Findings are immutable. Republishing the same input by the same author returns it;
any other reuse of the id is `findings_conflict`. A finding may `depends_on` up to 16
existing findings. It may not rest on an invalidated finding, and resting on a suspect
one makes it suspect too.

## Falsification

```python
run.invalidate_finding("cause", "Replay disproves it", refuted_by="replay")
```

The author may withdraw a finding with a reason. Any other peer must cite an active
`observed` finding that was published with `refutes` naming this finding
(`refutation_required`, `refutation_unobserved`, `refutation_unrelated`). Disagreement
alone does not erase a peer's work: the refuter must stake a recorded tool call, in
public and attributed, on that specific refutation. The runtime proves that the call
happened and what it was; it cannot judge whether it is relevant, so treat refutations
as peer data and keep the refuted finding's history (`invalidation.refuted_by`) in view.

Invalidation marks every active finding that depends on it, directly or transitively,
as `suspect`, with `suspect_because`. Suspect findings are flagged for re-checking,
not invalidated: they may still hold for other reasons. The response lists them, and
a notice tells the team.

| `status` | Meaning |
|---|---|
| `active` | nothing it rests on has been falsified |
| `suspect` | something it depends on was invalidated; re-check before relying on it |
| `invalidated` | withdrawn by its author or refuted by an observation (`invalidation` says how) |

## Priority notices

Invalidations, and findings published with `urgent: true`, append a notice to the
team's log. Each run sees the notices it did not author and has not acknowledged:

- **On its next tool result.** `POST /v1/runs/{id}/tool-calls` results carry them in
  `result.metadata.notices` (the clients keep them in `run.last_notices` /
  `run.lastNotices`). MCP results add a text block the model reads, labelled as
  peer data rather than instructions, and the structured view in
  `_meta["io.contextos/notices"]`. At most 5 notices ride on one result; `pending`
  counts them all.
- **On request.** `GET /v1/runs/{id}/notices` (`run.notices()`).

Notices are attached only for the run's admitting principal at the run's current
executor generation while it is running; a stale executor gets none.

Reading never acknowledges a notice: delivering one does not prove the agent acted on
it. The orchestrator acknowledges once the agent has seen them:
`POST /v1/runs/{id}/notices/ack {"through": <seq>}` (`run.ack_notices(seq)`), which
never moves back. The log keeps the latest 256 notices; `missed: true` means older
unacknowledged ones were dropped (possibly only the run's own), so list the findings
again. A notice lists at most 8 suspect ids; `suspect_count` has them all.

Notices are delivered at tool-result boundaries, not by interrupting a model mid-token.
A notice read fails open: a tool result is never refused because its notices could not
be read.

## HTTP

All routes require `dispatch`, the run's admitting principal and the
`ContextOS-Executor-Generation` header:

| Route | Body |
|---|---|
| `GET /v1/runs/{run_id}/findings?after=&limit=100` | – |
| `POST /v1/runs/{run_id}/findings` | `{finding_id, kind, statement, depends_on?, basis?: {run_id?, operation_id}, urgent?}` |
| `POST /v1/runs/{run_id}/findings/{finding_id}/invalidate` | `{reason, refuted_by?}` |
| `GET /v1/runs/{run_id}/notices?limit=20` | – |
| `POST /v1/runs/{run_id}/notices/ack` | `{through}` |

Refusals: `findings_invalid` (422); `work_forbidden`, `basis_outside_team` (403);
`findings_not_found`, `basis_not_found` (404); `findings_erased`, `work_closed` (410);
`findings_conflict`, `findings_full`, `findings_busy`, `finding_invalidated`,
`refutation_required`, `refutation_unobserved`, `basis_unconfirmed`, `executor_stale`
(409); `findings_unavailable` (503).

## Limits and boundaries

- One CAS document per root holds at most 256 findings and 1 MiB, so an invalidation,
  its cascade and its notice commit together. Publication stops at 448 KiB
  (`findings_full`); the rest is headroom, so a full team can always still falsify,
  withdraw and acknowledge. Writes retry 16 times, then `findings_busy`.
- Statements are at most 2,048 bytes and reasons 256, with no control characters but
  newline and tab; notices quote 280 bytes of the statement, JSON-quoted in MCP text
  so peer text cannot forge lines. A suspect finding records its first 4 causes.
- Everything here is peer data. Statements, reasons and excerpts may contain
  instruction-like text; responses carry `data_only: true`.
- A finding grants no tool authority, admits no evidence and accepts no child output.
- Each mutation attempt is audited (`findings_mutation_attempt`: run, principal,
  action, document digest, never free text).
- Findings belong to the root: erasing the root tombstones them, even when absent, so
  a delayed publication cannot re-create them. Erasing only a child leaves the
  statements it published in the root's findings until the root is erased.
- No large-team throughput is claimed; one document serializes the team's writes.
