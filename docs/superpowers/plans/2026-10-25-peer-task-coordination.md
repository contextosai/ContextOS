# Peer Task Coordination Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans to implement this plan task by task in this chat, as authorized by the user.

**Goal:** Let admitted peers discover and claim tasks with recoverable leases while retaining all effect controls.

**Architecture:** A bounded root-owned WorkBoard document supports atomic task/dependency transitions by CAS. Gateway methods validate trusted stored admissions, authenticated participant identity and current lifecycle eligibility; HTTP and three clients expose the same extension.

**Tech Stack:** Existing Rust workspace, protected memory/PostgreSQL stores, signed audit, Python sync/async and Node clients. No new dependencies.

**Spec:** [Approved design](../specs/2026-10-25-peer-task-coordination-design.md).

## Global constraints

- 256 tasks, 16 dependencies, 16 evidence refs, 1 MiB board; 1..3600 second leases; pages at most 100 tasks.
- Caller binds to nonempty admitted_by; root comes from protected admission lineage.
- Revision/epoch fencing is atomic within the board. RunState eligibility checks are separate and cannot eliminate lifecycle races.
- Task text/status/evidence refs are untrusted metadata, never effect authority or accepted child output.
- Board tombstones precede ReplayCase tombstones, including absent boards.
- Preserve existing code, normative schemas and pure-kernel semantics.

## Review focus

- Same-tenant dispatch principals must not impersonate another worker using its run id/generation.
- A delayed completion from an expired/replaced claim must not overwrite current ownership.
- Initial publication racing erasure must not recreate erased board content.
- A crash in root erasure must leave retention able to retry.
- Unknown prior effects must not be interpreted as safe merely because a work lease expired.

## Tasks

### Task 1: Gateway board and recovery

Files: new `crates/contextos-gateway/src/coordination.rs`, new `tests/coordination.rs`; module exports, store DocKind, and root erasure integration.

Interfaces: `WorkTaskInput`, `WorkCommand`, `WorkEvidence`, `WorkError`; `publish_work`, `work_tasks`, `work_task`, `update_work` on Gateway, accepting admission, authenticated principal and executor generation.

- [x] Write and run failing contention, dependency, lease expiry, takeover, identity, tenant/root isolation and retry tests.
- [x] Implement strict bounded models, participant loading from protected admission, CAS transitions and digest-only mutation-attempt audit.
- [x] Exercise absent-board erasure, partial-erasure and audit/store-failure tests; implement durable erasure fencing. A separate erasure-receipt regression was observed failing before its fix.
- [x] Verify gateway coordination tests and existing gateway suite pass.

### Task 2: HTTP and clients

Files: HTTP app routes and OpenAPI; Python sync/async and Node client methods/types; HTTP/client tests.

Consumes Task 1 types/methods. Produces four `/v1/runs/{run_id}/work[/task_id]` operations and client publish/list/inspect/command methods with explicit conditional revisions.

- [x] Write and run failing HTTP integration tests for auth, lifecycle, strict ingress and a complete peer flow.
- [x] Implement HTTP error mapping and bounded pagination; document every route in OpenAPI.
- [x] Write and run failing end-to-end client checks; implement sync, async and typed Node methods.
- [x] Verify HTTP dispatch/OpenAPI tests and both HTTP clients.

### Task 3: Example, guidance and verification

Files: `examples/peer-coordination/`, guide, ADR, threat model, changelog, README/plan links; verification records here.

- [x] Add a deterministic no-model demo of competing peers, expired lease recovery, stale completion refusal and a dependency chain.
- [x] Document capacity, contention, untrusted evidence, lifecycle-race boundary, effect reconciliation and root-owned erasure.
- [x] Run fmt, workspace clippy/tests, client checks and the demo; inspect every result.
- [x] Obtain one fresh independent final review, resolve important findings with regression tests, then summarize verified outcomes and limits.

## Execution ledger

- Approved by user: implement end to end in this chat. No further plan approval is needed.
- Baseline: gateway library 12 tests and pipeline 57 tests passed before implementation.
- Ruling: use the supplied clean checkout on a new feature branch, preserving the user's current location; no additional worktree or main-branch implementation.
- Ruling: leave changes reviewable and uncommitted until the repository's full pre-commit gate is satisfied; do not commit unrelated work or publish remotely.

- Task 1: gateway coordination tests 14/14 passed with PostgreSQL enabled; existing pipeline 57/57 passed. Deterministic CAS-race, audit/store failure, erasure ordering, expiry and takeover checks passed.
- Task 2: real HTTP peer integration and OpenAPI checks passed; Python sync/async and Node end-to-end checks passed; TypeScript declarations checked with tsc.
- Task 3 progress: peer demo passed; gate regression 7/7 passed, including the new demo failure check observed RED before adding it to the gate. Full repository verification is in progress.
- Final independent review: no Critical, Important or Minor findings. Accepted the approved capacity/partitioning limit and advisory evidence/effect-history boundaries; these remain documented limits, not additional implementation work. Separate RunState atomicity and unchanged erasure semantics for other document types remain outside this board extension. No new scope is inferred from deferred messaging, findings, model launching or Git integration.

- Task 3: complete. `scripts/check.sh` passed with CONTEXTOS_TEST_DATABASE_URL set to the local development PostgreSQL. The gate covered script/property checks, fmt, workspace Clippy/tests, release builds, Tower, both HTTP clients, every local example including peer coordination, and both demos from an unpacked release archive without cargo. TypeScript declarations also passed `tsc --noEmit --strict --lib es2022,dom`.
- Validation log: `/private/tmp/contextos-peer-check.log` (ephemeral local log). One pre-existing ignored Rust test remains ignored; no new tests were disabled.
