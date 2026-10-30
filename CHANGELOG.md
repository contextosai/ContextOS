# Changelog

All notable changes are listed here. Versions follow Semantic Versioning; before 1.0,
minor versions may break APIs and every break is listed.

## Unreleased

### Changed (breaking)
- Reconciliation: the principal that admitted a run can no longer assert its effect
  `not_applied` or `partial` (`403 reconcile_not_independent`), which released holds on
  its own word without the checks attest-absence makes. It may still query the provider
  or assert `confirmed`. Give on-call or reconciliation automation its own `reconcile`
  key; a principal that did not admit the run sends no executor generation. The Python
  client adds `Client.reconcile(run_id, operation_id, …)` for it, and the examples'
  on-call key (`svc_oncall`) now holds `reconcile`.
- Python client: redirects are no longer followed (they resent the bearer token), and
  a plain `http` URL to a non-loopback host is refused unless `allow_http=True`.

### Fixed
- Release builds unwind on panic again (`panic = "abort"` is gone), so the servers'
  panic layers and the bindings' `catch_unwind` contain a panic to one request instead
  of ending the process.
- Tower's AI assistant client no longer follows redirects, which carried its
  `x-api-key` to the redirect target.
- `--check-config` and startup warn about each effectful capability that declares no
  `amount` or no `resource_pointers`, which task amount and resource limits cannot
  bound.
- Docs: evidence gates trust the caller's labels; rollouts are steerable by run id;
  overage is lost, not doubled, by a crash between its two commits.

### Added
- `retired_capabilities`: manifests of versions an upgrade replaced. Operations
  claimed under a retired version are reconciled, attested and recorded with it; it is
  never dispatched. Before, upgrading a capability left those operations refused as
  `capability_not_pinned`, holding their budget and shared capacity. See "Upgrading a
  capability with operations open" in [docs/GUIDE.md](docs/GUIDE.md).

## 0.1.0-alpha.4 - 2026-10-30

Fourth alpha: an audited release for holds whose dispatch started and recorded no
fact, runs bound to the principal that admitted them, and MCP completion contracts.
Two changes are breaking; see the [release notes](docs/releases/v0.1.0-alpha.4.md)
before upgrading.

### Added
- Attesting absence: `POST /v1/runs/{run_id}/operations/{operation_id}/attest-absence`
  releases what an attempt holds when its dispatch started and it recorded no fact
  (its executor died mid-call), which reconciliation refuses (`dispatch_active`,
  `shared_guarantee_dispatch_active`) and nothing released before. It needs the new
  `attest` scope held without `admit` or `dispatch` (configuration refuses the
  combination), cites the provider's records, and is accepted only once they were
  checked through the attempt's start plus the capability's timeout plus 300
  seconds. `effect_absence_attested` is signed first; the attestation then seals the
  attempt as `not_applied` and releases shared capacity, the budget reservation and
  task-limit charges. See "Attesting absence" in
  [docs/SHARED_GUARANTEES.md](docs/SHARED_GUARANTEES.md).

### Changed (breaking)
- Runs are bound to the principal that admitted them. Tool calls, status, takeover,
  complete/fail/cancel, decisions, usage reservation, checkpoints, memory, peer work,
  findings, compensation and delegation from a parent now answer `404 run_not_found`
  to any other principal in the tenant, instead of letting any `dispatch` key that
  learned a run id drive it. Reconcile, attest, evaluate, meter, authorize and audit
  keep their own roles. Give each agent service its own principal.
- `[guards] require_completion_contracts` (on in production) refuses to start with an
  effectful MCP capability that declares no `recovery.completion`. With one, a finished
  MCP result is decided by the state at its `state_pointer` in `structuredContent`,
  as for HTTP: a result reporting `pending` or `failed` without `isError` is no longer
  a confirmed effect. `status_tool` is optional (MCP looks tasks up with `tasks/get`)
  and still required for HTTP.
- Hold inspection: `next_safe_step.action` `confirm_with_evidence_only` is now
  `confirm_or_attest_absence`, and `next_safe_step` carries `attest_absence` (the
  route, or `null`).

### Fixed
- An attestation of absence advances the run's executor generation before it is
  recorded, and a dispatch that stalls more than 120 seconds between its claim and the
  provider call sends nothing (`dispatch_stalled`), so an attestation cannot race a
  paused dispatcher.
- A guarded dispatch whose shared-guarantee link is missing when it marks its receipt
  started is withheld (`shared_guarantee_link_missing`) instead of being sent unmarked.
- The Tower console sets `X-Content-Type-Options: nosniff` and `Cache-Control:
  no-store` itself, however it is mounted.
- Guide: identical calls in one run share a derived operation key; how to make equal
  calls separate effects.

## 0.1.0-alpha.3 - 2026-10-29

Third alpha: the ten-minute path (preflight, configuration check, lost-response demo
and receipt), hold inspection, the PostgreSQL failure drill and review fixes; see the
[release notes](docs/releases/v0.1.0-alpha.3.md) before upgrading.

### Added
- `examples/postgres-drill`: a failure drill for one shared limit on PostgreSQL.
  Three `contextosd` processes share one store; agents race refunds on hot orders, a
  process is SIGKILLed after the provider applied its refund and restarted, a reply is
  lost, and (with `CONTEXTOS_DRILL_PG_RESTART`) the database restarts under load.
  Every hold is then found through the inspection API and resolved from the
  synthetic provider's ledger, and the protected balances are checked against that
  ledger. It runs in CI with a database restart and ships in release archives. Results
  and one stranded-hold finding are in
  [docs/research/2026-10-29-postgres-shared-limit-drill.md](docs/research/2026-10-29-postgres-shared-limit-drill.md).
- Shared-guarantee hold inspection (`audit:read`, read-only).
  `GET /v1/guarantees/{id}/holds` pages through the tenant's resources with capacity
  held. `GET /v1/guarantees/{id}/resources/{resource_digest}/holds` explains each open
  hold: its run, operation, attempt, action digest, amount, dispatch state, attempt
  start, last observation and observer, and the next safe step with the reconcile
  route to use. No tool arguments are returned, and nothing is released by viewing
  or by elapsed time. See "Find and explain holds" in
  [docs/SHARED_GUARANTEES.md](docs/SHARED_GUARANTEES.md).
- `DocumentStore::list`: one tenant's documents of one kind by id, in pages, served
  by the existing primary key on PostgreSQL. Stores that cannot list refuse.
- `contextosd --check-config <path>` runs startup's validation without serving: the
  configuration, packs and pinned manifests, the dispatch gateway, that the signing
  seed or KMS token and PostgreSQL URL variables are set, and that the listen address
  is free. It does not contact the key service or connect to the store.
- `examples/doctor.sh`, a preflight that checks the platform and glibc, that every
  binary starts and reports one version, Python 3.9+ for the examples and, with
  `--config`, the configuration. It names one fix per failure (for example building
  from source when the system's glibc is older than 2.28) and starts nothing. The
  shared-guarantees demo runs it first, and release archives include it.
- The shared-guarantees demo loses a provider response: the refund applies, the
  reservation stays held as unknown, and an operator confirms it from the provider's
  ledger export. Each step prints `limit / committed / held / available` and the next
  safe step. The audit log, keys, balances and the cited ledger export stay in
  `receipts/shared-guarantees/` (`CONTEXTOS_RECEIPT_DIR`), with the command to verify
  them again.

### Fixed
- Task-authorization amendments are audited before they take effect, so a widening
  never goes live without its signed record; a failed commit afterwards appends
  `task_authorization_amendment_aborted`.
- An amendment that changes `issued_by` or `confirmation_ref` is classified as
  widening, however narrow its scopes: whoever runs the task can no longer rewrite who
  authorized it.
- Tower: a review by the agent's current owner or declarer never counts as approval,
  checked when approval is evaluated, so a re-declaration racing the review cannot
  slip past separation of duties.
- `GET /v1/guarantees/{id}/holds` lists an unreadable ledger as
  `{"resource_digest", "unreadable": true}` instead of failing the whole page.
- `examples/doctor.sh` fails on platforms without a release archive (Intel Macs
  outside Rosetta, Linux other than x86_64/aarch64) instead of passing them.
- Docs: the 1,024-receipt lifetime cap per shared resource and how to size resources
  for it; Tower journal verifiers must treat two entries with one `collection_seq` and
  `change_id` as one change.
- A store failure while a shared-guarantee dispatch wrote its dispatch gate no longer
  strands the attempt's held capacity. The gateway now writes the gate before it marks
  the shared receipt started, so marking the receipt is the last write before the
  provider call. An attempt the failure stopped is recorded as not started, and
  asserting `not_applied` releases its hold; before, that assertion was refused with
  `shared_guarantee_dispatch_active` although nothing had been sent. Found by the
  PostgreSQL drill.

## 0.1.0-alpha.2 - 2026-10-29

Second alpha. Linux archives now run on glibc 2.28 and later, and this release
contains breaking changes to Tower reviews and HTTP capability manifests; see the
[release notes](docs/releases/v0.1.0-alpha.2.md) before upgrading.

### Added
- Linux release executables are built on AlmaLinux 8 against glibc 2.28, so the
  archives run on RHEL, AlmaLinux and Rocky 8+, Debian 10+ and Ubuntu 20.04+.
  `v0.1.0-alpha.1` was built on Ubuntu 24.04, and its `contextosd` fails to start on
  older systems (for example `GLIBC_2.38 not found` on Ubuntu 22.04).
  `scripts/check-glibc.sh` fails the build if an executable needs a newer glibc. The
  release workflow smoke-tests every archive on its runner and on AlmaLinux 8
  (`scripts/smoke-archive.sh`), and CI runs the baseline build and the
  shared-guarantees demo on every pull request.
- `contextosd --version` and `towerd --version`, like `ctx --version`.
- "Why not a database transaction?": a README section, a guide
  ([docs/WHY_NOT_A_TRANSACTION.md](docs/WHY_NOT_A_TRANSACTION.md)) and a runnable
  example (`examples/why-not-a-row-lock`). The example runs a row-lock refund service
  and ContextOS against the same lost-response, stalled-call and cross-system faults.
  It covers one guarantee spanning two adapters and operator reconciliation in both
  directions.
- Governed compensation (sagas). A capability manifest may declare `compensation`: the
  capability that undoes its effect and where that capability's arguments come from
  (the original call's arguments, or `/external_ref`, the provider reference recorded
  with the effect, which never reaches the agent). Before such an effect is sent, the
  gateway records what compensating it needs; an effect that could not be compensated
  is refused (`compensation_binding_incomplete`, `compensation_index_full`).
  `POST /v1/runs/{run_id}/operations/{operation_id}/compensate` runs the compensation
  as a new governed operation (authority, policy, approval, budget, claim, audit) whose
  claim the kernel checks against the original's outcome (`compensates_operation_id`);
  each effect is compensated at most once. `POST /v1/runs/{run_id}/compensate`
  compensates the run's effects newest first and stops at any effect in doubt;
  `GET /v1/runs/{run_id}/compensations` lists where each stands. Clients:
  `compensations`, `compensate`, `compensate_all` (Python) and `compensateAll` (Node).
  Erasure removes compensation records. Demo: `examples/compensation`.
- Shared findings and peer notices for a root run's team (alpha). A `claim` is a peer's
  assertion; an `observed` finding cites a recorded tool call of the team, and the
  runtime takes its basis (action digest, outcome, observation evidence) from the
  operation ledger, so peers cannot fabricate tool evidence. Only the author may
  withdraw a finding; others must cite an active observed finding that refutes it.
  Invalidation marks dependents `suspect` and notifies the team; urgent findings notify
  on publication. Notices ride on each member's tool results
  (`result.metadata.notices`; an MCP text block and `_meta`) until its orchestrator
  acknowledges them. Routes `GET/POST /v1/runs/{run_id}/findings`,
  `POST /v1/runs/{run_id}/findings/{finding_id}/invalidate`,
  `GET /v1/runs/{run_id}/notices`, `POST /v1/runs/{run_id}/notices/ack`; client
  methods `publish_finding`, `findings`, `invalidate_finding`, `notices`, `ack_notices`
  and `last_notices`. Erasing the root tombstones its findings. Guide:
  `docs/FINDINGS.md`.
- Operation ids beginning with `compensation:` are reserved; a tool call using one is
  rejected with `operation_id_reserved`.

### Changed (breaking)
- Tower reviews record each capability's risk (`capability_risks`), and an approval
  covers a capability only at that risk. A change in any dimension under the same id,
  approval mode included, voids the approval and raises `authority_drift` with the
  reviewed and current risk. Reviews made before this change recorded no risk and no
  longer count; re-review approved agents after upgrading. `graph_digest` now covers
  approval mode, so its values change.
- Every effectful HTTP capability must declare `recovery.completion`, the provider's
  reported-state contract, and its `2xx` responses are read under it: the body's state
  at `state_pointer` settles the effect only when listed, and a `200` reporting
  `pending`, `failed` or no state is unknown, keeping the body's `id` for the status
  lookup. A success status alone no longer confirms an effect. `contextosd` refuses to
  start with an effectful capability on an HTTP adapter whose manifest lacks the
  contract, and the HTTP adapter does not send such a call (`not_dispatched`).
  Read-only HTTP capabilities need no contract. See "Migrating an HTTP integration" in
  [docs/GUIDE.md](docs/GUIDE.md).
- The HTTP adapter no longer treats a client error from an effectful capability as
  definitively not applied. HTTP does not promise a handler changed nothing before it
  answered `400` or `422`, and "not applied" releases shared exposure and permits a
  retry. Such responses are now unknown until reconciled, unless the capability
  manifest lists the status in the new `recovery.not_applied_statuses` (at most 16
  distinct 4xx statuses the provider documents as returned before any effect).
  Read-only capabilities keep the previous mapping. The MCP adapter applies the same
  rule to HTTP 400, 401, 403, 404, 405 and 415 from the MCP endpoint, which it
  previously treated as not applied for every tool; JSON-RPC protocol errors
  (-32700, -32600, -32601, -32602) are unchanged.
- Tower journal entries for governance changes carry a `change_id` in their payload.
  Guardrail and waiver ids are full 32-character UUIDv7s; the 12-character ids were
  only the creation millisecond and could collide.

### Fixed
- Tower: an approved review stops counting when it expires. Expired reviews raise
  `unreviewed` ("review expired"), produce no drift baseline, and set `reviewed`
  false and `review_expired` true in guardrail facts and the console.
- Tower signs a governance change's journal entry only after the change commits.
  Previously an entry was signed first, so a crash, a store error or a concurrent
  refusal (two reviewers activating one draft) left a signed event for a change that
  never happened. Records now commit the change and its pending entry together;
  entries a crash leaves pending are journaled at startup or before the collection
  next changes, without repeating an entry already journaled.
- Tower checks an owner's team against the stored declaration at commit, so a
  concurrent transfer to another team is not overwritten.
- Tower resolves a pack version within the source that admitted the agent's runs.
  Previously sources publishing different content under one `id@version` overwrote
  each other, and an agent's authority graph and approval gates could come from
  another source's pack. Such conflicts raise `pack_version_conflict`.
- Creating a guardrail or waiver refuses an id that already exists.
- Tower: when an agent's packs declare one capability with different risk, each risk
  dimension keeps its most consequential value (previously the first pack's entry won,
  even if it declared less risk), and `capability_risk_conflict` is raised.
- Tower journals entries a crashed writer left pending once per lease period, so they
  no longer wait for the collection's next change.
- Tower journals each collection's changes in that collection's commit order (there
  is no order across collections). A change commits only after
  the previous change to that collection is journaled, waiting while another writer is
  still journaling; previously a stalled writer's entry could be journaled after a
  later change. Journal payloads carry `collection` and `collection_seq` (the
  collection's commit number). Numbering starts at 1 with each collection's first
  change after upgrading and has no gaps from there; earlier entries carry none.
- Tower keeps every interaction kind a capability's packs declare (`interactions`) and
  derives required controls from all of them. Previously a merge kept one kind, so a
  `browser` and a `computer` variant together required `isolation.required` but not
  `network.mediated`.

## 0.1.0-alpha.1 - 2026-10-26

First public alpha of the ContextOS runtime. APIs and storage formats are evolving;
this release is for evaluation and early integration. See the
[release notes](docs/releases/v0.1.0-alpha.1.md) for downloads and limitations.

### Security
- Upgrade Tokio to 1.54.1 to fix RUSTSEC-2026-0384, a timer race affecting
  interval-driven replica membership and retention on the multithreaded runtime.

### Peer task coordination
- Add a root-owned work board for admitted peers to publish immutable tasks, discover
  dependencies, and atomically claim, renew, release or report completion with leased
  ownership. Conditional revisions/epochs fence competing claims; expiry retains
  predecessor provenance and never establishes that earlier effects are safe to repeat.
- Bind board access to authenticated admission principals and protected lineage;
  audit mutation attempts by digest and fence board writes before root-content erasure.
- Add HTTP/OpenAPI, Python sync/async and typed Node client support, a local no-model
  peer demo, and concurrency, recovery, erasure and failure-injection checks. The alpha
  limit is 256 tasks/1 MiB per board; completion evidence is worker-reported.

### Shared business guarantees
- Reposition ContextOS around numeric business-resource limits shared by independent
  agent runs. Research records current alternatives and the differentiation hypothesis.
- Add opt-in `[[guarantees]]`, protected resource exposure and stable definition pins;
  reserve and activate exact attempts before dispatch, retain unknown/partial
  exposure, seal definitive observations and audit contradictory/stale refusals.
- Add conservative settlement recovery, current-generation reconciliation after
  terminal runs, and `audit:read` guarantee/exposure inspection endpoints with OpenAPI.
- Add a synthetic multi-agent example and regression coverage for cross-replica
  contention, dispatch/recovery races and store/audit interruptions. Static ceilings,
  1,024 receipts per resource and orphaned active-dispatch recovery limits are explicit.

### Public release preparation
- Align local, CI and container builds on Rust 1.99.1; refresh JSON Schema and Node
  native binding dependencies with offline-validation and marshalling regressions.
- Pin the legacy compiler's ICU comparator to 2.3.1 and test its persisted Unicode
  hashes. ICU 2.4 changes key ordering and requires a versioned encoding migration.
- Refresh the Tower UI, conformance tooling and JavaScript framework integrations;
  build the container's static UI with Node 26.12.1.
- Update the workflow actions, validate artifact upload/download on pull requests,
  and select binary archives and SBOMs explicitly for release publication.
- Include the pinned, attributed TypeScript reference and synthetic fixtures so
  contributors can regenerate conformance vectors without a private repository.
- The commit gate checks each example's exit status before accepting its success
  message; regression tests cover failing examples and output after the message.
- Release archives and the container carry the project's licenses, attribution and
  trademark notices, plus reproducible Rust and Tower dependency license texts.
- Alpha setup, support, contribution and private reporting guidance is explicit.
- Release archives are self-contained: `ctx`, `contextosd` and `towerd` in `bin/`, the
  Tower UI in `tower/dist`, the Python HTTP client, the runnable examples and the docs
  (`scripts/package-release.sh`). Examples use `bin/` (or `CONTEXTOS_BIN`) before
  building with cargo, so they run with Python, Bash and curl alone; the release
  workflow runs the shared-guarantees demo from each unpacked archive.

### Tower: the governance plane
- `towerd` governs an organisation's agents across ContextOS runtimes: it reads each
  runtime tenant with a read-only key, verifies every audit entry before using it, and
  maintains the agent inventory (with owner declarations), each agent's authority graph
  and the control profiles it requires, findings with fixes, organisation guardrails
  (JsonLogic over agent facts), time-boxed waivers, risk reviews with drift detection,
  anomalies against each agent's own baseline, and a fleet-wide kill switch. Roles
  (viewer, owner, risk, operator, admin) with separation of duties; every decision in a
  signed journal verifiable with `ctx audit-verify`.
- Optional intelligence with Claude: Ask Tower (read-only tools, checked citations),
  guardrail drafting checked against the inventory, intake review drafts, anomaly
  briefs and run explanations. Advisory only; every use is journalled.
- The Tower UI (`tower/`), served by `towerd`; `examples/tower`.
- Developer documentation in `docs/tower/`: concepts, architecture and flow diagrams, the
  governance model, intelligence, API, security, a step-by-step build guide and operations.
- Runtime: a `run_admitted` audit entry attributes each run to its agent, pack,
  contract, required controls, surfaced capabilities and release references;
  `GET /v1/deployment`, `GET /v1/packs`, and `head` on audit pages.
- Configuration review: a `config` scope (never with `admit` or `dispatch`),
  `GET /v1/config` and `POST /v1/config/validate`, which classifies every effective
  change as tightening, loosening or neutral for CI. Production refuses the published
  development keys.

### Licensing
- Code is licensed under Apache-2.0 and documentation prose under CC BY 4.0; the
  name and logo are covered by a separate trademark policy (`TRADEMARKS.md`).

### Decision kernel
- Context Pack compiler, ActionRisk evaluation, profile negotiation, authority and
  delegation validation, policy composition, approvals and authorization, execution
  boundary, data flow, memory lifecycle, run lifecycle and resume, operation and budget
  ledgers, and conformance assessment, matching the spec's reference on generated
  parity vectors.
- RFC 8785 canonical JSON and domain-separated digests; bounded JsonLogic with
  `json-logic-js` semantics and fail-visible errors.
- Verified properties: a catalog of the rules the runtime's safety rests on
  (`docs/verification/PROPERTIES.md`), each with its source, level of rigor and check.
  New property suites check scope narrowing, policy composition, budget conservation
  and task-authorization amendments on generated inputs, and the run lifecycle
  exhaustively; the gate fails when the catalog and the checks drift apart.
- Security: a task-authorization amendment that added an `amount_ceiling` to a scope
  without one was classified as narrowing, so a run's own executor could permit
  amounts the principal had not authorized. It is now a widening. Found by property
  AUTH-1, which also showed the specification's delegation rule and grant-scope check
  disagree on a missing ceiling (proposal spec-0004; grant chains are unaffected).
- Properties of the operation ledger (no new attempt after an applied effect or under
  conflicting evidence, at most one attempt in flight, applied stays applied) over
  random histories with late facts, and of canonical JSON (an independent RFC 8785
  encoder, fixed point, shortest round-trip numbers). Each guard they rest on was
  mutation-tested.
- The kernel follows specification revision `7e2462f`: a child grant scope that adds
  an `amount_ceiling` its parent lacks is `delegation_scope_expanded` (spec-0004).
  New reference vectors cover adding, dropping and omitting a ceiling.

### Runtime
- Crash recovery: a crash between an operation's claim and its provider call no longer
  strands the operation. Outside shared guarantees, a claimed attempt without facts
  could not be reconciled, and retries were refused as `operation_in_flight` for good.
  Reconciliation now treats it as unresolved. Each attempt has a dispatch gate, opened
  immediately before the provider call; recording the attempt as not applied closes
  it first, so a stranded dispatch that resumes sends nothing (`dispatch_aborted`) and
  releases its holds. Once the gate opened, the assertion is refused (`dispatch_active`).
  One more store write per dispatch. Found by exploring every single-crash point of a
  dispatch (properties DISPATCH-1..7).
- Crash recovery: a reconciliation that crashed after recording its fact is completed
  by the next reconciliation of the operation, which settles the held budget
  reservation, returns task-limit charges and clears the run's outstanding-effect entry
  (`reconciliation_completed`), auditing the completion with `source: "recovery"`.
  Before, the retry saw a settled operation and changed nothing, so the reservation
  stayed held and the run could not complete. An effect reconciled as not applied now
  also returns its task-limit charge, as a dispatch reported not applied already did.
  Found by exploring every single-crash point of a reconciliation (RECONCILE-1..4).
- Crash recovery: a crashed dispatch no longer leaves budget held. A crash between the
  budget reservation and the operation claim left the reservation open for good; a
  retry now reclaims it once its own claim succeeds, after closing the stranded
  attempt's dispatch gate so that attempt can never send. A crash after the provider's
  answer was recorded left the reservation, the shared exposure and the task-limit
  charge unsettled; the next dispatch of the operation now settles them. Reservation
  ids name their operation (`reservation:<operation tag>:<attempt_id>`); the earlier
  `reservation:<attempt_id>` form is still recognized. Shared-guarantee dispatches now
  open a dispatch gate too (one more store write for them). Found by checking release,
  not only conservation, at every crash point of a dispatch (DISPATCH-8, DISPATCH-9).
- Crash recovery: an attempt that reaches a closed dispatch gate (its reservation was
  reclaimed, or an operator recorded it never sent) now records itself
  `not_dispatched`. Before, it sent nothing but stayed claimed, so the operation was
  refused as `operation_in_flight` until an operator resolved it (DISPATCH-10).
- Crash recovery: a retry whose claim is refused (for example `retry_not_due`) now also
  returns reservations a crashed attempt of the operation left before its claim,
  skipping any attempt the operation ledger records. Before, only a successful claim
  reclaimed them, so an operation that was never claimed again kept the reservation
  and its run was refused completion as `effects_in_flight`. Found by exploring every
  pair of crash points of a dispatch and its retry (DISPATCH-12, 1,074 pairs).
- Tests: concurrent dispatches of one run, racing for one budget, one task's limits
  and one shared guarantee, across 48 seeded interleavings (DISPATCH-11).
- Contract hardening (spec H01–H03): HTTP 202/206/207 leave the effect unknown;
  provider idempotency keys are `ctxos:v1:<sha256>` over tenant, run and operation,
  persisted and reused on retry; MCP adapters may select the lossless
  `result_projection = "mcp_result_v1"` (`flat` stays the default).
- Compare-and-swap document stores and an append-only log (in-memory and PostgreSQL).
- Ed25519-signed, hash-chained audit with DecisionRecords and replay packets; group
  commit for parallel appends.
- Governed Tool Gateway: surface, bind, authorize, redeem approvals, reserve budget,
  claim the operation, dispatch, observe, settle and audit, failing closed throughout.
- Reconciliation of unknown effects by provider query (MCP `tasks/get`) or evidenced
  operator assertion.
- DecisionRecords over HTTP with lineage verified against the run's ledgers, the
  evidence gate enforced, signing into the audit chain and replay packets; per-run
  evidence bundles and paged audit export.
- Run completion, failure and cancellation through the kernel lifecycle: completion
  requires resolved effects and settled children; cancellation fences the executor,
  cancels and settles children and acknowledges once dispatch has stopped.
- Executor ownership and failover: runs start through the kernel lifecycle, effectful
  requests present the executor generation, and takeover fences the previous executor.
- Delegated child runs: narrowed tool surface, sub-budgets reserved from the parent,
  gateway-attested run links for kernel authority checks, and close that locks the
  child's remaining capacity before settling into the parent.
- Continuation of MCP tools that answer `input_required`, bound to the same action.
- MCP `2026-07-28` (stateless) and HTTP adapters with pinned HTTPS endpoints, no
  redirects and brokered credentials; remote authority, constraint and approval
  providers.
- Accepted HTTP jobs can be reconciled by provider query when the manifest declares
  `recovery.completion` (status endpoint, state pointer, confirmed/partial/not-applied
  states); unlisted states, missing jobs and failed lookups stay unknown. HTTP tool
  names `.` and `..` are no longer dispatched.
- Task authorization: a run may be admitted with what its principal asked for
  (`task_authorization`, `AuthorityGrant` scopes bound to the root run). Every effect
  must fall inside it, checked on the actual binding; outside, the action is denied
  or (`out_of_scope = "ask"`) waits for an exact approval first. Decisions,
  approvals and attestations bind its pinned reference, delegations inherit it, and
  `[guards] require_task_authorization` refuses effectful runs without one. The
  kernel exposes `scope_mismatch` and `valid_authority_scope`; the Python and Node
  clients add builders.
- Task corrections mid-run: `PUT /v1/runs/{run_id}/task-authorization` replaces the
  run's own task authorization under a revision fence. The executor may narrow it;
  widening needs the new `authorize` scope (refused alongside `admit`/`dispatch`),
  the principal's `confirmation_ref` and the same issuer. Every later action digest
  changes, so earlier approvals and claims cannot be redeemed; amendments are audited
  (`task_authorization_amended`) and counted
  (`contextos_task_authorization_amendments_total`). Clients add
  `amend_task_authorization`/`amendTaskAuthorization`.
- Task limits: a task authorization may bound the task as a whole (`limits`:
  `max_effects`, `amount_total`), counted across the issuing run and its delegated
  runs. Each effect is charged with compare-and-swap after its operation is claimed
  and before dispatch, so parallel effects cannot together exceed a limit; a charge
  is returned only when the provider definitively did not apply the effect. An
  effect past a limit is outside the task (`task_scope_extent`). Raising or dropping
  a limit widens the authorization. Clients take `max_effects`/`amount_total`
  (`maxEffects`/`amountTotal`).

### Server and tools
- `contextosd`: compile, contract negotiation, schema validation, run admission,
  governed tool calls, input continuation, reconciliation, audit verification, health,
  readiness and Prometheus metrics; API keys and OIDC JWT callers bound to one tenant;
  strict JSON ingress; overload protection (global load shedding, per-tenant rate and
  concurrent-dispatch limits); OTLP trace export with W3C trace-context propagation.
- A run cannot recall two promoted memories holding different values for one key
  (`memory_conflict`).
- Production mode refuses delegations whose `output_schema_ref` is not a registered
  `[[result_schemas]]` entry.
- Recalled memory superseded by a newer promotion or correction of its key is refused
  (`memory_superseded`).
- Tenth security review fixes: memory keys scoped by owner and namespace, taken only by
  newer claims, tombstoned on deletion; rejected children's effects hold the parent;
  decisions must name their model when a fallback is pinned.
- Model fallback is traceable: a decision names which pinned `model_profile` produced it
  (a pinned fallback), and an unpinned model is refused.
- Decisions record the model router's `routing_decision_id` in their lineage.
- Production turns on `completion_requires_scores` by default (policy 1.0, safety 0.9);
  the gate covers every applied effect and accepted children. Ninth security review fixes.
- `[guards] completion_requires_scores`: a run completes only when every effectful decision
  holds independent scores at or above the policy and safety floors.
- Production mode requires pinned `model_profile`/`evaluator_suite` release refs and a
  stated `user.role` by default (`[guards] required_release_refs`, `require_user_role`).
- Python and Node clients: `open_escalations`/`openEscalations`,
  `resolve_escalation`/`resolveEscalation`.
- Eighth security review fixes: output schemas govern every outcome's output; erasure
  cannot miss concurrent feedback; rollout waivers audited and never on feedback cases;
  delegated result checks fail closed; `ctx trajectory-gate --audit`; escalations
  reopen and are opened once.
- `ctx trajectory-gate`: compare baseline and candidate runs of the same cases by the
  capabilities used, decision outcomes, effects and tool calls; acknowledgements per case.
- `[guards] require_tool_schemas`: refuse to start with an effectful capability that lacks
  an input or output schema; a production checklist in the guide.
- Delegations: an accepted child's recorded decision outputs must conform to the schema
  its envelope names (`[[result_schemas]]`, `child_output_invalid`).
- Escalation records: an escalated call opens one per operation (audited), listed at
  `GET /v1/escalations` and resolved once by an operator; resolving grants nothing.
- Tool calls whose principal chain does not end with the run's agent, or which misstate
  the capability's approval mode, are refused (`principal_chain_mismatch`,
  `approval_mode_mismatch`); an adversarial corpus of nine attacks runs in CI.
- Metrics by capability, refusal reason, pack and decision status (bounded labels); spans
  for compile, admission, delegation, decisions, scores, memory and erasure.
  `contextos_dispatch_outcomes_total` gains a `capability` label.
- `docs/INCIDENT.md`: roles, severity matrix, containment with the kill switch, evidence
  collection, specific incidents (key compromise, failed verification, injection, data
  exposure, outages), recovery gated on feedback, and a postmortem template.
- Dispatch returns the policy's obligations with every verdict; an `escalate` verdict is a
  structured hand-off (`policy_escalation`, obligation `escalate`), not a bare block.
- Recalled memory is verified at admission against promoted, current memory state the
  run's user or agent may read
  (`memory_unverified`); production without memory governance refuses it unless
  `[guards] trust_supplied_memory`.
- Capability manifests take an `output_schema`: non-conforming tool output is withheld
  from the agent and audited, while the effect is still recorded.
- Tool results carry `risk_tags` (the action's effect and reversibility, `human_approved`
  when an approval was redeemed), `policy_decision_id`, and `metadata.instruction_treatment:
  data_only`; an injection regression test covers forged approvals in output.
- Decision lineage records the pinned model profile and evaluator suite (`release_refs`);
  `[guards] required_release_refs` makes them mandatory at admission.
- Rollouts: a candidate takes live traffic only after the server's release gate passes on
  named runs' replay cases and every open feedback case (`gate_runs`, `acknowledge`).
- Erasing a run redacts the free text of its operator feedback.
- `ctx gate --feedback`: the release gate fails while an open correction's replay case is
  missing from the corpus.
- Python and Node clients: `file_feedback`/`fileFeedback`, `open_feedback`/`openFeedback`,
  `close_feedback`/`closeFeedback`.
- Operator feedback for the improvement loop (`/v1/runs/{id}/feedback`, `/v1/feedback`):
  corrections bound to runs and decisions, replay obligations, closed only with evidence.
- KMS-held audit signing keys (`[audit.kms]`, Vault Transit protocol): one batched
  signing call per group commit, every signature verified before writing.
- Audit key rotation: `[audit] retired_keys` keeps entries signed with a previous key
  verifiable and published. `ctx audit-verify --continues` verifies only new entries
  from a trusted head.
- Independent audit verification: `GET /v1/audit/keys` publishes the signing keys and
  `ctx audit-verify` checks an exported chain offline.
- Orchestrator checkpoints (`/v1/runs/{id}/checkpoint`): fenced, optimistic on
  revision, audited by digest, read after takeover, erased with the run.
- Loop guard (`[guards] identical_tool_calls`, default 5): repeated identical tool
  calls in a run are refused with `loop_detected` and `change_approach`.
- Budgeted model calls and replans (`/v1/runs/{id}/usage/reserve|settle`): the same
  ledger as tool calls; metered usage (new `meter` scope) settles to what was
  measured, self-reported usage is charged in full.
- Staged rollout of pack versions (`/v1/rollouts`, `control` scope): sticky
  percentage routing from baseline to candidate, shadow governance diffs audited on
  live traffic, clear to roll back.
- Conformance assessment over HTTP (`POST /v1/conformance/assess`): the deployment
  supplies identity, support, registry, clock and configured trust anchors; audited.
- Time-based retention (`[retention] run_content_days`, off by default): the leader
  replica erases finished runs' personal content after the configured period.
- Erasure of a finished run's personal content (`POST /v1/runs/{id}/erase`, `control`
  scope): audited tombstones replace the replay case and compiled context.
- Cluster-wide tenant limits: replicas heartbeat into the store and each enforces its
  share of every tenant's rate, burst and dispatch cap (`contextos_replicas` gauge).
- `ctx scorecards` collects evaluator scorecards from evidence bundles into
  `ctx scorecard-gate` input. Python and TypeScript clients gain `revoke`, `restore`
  and `revocations` for operators.
- Kill switch: operators (`control` scope) revoke a tenant, pack, agent, adapter or
  capability; dispatch and admission refuse it from the next call; audited, restorable.
- Scorecard release gate (`ctx scorecard-gate`): per-scorecard policy/safety floors,
  no per-case policy/safety regression, bounded utility/latency/cost deltas; missing
  cases and measurements fail, as do underpowered comparisons.
- Measured wall clock: admissions record `admitted_at`; decisions report
  `budget_usage.wall_clock_ms` and scores report latency from it.
- Independent run scoring: evaluators with the `evaluate` scope (and neither `admit`
  nor `dispatch`) score recorded decisions; cost is measured by the runtime; scores
  are signed and kept in the evidence bundle. Unknown API-key scopes are refused.
- OpenAPI 3.1 description of the HTTP API (`openapi/contextosd.v1.json`, served at
  `GET /v1/openapi.json`), kept in step with the router by a test.
- Release gate for Context Pack changes (`ctx gate`; acknowledgements name the exact
  capabilities, gates and cases they accept): replayed cases compiled under
  baseline and candidate; unacknowledged widenings and compile regressions fail. Runs
  export their admission inputs as replay cases.
- Governed memory lifecycle: propose, promote, correct and delete decided by the
  kernel against trusted memory policy, audited, with current state per memory.
- Active execution boundary: an optional boundary controller's facts are evaluated by
  the kernel at run start, resume and every dispatch.
- Data permissions in dispatch: an optional data-governance provider supplies flow
  facts and the kernel's data-flow policy decides, bound to the exact action.
- MCP gateway mode: every run is an MCP server whose tools are its governed
  capabilities; reviewed input schemas on manifests, enforced on every call.
- TypeScript/Node HTTP client (`@contextos/kernel/client`, no dependencies, typed).
- Python HTTP client (`contextos.client`, standard library only) with typed outcomes,
  fencing handled, and a `governed_tool` decorator for agent frameworks.
- `ctx` command line; Python, Node and WebAssembly bindings over one JSON facade.

### Metered model usage
- A model request carries its run and reservation in `ContextOS-Run-Id` and
  `ContextOS-Usage-Reservation`; `metering_headers` / `meteringHeaders` produce them and
  `budgeted_model_call(..., metered=True)` leaves settlement to the metering gateway
  (settling in full only if the call fails before the gateway did).
- `examples/metering-proxy`: a reference metering gateway for OpenAI Chat Completions
  and Responses and Anthropic Messages, streamed or not, that settles each reservation
  with the reported tokens (and cost, given prices) under the `meter` scope and fails
  closed on missing or reused reservations and missing usage.

### Repeated effects
- A new operation whose effect is identical to one the run already applied, or may
  have applied, is refused with `effect_repeated` (obligation
  `reconcile_existing_operation`), whatever its idempotency key or route, so a host
  retrying under a fresh key or mixing keyed calls with derived-key MCP calls cannot
  apply an effect twice. Capabilities marked `repeatable` and `[guards]
  refuse_repeated_effects = false` opt out. The effect is claimed atomically before
  dispatch, so identical effects racing in parallel are sent once. **Behavior change:**
  identical effects under different keys in one run were previously each applied.

### Framework integrations
- Implementation guides (`docs/integrations/`) and runnable examples
  (`examples/frameworks/`) for LangGraph, the OpenAI Agents SDK (Python and
  TypeScript), Google ADK, the Claude Agent SDK, CrewAI, Pydantic AI, LlamaIndex,
  Microsoft Agent Framework, the Vercel AI SDK and Mastra. Each runs the framework's
  own agent loop with governed tools, a budget reservation around every model call and
  refusals the model can read; without a provider key it uses a scripted model.
- `ToolPaused.kind` in both clients says what a pause waits on (`approval`, `input`,
  `unknown_outcome`, `duplicate`), and `governed_tool` / `governedTool` take a
  `tool_call_id` derivation so a decision can cite the call.
- The development approval service records approval requests and grants an exact
  approval when a reviewer approves one; `examples/frameworks/run.sh <framework>
  --approval` pauses each framework example for approval, approves it through the
  framework's human-in-the-loop mechanism and redeems it with the identical call. CI
  runs every framework example in both modes.
- `contextos.aio`: the Python client for asyncio agents (`AsyncClient`, `AsyncRun`,
  async governed tools), still standard-library only. Both clients raise
  `BudgetExhausted` for a reservation the run cannot afford and have
  `budgeted_model_call` / `budgetedModelCall` to reserve and settle around one model
  call.
- MCP `tools/list` names tools as model APIs require (`[A-Za-z0-9_-]{1,64}`):
  `adp_payments.issue_refund` is listed as `adp_payments_issue_refund`, with the
  capability id in `title` and `_meta["io.contextos/capabilityId"]`; `tools/call` takes
  either name. **Behavior change:** hosts that matched listed names against capability
  ids see the new names.
- MCP `tools/call` accepts the host's call id in `_meta["io.contextos/toolCallId"]`,
  returns the call and operation ids in `_meta` on every result, and tells the model in
  the error text whether the refused call had any effect.

### Operations
- Distroless non-root image, hardened Helm chart, signed releases with provenance and
  SBOMs, cargo-deny policy, property fuzzing, threat model, benchmarks.

- Budget-ledger compaction (ADR-0003): settled reservations move to chained archives
  with unchanged counters, so runs are no longer limited to about 64 effects and
  per-effect cost stays flat.

### Known limits
- At most 64 reservations can be open at once in one run.
