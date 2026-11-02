# Business correctness: from configured limits to verified outcomes

Status: plan, decisions taken, 2026-11-01. Baseline: main `4ad3d46` (v0.1.0-alpha.11).

This plan responds to an external scope assessment. That assessment proposed growing
ContextOS from "shared business limits for AI agents" into "coordinating consequential
agent actions against shared business state, verifying their outcomes and managing
unresolved obligations." It ranked eight additions. This plan checks each one against
the code, keeps the parts that close gaps the project already documents, narrows the
parts that would repeat past mistakes, and defers the rest until a pilot needs them.

Each workstream names its user, what changes, the files it touches, how it is tested
and what it does not do.

## 1. What the code says about the assessed additions

| # | Assessment | After reading the code |
|---|---|---|
| 1 Trusted resource state | Ceilings ignore prior exposure; integrations must resolve aliases | **Confirmed.** `SharedGuarantee` (`gateway/src/shared_guarantees.rs:55`) is `{id, capability_ids, resource_pointer, amount_pointer, limit, unit}`. Every ledger starts empty from `empty_exposure` (`kernel/src/shared_exposure.rs:147`). The resource is the raw string at `resource_pointer`, hashed as is (`shared_guarantees.rs:254`), so `ord_881` and `ORD-881` are two ledgers. `SHARED_GUARANTEES.md` tells operators to "start with resources whose prior exposure is accounted for". Shared exposure is a runtime extension with no conformance vectors, so a new kernel transition here needs no spec change. |
| 2 Coverage and recovery | Expand Tower with exposure, coverage, uncertainty, recovery and drift views | **Recovery is mostly built; coverage cannot be built from the gateway.** Holds are inspectable (`contextosd/src/exposure.rs`, with owner and `next_safe_step` per hold), swept into gauges (`governance_sweep.rs`), alerted on (`ContextOSHeldEffectsAging`, `ContextOSReceiptsNearCap`, `ContextOSConflictingFacts`), backed by runbooks in `INCIDENT.md`, and listed for on-call by `examples/ops/unresolved.py`. Escalation webhooks exist (#98). What is missing is routing a hold to its *business* owner, not only to on-call. Coverage needs a list of every call path to compare against, which the gateway cannot see. A broad Tower console was already tried and rejected on 2026-10-21. |
| 3 Verified evidence | Callers can satisfy gates with labels | **Confirmed, in two places.** (a) A required-evidence item is satisfied by any non-null, non-`false` value under its name in `request.input.context` (`kernel/src/compiler.rs:597`). (b) An evidence entry's `integrity` and `freshness` are the caller's labels (`compiler.rs:1044`). `observed_at` and `valid_until` are copied into the manifest and never compared with a clock. Nothing binds an entry to an issuer or a resource. The compiler is pure and locked to TS parity (`compiled_context_hash`), so the fix belongs in contextosd before compilation, as `pack_intents` was (spec-0006). |
| 4 Outcome contracts | Tool success is not business success | **Confirmed gap, with a natural hook.** `complete_run` already refuses while effects are unresolved (`gateway/src/lifecycle.rs:13`, `outstanding_effects`). A confirmed provider effect closes the operation. Nothing asks whether the business state the task needed now holds. |
| 5 Multiple invariants | One guarantee per capability | Confirmed (`config.rs:380` rejects a capability in two guarantees). Lifting it means reserving on several ledgers atomically with no multi-document transaction in the store port. **Deferred**, see section 5. |
| 6 Obligations | Responsibilities outlive runs | Partly covered: unknown effects already outlive runs, and feedback becomes replay obligations (slice 50+). A general obligation record overlaps with workflow engines. **Deferred.** |
| 7 Failure simulation | Fault injection for policy changes | Partly covered by `release_gate` and replay cases (slice 36). **Deferred.** |
| 8 Adoption | Packages are not published | **Confirmed, and it matters most right now.** Every release note says "does not publish packages to PyPI, npm or crates.io". `bindings/node/package.json` is `"private": true`. `bindings/python/pyproject.toml` builds a maturin wheel named `contextos`. A newcomer who cannot install a client never reaches the gaps above. |

Constraint across all of this: `contextosd/src/app.rs` and `contextos-gateway/src/lib.rs`
are already past the 600-line limit in `AGENTS.md`. New work goes into new modules and
adds route wiring only.

## 2. Who this is for

- **Agent developer.** "Can I put one of my existing tools under ContextOS this
  afternoon, see it refuse something, and see why?" Installs from a package
  registry, does not build Rust.
- **Platform or security engineer.** "Can an agent satisfy a gate by saying it checked
  something? Does a ceiling reflect money already spent before we installed this?"
- **Business owner of a limit** (refund lead, finance). "This order's refund
  capacity is stuck. Is it mine to resolve, and what do I need to provide?" Does not
  watch Grafana.
- **Compliance reviewer.** "When the agent says the task is done, what proves it?"

Scale assumption for design: thousands of resources under a guarantee per tenant,
tens of tenants per deployment, 3 to 30 replicas, imports of up to a few hundred
thousand prior-exposure rows per guarantee at onboarding.

## 3. Workstreams, in order

### A. Installable clients (now, agent developer)

**A1. Publish the clients.** Publish the Python client and native kernel wheel to
PyPI and the Node client to npm from the release workflow, using trusted publishing
(PyPI OIDC, npm provenance), no long-lived tokens. Wheels for the three platforms the
release already builds. The package version is the release tag. `/v1/deployment` gains
`runtime_version` and `contract_version` (no version route exists today); the client
refuses a server whose contract version differs, with a message naming both.

**A2. One-tool walkthrough.** `ctx init-tool` reads one MCP server's saved
`tools/list` and writes a draft capability manifest with every authority decision
left `REVIEW:`, so `ctx manifest` and contextosd refuse it until a person fills it in.
OpenAPI is not supported: the HTTP adapter only sends `POST {endpoint}/{protocol_tool}`
with a JSON body, so a manifest drafted from an arbitrary OpenAPI operation would not
be callable through it. The
README's "Govern your own agent" path becomes: install, `ctx init-tool`, review,
run `examples/dev-server.sh`, trigger a refusal, read the refusal's
`next_safe_step`, export the evidence.

**Tests.** Release workflow installs the published wheel and npm package in a clean
job and runs `examples/agent-loop` against a released `contextosd` binary.
`ctx init-tool` tests: the draft pins the tool, marks every decision and fails to
load; the same draft with decisions filled in validates.

**Not doing.** crates.io (the Rust crates are not a supported embedding API yet).
Generating manifests that activate without review.

### B. Strict evidence admission (next, platform engineer)

`[guards] evidence = "strict"`, required under `contextos.enterprise`, enforced in
contextosd before the request reaches the compiler, in a new
`contextosd/src/evidence_admission.rs`.

**B1. No gate satisfied from request context.** In strict mode, admission refuses a
run whose `request.input.context` has a key that names a `required_evidence` item of
any DecisionSpec in the pack (`evidence_in_request_context`). Gated facts must
arrive as evidence entries. The compiler's existing path stays as is for parity.

**B2. Issuers.** A new `[[evidence_issuers]]` table names each trusted issuer: its id,
the verification key (JWKS URL or PEM, reusing the OIDC verifier and
`CONTEXTOS_CA_BUNDLE`), the requirement names it may satisfy and the maximum validity
it may claim. An evidence entry under strict mode carries a compact JWS from its
issuer whose payload is `{iss, sub, satisfies, content_hash, observed_at,
valid_until, source_version}`. `sub` is the canonical resource (see C1) the fact is
about.

**B3. Relabelling.** contextosd verifies each entry against the configured issuers
and the server clock, then rewrites the labels the compiler reads:

| Check | Result |
|---|---|
| Signature valid, issuer allowed for every `satisfies` name, `content_hash` matches | `integrity = "verified"`, else `"untrusted"` |
| `observed_at <= now < valid_until`, and `valid_until - observed_at <= issuer max` | `freshness = "current"`; past `valid_until` → `"stale"`; missing → `"unknown"` |
| `sub` differs from the resource the action names | `integrity = "untrusted"`, warning `evidence_subject_mismatch` |

The caller's own labels are ignored in strict mode. Because the compiler only sees
labels, it stays pure and parity holds. The evaluation time and each verification
result are recorded in the replay case, so replay reproduces the decision without
the clock.

**Status.** B1 is PR #124. B2 and B3 follow with these differences: issuer keys are an
inline JWK Set per issuer (no JWKS URL fetching yet), issuers are scoped to tenants,
and the `sub` comparison waits for C1, so `evidence_subject_mismatch` is not yet
raised; `sub` is recorded in each entry's `verification`.

**Tests.** Expired, future-dated, wrong-issuer, wrong-subject, tampered-content and
over-long-validity entries each fail the gate while labelled `"current"` and
`"verified"` by the caller. Replay of a strict run gives the same decision a day later.

**Not doing.** Revocation lists for evidence (an issuer shortens validity instead).
Detecting a lying issuer (it stays in `SCOPE.md`). A spec change: strict mode is a
deployment control; a spec proposal (spec-0008) records it for upstream.

### C. Resource identity and prior exposure (next, platform engineer)

**C1. Canonical identity.** A guarantee may name a `resource_canonicalizer`:
`"exact"` (today), `"ascii_casefold"`, or `"provider"`. With `"provider"`, a new
`ResourceIdentityProvider` port, called at reservation time, maps the extracted
identifier to a canonical id and returns a signed observation of that mapping. The
ledger is keyed by the canonical id; the receipt records both. A provider that is
unavailable withholds the call (`shared_guarantee_identity_unavailable`). Changing the
canonicalizer changes the definition digest, so the existing definition pin refuses
mixed replicas.

**Status.** C1 is implemented with `exact`, `ascii_casefold` and `provider`. The
provider's answer is `{canonical_id, evidence_ref}` over the same trusted transport as
the other fact services, not a separately signed observation; the reservation audit
entry records the canonicalizer, the extracted identifier's digest and the evidence
ref. Comparing an evidence attestation's `sub` with the action's canonical resource
(B3's `evidence_subject_mismatch`) still needs the evidence a decision relied on to be
tied to the call, and is not done yet.

**C2. Prior exposure import.** A new kernel transition
`import_exposure(state, binding, import)` in `shared_exposure.rs` adds a committed,
non-releasable receipt with `{import_id, amount, source, as_of, evidence_ref}`. It is
idempotent per `import_id` and may only add committed exposure. It is accepted even
when it makes `committed + held > limit` (decision 3): the resource is then over its
limit and refuses new effects, so the operator sees it was already over before
onboarding. Imported receipts are archived like settled ones, folding into
`archived_committed`.

Route: `POST /v1/guarantees/{id}/imports` under a new `exposure:import` scope,
accepting up to 1,000 rows per call, each row keyed by canonical resource. `ctx
guarantees import --file prior.csv` pages through a file and resumes from the last
accepted `import_id`. Every row is a signed audit entry.

**Status.** C2 is implemented with two differences. Imports live in the ledger apart
from receipts (at most 1,024 per resource) rather than as archived receipts: archiving
would forget the `import_id` and let a re-sent row count twice. The CSV loader is
`examples/ops/import_exposure.py` (ctx is offline); idempotency makes re-running it the
resume. The over-limit alert fires on `contextos_shared_guarantee_over_limit_imports_total`.

**C3. Adjustments after onboarding.** The same transition handles exposure created
outside ContextOS later (a refund issued from the legacy back office). It can only
consume capacity. Nothing in ContextOS ever replenishes a resource from an outside
reading; replenishment stays a definition change (a new limit), which is pinned and
audited. This is the consistency rule: ContextOS does not try to stay in sync with a
source-of-record balance, because reading a balance and then reserving against it is
the distributed transaction that `WHY_NOT_A_TRANSACTION.md` declines. Outside
spending reaches ContextOS as a one-way import, and a late import can push a resource
past its limit. That shows as `over_limit` in inspection, a new
`ContextOSResourceOverLimit` alert, and refusals of new effects; it is never hidden.

**Tests.** Kernel properties: imports never reduce `committed`, never touch held
receipts, are idempotent, and survive compaction. Gateway: two aliases of one order
share one ledger under `"provider"`; import survives restart on PostgreSQL; a late
import over the limit refuses the next reservation and raises the alert.

**Not doing.** Reading balances from a source-of-record system at reservation time. A
master-data service. Currency conversion.

### D. Hold ownership for the business (after C, business owner)

On-call already has alerts, gauges, runbooks and `unresolved.py`. The missing
piece is that a hold on a refund is often the refund lead's to resolve, not the SRE's.

**D1.** A guarantee may name `owner_route`, an escalation webhook target already
supported by `notifications.rs`. When the governance sweep sees a hold older than the
guarantee's `owner_after` (default 30 minutes), it emits one notification per hold
with the resource, amount, diagnosed state, `next_safe_step`, and the evidence the
reconcile route needs. Delivery reuses the audit-chain cursor, so it is exactly what
was audited.

**Status.** D1 is implemented as `owner_route` plus `owner_after_seconds` on the
guarantee, kept out of the pinned definition. The sweep appends `shared_hold_aged` and
the dispatcher delivers it to that webhook only. Building it fixed the census, which
reported a ledger's store key as its `resource_digest`.

**D2. Deployment recipe.** `docs/integrations/egress.md` and Helm values that make
contextosd the only workload holding provider credentials and allowed to reach
provider hosts (extending `networkpolicy.yaml` with an egress allow-list). This is
how coverage is established: by construction, not by a dashboard.

**Status.** D2 is implemented as the chart's `agentEgress` values: a NetworkPolicy in
the agents' namespace allowing DNS, contextosd and `allowTo` (the model gateway), and a
matching ingress peer on contextosd's policy. An empty selector is refused at render.
The recipe is `docs/integrations/egress.md`. The kind e2e shows an agent pod reaching
contextosd but not a stand-in provider, which an unselected pod still reaches.

**Tests.** Sweep emits one notification per aged hold, none after it settles; Helm
template test for the egress policy; kind e2e confirms an agent pod cannot reach a
provider directly.

**Not doing.** New Tower pages. A coverage percentage.

### E. One outcome contract (after B and C, compliance reviewer)

**E1.** A capability manifest may declare `outcome`:

```toml
[capabilities.outcome]
witness = "refund-ledger"        # an [[evidence_issuers]] id
postcondition = "refund_posted"  # a requirement name the witness may satisfy
within = "PT15M"
on_missed = "escalate"           # escalate | hold
```

After a confirmed effect, the operation is recorded as `effect_confirmed,
outcome_pending` and added to the run's `outstanding_effects`, so `complete_run`
already refuses. The witness (or a service relaying its signed observation) posts it
to `POST /v1/runs/{run_id}/operations/{operation_id}/outcome`; contextosd verifies it
with workstream B's issuer check, binds it to the action's canonical resource, and
closes the outcome. Past `within`, the governance sweep escalates (`escalate`) or
also keeps the shared-guarantee hold open (`hold`).

**Status.** E1 is implemented, with two departures. Outcome state lives in the gateway
(an `Outcome` record per operation and action, indexed per run and tenant), not in
`outstanding_effects`, which the kernel validates and reconciliation owns; `complete`
refuses with `outcome_pending`. The deadline is `within_seconds` rather than an ISO
duration, like `owner_after_seconds`. `on_missed = "hold"`, E2 and the refund pilot
follow.

**E2.** The DecisionRecord for a decision whose operations have outcome contracts
cites the witness observation. The evidence bundle includes it.

**Pilot.** The refund example: the provider confirms the refund call, and a separate
ledger read must show the refund posted for the right order and amount.

**Tests.** A confirmed effect without a witness observation leaves the run
incomplete. A witness for another resource, an expired witness and an unlisted issuer
are each refused. A missed deadline escalates once.

**Not doing.** A predicate language over business state. Model-judged postconditions.
More than one postcondition per capability until the pilot needs it.

## 4. Sequence

| Order | Workstream | Ships in | Go/no-go evidence |
|---|---|---|---|
| 1 | A Installable clients | alpha.12 | A clean machine installs both clients and runs the agent-loop example against a released binary |
| 2 | B Strict evidence | alpha.13 | Enterprise profile rejects caller-labelled, stale and wrong-subject evidence |
| 3 | C Identity and prior exposure | alpha.13 | Refund demo starts from imported prior refunds; two order-id spellings share one ledger |
| 4 | D Hold ownership | alpha.14 | A refund lead receives an aged hold with what to provide, and resolves it through reconcile |
| 5 | E One outcome contract | alpha.14 | The refund pilot cannot complete until the ledger witness confirms the refund |

B and C can run in parallel; both touch `contextosd/src/config.rs` and should land
the config schema first in one small PR.

## 5. Not doing

- **Several guarantees per capability.** Needs atomic reservation across ledgers,
  which the store port does not offer, or a reservation protocol with its own
  recovery. Revisit when a pilot shows a constraint one ceiling plus C1 cannot
  express.
- **General obligation records.** Outcome contracts (E) cover the case that matters
  first. Timers and long-running workflows belong to the caller's scheduler.
- **Fault-injection simulator.** Extend `release_gate` when a policy change in a pilot
  needs it.
- **Memory store, vector search, agent builder, orchestration, model routing,
  connector marketplace, cross-organization federation.** Unchanged from
  `SCOPE.md`.
- **Tower exposure and coverage views.** See D.

## 6. Decisions

Decided 2026-11-01 by the maintainer, as proposed.

1. **Package names.** PyPI `contextos`; npm `contextos-client` (unscoped: the `@contextosai`
   and `@contextos` scopes and the name `contextos` belong to unrelated publishers).
   Both must be claimed by the project before the first publish.
2. **Strict evidence under the enterprise profile.** Required. This is a breaking
   change, listed in CHANGELOG Unreleased, as agent binding and pack intents were.
3. **Over-limit after import.** The import is accepted and recorded; the resource
   refuses new effects and raises `ContextOSResourceOverLimit`. Refusing the import
   would hide real past spending.
4. **Outcome deadline default.** `escalate`. `hold` only when the guarantee owner opts
   in, since it ties up capacity.
