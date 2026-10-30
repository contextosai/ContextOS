# Threat model

Scope: `contextosd`, the Tool Gateway, adapters, stores, the audit chain and the
in-process bindings. Assets: the authority to cause external effects, tenant data,
budgets, and the integrity of the evidence record.

## Trust boundaries

| Boundary | Trusted side | Untrusted side |
|---|---|---|
| Model output → gateway | manifests, admission, kernel | capability choice and arguments proposed by the model |
| Caller → `contextosd` | authenticated tenant-bound principal | request bodies |
| Gateway → fact providers | provider responses *after* kernel verification | transport, availability |
| Gateway → adapters/providers | pinned endpoint, brokered credential | provider responses, timing |
| Runtime → store | compare-and-swap semantics | concurrent writers, stale executors |
| Auditors → audit log | signing keys, key ring | stored rows |

## Threats and controls

| # | Threat | Control (where) | Test |
|---|---|---|---|
| T1 | Prompt-injected instructions in retrieved data or tool output drive an effect | Retrieved and recalled blocks are `data_only`/`untrusted`; tool results are labelled `instruction_treatment: data_only` and carry their risk tags and authorization id; only pinned, surfaced capabilities dispatch; evidence must be admitted; approval is digest-bound, so text claiming one grants nothing (`compiler`, `gateway`) | compiler vectors; `unsurfaced_and_unadmitted_inputs_are_rejected`; `tool_output_is_labelled_data_and_cannot_grant_authority` |
| T2 | Arguments changed after approval | RFC 8785 action digest binds arguments, amount, resources, evidence, policy; approvals bind the digest (`authorization`) | `exact_approval_is_redeemed_once_then_dispatches` |
| T3 | Approval replay for another operation | single-use redemption CAS bound to operation + digest (`transition_approval_redemption`, store CAS) | authorization vectors |
| T4 | Stale/revoked authority | grant observations must be verified, current and unrevoked; unknown revocation blocks (`validate_authority`) | authorization vectors (revoked, unknown, stale) |
| T5 | Delegation widening | child grants must strictly narrow scope, depth and validity (`validate_authority`) | delegation vectors |
| T6 | Duplicate effects (retries, races, lost responses, re-keyed retries) | operation ledger: one in-flight attempt, unknown outcomes block blind retries, idempotent retry only with verified provider proof; CAS commits; an effect identical to one the run applied is refused under any new key (`effect_repeated`); a per-attempt dispatch gate, opened immediately before the provider call, decides once between "sent" and an operator's "never sent", so recovering a crashed dispatch cannot race a live one | `concurrent_duplicates_dispatch_once`, `timeout_is_unknown_and_blocks_blind_retry`, `an_effect_is_not_applied_twice_under_a_new_key`, `identical_effects_racing_under_different_keys_dispatch_once`, `every_crash_point_of_a_dispatch_is_safe_to_retry`, `reconciliation_and_a_live_dispatch_race_on_the_dispatch_gate`, `every_crash_point_of_a_reconciliation_is_safe_to_retry`, `a_reclaimed_attempt_never_sends`, store contention suite |
| T7 | Budget overspend under concurrency | conserved budget ledger with reservations; unknown usage keeps reservations | `concurrent_budget_is_conserved` |
| T8 | Stale executor acting after failover | kernel run lifecycle with a generation per event; every effectful request must present the current generation, re-checked after the operation claim commits and before dispatch (a claim that loses that check is recorded as not dispatched and its budget released); takeover by fenced suspend/resume; in-flight work stays visible in the operation ledger for reconciliation; generation forwarded for target-side fencing | durable vectors |
| T9 | Cross-tenant access | every key includes tenant; callers bound to one tenant; lookups scoped by caller tenant | server tests (other tenant → 403/404) |
| T10 | Parser differentials (duplicate keys, deep nesting) | strict ingress rejects duplicates, depth > 64, oversized bodies (`ingress`) | ingress tests, server hostile-body test, fuzz |
| T11 | Policy evaluation errors treated as "false" | structured `policy_eval_error`; JsonLogic prototype access and identity comparisons fail visibly; bounded steps | compiler error vectors, ADR-0002 |
| T12 | Audit tampering, forks, key compromise | ed25519 hash chain; append-only table with no-update trigger; fork-proof sequence PK; key rotation via key ring | `tampering_is_detected` |
| T13 | SSRF / effect redirection | pinned HTTPS endpoints, no redirects, response size limits, tool names are path segments only | adapter tests |
| T14 | Credential exposure to the model | credentials come from a broker per call, never from model-visible state; `Debug` redacts; OAuth client-credentials tokens are requested for the provider as their RFC 8707 resource, cached in memory only, and never logged; caller tokens are never forwarded | adapter tests, `oauth.rs` tests |
| T15 | Denial of service | global in-flight cap with load shedding, per-tenant request-rate and concurrent-dispatch limits after authentication, body limits, request timeouts, JsonLogic step/depth limits, canonicalization limits, bounded retries with backoff | ingress/jsonlogic tests |
| T16 | Supply chain | rustls only, cargo-deny (advisories, licenses, sources), lockfile, distroless non-root image | CI |
| T19 | Unknown effects resolved by guesswork, or resolution used to rewrite history | reconciliation records only definitive facts through the kernel, which refuses misbound or conflicting facts; provider queries never re-invoke the tool; operator assertions need the `reconcile` scope and cited evidence and are audited with the principal, and one that returns a hold (`not_applied`, `partial`) must come from a principal other than the run's admitter (`reconcile_not_independent`); held budgets settle without extra charge | `task_effects_are_reconciled_by_querying_the_provider`, `lost_responses_need_an_operator_with_evidence`, `long_running_mcp_tasks_are_reconciled`, `only_an_independent_principal_asserts_that_an_effect_did_not_apply` |
| T20 | Tool input requests used to rewrite an approved action, harvest secrets, or replay answers | continuation must bind to the same action digest and is re-authorized end to end; answers validated against the pending request's keys and schema; requests are single-use (superseded by the new attempt); password-like fields and non-form requests (e.g. sampling) refused; answers audited by digest with the responder | `input.rs` tests, `tools_that_need_input_continue_the_same_operation` |
| T21 | Delegation used to widen authority, escape the budget or keep spending after reporting | only the parent's current executor may delegate; a replayed delegation never compensates a reservation it did not create; closing a child ends its run; envelope bound to parent (tenant, trace, issuer, subject, claim hash); capabilities, ceiling, expiry and sub-budget must not exceed the parent; sub-budget reserved from the parent first; child surface narrowed, `read_only` gets no effects; kernel requires a narrowing grant chain and verified run links to the root; closing locks remaining capacity atomically before settling | `delegated_children_*`, `closed_children_cannot_spend`, `delegations_cannot_widen_the_parent` |
| T22 | MCP hosts treating discovery as permission, retrying effects, or sending arguments outside the reviewed shape | MCP mode lists only surfaced capabilities and re-governs every call; effectful calls without an explicit key derive operation identity from capability and arguments, so host retries hit the operation ledger; reviewed input schemas enforced before authorization with path-only errors; executor generation required | `agent_hosts_use_governed_tools_over_mcp` |
| T23 | Data sent to an unapproved destination, purpose, processor, residency or classification | optional data-governance port: request bound to the exact action and adapter destination, kernel `evaluate_data_flow` against the pinned policy, decision audited, unknown facts block | `data_sent_to_a_destination_must_pass_the_flow_policy` |
| T24 | Effects running outside an active isolation boundary | optional boundary-controller port: kernel `evaluate_boundary_readiness` at run start, resume and every dispatch, bound to the run; refusals audited; without the port, boundary controls are attested per action | `an_inactive_boundary_blocks_start_and_dispatch` |
| T25 | Agent memory widened, retained too long, promoted without review, or deleted without propagation | memory operations governed by kernel `validate_memory_lifecycle` against context from the deployment's memory-governance service (never the caller); records bound to the run; review digest covers the exact record; every decision audited; refused without the service | `memory_operations_are_governed_by_trusted_context`, `memory_operations_need_a_memory_policy_service` |
| T26 | Governance plane used to steal credentials, act with more authority than intended, show forged history, or let AI drive changes | towerd reads runtimes with read-only `audit:read` keys and acts only through their own scoped endpoints (kill switch: optional `control` key), so every action is also in the runtime's chain; every runtime entry is verified (digest, link, Ed25519) before use and a broken chain stops that source; roles enforced server-side with separation of duties (owners cannot review their agents; guardrails and waivers decided by someone other than their author); AI is advisory only: read-only tools scoped to the asker, tool output wrapped as data, citations checked, drafts validated deterministically, every use journalled; Tower's own decisions in a signed journal; the UI under a strict CSP with tokens in tab session storage only (`towerd`) | `towerd` e2e tests, `jobs.rs` tests (injection text in tool output, refusals, hallucinated fields), `console.rs` tests |
| T27 | Configuration changed to weaken governance (guards off, new credentials, wider scopes) without anyone noticing | the server never modifies its own configuration; `config` scope cannot hold `admit`/`dispatch`; `POST /v1/config/validate` runs the startup checks and classifies every effective change so CI can require approval of loosenings; published development keys refused in production (`configs`) | `configs` unit tests, `config_review.rs` |
| T28 | An agent acting beyond what its principal asked (a larger amount, another order or recipient, an unrequested capability) while staying within broker authority, including by stating one amount and sending another | optional per-run `task_authorization` (`AuthorityGrant` scopes fixed at admission, root-run bound, inherited by delegations) checked on the actual action binding with the kernel's grant-scope rules; outside it a guardrail outcome denies or requires an exact approval before the effect; the pinned reference is bound into the action binding, approvals and constraint attestations and recorded in `run_admitted`; `[guards] require_task_authorization` refuses effectful runs without one; mid-run corrections (`PUT …/task-authorization`) are fenced by revision, may narrow from the executor but widen only from an `authorize` principal that does not run tasks, with the principal's confirmation and the same issuer, change every later action digest (so earlier approvals and claims cannot be redeemed) and are audited; optional `limits` (`max_effects`, `amount_total`) bound the task as a whole across the issuing run and its delegations, charged by compare-and-swap before dispatch and returned only on a definitive not-applied outcome (`task_scope_extent`) | `effects_outside_what_the_principal_authorized_are_refused`, `effects_outside_the_task_can_wait_for_the_principal`, `task_authorizations_are_reviewed_at_admission`, `principals_correct_the_task_mid_run`, `the_task_as_a_whole_stays_within_its_limits`, `an_executor_cannot_allow_itself_amounts`, `task_authorization.rs` tests, properties TASK-1 and TASK-2 |
| T29 | Another principal in the tenant drives, ends, takes over or delegates from a run it learned the id of | the routes that drive a run (tool calls, status, takeover, complete/fail/cancel, decisions, usage reservation, checkpoints, memory, peer work, findings, compensation, delegation from a parent) require the caller to be the run's nonempty `admitted_by`; another principal's run is `404 run_not_found`. Routes for separate roles (reconcile, attest, evaluate, meter, authorize, audit) keep their own scopes and separation-of-duties checks | `another_principal_in_the_tenant_cannot_drive_or_see_a_run` |
| T30 | A credential admits runs as an agent it was not issued for, so revocations, attributions and policy keyed by agent apply to a name, not a workload | agent binding (`[guards] agent_binding`): the declared agent must be one the credential names (an OIDC `agent_claim`, optionally mapped through `agents`, or an API key's `agent_ids`); `required` refuses (`agent_not_bound`), and is the default and a startup requirement with the enterprise profile; `observe` counts and records mismatches; every `run_admitted` records the verdict; delegated runs inherit it (`agent_binding`) | `required_binding_admits_only_the_agents_a_credential_is_issued_for`, `observed_binding_admits_and_counts_an_unbound_agent`, `the_enterprise_profile_requires_every_admitting_credential_to_name_its_agents`, `an_agent_claim_names_the_agents_a_token_is_issued_for` |
| T31 | Escalation notifications forged, replayed, lost, leaking tool arguments, or used to approve | notifications are derived only from signed `escalation_opened`/`escalation_resolved` audit entries, delivered from a per-webhook cursor (at least once, ids for dedupe), signed with HMAC-SHA256 over timestamp and body, HTTPS only outside development with no redirects; payloads carry identifiers and reason codes, never arguments; a notification grants nothing, approval stays bound to the action digest (T2, T3) | `escalations_in_the_chain_reach_the_webhook_signed_and_once`, `events_carry_identifiers_and_never_arguments`, `the_signature_is_hmac_sha256_over_timestamp_and_body` |
| T32 | An upstream MCP server changes what a pinned tool does (wider input, different output, new annotations, removal) while keeping its name, so an approved capability now runs a different action | optional `upstream_tool_digest` (RFC 8785 digest of name, schemas, annotations) checked against `tools/list` at startup and every 5 minutes on each replica; while it differs or the tool is gone, calls are refused with `upstream_tool_drifted` before anything is reserved; description changes reported (`upstream_description_digest`); required for effectful MCP capabilities under the enterprise profile; an unreachable server keeps the last verdict | `a_changed_upstream_tool_is_refused_until_it_matches_its_pin_again`, `a_reworded_description_is_reported_but_not_refused`, `tools_are_listed_across_pages_with_the_discovery_credential` |
| T33 | Injected or sensitive content in a tool's output reaches the agent (beyond what `data_only` labelling contains) | optional result-screening port: every confirmed effect's output is judged before the agent sees it; `withhold` returns nothing, `redact` replaces pointed-at values, a failing or malformed provider withholds (fail closed); the effect is recorded and settled regardless; non-pass verdicts audited as `result_screened` with pointers and reasons, never content | `screening_passes_redacts_or_withholds_and_fails_closed`, `verdicts_pass_redact_or_withhold_and_malformed_ones_withhold` |
| T18 | Forged or misdirected caller tokens | JWTs verified against the issuer's published asymmetric keys only (no `HS*`/`none`, key-declared algorithm enforced); exact `iss`/`aud`; `exp`/`nbf` with bounded leeway; each issuer may assert only its configured tenants; unknown `kid` refresh rate-limited; HTTPS-only, no-redirect, size-limited JWKS fetch | `oidc.rs` tests (audience, issuer, expiry, foreign tenant, wrong key, algorithm confusion, tampering) |
| T17 | Panics on hostile input | kernel validators are total; a panic is caught per request (servers) and per call (bindings), which release builds keep by unwinding; property fuzzing | `fuzz.rs` |

## Review log

Shared business guarantees extend the enforcement domain to a tenant/guarantee/resource
on one protected store. Trusted configuration pins exact resource/amount pointers,
unit and numeric limit. Provider resource canonicalization and accepted finality
observations remain trust assumptions. Hashes are correlation identifiers, not
anonymization. Guarantee state retains amounts and hashed resource/action identities
for conservation and replay protection; it is not erased with run content.

| Threat | Control | Regression evidence |
|---|---|---|
| Unrelated runs collectively exceed one resource ceiling | CAS conservation of committed plus held exposure, independent of run/agent identity | kernel shared_exposure tests; gateway cross-run and server cross-replica tests |
| Changed rule/pointer or restart resets capacity | Stable tenant/guarantee definition pin before resource extraction; durable resource ledger; reviewed config changes | definition-pin and replica tests |
| Recovery releases capacity while a delayed worker later invokes | Exact-attempt activation competes with durable abort/tombstones on the resource receipt; active/unobserved absence release refused | deterministic pauses before/after reserve CAS; activation/abort kernel tests |
| Archiving a settled receipt lets a stalled worker spend a released hold again | A settled receipt is archived only `EXPOSURE_RECEIPT_RETENTION_SECONDS` (3,600) after it is first seen settled, far past `DISPATCH_STALL_SECONDS` (120), after which a resumed dispatch sends nothing; held receipts are never archived and archived commitments keep counting | kernel archival tests; `settled_receipts_leave_the_ledger_after_their_retention`; ATTEST-2 stall test |
| Contradictory concurrent resolutions invalidate an already released balance | Shared latest-attempt first-definitive CAS seal; signed refusals for later/stale facts; pre-existing conflicts retain exposure | delayed stale-confirmation test and audit verification |
| Crash, timeout, partial effect or failed audit/write silently restores capacity | Unknown/partial holds never expire; immutable recovery link; signed settlement before CAS; repair from protected operation evidence | injected store/audit failures, pending/partial and terminal HTTP recovery tests |

An orphaned started dispatch without a recorded observation remains conservatively
held. A confirmed assertion may commit the full exposure; externally fenced absence
recovery is not implemented. Deleting protected state, deploying a replica without
the guarantee, bypassing the gateway, unaccounted prior spend and upstream identifier
aliases are outside this numeric guarantee. There is no claim of universal safety,
external outcome proof or regulatory certification.

- 2026-10-20: adversarial review of MCP mode, delegation, failover, lifecycle,
  reconciliation, decisions, OIDC, limits and the PostgreSQL/audit changes. Fixed: a
  replayed delegation could release a live child's budget (critical); the ownership
  check ran before a network call that preceded the claim; delegation did not require
  the parent's executor; decision reports were unbounded and signed before the per-run
  cap; a closed child's run stayed running; backend error text reached callers. Each
  fix has a regression test.
- 2026-10-20: second review, of data permissions, the execution boundary, memory
  lifecycle and the release gate. Fixed: the gate scored policy by the most
  restrictive rule instead of the runtime's priority composition, so a higher-priority
  allow bundle passed unseen; a removed blocking evidence gate, dropped obligations
  and cases only the candidate compiles were not widenings; an empty corpus passed; a
  memory record id could be taken over by another owner or namespace, re-proposed, or
  revived after deletion; memory operations skipped the boundary; an allowed memory
  decision lost to a concurrent update had no "not applied" audit entry; data flow
  was skipped for fixed-recipient capabilities (now `sends_data`) and judged the
  adapter rather than the recipient the arguments name. Each fix has a regression test.

- 2026-10-20: third review, of independent scoring, wall-clock measurement, the
  OpenAPI endpoint and the release-gate changes. Fixed: evaluator independence was
  checked per token and against the caller-named agent id, so an executor with a second
  evaluate-only token could score its own runs, and an admitter could lock out a real
  evaluator by naming it as the agent (now: the admitting and recording principals are
  refused, and keys sharing a principal across evaluate and admit/dispatch are refused
  at startup); a `/` in run or record ids could alias another run's documents (run ids
  with `/` are refused at admission; only issued record ids can be scored); a store
  failure after a score was signed left no not-applied entry; duplicate replay-case
  names let one acknowledgement cover several cases. Each fix has a regression test.

- 2026-10-20: fourth review, of the kill switch, cluster limits, erasure and
  retention, conformance assessment and staged rollout. Fixed: conformance accepted
  caller-asserted verification (attestations now need Ed25519 signatures by the
  configured principals, and the report signature binds the contract and features);
  agent revocation keyed on the caller-named agent id (a `principal` kind now revokes
  the authenticated identity and its runs); a run on a revoked pack could delegate a
  child onto another pack (children must use the parent's pack and are refused while the
  parent is revoked); pending input requests survived erasure and never-started or
  expired runs could not be erased; shadow diffs were unbounded CPU work (now a few
  blocking slots, dropped when busy); a heartbeat dated in the future inflated the
  replica count; the PostgreSQL age scan could not use its index; published example
  keys are refused in production mode. Each fix has a regression test. A tenant cap
  smaller than the replica count is exceeded by design (documented).

- 2026-10-21: fifth review, of model and replan budgets, the loop guard and
  orchestrator checkpoints. Fixed: an executor could reserve a model call for zero and
  self-settle it for free, and a meter's measurement was capped at the executor's
  reservation (model calls now reserve at least a configured floor, metered overage is
  charged up to the remaining capacity and audited, and the run's admitter cannot meter
  it); an erased checkpoint could be re-created, and written past the deadline; any
  dispatch caller in the tenant could read another run's checkpoint (now only the
  current executor); the loop guard stopped counting new signatures once its table was
  full (it now refuses them, with a smaller table) and lost counts under contention
  silently (more retries, and an audited loss); cost arithmetic now refuses overflow.
  Each fix has a regression test.

- 2026-10-21: sixth review, of independent verification, key rotation and KMS
  signing. Fixed: the KMS public key was trusted on first use and the KMS URL could be
  plain HTTP (the key is now pinned in configuration and HTTPS is required outside
  development); the key id was not bound to a Vault key version (the version is pinned,
  requested and checked on every signature); `ctx audit-verify` reported an empty export
  as verified and loaded malformed key entries (such as a null `retired_at`) as fully
  trusted (both refused; the assumed anchor is now reported); an encoding failure late in
  a commit could skip a sequence number (the batch now fails as a whole). Each fix has a
  regression test.

- 2026-10-21: seventh review, of operator feedback. Fixed: feedback ids derived from
  the filing time could collide under concurrent filings, and an id left in the open
  index without a record (or a closed record whose index entry survived an interrupted
  close) could never be removed, so repeated filings could fill the tenant's bound for
  good (ids are now random, indexing is idempotent, and listing or closing drops such
  entries); a closure was audited before it took effect, so racing closers both
  appeared in the chain (the closure now takes effect first, is audited once, and is
  put back if it cannot be audited); `evidence_ref` accepted any JSON and copied it into
  the audit chain (now exactly three fields of bounded length). Accepted: the evidence
  digest is recorded, not checked against a stored artifact, so closing is an
  operator's attributable, audited assertion. Each fix has a regression test.

- 2026-10-21: adversarial corpus (`adversarial_corpus_never_reaches_the_provider`):
  nine attacks a compromised or injected executor could make (cross-run and
  cross-trace envelopes, an unpinned capability, forged approval fields, an approval
  mode downgrade, an impersonated principal chain, unadmitted evidence, a changed
  recipient, an inflated amount), each run under a permissive and an approval-requiring
  policy, must never reach the provider and must be refused for its own reason. Writing
  it found two claims the gateway accepted silently though they decided nothing: a
  principal chain not ending with the run's agent, and an approval mode below the
  capability's declared ceiling. Both are now refused (`principal_chain_mismatch`,
  `approval_mode_mismatch`). The test authority now pins its grant's recipients, as a
  real broker does, instead of echoing the call's.

- 2026-10-21: eighth review, of rollout gating, memory verification, feedback
  redaction, tool-output labels and schemas, envelope checks, escalations, delegated
  result schemas and the trajectory gate. Fixed: raw tool output still reached the agent
  on input-required, failed and unresolved outcomes despite an output schema (now
  reduced to the input requests or withheld); an erasure could miss feedback filed
  while it ran (the replay case is now tombstoned before feedback is read, so either
  side sees the other); rollout acknowledgements were authority without a record and
  could waive open-feedback cases (the waived changes are now in the audit entry,
  feedback cases cannot be waived, and named gate runs must be runs of the baseline);
  the delegated result check failed open on unknown schema references, on children
  with no decisions and on decisions recorded during the close (refused, refused, and
  rechecked after the capacity lock); `ctx trajectory-gate` trusted the agent's own
  decision reports (it now reads claimed capabilities and confirmed effects from the
  signed audit export, flags unpaired cases and refuses a disabling ratio, with
  `operation_claim` entries now naming run and capability); escalations could vanish
  from the listing, recur silently after resolution, be audited twice, or be crowded
  out by one run (opened through an audited `opening` state, reopened with history,
  capped per run). `require_tool_schemas` now covers read-only tools. Each fix has a
  regression test.

- 2026-10-21: ninth review, of production defaults, the completion score gate,
  production result schemas and memory conflicts. Fixed: the completion gate judged
  only decisions the agent recorded, so a run could apply an effect, report no decision
  for it and complete (the runtime now tracks every applied effect and refuses
  `effect_undecided`), and accepting a delegated child completed it without the gate
  (the child is judged first); a decision whose entry was missing was skipped (now
  counted as unscored); a memory without a key escaped the conflict check and keys
  differing only in case did not match (refused, and compared case-insensitively); a
  zero-width character passed as a user role (a role must be a visible identifier);
  production opt-outs were silent (now logged at startup); the clients accepted `.` and
  `..` as ids (refused). Each fix has a regression test.

- 2026-10-21: tenth review, of model attribution, memory supersession and the
  completion gate's effect tracking. Fixed: the memory key index ignored owner and
  namespace and folded case, so one namespace could take over another's key (keys are
  now exact and scoped, in their own document kind); concurrent promotions could leave
  an older value holding a key and contention gave up silently (a key is taken only by
  a newer claim, before the record is written, and failing to take it fails the
  operation); deleting the current value revived the one it replaced (a deletion leaves
  a tombstone); index documents shared id space with caller-chosen ids (own document
  kinds); a rejected child's effects escaped the parent's completion gate (closed
  children are judged with the parent); a decision could omit its model while a
  fallback was pinned (it must name one). Each fix has a regression test.

## Residual risks and deployment obligations

- **Runs are bound to principals, not to keys or processes.** Keys and tokens that
  share a principal id share its runs; give each agent service its own principal.
  Takeover across processes of one service works because they share it.
- **An attestation of absence is a claim, not a proof.** It releases a started effect
  only after the provider's records are checked through the attempt's start plus the
  timeout plus 300 seconds, advances the run's executor generation first, and a
  dispatch that stalled more than `DISPATCH_STALL_SECONDS` (120) between its claim and
  the adapter call sends nothing. What remains is a stall inside the adapter after
  that check, or a provider that applies an effect minutes after accepting it; a
  provider that fences on the forwarded `executor_generation` closes the first.

- **Release pins are not verified against a registry.** Production requires
  `model_profile` and `evaluator_suite` release refs, and decisions record them, but
  the runtime checks their presence and digest form, not that the model or evaluator
  exists; verify pins in your release process.
- **Memory supersession covers memory governed by this runtime.** A recalled memory is
  refused if a newer promotion or correction through `POST /v1/runs/{id}/memory` holds
  its key, or the key was deleted; memory promoted before this index existed, or written
  to the store by other means, is checked only against the other memories the run
  recalls. Effects applied while the completion gate was off are not tracked if it is
  turned on later.

- **Invented role in policy inputs.** When the user claims carry no `role`, the
  compiler evaluates policy as if it were `support_agent`, mirroring the spec's
  reference compiler (parity vectors). A pack rule granting to that role would treat
  callers that omit their role as holding it. Production refuses such runs at
  admission (`[guards] require_user_role`, on by default there; `user_role_missing`),
  so the default never applies; [spec proposal 0002](../proposals/spec-0002-no-default-role.md)
  removes it from the compiler.
- **Pack rules read the stated request.** A policy rule over `request.context` (for
  example "refunds above 3000 need approval") is evaluated on what the request stated
  at compile time, not on the arguments the agent later sends. Without a task
  authorization, a call larger than the stated amount is held only by broker grants.
  Admit effectful runs with a `task_authorization` (`[guards] require_task_authorization`).
- **Evidence gates trust the caller's labels.** A requirement is satisfied by a truthy
  key in the request's `context`, or by an evidence entry the caller labels `verified`
  and `current`; the compiler checks the labels, budget and conflicts, not the
  evidence itself (it is pure and parity-locked with the spec's reference). The
  admitting caller can therefore open its own gate. Have a service you trust build
  the run request's context and evidence, and treat `evidence_gate_open` as a check on
  the agent's reasoning, not on its honesty.
- **Limits bind only what manifests point at.** A task scope's `amount_ceiling` and
  `resource_ids`, and a task's `amount_total`, read the action's amount and resources
  from the capability's `amount` and `resource_pointers`. An effectful capability that
  declares neither passes them whatever it moves; `--check-config` and startup warn
  about each one. Declare both for every money-moving tool.
- **Rollouts are steerable.** Routing hashes the caller-chosen run id, so a caller can
  pick which pack its runs get; rollouts measure a candidate, they do not restrict.
- **Overage can be lost to a crash.** Measured usage above a reservation is charged in
  a second commit after the reservation settles; a crash between them charges only the
  reservation (an undercharge, never an overcharge).
- **A task authorization is as accurate as its source.** The runtime enforces the
  scopes it is given. Deriving them from the principal's instruction, and confirming
  them with the principal, is the deployment's job; `confirmation_ref` records that
  evidence. Scope ceilings apply per action; totals need the task's `limits`.
- **Task limits fail closed on unknown outcomes.** An effect whose outcome was unknown
  or partial keeps its charge even when reconciliation later finds it was not applied,
  so a task with many lost responses may stop short of its limits. The limits track at
  most 4096 effects per task (`task_limits_saturated`).
- **Task corrections take effect for later decisions.** An action authorized before
  an amendment commits may still dispatch under the previous authorization, like a
  revocation racing a dispatch. Amending a parent run does not change the copies its
  existing children inherited; narrow or revoke those children too.
- **Fact providers are trusted after verification.** The kernel checks currency, binding
  and scope of observations; it cannot detect a dishonest provider. Operate identity,
  control-plane and approval services with their own hardening and audit.
- **Repeatable capabilities.** Capabilities marked `repeatable`, and deployments with
  `[guards] refuse_repeated_effects = false`, rely on operation keys alone: a host that
  retries under a fresh key applies the effect again.
- **Provider idempotency.** Duplicate prevention across a lost response relies on the
  provider honouring the `Idempotency-Key`/operation identity, or on reconciliation.
- **Signing keys** should stay in a KMS (`[audit.kms]`): the runtime then never holds
  the private key and checks every signature it receives. A seed in the environment
  (`signing_seed_env`) is for development. Retired keys verify only up to their
  `retired_at`, and rotations are recorded in each tenant's chain.
- **PostgreSQL role** should be granted `SELECT, INSERT, UPDATE` on documents and
  `SELECT, INSERT` only on the audit log.
- **Synthetic evidence never establishes deployed conformance**; conformance claims
  need runtime evidence for the exact workflow, release and environment.

## Peer task coordination extension

The work board accepts explicitly published titles, criteria, dependencies and
evidence references. All are untrusted peer data, including text containing
instructions. The runtime labels responses `data_only` and `evidence_verified:false`
and never promotes board reports into admitted evidence, accepted child output,
authority or a provider-effect observation. Metadata is shared across a root's
descendants irrespective of lane; no admission/context/result contents are copied
automatically. Callers must keep task text inside that explicit sharing boundary.

Guessing a same-tenant run id and generation must not impersonate its worker.
Coordination reloads protected admissions, binds the authenticated principal to
nonempty `admitted_by`, and resolves the board root from trusted lineage. Shared API
principals remain shared identities. Tenant keys and distinct root keys isolate
boards. Current worker/root lifecycle and deadlines are checked on entry and each
CAS retry; these reads are separate from the board CAS, so an admitted request may
commit during cancellation/takeover. No effect authority follows from that change.

Conditional task revisions, epochs and matching run/generation prevent stale owners
overwriting a replaced lease. Expiry/release does not prove non-application of prior
effects. Frameworks must inspect/reconcile previous operations before repeating work;
predecessor metadata is not a complete effect history. Dependencies describe reported
completion only, and cannot bypass result schemas, acceptance or merge controls.

Bound tasks, content, dependencies, evidence lists, leases, pages and CAS retries to
limit resource abuse. Audit mutation attempts before CAS by digest, excluding free
text; an audit attempt is not proof of commit. Audit/store errors stop mutations.
Root-owned board content is tombstoned even when absent before erasing ReplayCase,
preventing delayed recreation and keeping partial erasure retryable by retention.
Child-only erasure leaves root-owned shared metadata. Regression coverage is in
`crates/contextos-gateway/tests/coordination.rs` and the peer HTTP test in
`crates/contextosd/tests/dispatch/coordination.rs`.
