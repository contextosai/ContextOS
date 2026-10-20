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
| T1 | Prompt-injected instructions in retrieved data drive an effect | Retrieved and recalled blocks are `data_only`/`untrusted`; only pinned, surfaced capabilities dispatch; evidence must be admitted (`compiler`, `gateway`) | compiler vectors; `unsurfaced_and_unadmitted_inputs_are_rejected` |
| T2 | Arguments changed after approval | RFC 8785 action digest binds arguments, amount, resources, evidence, policy; approvals bind the digest (`authorization`) | `exact_approval_is_redeemed_once_then_dispatches` |
| T3 | Approval replay for another operation | single-use redemption CAS bound to operation + digest (`transition_approval_redemption`, store CAS) | authorization vectors |
| T4 | Stale/revoked authority | grant observations must be verified, current and unrevoked; unknown revocation blocks (`validate_authority`) | authorization vectors (revoked, unknown, stale) |
| T5 | Delegation widening | child grants must strictly narrow scope, depth and validity (`validate_authority`) | delegation vectors |
| T6 | Duplicate effects (retries, races, lost responses) | operation ledger: one in-flight attempt, unknown outcomes block blind retries, idempotent retry only with verified provider proof; CAS commits | `concurrent_duplicates_dispatch_once`, `timeout_is_unknown_and_blocks_blind_retry`, store contention suite |
| T7 | Budget overspend under concurrency | conserved budget ledger with reservations; unknown usage keeps reservations | `concurrent_budget_is_conserved` |
| T8 | Stale executor acting after failover | executor generation fencing in run/operation/budget ledgers; resume rechecks controls | durable vectors |
| T9 | Cross-tenant access | every key includes tenant; callers bound to one tenant; lookups scoped by caller tenant | server tests (other tenant → 403/404) |
| T10 | Parser differentials (duplicate keys, deep nesting) | strict ingress rejects duplicates, depth > 64, oversized bodies (`ingress`) | ingress tests, server hostile-body test, fuzz |
| T11 | Policy evaluation errors treated as "false" | structured `policy_eval_error`; JsonLogic prototype access and identity comparisons fail visibly; bounded steps | compiler error vectors, ADR-0002 |
| T12 | Audit tampering, forks, key compromise | ed25519 hash chain; append-only table with no-update trigger; fork-proof sequence PK; key rotation via key ring | `tampering_is_detected` |
| T13 | SSRF / effect redirection | pinned HTTPS endpoints, no redirects, response size limits, tool names are path segments only | adapter tests |
| T14 | Credential exposure to the model | credentials come from a broker per call, never from model-visible state; `Debug` redacts | adapter tests |
| T15 | Denial of service | global in-flight cap with load shedding, per-tenant request-rate and concurrent-dispatch limits after authentication, body limits, request timeouts, JsonLogic step/depth limits, canonicalization limits, bounded retries with backoff | ingress/jsonlogic tests |
| T16 | Supply chain | rustls only, cargo-deny (advisories, licenses, sources), lockfile, distroless non-root image | CI |
| T19 | Unknown effects resolved by guesswork, or resolution used to rewrite history | reconciliation records only definitive facts through the kernel, which refuses misbound or conflicting facts; provider queries never re-invoke the tool; operator assertions need the `reconcile` scope and cited evidence and are audited with the principal; held budgets settle without extra charge | `task_effects_are_reconciled_by_querying_the_provider`, `lost_responses_need_an_operator_with_evidence`, `long_running_mcp_tasks_are_reconciled` |
| T20 | Tool input requests used to rewrite an approved action, harvest secrets, or replay answers | continuation must bind to the same action digest and is re-authorized end to end; answers validated against the pending request's keys and schema; requests are single-use (superseded by the new attempt); password-like fields and non-form requests (e.g. sampling) refused; answers audited by digest with the responder | `input.rs` tests, `tools_that_need_input_continue_the_same_operation` |
| T18 | Forged or misdirected caller tokens | JWTs verified against the issuer's published asymmetric keys only (no `HS*`/`none`, key-declared algorithm enforced); exact `iss`/`aud`; `exp`/`nbf` with bounded leeway; each issuer may assert only its configured tenants; unknown `kid` refresh rate-limited; HTTPS-only, no-redirect, size-limited JWKS fetch | `oidc.rs` tests (audience, issuer, expiry, foreign tenant, wrong key, algorithm confusion, tampering) |
| T17 | Panics on hostile input | kernel validators are total; facade isolates panics; property fuzzing | `fuzz.rs` |

## Residual risks and deployment obligations

- **Fact providers are trusted after verification.** The kernel checks currency, binding
  and scope of observations; it cannot detect a dishonest provider. Operate identity,
  control-plane and approval services with their own hardening and audit.
- **Provider idempotency.** Duplicate prevention across a lost response relies on the
  provider honouring the `Idempotency-Key`/operation identity, or on reconciliation.
- **Signing keys** must come from a KMS/HSM-backed secret; rotate by adding the new key
  to verifiers before switching writers.
- **PostgreSQL role** should be granted `SELECT, INSERT, UPDATE` on documents and
  `SELECT, INSERT` only on the audit log.
- **Synthetic evidence never establishes deployed conformance**; conformance claims
  need runtime evidence for the exact workflow, release and environment.
