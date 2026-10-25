# Verified properties

The specification is the contract; the reference vectors show the runtime matches it
case by case. That is evidence for the cases, not for the rules. This catalog lists the
rules the runtime's safety rests on, each with where it comes from, how strongly it is
checked and the check itself. `scripts/check_properties.py` (part of `scripts/check.sh`)
fails when a listed check is missing, or a check names a property not listed here.

## Levels of rigor

| Level | Meaning | Here |
|---|---|---|
| L1 example | Fixed inputs with expected outputs | the specification's reference vectors (`conformance/vectors`), unit tests |
| L2 property | A rule checked on thousands of generated inputs, shrunk to a minimal counterexample on failure | `proptest` suites below |
| L3 exhaustive | Every state or interleaving of a bounded model | the run lifecycle; every single-crash point of the real dispatch and reconciliation paths |
| L4 proof | A machine-checked proof for all inputs | none yet |

An L2 property is only as good as how often its premise holds. Run a suite with
`PROPERTY_STATS=1 cargo test --test <suite> -- --nocapture` to print the counts; the
rates below are from 4096 to 8192 cases. A property marked *mutation-tested* was shown
to fail when the code it guards was deliberately broken.

## Catalog

| ID | Property | Source | Level | Check | Status |
|---|---|---|---|---|---|
| AUTH-1 | A grant scope that narrows another covers no action the other does not | Execution contract, `AuthorityGrant` delegation rule | L2 | `narrowing_never_admits_more` in `crates/contextos-kernel/tests/properties.rs` | Holds (premise met in about 620 of 8192 cases per run) |
| AUTH-2 | Narrowing each dimension is recognised as narrowing; narrowing is reflexive and transitive, so a delegation chain narrows its root | Delegation rule | L2 | `narrowing_is_a_preorder` in `crates/contextos-kernel/tests/properties.rs` | Holds |
| SPEC-1 | A missing `amount_ceiling` means "no amount" when narrowing as when checking scope: a child scope may not add or drop a ceiling | Found by AUTH-1 when the two disagreed; [spec-0004](../proposals/spec-0004-amount-ceiling-narrowing.md) | L1 | `spec_1_a_ceiling_where_none_was_widens` in `crates/contextos-kernel/tests/properties.rs` | Resolved in specification revision `7e2462f`; reference vectors `delegation:child_adds_ceiling`, `neither_has_ceiling`, `child_drops_ceiling` |
| POLICY-1 | Policy composition depends on the set of outcomes, not their order | Policy composition rules | L2 | `composition_ignores_order` in `crates/contextos-kernel/tests/properties.rs` | Holds |
| POLICY-2 | Adding a guardrail outcome never makes the verdict less strict; a guardrail deny always refuses | "Guardrail deny wins"; task authorization "only narrows" | L2 | `a_guardrail_only_restricts` in `crates/contextos-kernel/tests/properties.rs` | Holds |
| RUN-1 | Every run status is reachable, terminal statuses admit no event, and every other status can still fail or expire | Run lifecycle transition table | L3 | `the_run_lifecycle_always_ends_and_never_reopens` in `crates/contextos-kernel/tests/properties.rs` | Holds |
| BUDGET-1 | Used plus reserved never exceeds the ceiling, for any history of reservations, settlements and replays | Conserved budget ledger | L2 | `budgets_are_conserved` in `crates/contextos-kernel/tests/properties.rs` | Holds (about 3100 accepted mutations per run) |
| BUDGET-2 | What is reserved is exactly what open reservations still hold; what is used is what reservations used | Conserved budget ledger | L2 | `budgets_are_conserved` in `crates/contextos-kernel/tests/properties.rs` | Holds |
| BUDGET-3 | A rejected mutation changes nothing, an accepted one advances the revision by one, a replay is answered from its receipt | Compare-and-swap mutations, idempotent receipts | L2 | `budgets_are_conserved` in `crates/contextos-kernel/tests/properties.rs` | Holds (about 1550 replays per run) |
| OP-1 | A new attempt is claimed only when no attempt was definitively applied, the evidence does not conflict, the strategy allows retries, and an unknown outcome only under a verified idempotency contract | Operation ledger: "retried only when it is provably safe" | L2 | `effects_are_never_applied_twice` in `crates/contextos-kernel/tests/properties.rs` | Holds (about 345 retries, 134 after an unknown outcome, per run); mutation-tested (removing the confirmed or the unknown-outcome guard fails within 0.4 s) |
| OP-2 | At most one attempt of an operation is in flight, and it is the last | Operation ledger: "never while an attempt is in flight" | L2 | `effects_are_never_applied_twice` in `crates/contextos-kernel/tests/properties.rs` | Holds. Removing the in-flight guard does not break it: an attempt in flight has no facts, so `retry_not_due` also refuses the claim |
| OP-3 | Once applied, an operation is never again `not_applied` or `not_dispatched`; contradicting evidence makes it `unknown` with a conflict that stays | Effect outcomes, late facts | L2 | `effects_are_never_applied_twice` in `crates/contextos-kernel/tests/properties.rs` | Holds (about 1650 observations of applied operations per run, late facts included) |
| OP-4 | A rejected transition changes nothing, an accepted change advances the revision by one, and attempts never exceed `max_attempts` | Compare-and-swap ledger transitions | L2 | `effects_are_never_applied_twice` in `crates/contextos-kernel/tests/properties.rs` | Holds |
| CANON-1 | Canonical JSON equals an independent RFC 8785 encoder: members by UTF-16 code units, strings escaped as the reference does | RFC 8785; every execution-contract digest | L2 | `canonical_text_matches_an_independent_encoder` in `crates/contextos-contract/tests/canonical_properties.rs` | Holds; mutation-tested (sorting members by UTF-8 bytes fails) |
| CANON-2 | The encoding is a fixed point, independent of member insertion order, and different values encode differently | RFC 8785 | L2 | `canonical_text_is_stable_and_distinguishing` in `crates/contextos-contract/tests/canonical_properties.rs` | Holds |
| CANON-3 | A number's text is ECMAScript's shortest round trip: it reads back as the same double, integral doubles print as integers, `-0` as `0` | RFC 8785 number serialization | L2 | `numbers_read_back_exactly` in `crates/contextos-contract/tests/canonical_properties.rs` | Holds |
| DISPATCH-1 | The provider is called only under a durable claim: never more calls than recorded attempts | Operation ledger: "claimed before dispatch" | L3 | `every_crash_point_of_a_dispatch_is_safe_to_retry` in `crates/contextos-gateway/tests/pipeline.rs` | Holds at all 150 single-crash points |
| DISPATCH-2 | After any single crash and a retry, an effect is sent at most once, unless the provider definitively reported it not applied | Durable effects, at-most-once | L3 | `every_crash_point_of_a_dispatch_is_safe_to_retry` in `crates/contextos-gateway/tests/pipeline.rs` | Holds |
| DISPATCH-3 | A retry reports `completed` only for a confirmed effect | Tool result semantics | L3 | `every_crash_point_of_a_dispatch_is_safe_to_retry` in `crates/contextos-gateway/tests/pipeline.rs` | Holds |
| DISPATCH-4 | Budget, task limits and shared exposure stay conserved across a crash and never charge usage for an effect that was not sent | Conserved accounting | L3 | `every_crash_point_of_a_dispatch_is_safe_to_retry` in `crates/contextos-gateway/tests/pipeline.rs` | Holds |
| DISPATCH-5 | The signed audit chain verifies after a crash at any write | Audit integrity | L3 | `every_crash_point_of_a_dispatch_is_safe_to_retry` in `crates/contextos-gateway/tests/pipeline.rs` | Holds |
| DISPATCH-6 | A dispatch stranded by a crash before its effect was sent recovers: once an operator records it not applied, the next retry sends it exactly once; after the dispatch gate opened, that assertion is refused | Reconciliation | L3 | `every_crash_point_of_a_dispatch_is_safe_to_retry` in `crates/contextos-gateway/tests/pipeline.rs` | Holds since the dispatch gate (14 recovered, 2 refused as in flight per run). Found failing: outside shared guarantees a claimed attempt without facts could not be reconciled, so a crash between claim and send stranded the operation |
| DISPATCH-7 | Of an operator recording an attempt as never sent and its live dispatch, exactly one wins: the dispatch sends nothing and releases its holds, or the assertion is refused | Dispatch gate | L1 | `reconciliation_and_a_live_dispatch_race_on_the_dispatch_gate` in `crates/contextos-gateway/tests/pipeline.rs` | Holds |
| DISPATCH-8 | After any single crash and a retry, nothing stays held for an attempt whose outcome is known: no budget reservation (including one a crash left before its claim), no shared exposure for a confirmed or unapplied effect, no task-limit charge for an effect not applied | Conserved budget ledger; task limits (spec-0003) | L3 | `every_crash_point_of_a_dispatch_is_safe_to_retry` in `crates/contextos-gateway/tests/pipeline.rs` | Holds |
| DISPATCH-9 | A retry reclaims the reservation of an attempt that never claimed the operation only after closing that attempt's dispatch gate: if its process was only paused and claims later, it sends nothing | Durable effects; conserved budget ledger | L1 | `a_reclaimed_attempt_never_sends` in `crates/contextos-gateway/tests/pipeline.rs` | Holds |
| RECONCILE-1 | After any single crash of a reconciliation and a retry, the operation ends with the resolved outcome | Reconciliation: a definitive fact resolves the latest attempt | L3 | `every_crash_point_of_a_reconciliation_is_safe_to_retry` in `crates/contextos-gateway/tests/pipeline.rs` | Holds |
| RECONCILE-2 | Nothing stays held for a reconciled operation: no budget reservation, task-limit or shared-exposure hold, no outstanding-effect entry; a confirmed effect is charged exactly once | Conserved budget ledger; task limits (spec-0003); run completion | L3 | `every_crash_point_of_a_reconciliation_is_safe_to_retry` in `crates/contextos-gateway/tests/pipeline.rs` | Holds |
| RECONCILE-3 | The signed audit chain verifies after a crash at any write of a reconciliation, and records the reconciliation | Audit integrity | L3 | `every_crash_point_of_a_reconciliation_is_safe_to_retry` in `crates/contextos-gateway/tests/pipeline.rs` | Holds |
| RECONCILE-4 | A stranded effect recorded not applied through a crashed reconciliation is then sent exactly once | Durable effects | L3 | `every_crash_point_of_a_reconciliation_is_safe_to_retry` in `crates/contextos-gateway/tests/pipeline.rs` | Holds |
| TASK-1 | An amendment classified `narrowed` permits nothing the current task authorization did not, for every action, effect and usage so far | Proposal spec-0003, replacement rule | L2 | `a_narrowed_task_permits_nothing_new` in `crates/contextos-gateway/tests/task_properties.rs` | Holds; mutation-tested (found SPEC-1 within 0.2 s when the narrowing fix was removed) |
| TASK-2 | Of effects racing for a task's limits, no more are charged than fit; a returned charge frees exactly its share | Proposal spec-0003, limits | L2 | `charges_are_conserved_under_concurrency` in `crates/contextos-gateway/src/task_authorization.rs` | Holds (8 concurrent charges) |

## Not yet covered

- **More than one crash.** DISPATCH-1..6 and RECONCILE-1..4 explore every single crash
  of one dispatch or one reconciliation, followed by one retry; two crashes and
  concurrent dispatches of one run are not explored.
- **A reclaimed attempt that claims later** (DISPATCH-9) sends nothing, but leaves its
  claim without facts: the operation is refused as in flight until an operator
  records that attempt not applied, which its closed gate then allows.
- **A crash after the dispatch gate opened but before the provider was called** is
  refused as possibly in flight (DISPATCH-6): it needs the provider's own record, a
  confirmed assertion, or provider idempotency to resolve. A gate cannot tell "about
  to send" from "sent".
- **Recovery under a new operation id.** DISPATCH-6 retries the same operation;
  whether an orchestrator that retries the stranded effect under a fresh operation id
  is served is not explored.
- **Executor generations** in the operation ledger (late facts from an earlier
  generation are recorded but never authorize dispatch) are covered by the reference
  vectors, not by OP-1..4, whose histories use one generation.
