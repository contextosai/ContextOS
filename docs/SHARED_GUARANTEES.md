# Shared business guarantees

ContextOS can enforce a numeric ceiling shared by unrelated agent runs. A guarantee
belongs to a tenant and business resource; agents do not choose its ledger, unit or
ceiling. This opt-in runtime extension is separate from normative run/delegation
budgets and does not require changing an agent client.

## Try it

From the repository root, with the pinned Rust toolchain and Python 3.9+:

```sh
./examples/shared-guarantees/run.sh
```

The synthetic demo races two agents, holds capacity for a pending effect, queries its
outcome and verifies exported evidence offline. It needs no model key or payment
account. See [the demo](../examples/shared-guarantees/README.md).

## Configure the business boundary

Add this top-level array to the runtime TOML alongside your existing providers,
capability manifests and adapters:

```toml
[[guarantees]]
id = "refunds-per-order"
capability_ids = ["adp_payments.issue_refund"]
resource_pointer = "/order_id"
amount_pointer = "/amount_minor"
limit = 100000
unit = "INR_minor"
```

Every distinct canonical order identifier receives a lifetime ceiling of INR 1,000.
This is a policy ceiling, not an automatic reading of captured payment or previously
refunded money. Start with resources whose prior exposure is accounted for. Existing
business APIs should retain their own invariant checks.

The runtime extracts both fields from the same arguments bound to the authorized
action and sent to the provider. Pointers use RFC 6901; missing values, invalid
resource identifiers and zero, fractional, negative or unsafe amounts withhold the
call. Amount and limit are positive integers at most 9,007,199,254,740,991.
Resource strings contain 1–256 ASCII letters, digits or `_.:-`; they are
case-sensitive. Upstream aliases, case folding and identifier canonicalization must
be resolved by your integration. Unit is trusted configuration metadata; the
runtime performs no currency conversion.

A guarantee can cover several effectful capabilities with the same resource/amount
shape and unit. Each capability belongs to at most one guarantee; unknown or
read-only capabilities refuse startup. There are at most 128 guarantees per
deployment and 64 capabilities per guarantee.

Deploy every replica participating in the boundary with the same guarantee
definitions, tenant identities and protected store. A separate store is a separate
enforcement domain. Memory storage shares capacity only within the same process;
use PostgreSQL for durable multi-process operation.

## Conservation and execution

For each tenant, guarantee and resource:

```text
committed + held <= limit
available = limit - committed - held
```

The gateway retains its ordinary authorization, approvals, run budgets, operation
claim and repeat-effect checks. It then pins the tenant's guarantee definition,
creates the resource ledger, persists the immutable operation link and reserves
exposure through CAS. A signed reservation precedes dispatch.

The exact receipt must win a durable dispatch-start transition before the adapter
runs. Pre-dispatch recovery competes on that same receipt: it can abort an
unstarted attempt, including creating a closed tombstone before a delayed
reservation lands. A delayed worker cannot revive that attempt.

| Observed state | Exposure |
|---|---|
| Reserved, not started | Held; an evidenced abort closes this exact attempt before release |
| Started, no recorded observation | Held; non-application assertions cannot free it while dispatch may still start or run |
| Recorded unknown outcome | Fully held until an accepted definitive reconciliation |
| Partial effect or pre-existing conflict | Fully held; manual investigation required |
| Confirmed definitive effect | Entire reservation committed |
| Every potentially dispatched attempt definitively absent | Released once; receipt retained |

Time, restart, run completion, cancellation, failure and content erasure do not
replenish the resource. Shared unknown operations must reconcile before retry,
including operations whose ordinary provider contract supports idempotent retry.

The first accepted definitive fact seals a shared attempt. Concurrent or later
contradictory assertions are refused and signed as
`shared_guarantee_observation_refused`; they do not rewrite an already released
balance. An authorized principal's finality claim and the provider's correctness
remain trust assumptions. Treat contradictory evidence as an incident requiring
investigation, not an instruction to retry.

Settlement reads its receipt before the accepted whole-operation history, signs
the settlement request, and commits through CAS. It never derives release from an
isolated adapter response. An interruption before settlement leaves a conservative
hold; repeating reconciliation repairs settlement from protected evidence.

## Inspect and recover

The read routes require `audit:read`; the tenant always comes from authentication:

```text
GET /v1/guarantees
GET /v1/guarantees/{id}/resources/{resource_digest}
GET /v1/guarantees/{id}/holds?after=<cursor>&scan=<n>
GET /v1/guarantees/{id}/resources/{resource_digest}/holds
```

The resource digest is SHA-256 of the RFC 8785 canonical JSON string, including its
JSON quotes. For an accepted ASCII identifier, for example:

```sh
python3 - <<'PY'
import hashlib, json
print("sha256:" + hashlib.sha256(json.dumps("ord_881").encode()).hexdigest())
PY
```

An existing resource returns `guarantee_id`, `definition_digest`,
`resource_digest`, `unit`, `limit`, `committed`, `held`, `available` and
`receipt_count`. Missing resources and other tenants' resources return 404.
The view contains no raw resource value or tool arguments. Hashes are correlation
identifiers, not anonymization; predictable identifiers may be guessed.

### Find and explain holds

`GET /v1/guarantees/{id}/holds` answers *which resources have capacity held*. It reads
at most `scan` (default and maximum 1,000) of the tenant's ledgers after the `after`
cursor and returns those under this guarantee with `held > 0`, each with the balance
above and `open_holds`. Continue from `next` until it is `null`; a page can be empty
while `next` is not. The store lists ledgers by key, so a tenant with many resources
needs several pages.

`GET /v1/guarantees/{id}/resources/{resource_digest}/holds` answers *why this resource
is blocked and what can safely happen next*. It returns the balance, `as_of`, and each
open hold, oldest attempt first: `run_id`, `operation_id`, `attempt_id`,
`action_digest`, `amount`, `dispatch_started`, `attempt_started_at`,
`operation_outcome`, `last_observation` (outcome, finality, `observed_at`,
`external_ref`, observer and evidence reference), and `next_safe_step`:

| `state` | `next_safe_step.action` | Meaning |
| --- | --- | --- |
| `reserved_not_sent` | `wait_or_reconcile` | Reserved but not sent. If the executor is gone, reconciling closes the dispatch gate first, so the attempt cannot be sent later, and releases the capacity. |
| `dispatch_active` | `confirm_or_attest_absence` | Sent with nothing observed; it may still apply. Do not retry. Reconciling absence is refused (`shared_guarantee_dispatch_active`); an operator may confirm with evidence, or an attester may release it (see "Attesting absence"). |
| `unknown_provider_reference` | `provider_query` | Unknown, with a provider reference: reconcile with `{"source":"provider"}`. |
| `unknown` | `operator_reconcile` | Unknown, with nothing to query: check the provider's records, then reconcile as an operator citing them. |
| `partial` | `operator_reconcile` | Part of the effect applied, so capacity cannot be released; an operator may confirm it, committing the full amount. |
| `settlement_pending` | `reconcile_again` | The outcome is decided but the balance was not updated; reconciling again repairs it without sending anything. |
| `conflicting_facts` | `incident` | Contradictory outcomes were recorded; capacity stays held. |
| `unlinked` | `investigate` | No readable operation record; capacity stays held. |

`next_safe_step.reconcile` is the reconcile route for that operation, called with
the `reconcile` scope and the run's current executor generation as described below.
`next_safe_step.attest_absence` is the attestation route, set only for
`dispatch_active`.
Viewing never resolves anything: the inspection routes are read-only, their scope
grants no reconciliation, and no state is resolved by waiting. The views contain no
tool arguments. Run and operation identifiers and provider references are visible
to `audit:read` holders, as they are in the audit log.

Use the existing endpoint with the `reconcile` scope and the run's **current**
executor generation, including after the run fails or is cancelled:

```text
POST /v1/runs/{run_id}/operations/{operation_id}/reconcile
contextos-executor-generation: <current generation>

{"source":"provider"}
```

A provider query never re-invokes the effect. An operator can instead provide an
attributable assertion with an artifact reference:

```json
{
  "source": "operator",
  "outcome": "not_applied",
  "evidence_ref": {
    "artifact_type": "provider_ledger",
    "artifact_id": "incident-42",
    "version": "1",
    "sha256": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  }
}
```

Only assert definitive absence with evidence that the effect did not apply and
cannot still apply. Artifact references are attributed, audited assertions; this
runtime does not independently fetch and validate an operator's cited artifact.

If a worker vanished after dispatch started and before recording an observation,
reconciliation refuses absence-based release with
`shared_guarantee_dispatch_active`: the call may still be in flight. A truthful
confirmed assertion can commit the full amount conservatively. When usage was not
observed, this also charges the protected original run-budget allocation in full.
If the provider shows no effect, use an attestation. Never delete documents to make
capacity available.

### Attesting absence

An attestation releases a hold whose dispatch started and recorded nothing, on a
named principal's evidenced statement that the provider's records show no effect:

```text
POST /v1/runs/{run_id}/operations/{operation_id}/attest-absence

{"evidence_ref": {"artifact_type": "provider_ledger", "artifact_id": "export-2026-10-29",
  "version": "1", "sha256": "sha256:…"},
 "checked_through": "2026-10-29T10:20:00.000000Z"}
```

- **Who:** a key or token with the `attest` scope and neither `admit` nor
  `dispatch`. Configuration refuses a principal holding both; give `attest` to the
  team that reconciles against the provider (payments operations, finance), not to
  the agent's orchestrator. No executor generation is needed: the executor that
  sent the call is usually gone.
- **When:** only for the latest attempt of an operation that was claimed, whose
  dispatch gate is `started`, and that has no definitive fact; anything else is
  `attestation_not_applicable` and goes through reconcile. `checked_through`, the
  time the provider's records were checked up to, must be no earlier than the
  attempt's start plus the capability's `timeout_ms` plus 300 seconds, so a call
  still in flight had time to land in what was checked
  (`attestation_too_early`, with `output.checked_through_not_before`), and not in
  the future (`attestation_checked_in_future`).
- **Fencing:** a running run's executor generation is advanced first, so the executor
  that sent the call must take the run over before dispatching again, and a provider
  that fences on the forwarded generation refuses it. Independently, a dispatch that
  stalls more than 120 seconds between its claim and the provider call sends nothing
  (`dispatch_stalled`), so a stalled dispatcher cannot send after an attestation.
- **What is recorded:** `effect_absence_attested` (run, operation, attempt, action
  digest, attempt start, `checked_through`, evidence, attester and the new executor
  generation) is signed before anything else changes. The attestation then becomes the attempt's definitive
  `not_applied` fact, followed by the usual `effect_reconciliation` (`source:
  "attestation"`) and `shared_guarantee_settlement_requested`/`settled` entries. It
  releases the shared capacity, the run's budget reservation and any task-limit
  charge.
- **If it was wrong:** the fact seals the attempt. A later contrary report (a
  revived executor reporting the effect applied) is refused and audited as
  `shared_guarantee_observation_refused`; outside a shared guarantee it marks the
  operation conflicting, for escalation. The capacity already released is not
  taken back automatically: treat such an entry as an incident. The audit proves
  who attested and on what evidence, not that the attestation was true.

After a recorded final observation, repeat reconciliation to repair a failed
settlement write without dispatching again. Retain run admission and operation
metadata while exposure needs recovery; these protected records and the guarantee
links/ledgers are not erased with personal run content.
Keep the original pinned capability manifests and required providers available while
operations remain unresolved; recovery does not substitute a different tool version.

## Definition changes, limits and evidence

The full semantic definition is pinned under a stable tenant/guarantee identity
**before resource extraction**. A changed pointer, capability set, unit or limit
under the same id fails closed even when it would address a new resource. Reordering
capabilities is harmless. The first version has no live migration API.

Removing/renaming a guarantee, omitting it from another replica, or changing stores
can escape the boundary. Configuration review classifies removed/rebound
protections and increased limits as loosenings. Lowering a limit is classified as
tightening, but still needs an accounted migration because the pinned definition
will refuse it. Review and coordinate deployment changes explicitly.

Each resource retains at most 1,024 operation receipts for its lifetime, including
released and settled ones: settled receipts are not compacted. Saturation refuses
new operations; retries of an existing receipt do not consume another slot. There
is no unsafe TTL or deletion-based rollover. Production rollover and trusted
dynamic balances are future work.

Size resources to that cap. A resource bound to one order, one invoice or one
ticket fits easily. A resource that accumulates without end, such as one per
customer or one per merchant, reaches 1,024 operations and then refuses every new
one, permanently. Until rollover exists, put a bounded period into the resource
identity (for example customer and calendar day) only if a per-period limit is what
you mean to enforce, and alert on `shared_guarantee_saturated` refusals.

Audit events include reservation, refusal, settlement request, settlement completion
and refused observations. Export the tenant chain and verify it with
`ctx audit-verify --entries entries.json --keys keys.json`. Verification establishes
integrity relative to trusted keys and the stated anchor. It does not independently
prove that external effects happened, that every call was mediated, or that a
deployment complies with a regulation.

See [research](research/2026-10-22-value-proposition.md),
[design](superpowers/specs/2026-10-22-shared-business-guarantees-design.md) and
[threat model](security/THREAT_MODEL.md). The
[validation record](research/2026-10-22-shared-guarantees-validation.md) records the
checks and their limits. The runnable local demo uses memory. The
[PostgreSQL failure drill](../examples/postgres-drill) runs the limit across separate
processes with SIGKILLs and a database restart, checked against the provider's own
ledger; its [record](research/2026-10-29-postgres-shared-limit-drill.md) gives results
and limits. Dedicated Tower exposure views are planned.
