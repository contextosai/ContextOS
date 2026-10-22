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

Both read routes require `audit:read`; the tenant always comes from authentication:

```text
GET /v1/guarantees
GET /v1/guarantees/{id}/resources/{resource_digest}
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
the first version refuses absence-based release with
`shared_guarantee_dispatch_active`. A truthful confirmed assertion can commit the
full amount conservatively. When usage was not observed, this also charges the
protected original run-budget allocation in full. Establishing externally fenced
absence and reclaiming an orphaned active dispatch requires additional recovery
tooling; do not delete documents to make capacity available.

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

Each resource retains at most 1,024 operation receipts, including released ones.
Saturation refuses new operations; retries of an existing receipt do not consume
another slot. There is no unsafe TTL or deletion-based rollover. Production
rollover and trusted dynamic balances are future work.

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
checks and their limits. PostgreSQL contention benchmarks and
dedicated Tower exposure views are planned; the runnable local demo uses memory.
