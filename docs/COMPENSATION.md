# Compensation (sagas)

Agents rarely make one isolated change. A support case refunds an order, grants store
credit and ships a replacement; when the third step fails, the first two have already
happened at the provider. ContextOS lets a capability declare how its effect is undone
and runs that undo as a **new governed operation**: never a rollback, never a silent
retry, and never more than once.

## Try it

```sh
./examples/compensation/run.sh
```

See [the demo](../examples/compensation/README.md).

## Declare compensation

A capability whose effect can be undone names the capability that undoes it, and where
each of that capability's arguments comes from:

```json
{
  "capability_id": "adp_payments.issue_refund",
  "action_risk": {"effect": "external_state", "reversibility": "compensatable", "...": "..."},
  "compensation": {
    "capability_id": "adp_payments.reverse_refund",
    "arguments": {
      "refund_ref": "/external_ref",
      "order_id": "/arguments/order_id",
      "amount_minor": "/arguments/amount_minor"
    }
  }
}
```

| Source | Value |
|---|---|
| `/arguments/<pointer>` | that value from the original call's arguments |
| `/external_ref` | the provider's reference recorded with the original effect (the spec's reversal token) |

Rules checked when the manifest is pinned: only `reversible` or `compensatable`
capabilities may declare compensation, the compensating capability must be a different
one, and there are at most 32 arguments. The compensating capability is pinned and
surfaced by the pack like any other: compensating needs current authority for it.

`/external_ref` comes from the effect's definitive observation in the operation ledger:
the HTTP adapter records the job or resource `id`, and the MCP adapter records a task
id. It is sent to the compensating adapter and never shown to the agent, which names the
operation to compensate, not the token. Synchronous MCP results carry no reference; map
the arguments instead.

## Before the effect is sent

For a capability that declares compensation, the gateway records what compensating the
effect will need (the mapped arguments) after authorization and before reserving
budget. If the call lacks an argument the compensation needs, or the run already has
1,024 compensable effects, the effect is refused and never sent:

| Reason | Meaning |
|---|---|
| `compensation_binding_incomplete` | a `/arguments/...` source is missing from the call |
| `compensation_index_full` | the run has `MAX_COMPENSABLE_EFFECTS` (1,024) compensable effects |

An effect ContextOS sends can therefore always be compensated as its manifest says.

## Compensate one effect

```http
POST /v1/runs/{run_id}/operations/{operation_id}/compensate
ContextOS-Executor-Generation: 2
{"tool_call_id": "tc_undo_1"}
```

Scope `dispatch`, fenced by the executor generation. The response is a tool-call
outcome (`{"result", "report"}`) for the compensating capability, with
`result.metadata.compensates_operation_id` naming the effect.

The compensation passes the whole dispatch pipeline under its own action digest:
surfacing, authority, policy, approval (the original's approval does not cover it),
data flow, budget, revocations, claim, observation, settlement and audit. Its operation
id is `compensation:<digest of the original id>`, so it is one operation per effect:

- a confirmed or partial compensation is never sent again (`compensation_already_applied`);
- an unknown one is reconciled like any effect (`compensation_unresolved`);
- one the provider definitively did not apply may be retried, as the same operation,
  under the compensating capability's recovery rules.

At the claim the kernel checks the link (`compensates_operation_id`): the original must
be an applied (`confirmed` or `partial`) operation of the run, with a different action.
Each operation has its own ledger document, so the claim is evaluated on a projection
holding the original as well, read again just before the claim; the original's history
is never rewritten. Records are keyed by operation and action, so reusing an operation
id with other arguments cannot strand the effect the ledger holds.

| Refusal | Status | Meaning |
|---|---|---|
| `compensation_not_declared` | rejected | no compensation was recorded for this operation |
| `compensation_not_applicable` | rejected | the effect was not applied; there is nothing to undo |
| `compensation_original_unresolved` | paused | the effect is unknown or in flight; reconcile it first |
| `compensation_exhausted` | rejected | the compensation failed and its recovery rules allow no further attempt (obligation `escalate`) |
| `compensation_reference_missing` | rejected | `/external_ref` is needed but the provider recorded none (obligation `escalate`) |
| `operation_id_reserved` | rejected | a tool call used an id beginning with `compensation:` |

## Compensate a run (saga)

```http
POST /v1/runs/{run_id}/compensate
ContextOS-Executor-Generation: 2
```

Compensates the run's compensable effects **newest first**, each as above. It stops:

- before doing anything, when any effect of the run is unknown, compensable or not:
  what to undo depends on whether it happened (`stopped_at.reason: "unresolved"`), or
  still in flight (`effects_in_flight`);
- at an effect or compensation still in doubt (`unresolved`, `compensating`) or
  partially compensated;
- at the first compensation that does not complete (`compensation_incomplete`), or one
  that may not be attempted again (`compensation_exhausted`);
- after `MAX_SAGA_STEPS` (16) compensations in one request (`step_limit`): call again
  to continue.

```json
{"run_id": "run_saga", "status": "compensated", "steps": [{"operation_id": "...", "result": {}, "report": {}}],
 "stopped_at": null}
```

Calling it again is safe: compensated and never-applied effects are skipped.

## List where effects stand

`GET /v1/runs/{run_id}/compensations` (scope `dispatch`) lists the run's effects whose
capabilities declare compensation, in the order they were requested:

| `state` | Meaning |
|---|---|
| `compensable` | applied; can be compensated (also after a compensation definitively failed, while its recovery rules allow another attempt) |
| `compensation_exhausted` | the compensation definitively failed and may not be attempted again; escalate |
| `compensating` | the compensation is in flight or its outcome is unknown |
| `compensated` | the compensation applied |
| `partially_compensated` | the compensation applied in part; needs an operator |
| `unresolved` | the original effect is in flight or unknown |
| `not_applied` | the original never applied |

## Clients

```python
run.compensations()                 # {"run_id", "effects": [...]}
run.compensate("refund:ord_881")    # the compensation's output, or raises a ToolOutcome
run.compensate_all()                # {"status": "compensated" | "stopped", "steps", "stopped_at"}
```

```js
await run.compensations();
await run.compensate("refund:ord_881");
await run.compensateAll();
```

## Limits and boundaries

- Compensation runs while the run is `running`. Compensate before failing or cancelling
  a run: a cancelled run accepts no new effects, compensations included.
- Only effects of capabilities that declare compensation are listed and compensated;
  effects of other capabilities still stop the saga while they are unknown.
- A compensation is not compensable itself.
- A compensating capability that asks for input (`input_required`) cannot be continued
  through `/input`; the agent never holds its arguments. Give compensating tools
  everything they need in the mapped arguments.
- The original is re-read just before the compensation is claimed; a reconciliation
  landing between that read and the claim is not seen by that claim.
- A heavily contended compensation index (many parallel compensable calls in one run)
  can refuse an effect with `compensation_index_full`; it fails closed and the call may
  be repeated.
- Compensation records hold the arguments compensation needs; erasure of the run
  tombstones them.
- Compensation does not make an `irreversible` effect reversible, and it cannot prove
  the provider's undo is complete: `partial` compensations stay visible for an
  operator, and the original's ledger history is kept.
