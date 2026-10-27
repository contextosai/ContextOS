# Compensation (sagas)

A support workflow fails halfway and its applied effects are compensated, newest
first. Each compensation is a new governed operation: authority, policy, budget,
claim, observation and audit, like any tool call. Synthetic and local: no model key,
cloud account or payment service.

From the repository or release archive root:

```sh
./examples/compensation/run.sh
```

Expected output:

```text
Workflow: resolve a damaged-goods case
  1. refund INR 600 for ord_881          completed
  2. store credit INR 250 for cus_77     completed
  3. ship a replacement for ord_881      tool error: outcome unknown
Saga refused: ship:ord_881 may have shipped; nothing is undone while it is in doubt.
On-call reconciles it with ticket FUL-4471: not shipped.
The case cannot be completed; compensating its applied effects, newest first:
  adp_payments.revoke_credit             completed (compensates credit:cus_77)
  adp_payments.reverse_refund            completed (compensates refund:ord_881)
Compensation states: compensated, compensated
A second compensation is refused before the provider; provider calls: 5
Offline audit verification: {... "verified": true}
saga compensated
```

What it shows:

- The refund and credit manifests declare `compensation`; the agent never supplies
  the compensating arguments, the runtime derives them from the original calls.
- The fulfilment tool errors, so whether it shipped is unknown. The saga refuses to
  undo anything while an effect of the run is in doubt; on-call reconciles it with
  evidence first.
- Compensations run newest first, are linked to the effects they undo in the operation
  ledger and the audit chain, and are never sent twice.

See [the guide](../../docs/COMPENSATION.md) for the manifest fields, API, states and
limits.
