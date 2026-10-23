# Quickstart: a governed refund

Runs `contextosd` locally with an in-memory store, development stand-ins for the fact
services, and a stateless MCP payments tool. Requires Rust and Python 3.

```sh
./examples/support-refund/run.sh
```

Expected output:

```text
== admit run
{'run_id': 'run_demo_1', 'executor_generation': 2, 'features': {… 'external_effects': True, 'sensitive_data': True …}}
== dispatch refund
{'status': 'completed', 'output': {'refund_id': 'rf_ord_881'}, 'audit': [3, 4, 5]}
== replay the same operation (must not refund twice)
{'status': 'paused', 'reasons': ['retry_unsafe']}
== refund four times what the user asked (must not run)
{'status': 'blocked', 'reasons': ['guardrail_denied', 'outside_task_authorization', 'task_scope_amount']}
== verify audit chain
{"entries":7,"verified":true}
```

What happened:

1. **Admission** compiled the support pack for the request, derived the workflow's
   features from the capabilities it can use (external effects, sensitive data),
   negotiated the `contextos.core` profile plus the controls those features require,
   pinned the policy outcomes, opened the run's budget ledger and started the run,
   returning the executor generation the caller presents with every effectful request.
2. **Dispatch** bound the exact refund (order, customer, amount, evidence) into an RFC
   8785 digest, authorized it against the broker's grant, the pinned policy and the
   control plane's attestations, reserved budget, claimed the operation, called the MCP
   tool, recorded the outcome and settled the budget — appending three signed audit
   entries.
3. **Replay** of the same operation was refused before reaching the provider.
4. **Over-reach** was refused: the run carries what the user asked for (refund ord_881
   to cus_77, up to INR 1200) as a task authorization, and a refund of INR 4800 falls
   outside it, whatever the broker would grant. It never reached the provider, and the
   pack's approval rule — which reads the amount the request *stated* — could not be
   sidestepped by sending a larger one.

Try: change `amount_minor` in `requests/tool_call.json` while keeping the idempotency
key — the gateway rejects it as incompatible reuse. Raise `refund_amount` in
`requests/run.json` above 3000 — the pack's high-value rule pins `require_approval` and
dispatch pauses for approval. Approving the request in the development approval service
(`{"op": "approve", "approval_request_id": …}` to its port) and re-sending the identical
call redeems the approval once; `./examples/frameworks/run.sh <framework> --approval`
does this through each framework's human-in-the-loop path.

`dev_services.py` vouches for anything and is for local development only.
