# Quickstart: a governed refund

Runs `contextosd` locally with an in-memory store, development stand-ins for the fact
services, and a stateless MCP payments tool. Requires Rust and Python 3.

```sh
./examples/support-refund/run.sh
```

Expected output:

```text
== admit run
{'run_id': 'run_demo_1', 'compiled_context_hash': 'sha256:…', 'features': {… 'external_effects': True, 'sensitive_data': True …}}
== dispatch refund
{'status': 'completed', 'output': {'refund_id': 'rf_ord_881'}, 'audit': [1, 2, 3]}
== replay the same operation (must not refund twice)
{'status': 'paused', 'reasons': ['retry_unsafe']}
== verify audit chain
{"entries":4,"verified":true}
```

What happened:

1. **Admission** compiled the support pack for the request, derived the workflow's
   features from the capabilities it can use (external effects, sensitive data),
   negotiated the `contextos.core` profile plus the controls those features require,
   pinned the policy outcomes and opened the run's budget ledger.
2. **Dispatch** bound the exact refund (order, customer, amount, evidence) into an RFC
   8785 digest, authorized it against the broker's grant, the pinned policy and the
   control plane's attestations, reserved budget, claimed the operation, called the MCP
   tool, recorded the outcome and settled the budget — appending three signed audit
   entries.
3. **Replay** of the same operation was refused before reaching the provider.

Try: change `amount_minor` in `requests/tool_call.json` while keeping the idempotency
key — the gateway rejects it as incompatible reuse. Raise `refund_amount` in
`requests/run.json` above 3000 — the pack's high-value rule pins `require_approval` and
dispatch pauses for approval.

`dev_services.py` vouches for anything and is for local development only.
