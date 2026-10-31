# OpenAI Agents SDK (Python) under ContextOS

An `Agent` driven by the SDK's own loop (`Runner.run`, openai-agents 0.24) that
refunds the quickstart's damaged order through `contextosd`. ContextOS enters through
the tools, a `ModelProvider` wrapper and the run's checkpoint.

```sh
./examples/frameworks/run.sh openai-agents
```

Without `OPENAI_API_KEY` the SDK's scripted test model (`agents.testing.ScriptedModel`)
drives the same loop: it looks the order up, refunds it, then asks for the refund
again. The gateway refuses the repeat, and the model is told it was already requested
and not repeated:

```
admitted run_openai_agents_1792550735238 (executor generation 2)
tool lookup_order -> {'amount_minor': 120000, 'currency': 'INR', 'customer_id': 'cus_77', 'order_id': 'ord_881', 'refundable': True, 'status': 'delivered_damaged'}
SDK approval requested (local, before ContextOS): issue_refund({"order_id":"ord_881","customer_id":"cus_77","amount_minor":120000})
approved; checkpoint revision 1
tool issue_refund -> {'refund_id': 'rf_ord_881'}
SDK approval requested (local, before ContextOS): issue_refund({"order_id":"ord_881","customer_id":"cus_77","amount_minor":120000})
approved; checkpoint revision 2
tool issue_refund -> ALREADY REQUESTED (retry_unsafe): this exact action was submitted before and was not repeated.
agent: Refunded ord_881 in full. The repeat refund was refused: ALREADY REQUESTED (retry_unsafe): this exact action was submitted before and was not repeated.
decision decision_01a15c598dcb7048aa807c818fb7b8d0 (refunded)
run completed
evidence: budget used {'cost_units': 100, 'replans': 0, 'tokens': 4000, 'tool_calls': 2}, <n> signed audit entries
```

## Approval

```sh
./examples/frameworks/run.sh openai-agents --approval
```

With `--approval` the run is admitted for a refund above the pack's 3,000 threshold, so
the gateway gates every call of the run, the lookup included, on an exact approval. The
gateway decides only when a call arrives, after the SDK's own `needs_approval` point,
and a running tool cannot raise an SDK interruption. So the pause waits inside the tool
call (`awaiting_reviewer`): `approve(paused)` plays the reviewer in the development
approval service, then the identical call (same arguments, same operation key) is
re-sent and redeems that approval. The model never sees the pause; the SDK's
interruption and checkpoint for the refund are unchanged:

```
admitted run_openai_agents_1792551980932 (executor generation 2)
paused for approval: dev_approval:d4af686049c9
reviewer approved dev_approval:d4af686049c9
resumed: re-sending the same lookup_order call
tool lookup_order -> {'amount_minor': 120000, 'currency': 'INR', 'customer_id': 'cus_77', 'order_id': 'ord_881', 'refundable': True, 'status': 'delivered_damaged'}
SDK approval requested (local, before ContextOS): issue_refund({"order_id":"ord_881","customer_id":"cus_77","amount_minor":120000})
approved; checkpoint revision 1
paused for approval: dev_approval:aa6ac12c8b74
reviewer approved dev_approval:aa6ac12c8b74
resumed: re-sending the same issue_refund call
tool issue_refund -> {'refund_id': 'rf_ord_881'}
SDK approval requested (local, before ContextOS): issue_refund({"order_id":"ord_881","customer_id":"cus_77","amount_minor":120000})
approved; checkpoint revision 2
tool issue_refund -> ALREADY REQUESTED (retry_unsafe): this exact action was submitted before and was not repeated.
agent: Refunded ord_881 in full. The repeat refund was refused: ALREADY REQUESTED (retry_unsafe): this exact action was submitted before and was not repeated.
decision decision_01a15c6c8fcf75c1a6407f77569322f4 (refunded)
run completed
evidence: budget used {'cost_units': 100, 'replans': 0, 'tokens': 4000, 'tool_calls': 2}, <n> signed audit entries
```

## What is governed

- **Tools.** `lookup_order` and `issue_refund` are `governed_tool` functions wrapped
  with `function_tool`. Their bodies never run; each call goes to `contextosd`, which
  authorizes, dispatches, records and audits it. The refund is keyed `refund:ord_881`,
  so the second call cannot apply twice.
- **Model calls.** `BudgetedProvider` wraps every model the runner resolves, so each
  call (and each SDK retry of it) reserves 1,000 tokens first and settles after, even
  when it raises: four calls here, 4,000 tokens. On the event loop the run is an
  `AsyncRun` (`contextos.aio`); the sync tools run in the SDK's worker thread.
- **Outcomes.** `failure_error_function=governed_failure` turns refusals and a paused
  repeat (`paused.kind == "duplicate"`) into `refusal()` text, instead of the SDK's
  default "Please try again". A pause whose `kind` is `approval`, `input` or
  `unknown_outcome` is re-raised and stops the run (the SDK wraps it in `UserError`);
  an approval pause first waits in the tool call for the reviewer (see Approval).
- **Approval and checkpoint.** `needs_approval` interrupts before each refund. The
  approved `RunState` (`state.to_json()`) is saved as the run's checkpoint, so another
  executor can `take_over()` and resume it with `RunState.from_json`. The gateway still
  decides: the second approved refund is refused.
- **Decision.** `finish()` records the DecisionRecord (its tool lineage verified by the
  gateway), completes the run and reads its evidence.

## With a real model

```sh
OPENAI_API_KEY=... ./examples/frameworks/run.sh openai-agents
```

uses `gpt-6.1-sol` through the SDK's default provider, with the shared `GOAL` and
`INSTRUCTIONS`; set `OPENAI_MODEL` for another model. Tracing is then on, without tool
arguments or outputs (`trace_include_sensitive_data=False`). The script auto-approves
interruptions; put a reviewer there.

The integration guide is [docs/integrations/openai-agents.md](../../../docs/integrations/openai-agents.md).
The TypeScript version is [../openai-agents-js](../openai-agents-js).
