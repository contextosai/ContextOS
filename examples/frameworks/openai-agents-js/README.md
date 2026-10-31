# OpenAI Agents SDK (TypeScript) under ContextOS

An `Agent` driven by the SDK's own loop (`Runner.run`, `@openai/agents` 0.21) that
refunds the quickstart's damaged order through `contextosd`. It is the TypeScript twin
of [../openai-agents](../openai-agents): same tools, budget, outcome mapping, approval
and checkpoint. `agent.ts` runs on Node 24 with type stripping, no build step.

```sh
./examples/frameworks/run.sh openai-agents-js
```

Without `OPENAI_API_KEY` the SDK's scripted test model (`ScriptedModel` from
`@openai/agents/testing`) looks the order up, refunds it, then asks for the refund
again. The gateway refuses the repeat, and the model is told it was already requested
and not repeated:

```
admitted run_openai_agents_js_1792550736578 (executor generation 2)
tool lookup_order -> {"amount_minor":120000,"currency":"INR","customer_id":"cus_77","order_id":"ord_881","refundable":true,"status":"delivered_damaged"}
SDK approval requested (local, before ContextOS): issue_refund({"order_id":"ord_881","customer_id":"cus_77","amount_minor":120000})
approved; checkpoint revision 1
tool issue_refund -> {"refund_id":"rf_ord_881"}
SDK approval requested (local, before ContextOS): issue_refund({"order_id":"ord_881","customer_id":"cus_77","amount_minor":120000})
approved; checkpoint revision 2
tool issue_refund -> ALREADY REQUESTED (retry_unsafe): this exact action was submitted before and was not repeated.
agent: Refunded ord_881 in full. The repeat refund was refused: ALREADY REQUESTED (retry_unsafe): this exact action was submitted before and was not repeated.
decision decision_01a15c59930671d288f2b086b9c6327f (refunded)
run completed
evidence: budget used {"cost_units":100,"replans":0,"tokens":4000,"tool_calls":2}, <n> signed audit entries
```

## Approval

```sh
./examples/frameworks/run.sh openai-agents-js --approval
```

With `--approval` the run is admitted for a refund above the pack's 3,000 threshold, so
the gateway gates every call of the run, the lookup included, on an exact approval. The
gateway decides only when a call arrives, after the SDK's own `needsApproval` point,
and a running tool cannot raise an SDK interruption. So the pause waits inside the tool
call (`awaitingReviewer`): `approve(paused)` plays the reviewer in the development
approval service, then the identical call (same arguments, same operation key) is
re-sent and redeems that approval. The model never sees the pause; the SDK's
interruption and checkpoint for the refund are unchanged:

```
admitted run_openai_agents_js_1792552003266 (executor generation 2)
paused for approval: dev_approval:6a3c17af6d67
reviewer approved dev_approval:6a3c17af6d67
resumed: re-sending the same lookup_order call
tool lookup_order -> {"amount_minor":120000,"currency":"INR","customer_id":"cus_77","order_id":"ord_881","refundable":true,"status":"delivered_damaged"}
SDK approval requested (local, before ContextOS): issue_refund({"order_id":"ord_881","customer_id":"cus_77","amount_minor":120000})
approved; checkpoint revision 1
paused for approval: dev_approval:bdbf1e9020d0
reviewer approved dev_approval:bdbf1e9020d0
resumed: re-sending the same issue_refund call
tool issue_refund -> {"refund_id":"rf_ord_881"}
SDK approval requested (local, before ContextOS): issue_refund({"order_id":"ord_881","customer_id":"cus_77","amount_minor":120000})
approved; checkpoint revision 2
tool issue_refund -> ALREADY REQUESTED (retry_unsafe): this exact action was submitted before and was not repeated.
agent: Refunded ord_881 in full. The repeat refund was refused: ALREADY REQUESTED (retry_unsafe): this exact action was submitted before and was not repeated.
decision decision_01a15c6ce71272728c853a1aeb6dc393 (refunded)
run completed
evidence: budget used {"cost_units":100,"replans":0,"tokens":4000,"tool_calls":2}, <n> signed audit entries
```

## What is governed

- **Tools.** `tool({ execute })` calls the shared `governedTool` functions; nothing runs
  locally. The refund is keyed `refund:ord_881`, so the repeat cannot apply twice.
- **Model calls.** `budgetedProvider` wraps every model the runner resolves:
  `getResponse` runs inside `budgeted()`, `getStreamedResponse` reserves before the
  first event and settles in `finally`. Four calls, 4,000 tokens.
- **Outcomes.** `errorFunction: governedFailure` returns `refusal()` text for refusals
  and a paused repeat (`kind` `"duplicate"`), instead of the SDK's default "Please try
  again"; it rethrows a pause whose `kind` is `approval`, `input` or `unknown_outcome`,
  which stops the run. An approval pause first waits in the tool call for the reviewer
  (see Approval).
- **Approval and checkpoint.** `needsApproval: true` interrupts before each refund; the
  approved `result.state` (`state.toString()`) is saved as the run's checkpoint and the
  run resumes with `runner.run(agent, state)`. The gateway still decides.
- **Decision.** `finish()` records the DecisionRecord, completes the run and reads its
  evidence.

## With a real model

```sh
OPENAI_API_KEY=... ./examples/frameworks/run.sh openai-agents-js
```

uses `gpt-6.1-sol` through `OpenAIProvider`; set `OPENAI_MODEL` for another model.
Tracing is then on, without tool inputs or outputs (`traceIncludeSensitiveData: false`).
The script auto-approves interruptions; put a reviewer there.

The integration guide is [docs/integrations/openai-agents.md](../../../docs/integrations/openai-agents.md).
