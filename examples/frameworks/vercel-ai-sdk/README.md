# Vercel AI SDK under ContextOS

An AI SDK 7 agent (`ToolLoopAgent`, `ai@7.0.147`) that refunds the quickstart's damaged
order through `contextosd`. The agent loop is the AI SDK's; ContextOS enters through the
tools' `execute` functions and one language-model middleware.

```sh
./examples/frameworks/run.sh vercel-ai-sdk
```

Without `OPENAI_API_KEY` the AI SDK's own `MockLanguageModelV4` (from `ai/test`) drives
the same loop, scripted from the tool results it has seen: it looks the order up,
refunds `amount_minor`, then asks for the refund again. The gateway refuses the repeat
and the model is told it was already requested:

```
admitted run_vercel_ai_sdk_1792550486958 (executor generation 2)
lookupOrder -> {"amount_minor":120000,"currency":"INR","customer_id":"cus_77","order_id":"ord_881","refundable":true,"status":"delivered_damaged"}
issueRefund -> {"refund_id":"rf_ord_881"}
issueRefund -> ALREADY REQUESTED (retry_unsafe): this exact action was submitted before and was not repeated.
agent (4 steps): Refunded 120000 minor units for ord_881. A second refund was refused: ALREADY REQUESTED (retry_unsafe): this exact action was submitted before and was not repeated.
decision decision_01a15c55c3e674cfaeee92153df5b796 (refunded)
run completed
evidence: budget used {"cost_units":100,"replans":0,"tokens":4000,"tool_calls":2}, 10 signed audit entries
```

## What is governed

- **Tools.** `lookupOrder` and `issueRefund` are AI SDK `tool({ inputSchema, execute })`s
  whose `execute` calls a `governedTool` function. Nothing runs locally: `contextosd`
  authorizes, dispatches, records and audits each call. The refund is keyed
  `refund:ord_881`, so the second call cannot apply twice.
- **Model calls.** A `wrapLanguageModel` middleware reserves 1,000 tokens from the run's
  budget before every provider call (`wrapGenerate`, and `wrapStream` settling when the
  stream ends) — four calls here, 4,000 tokens. When the budget is spent the
  reservation is refused and the loop stops, whatever the model wants.
- **Outcomes.** `ToolBlocked`, `ToolRejected`, `ToolFailed` and a paused repeat
  (`retry_unsafe`) become a tool result with `refusal()` text. A pause that waits on
  someone (`kind` is `approval`, `input` or `unknown_outcome`)
  also stops the loop through a `stopWhen` condition and leaves the run open.
- **Ordering.** `toolCallConcurrency: 1` keeps effectful calls in one step sequential.
- **Decision.** `finish()` records the DecisionRecord (its tool lineage verified by the
  gateway), completes the run and reads its evidence. If the loop throws, the run is
  failed.

## With a real model

```sh
OPENAI_API_KEY=... ./examples/frameworks/run.sh vercel-ai-sdk
```

uses `@ai-sdk/openai` with `gpt-6.1-sol` (set `OPENAI_MODEL` for another id) and the shared
`GOAL` and `INSTRUCTIONS`. Any AI SDK provider works the same way: the middleware wraps
whatever `LanguageModel` you pass.

The integration guide is [docs/integrations/vercel-ai-sdk.md](../../../docs/integrations/vercel-ai-sdk.md).
