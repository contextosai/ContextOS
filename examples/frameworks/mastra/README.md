# Mastra under ContextOS

A Mastra `Agent` (`@mastra/core@1.78.0`) that refunds the quickstart's damaged order
through `contextosd`. The agent loop is Mastra's; ContextOS enters through the tools'
`execute` functions and one processor that budgets every model call.

```sh
./examples/frameworks/run.sh mastra
```

Without `OPENAI_API_KEY` a minimal scripted AI SDK model (the v4 model specification,
which Mastra accepts directly) drives the same loop: it looks the order up, refunds
`amount_minor`, then asks for the refund again. The gateway refuses the repeat and the
model is told it was already requested:

```
admitted run_mastra_1792550488237 (executor generation 2)
lookupOrder -> {"amount_minor":120000,"currency":"INR","customer_id":"cus_77","order_id":"ord_881","refundable":true,"status":"delivered_damaged"}
issueRefund -> {"refund_id":"rf_ord_881"}
issueRefund -> ALREADY REQUESTED (retry_unsafe): this exact action was submitted before and was not repeated.
agent (4 steps): Refunded 120000 minor units for ord_881. A second refund was refused: ALREADY REQUESTED (retry_unsafe): this exact action was submitted before and was not repeated.
decision decision_01a15c55c8fe734ca756b3f7f00f54e4 (refunded)
run completed
evidence: budget used {"cost_units":100,"replans":0,"tokens":4000,"tool_calls":2}, 10 signed audit entries
```

The first install pulls about 140 MB (`@mastra/core` brings Hono, the A2A SDK, PostHog
and three AI SDK provider generations); no Mastra server, storage or network service is
needed to run it.

## What is governed

- **Tools.** `lookupOrder` and `issueRefund` are Mastra `createTool()`s whose `execute`
  calls a `governedTool` function. Nothing runs locally: `contextosd` authorizes,
  dispatches, records and audits each call. The refund is keyed `refund:ord_881`, so the
  second call cannot apply twice.
- **Model calls.** A processor (`inputProcessors`) reserves 1,000 tokens from the run's
  budget in `processLLMRequest`, just before every provider call (each attempt, Mastra's
  retries included), and settles in `processLLMResponse` — four calls here, 4,000
  tokens. When the budget is spent the reservation is refused and the loop stops
  before the provider is contacted.
- **Outcomes.** `ToolBlocked`, `ToolRejected`, `ToolFailed` and a paused repeat
  (`retry_unsafe`) become a tool result with `refusal()` text. A pause that waits on
  someone (`kind` is `approval`, `input` or `unknown_outcome`)
  ends the turn through `stopWhen` and leaves the run open.
- **Ordering.** `toolCallConcurrency: 1` keeps effectful calls in one step sequential.
- **Decision.** `finish()` records the DecisionRecord (its tool lineage verified by the
  gateway), completes the run and reads its evidence. If the loop throws, the run is
  failed.

## With a real model

```sh
OPENAI_API_KEY=... ./examples/frameworks/run.sh mastra
```

uses Mastra's model router with `openai/gpt-6.1-sol` (set `MASTRA_MODEL` for another
`provider/model` id from [mastra.ai/models](https://mastra.ai/models); the example
leaves its scripted mode only when `OPENAI_API_KEY` is set). No provider package is
needed, and the processor budgets whichever model the router resolves.

The integration guide is [docs/integrations/mastra.md](../../../docs/integrations/mastra.md).
