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
evidence: budget used {"cost_units":100,"replans":0,"tokens":4000,"tool_calls":2}, <n> signed audit entries
```

The first install pulls about 140 MB (`@mastra/core` brings Hono, the A2A SDK, PostHog
and three AI SDK provider generations); no Mastra server, storage (beyond the in-memory
store approval mode adds) or network service is
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
  (`retry_unsafe`) become a tool result with `refusal()` text. An approval pause
  suspends the agent (`context.agent.suspend`) until it is resumed (below); a pause
  that waits on anything else (`kind` is `input` or `unknown_outcome`) ends the turn
  through `stopWhen` and leaves the run open.
- **Ordering.** `toolCallConcurrency: 1` keeps effectful calls in one step sequential.
- **Decision.** `finish()` records the DecisionRecord (its tool lineage verified by the
  gateway), completes the run and reads its evidence. If the loop throws, the run is
  failed.

## Approval

```sh
./examples/frameworks/run.sh mastra --approval
```

The run is admitted for a refund above the pack's 3,000 threshold, so the gateway holds
every call of the run for an exact approval. The tool suspends the agent on the pause
(`generate` returns `finishReason: "suspended"`); the example plays the reviewer
(`approve` grants the request in the development approval service) and calls
`agent.resumeGenerate({ approved: true }, { runId })`, which re-runs the tool: it
re-sends the identical call, which redeems the approval. Suspend/resume persists the
suspended run, so approval mode registers the agent with a `Mastra` instance on an
`InMemoryStore`:

```
admitted run_mastra_1792552172686 (executor generation 2)
lookupOrder -> paused for approval: dev_approval:be6afd03d471
reviewer approved dev_approval:be6afd03d471
resuming run 19f1b7b1-ac47-443f-8bbf-e0801c578056
lookupOrder -> {"amount_minor":120000,"currency":"INR","customer_id":"cus_77","order_id":"ord_881","refundable":true,"status":"delivered_damaged"}
issueRefund -> paused for approval: dev_approval:71a26231dd46
reviewer approved dev_approval:71a26231dd46
resuming run 19f1b7b1-ac47-443f-8bbf-e0801c578056
issueRefund -> {"refund_id":"rf_ord_881"}
issueRefund -> ALREADY REQUESTED (retry_unsafe): this exact action was submitted before and was not repeated.
agent (4 steps): Refunded 120000 minor units for ord_881. A second refund was refused: ALREADY REQUESTED (retry_unsafe): this exact action was submitted before and was not repeated.
decision decision_01a15c6f7cf370458f3aa2047bb58430 (refunded)
run completed
evidence: budget used {"cost_units":100,"replans":0,"tokens":4000,"tool_calls":2}, <n> signed audit entries
```

## With a real model

```sh
OPENAI_API_KEY=... ./examples/frameworks/run.sh mastra
```

uses Mastra's model router with `openai/gpt-6.1-sol` (set `MASTRA_MODEL` for another
`provider/model` id from [mastra.ai/models](https://mastra.ai/models); the example
leaves its scripted mode only when `OPENAI_API_KEY` is set). No provider package is
needed, and the processor budgets whichever model the router resolves.

The integration guide is [docs/integrations/mastra.md](../../../docs/integrations/mastra.md).
