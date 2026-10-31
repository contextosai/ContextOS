# LlamaIndex

A LlamaIndex `FunctionAgent` (`llama-index-core` 0.14) runs the quickstart's refund of
order `ord_881`. The agent loop is LlamaIndex's own; ContextOS governs what it does.

```sh
./examples/frameworks/run.sh llamaindex
```

```text
admitted run_llamaindex_1792550484648 (executor generation 2)
lookup_order({'order_id': 'ord_881'}) -> {"amount_minor": 120000, "currency": "INR", "customer_id": "cus_77", "order_id": "ord_881", "refundable": true, "status": "delivered_damaged"}
issue_refund({'order_id': 'ord_881', 'customer_id': 'cus_77', 'amount_minor': 120000}) -> {"refund_id": "rf_ord_881"}
issue_refund({'order_id': 'ord_881', 'customer_id': 'cus_77', 'amount_minor': 120000}) -> ALREADY REQUESTED (retry_unsafe): this exact action was submitted before and was not repeated.
agent: Refunded ord_881 in full. The repeated refund was refused: ALREADY REQUESTED (retry_unsafe): this exact action was submitted before and was not repeated.
decision decision_01a15c55bb137555a967bf4e3ec3eb71 (refunded)
run completed
evidence: budget used {'cost_units': 100, 'replans': 0, 'tokens': 4000, 'tool_calls': 2}, <n> signed audit entries
```

What is governed:

- **Tools.** `lookup_order` and `issue_refund` are `FunctionTool`s over the run's
  governed functions, async through `contextos.aio`'s `AsyncRun`. contextosd authorizes, dispatches and audits each call; the
  refund cites the order snapshot and is keyed `refund:ord_881`, so the second refund
  is refused (`retry_unsafe`) and the model is told it was already requested and not
  repeated.
- **Approvals.** A call paused for approval (`paused.kind == "approval"`) waits on the
  workflow's `InputRequiredEvent` / `HumanResponseEvent` (see [Approval](#approval));
  the replayed step re-sends the identical call, which redeems the exact approval. Any
  other pause is reported, never retried.
- **Model calls.** `BudgetedLLM` wraps the agent's LLM: each of the four model calls
  reserved 1,000 tokens from the run's budget first (`tokens: 4000` above).
- **Decision.** `finish` records the DecisionRecord (its tool lineage verified by the
  gateway), completes the run and reads its evidence.

## Approval

```sh
./examples/frameworks/run.sh llamaindex --approval
```

The run is admitted for a refund above the pack's 3,000 threshold, so the gateway holds
every call of the run for an exact approval. Each pause becomes an `InputRequiredEvent`
from `ctx.wait_for_event`; the event loop plays the reviewer (`approve` grants the
request in the development approval service) and sends the `HumanResponseEvent`; the
workflow replays the tool step, which re-sends the identical call (same arguments, same
idempotency key) and completes:

```text
admitted run_llamaindex_1792552165015 (executor generation 2)
paused for approval: dev_approval:44fb6e9cea0e (approve lookup_order{'order_id': 'ord_881'}?)
reviewer approved dev_approval:44fb6e9cea0e
resuming: re-sending the identical call (lookup:ord_881)
lookup_order({'order_id': 'ord_881'}) -> {"amount_minor": 120000, "currency": "INR", "customer_id": "cus_77", "order_id": "ord_881", "refundable": true, "status": "delivered_damaged"}
paused for approval: dev_approval:d89e08a172e6 (approve issue_refund{'order_id': 'ord_881', 'customer_id': 'cus_77', 'amount_minor': 120000}?)
reviewer approved dev_approval:d89e08a172e6
resuming: re-sending the identical call (refund:ord_881)
issue_refund({'order_id': 'ord_881', 'customer_id': 'cus_77', 'amount_minor': 120000}) -> {"refund_id": "rf_ord_881"}
issue_refund({'order_id': 'ord_881', 'customer_id': 'cus_77', 'amount_minor': 120000}) -> ALREADY REQUESTED (retry_unsafe): this exact action was submitted before and was not repeated.
agent: Refunded ord_881 in full. The repeated refund was refused: ALREADY REQUESTED (retry_unsafe): this exact action was submitted before and was not repeated.
decision decision_01a15c6f5f0f73cdbd99dbcbbdf4daf9 (refunded)
run completed
evidence: budget used {'cost_units': 100, 'replans': 0, 'tokens': 4000, 'tool_calls': 2}, <n> signed audit entries
```

## With a real model

Without `OPENAI_API_KEY` the model is a scripted `MockFunctionCallingLLM` that emits
the tool calls above. With the key set, the agent uses `llama-index-llms-openai`
(`OPENAI_MODEL`, default `gpt-6.1-sol`):

```sh
OPENAI_API_KEY=sk-… ./examples/frameworks/run.sh llamaindex
```

Implementation guide: [docs/integrations/llamaindex.md](../../../docs/integrations/llamaindex.md).
