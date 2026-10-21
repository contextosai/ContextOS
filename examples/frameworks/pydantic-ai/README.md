# Pydantic AI, governed by ContextOS

`agent.py` runs Pydantic AI's own agent loop (`Agent.run_sync`) on the quickstart's
refund of order `ord_881`, with `contextosd` governing every tool call and model
request:

- **Tools**: `lookup_order` and `issue_refund` are the shared `governed_tool`
  functions in a `FunctionToolset`, wrapped by `ContextOSToolset`. Each call is
  authorized, dispatched, recorded and audited by `contextosd`; the bodies never run
  locally. The wrapper turns outcomes into what the model should see: a refusal
  becomes a failed tool result (`ToolFailed`) saying the action did not happen, an
  approval pause becomes `ApprovalRequired`, and an unknown effect becomes
  `CallDeferred` for reconciliation. Nothing is turned into `ModelRetry`.
- **Model**: `BudgetedModel` (a `WrapperModel`) reserves 1,000 tokens from the run's
  budget before every request and settles after it. A run that cannot afford the next
  request stops with `UsageLimitExceeded` before anything is sent.
- **Decision**: the run ends with a DecisionRecord whose tool lineage the gateway
  verifies, then completes and prints its evidence.

```sh
./examples/frameworks/run.sh pydantic-ai
```

Without `OPENAI_API_KEY` or `ANTHROPIC_API_KEY`, a scripted `FunctionModel` drives
the loop: it looks the order up, refunds its `amount_minor`, then asks for the same
refund again. The gateway refuses the repeat (`retry_unsafe`) and the model reads the
refusal. Output from a real run:

```text
admitted run_pydantic_ai_1792550525700 (executor generation 2)
tool lookup_order: {'amount_minor': 120000, 'currency': 'INR', 'customer_id': 'cus_77', 'order_id': 'ord_881', 'refundable': True, 'status': 'delivered_damaged'}
tool issue_refund: {'refund_id': 'rf_ord_881'}
tool issue_refund: ALREADY REQUESTED (retry_unsafe): this exact action was submitted before and was not repeated.
agent: Refunded ord_881 ({'refund_id': 'rf_ord_881'}). The repeated refund was refused by the gateway: ALREADY REQUESTED (retry_unsafe): this exact action was submitted before and was not repeated.
decision decision_01a15c565b3e73f5a2a705b236d5bb28 (refunded)
run completed
evidence: budget used {'cost_units': 100, 'replans': 0, 'tokens': 4000, 'tool_calls': 2}, 10 signed audit entries
```

Four model requests reserved 4,000 tokens; two tool calls were dispatched. The
refused repeat is not a new dispatch.

**Approval**

```sh
./examples/frameworks/run.sh pydantic-ai --approval
```

With `--approval` the run is admitted for a refund above the pack's 3,000 threshold, so
every governed call needs an exact approval. Each pause raises `ApprovalRequired`, and the
run ends with `DeferredToolRequests.approvals`. `approve()` plays the reviewer in the
development approval service, then a second `run_sync` over `result.all_messages()` with
`DeferredToolResults(approvals={tool_call_id: True})` re-sends the identical call (same
arguments, same operation key) and the gateway redeems the approval. The model's later
steps run as before:

```
admitted run_pydantic_ai_1792551960906 (executor generation 2)
tool lookup_order: awaiting approval
paused for approval: dev_approval:5f4a60415cd6 (lookup_order {'order_id': 'ord_881'})
reviewer approved dev_approval:5f4a60415cd6
resuming with DeferredToolResults
tool lookup_order: {'amount_minor': 120000, 'currency': 'INR', 'customer_id': 'cus_77', 'order_id': 'ord_881', 'refundable': True, 'status': 'delivered_damaged'}
tool issue_refund: awaiting approval
paused for approval: dev_approval:16a082b24fd7 (issue_refund {'order_id': 'ord_881', 'customer_id': 'cus_77', 'amount_minor': 120000})
reviewer approved dev_approval:16a082b24fd7
resuming with DeferredToolResults
tool issue_refund: {'refund_id': 'rf_ord_881'}
tool issue_refund: ALREADY REQUESTED (retry_unsafe): this exact action was submitted before and was not repeated.
agent: Refunded ord_881 ({'refund_id': 'rf_ord_881'}). The repeated refund was refused by the gateway: ALREADY REQUESTED (retry_unsafe): this exact action was submitted before and was not repeated.
decision decision_01a15c6c418e708b83168e9c159e448c (refunded)
run completed
evidence: budget used {'cost_units': 100, 'replans': 0, 'tokens': 4000, 'tool_calls': 2}, 12 signed audit entries
```

**With a real model**: set `ANTHROPIC_API_KEY` (uses `anthropic:claude-sonnet-5-5`)
or `OPENAI_API_KEY` (uses `openai:gpt-6.1-sol`). Set `PYDANTIC_AI_MODEL` to any other
Pydantic AI model string. A real model decides for itself whether to refund; if it
tries to repeat the refund, it gets the same refusal.

Pinned: `pydantic-ai-slim[openai,anthropic]==2.58.0`. The full guide is
[docs/integrations/pydantic-ai.md](../../../docs/integrations/pydantic-ai.md).
