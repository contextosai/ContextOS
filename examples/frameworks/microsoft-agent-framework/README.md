# Microsoft Agent Framework

A Microsoft Agent Framework `Agent` (`agent-framework-core` 1.22, the successor to
AutoGen and Semantic Kernel agents) runs the quickstart's refund of order `ord_881`.
The tool-calling loop is the framework's own; ContextOS governs what it does.

```sh
./examples/frameworks/run.sh microsoft-agent-framework
```

```text
Function issue_refund failed (ToolPaused).
admitted run_maf_1792550485897 (executor generation 2)
lookup_order({'order_id': 'ord_881'}) -> {"amount_minor": 120000, "currency": "INR", "customer_id": "cus_77", "order_id": "ord_881", "refundable": true, "status": "delivered_damaged"}
issue_refund({'order_id': 'ord_881', 'customer_id': 'cus_77', 'amount_minor': 120000}) -> {"refund_id": "rf_ord_881"}
issue_refund({'order_id': 'ord_881', 'customer_id': 'cus_77', 'amount_minor': 120000}) -> ALREADY REQUESTED (retry_unsafe): this exact action was submitted before and was not repeated.
agent: Refunded ord_881 in full. The repeated refund was refused: ALREADY REQUESTED (retry_unsafe): this exact action was submitted before and was not repeated.
decision decision_01a15c55bfbc77d68fb9b43838f2c4ca (refunded)
run completed
evidence: budget used {'cost_units': 100, 'replans': 0, 'tokens': 4000, 'tool_calls': 2}, 10 signed audit entries
```

(The first line is the framework's own log of the refused call, on stderr.)

What is governed:

- **Tools.** `lookup_order` and `issue_refund` are the run's governed functions,
  registered with `tool`. contextosd authorizes, dispatches and audits each call; the
  refund cites the order snapshot and is keyed `refund:ord_881`, so the second refund
  is refused (`retry_unsafe`).
- **Outcomes.** Function middleware turns a call that did not complete into a tool
  result that says it did not happen. A pause for approval (`paused.kind == "approval"`)
  becomes the framework's `function_approval_request`; an approved replay is the same
  operation and is governed again. Any other pause is reported, never retried.
- **Model calls.** Chat middleware reserves 1,000 tokens before every model call and
  settles after (`tokens: 4000` for four calls); `budget_exhausted` ends the loop.
- **Decision.** `finish` records the DecisionRecord (its tool lineage verified by the
  gateway), completes the run and reads its evidence.

Without `OPENAI_API_KEY` the model is a scripted chat client built on `BaseChatClient`
with the framework's function-invocation and middleware layers. With the key set, the
agent uses `OpenAIChatClient` from `agent-framework-openai` (`OPENAI_MODEL`, default
`gpt-6.1-sol`):

```sh
OPENAI_API_KEY=sk-… ./examples/frameworks/run.sh microsoft-agent-framework
```

Implementation guide: [docs/integrations/microsoft-agent-framework.md](../../../docs/integrations/microsoft-agent-framework.md).
