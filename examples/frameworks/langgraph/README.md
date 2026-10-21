# LangGraph under ContextOS

A LangGraph agent built with LangChain's `create_agent` (LangGraph 1.2, LangChain 1.4)
that refunds the quickstart's damaged order through `contextosd`. The agent loop is
LangGraph's; ContextOS enters through one `AgentMiddleware`.

```sh
./examples/frameworks/run.sh langgraph
```

Without `ANTHROPIC_API_KEY` a scripted fake chat model (LangChain's
`GenericFakeChatModel`, given tools) drives the same graph: it looks the order up,
refunds it, then asks for the refund again. The gateway refuses the repeat and the
model is told it was already requested and not repeated:

```
admitted run_langgraph_1792550477081 (executor generation 2)
checkpoint revision 1: thread run_langgraph_1792550477081
  lookup_order -> {"amount_minor": 120000, "currency": "INR", "customer_id": "cus_77", "order_id": "ord_881", "refundable": true, "status": "delivered_damaged"}
  issue_refund -> {"refund_id": "rf_ord_881"}
  issue_refund -> ALREADY REQUESTED (retry_unsafe): this exact action was submitted before and was not repeated.
agent: Order ord_881 was refundable; I refunded it once. A repeat refund was refused and did not happen.
decision decision_01a15c559d47735db4259794ea890767 (refunded)
run completed
evidence: budget used {'cost_units': 100, 'replans': 0, 'tokens': 4000, 'tool_calls': 2}, 11 signed audit entries
```

## What is governed

- **Tools.** `lookup_order` and `issue_refund` are `governed_tool` functions passed to
  `create_agent` as plain callables. Their bodies never run; each call goes to
  `contextosd`, which authorizes, dispatches, records and audits it. The refund is keyed
  `refund:ord_881`, so the second call cannot apply twice.
- **Model calls.** `wrap_model_call` reserves 1,000 tokens from the run's budget before
  every model call (four here, 4,000 tokens). When the budget is spent the reservation
  is refused and the loop stops, whatever the model wants.
- **Outcomes.** `wrap_tool_call` turns `ToolBlocked`, `ToolRejected`, `ToolFailed` and a
  paused duplicate or unknown outcome into an error `ToolMessage` with `refusal()` text. A
  pause for approval (`paused.kind == "approval"`) becomes a LangGraph `interrupt()`;
  resuming with `Command(resume=...)` re-sends the same governed call, which runs only once approved.
- **Decision.** `finish()` records the DecisionRecord (its tool lineage verified by the
  gateway), completes the run and reads its evidence.

## With a real model

```sh
ANTHROPIC_API_KEY=... ./examples/frameworks/run.sh langgraph
```

uses `anthropic:claude-sonnet-5-5` with the shared `GOAL` and `INSTRUCTIONS`. Set
`LANGGRAPH_MODEL` to any `provider:model` string `init_chat_model` accepts (and add that
provider's `langchain-*` package to `requirements.txt`) to use another model.

The integration guide is [docs/integrations/langgraph.md](../../../docs/integrations/langgraph.md).
