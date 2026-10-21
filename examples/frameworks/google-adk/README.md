# Google ADK (Python) governed by ContextOS

An ADK `LlmAgent` run by ADK's own `InMemoryRunner`, refunding order `ord_881`. ADK
drives the loop; `contextosd` decides what each step may do.

```sh
./examples/frameworks/run.sh google-adk
```

Without a Google key, a scripted `BaseLlm` plays the model. It looks the order up,
refunds its `amount_minor`, then tries the refund again. Output from a real run:

```
admitted run_google_adk_1792550605199 (executor generation 2)
model: scripted (set GOOGLE_API_KEY for Gemini)
tool lookup_order: {"amount_minor": 120000, "currency": "INR", "customer_id": "cus_77", "order_id": "ord_881", "refundable": true, "status": "delivered_damaged"}
tool issue_refund: {"refund_id": "rf_ord_881"}
tool issue_refund: ALREADY REQUESTED (retry_unsafe): this exact action was submitted before and was not repeated.
agent: Refunded order ord_881 in full; the repeated refund was refused, so it was issued once.
decision decision_01a15c5792a2756eac9b39ca6d1f7d56 (refunded)
run completed
evidence: budget used {'cost_units': 100, 'replans': 0, 'tokens': 4000, 'tool_calls': 2}, 10 signed audit entries
```

## Approval

```sh
./examples/frameworks/run.sh google-adk --approval
```

With `--approval` the run is admitted for a refund above the pack's 3,000 threshold, so
every governed call needs an exact approval. `on_tool_error_callback` calls
`tool_context.request_confirmation(...)` and sets `skip_summarization`, so the
invocation ends with ADK's `adk_request_confirmation` call. `approve()` plays the
reviewer in the development approval service, then the client sends the confirmation
`FunctionResponse` (`{"confirmed": True}`); ADK runs the same tool call again, which
re-sends the identical governed call (same arguments, same operation key) and the
gateway redeems the approval. The model's later steps run as before:

```
admitted run_google_adk_1792551965281 (executor generation 2)
model: scripted (set GOOGLE_API_KEY for Gemini)
tool lookup_order: awaiting approval
paused for approval: dev_approval:aa53a88bf9bc (lookup_order {'order_id': 'ord_881'})
reviewer approved dev_approval:aa53a88bf9bc
resuming with the confirmation response
tool lookup_order: {"amount_minor": 120000, "currency": "INR", "customer_id": "cus_77", "order_id": "ord_881", "refundable": true, "status": "delivered_damaged"}
tool issue_refund: awaiting approval
paused for approval: dev_approval:8fa6bc7dbc51 (issue_refund {'order_id': 'ord_881', 'customer_id': 'cus_77', 'amount_minor': 120000})
reviewer approved dev_approval:8fa6bc7dbc51
resuming with the confirmation response
tool issue_refund: {"refund_id": "rf_ord_881"}
tool issue_refund: ALREADY REQUESTED (retry_unsafe): this exact action was submitted before and was not repeated.
agent: Refunded order ord_881 in full; the repeated refund was refused, so it was issued once.
decision decision_01a15c6c5341731bb5bacf3b4b6cf5ed (refunded)
run completed
evidence: budget used {'cost_units': 100, 'replans': 0, 'tokens': 4000, 'tool_calls': 2}, 12 signed audit entries
```

## What is governed

- **Tools.** `lookup_order` and `issue_refund` are `governed_tool` functions from
  `_shared/demo.py`, wrapped in ADK `FunctionTool`s. ADK builds their declarations from
  the signatures and docstrings. Their bodies never run locally: each call goes through
  the gateway, which authorizes it, dispatches it and audits it.
- **Exactly once.** The refund is keyed `refund:ord_881`. The model's second refund
  maps to the same operation, so the gateway refuses it (`retry_unsafe`).
- **Refusals the model can read.** `on_tool_error_callback` turns a governed refusal
  into a tool result that says the action did not happen (or, for a repeat, that it was
  already requested and not repeated). An approval pause becomes
  ADK's tool confirmation. An unknown outcome is reconciled. None of them is retried.
- **Model budget.** `before_model_callback` reserves 1,000 tokens from the run's budget
  before each model call, and answers in the model's place if the run cannot afford
  it. `after_model_callback` settles the reservation. The four model calls account for
  the 4,000 tokens shown.
- **Decision and evidence.** `finish` records the signed DecisionRecord, whose tool
  lineage the gateway verifies, completes the run and reads its evidence.

## Use a real model

Set a Gemini API key from Google AI Studio:

```sh
GOOGLE_API_KEY=... ./examples/frameworks/run.sh google-adk
```

The default model is `gemini-3.8-flash`; set `GEMINI_MODEL` to use another. For Google
Cloud (Vertex AI), set `GOOGLE_GENAI_USE_ENTERPRISE=true` (older releases read
`GOOGLE_GENAI_USE_VERTEXAI`), `GOOGLE_CLOUD_PROJECT` and `GOOGLE_CLOUD_LOCATION`, and
authenticate with `gcloud auth application-default login`.
A real model may not try the refund twice, so the refusal line may not appear.

For the full integration (approvals, checkpoints, sub-agents, MCP) see
[docs/integrations/google-adk.md](../../../docs/integrations/google-adk.md).
