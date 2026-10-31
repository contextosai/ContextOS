# CrewAI under ContextOS

A CrewAI crew (CrewAI 1.15: `Agent`, `Task`, sequential `Crew`, native tool calling)
that refunds the quickstart's damaged order through `contextosd`. The agent loop is
CrewAI's; ContextOS enters through the agent's tools, one `before_llm_call` hook and
two event-bus listeners.

```sh
./examples/frameworks/run.sh crewai
```

Without `OPENAI_API_KEY` a scripted model (a `BaseLLM` subclass that answers with native
tool calls and reports its calls on CrewAI's event bus like a provider) drives the same
crew. It looks the order up, refunds it, then asks for the same refund again. The gateway
refuses the repeat, and the model is told it was already requested and not repeated:

```
admitted run_crewai_1792550564166 (executor generation 2)
model: scripted
lookup_order({'order_id': 'ord_881'}) -> {'amount_minor': 120000, 'currency': 'INR', 'customer_id': 'cus_77', 'order_id': 'ord_881', 'refundable': True, 'status': 'delivered_damaged'}
issue_refund({'order_id': 'ord_881', 'customer_id': 'cus_77', 'amount_minor': 120000}) -> {'refund_id': 'rf_ord_881'}
issue_refund({'order_id': 'ord_881', 'customer_id': 'cus_77', 'amount_minor': 120000}) -> ALREADY REQUESTED (retry_unsafe): this exact action was submitted before and was not repeated.
crew answer: Refunded order ord_881 (120000 minor units) to cus_77. A repeated refund was refused by the gateway: ALREADY REQUESTED (retry_unsafe): this exact action was submitted before and was not repeated. (code: paused)
crewai recorded a failed call: issue_refund {'order_id': 'ord_881', 'customer_id': 'cus_77', 'amount_minor': 120000} (paused)
decision decision_01a15c56f18572de9446aefd8694bb84 (refunded)
run completed
evidence: budget used {'cost_units': 100, 'replans': 0, 'tokens': 4000, 'tool_calls': 2}, <n> signed audit entries
```

## Approval

```sh
./examples/frameworks/run.sh crewai --approval
```

With `--approval` the run is admitted for a refund above the pack's 3,000 threshold, so
every governed call needs an exact approval. The tool returns an `AWAITING APPROVAL`
`ToolFailure`, the agent answers that it is waiting, and CrewAI's human input step
(`Task(human_input=True)`, served by the `Reviewer` provider) hands the pause to the
reviewer: `approve()` grants it in the development approval service, and the approval is
appended as feedback to the same conversation. CrewAI runs the agent loop again, the
model re-sends the identical call (same arguments, same operation key) and the gateway
redeems the approval. The model's later steps run as before:

```
admitted run_crewai_1792551963060 (executor generation 2)
model: scripted
lookup_order({'order_id': 'ord_881'}) -> awaiting approval dev_approval:0bae4d3fb807
paused for approval: dev_approval:0bae4d3fb807
reviewer approved dev_approval:0bae4d3fb807
resuming the agent loop with the reviewer's decision
lookup_order({'order_id': 'ord_881'}) -> {'amount_minor': 120000, 'currency': 'INR', 'customer_id': 'cus_77', 'order_id': 'ord_881', 'refundable': True, 'status': 'delivered_damaged'}
issue_refund({'order_id': 'ord_881', 'customer_id': 'cus_77', 'amount_minor': 120000}) -> awaiting approval dev_approval:8fa1623d2ee5
paused for approval: dev_approval:8fa1623d2ee5
reviewer approved dev_approval:8fa1623d2ee5
resuming the agent loop with the reviewer's decision
issue_refund({'order_id': 'ord_881', 'customer_id': 'cus_77', 'amount_minor': 120000}) -> {'refund_id': 'rf_ord_881'}
issue_refund({'order_id': 'ord_881', 'customer_id': 'cus_77', 'amount_minor': 120000}) -> ALREADY REQUESTED (retry_unsafe): this exact action was submitted before and was not repeated.
crew answer: Refunded order ord_881 (120000 minor units) to cus_77. A repeated refund was refused by the gateway: ALREADY REQUESTED (retry_unsafe): this exact action was submitted before and was not repeated. (code: paused)
crewai recorded a failed call: lookup_order {'order_id': 'ord_881'} (paused)
crewai recorded a failed call: issue_refund {'order_id': 'ord_881', 'customer_id': 'cus_77', 'amount_minor': 120000} (paused)
crewai recorded a failed call: issue_refund {'order_id': 'ord_881', 'customer_id': 'cus_77', 'amount_minor': 120000} (paused)
decision decision_01a15c6c4a0b76c79cbd418fe648454c (refunded)
run completed
evidence: budget used {'cost_units': 100, 'replans': 0, 'tokens': 8000, 'tool_calls': 2}, <n> signed audit entries
```

Eight model calls reserved 8,000 tokens: the agent answers once per pause (that it is
waiting) before CrewAI asks for human input, and re-sends each call once approved.

## What is governed

- **Tools.** `lookup_order` and `issue_refund` are `governed_tool` functions turned into
  CrewAI tools with `crewai.tools.tool`, which builds the schema from the signature and
  docstring `governed_tool` preserves. Their bodies never run; each call goes to
  `contextosd`, which authorizes, dispatches, records and audits it. The refund is keyed
  `refund:ord_881`, so the second call cannot apply twice.
- **Outcomes.** A `ToolPaused`, `ToolBlocked`, `ToolRejected` or `ToolFailed` is caught in
  the tool and returned as a CrewAI `ToolFailure` whose message is `refusal()` text, so
  the model reads what happened (not done, or already requested) and CrewAI records the failed call
  (`TaskOutput.tool_failures`). Raising would not help: CrewAI's text-based loop retries
  a tool that raised, and its native loop gives the model a bare `Error executing tool`
  string. A pause for input or reconciliation also stops the crew: the next model call
  is aborted, so the agent cannot argue past it. A pause for approval waits for the
  reviewer at CrewAI's human input step (see Approval above).
- **No cached results.** The crew runs with `cache=False`, and each tool's
  `cache_function` refuses caching. With crew caching on, CrewAI answers a repeated
  identical call from its cache: the second refund would never reach the gateway and the
  model would be told it succeeded.
- **Model calls.** A `before_llm_call` hook reserves 1,000 tokens from the run's budget
  before every model call (four here, 4,000 tokens) and raises `HookAborted` when the
  reservation is refused, which stops the crew. `LLMCallCompletedEvent` and
  `LLMCallFailedEvent` settle the reservation.
- **Decision.** `finish()` records the DecisionRecord (its tool lineage verified by the
  gateway), completes the run and reads its evidence.
- **Telemetry.** `CREWAI_DISABLE_TELEMETRY`, `OTEL_SDK_DISABLED` and
  `CREWAI_TRACING_ENABLED=false` are set before CrewAI is imported, so nothing leaves
  the machine.

## With a real model

```sh
OPENAI_API_KEY=... ./examples/frameworks/run.sh crewai
```

uses `openai/gpt-6.1-sol` through CrewAI's native OpenAI provider, with the shared `GOAL`
and `INSTRUCTIONS` as the task and backstory. Set `MODEL` to another `provider/model` id
CrewAI accepts to change it (for Anthropic, add `crewai[anthropic]` to
`requirements.txt`). The governed path is unchanged: the hook and listeners budget every
call the provider makes.

The integration guide is [docs/integrations/crewai.md](../../../docs/integrations/crewai.md).
