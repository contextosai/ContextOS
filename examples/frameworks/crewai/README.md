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
evidence: budget used {'cost_units': 100, 'replans': 0, 'tokens': 4000, 'tool_calls': 2}, 10 signed audit entries
```

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
  string. A pause for approval, input or reconciliation also stops
  the crew: the next model call is aborted, so the agent cannot argue past it.
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
