# Integrate a framework that has no guide yet

The [framework guides](README.md) cover ten agent frameworks. Any other framework that
accepts plain functions as tools, or speaks MCP, integrates the same way. This page is
the checklist, and four scenarios to run before calling an integration done: each one
is a place where a framework's defaults quietly undo what the gateway decided.

## Start from the shared example

[`examples/frameworks/_shared/demo.py`](../../examples/frameworks/_shared/demo.py) (and
`demo.mjs` for TypeScript) holds everything an integration needs that is not specific
to a framework: admission, the governed tools, the model-call budget, the refusal text,
approval for the demo, and the closing decision. Copy one of the existing examples that
is closest to your framework (a function-calling loop, a graph, a crew, an MCP client),
replace its agent construction with your framework's, and keep `_shared` as it is.

## Checklist

| Seam | Done when |
|---|---|
| Admission | The run is admitted before the agent starts, and every tool and model call uses that run. |
| Tools | Every effectful tool is a governed tool or reaches the run's MCP endpoint. The agent process holds no credential for the systems it acts on, and has no network route to them ([egress.md](egress.md)). |
| Model calls | Every model request, including the framework's own retries, is inside `budgeted_model_call`; `BudgetExhausted` stops the loop. |
| Outcomes | Each outcome in the [table](README.md#outcomes) reaches the model as a normal tool result, never as an exception the framework turns into "try again". |
| Pauses | An approval pause suspends through the framework's human-in-the-loop mechanism; an unknown outcome stops further effects until it is reconciled. |
| Checkpoint | The framework's thread or state id is saved in the run's checkpoint, and a second executor can take the run over. |
| Subagents | A subagent or handoff runs as a delegated child run with a narrower lane. |
| Decision | The run ends with a decision citing the tool calls it relied on, then `complete()`. |

## Four scenarios to run

Run each against a local gateway, as `./examples/frameworks/run.sh <framework>` does for
the existing examples (it starts the development environment in
`examples/dev-env.sh`), and check the audit log as well as what the model saw. In every case the
model must be told the truth about what happened, and the gateway must have been asked
exactly as often as the agent decided to act.

| Scenario | How to cause it | Expected | What goes wrong in frameworks |
|---|---|---|---|
| **Refusal** | Ask for a refund above the run's task authorization or the pack's limit | `ToolBlocked`; the model reads a refusal that says nothing happened; one `authorization_decision` in the audit, no second attempt | The framework's default error handler turns the refusal into an invitation to retry, or retries itself |
| **Approval pause** | Run the example with `--approval` (a refund above the pack's 3,000 approval line) | `ToolPaused` with `kind == "approval"`; the run suspends; once approved, the identical call is re-sent and completes once | The pause is reported as a failure, or the call is re-sent with different arguments, which an approval bound to the exact action refuses |
| **Duplicate delivery** | Send the same effectful call twice with the same idempotency key, as a retried message or a replayed step would | The second returns the first's result or `ToolPaused` with `kind == "duplicate"`; the provider applied it once | A tool-result cache or loop guard drops the second call before the gateway sees it, and the model is told the effect happened twice |
| **Lost response** | Make the provider apply the effect and drop its response: the Failure Lab's synthetic provider does this (`examples/failure-lab/provider.py`, mode `lose_response`), or stop your test provider after it applies | `ToolPaused` with `kind == "unknown_outcome"`; the reservation stays held; a retry of the same operation is refused until `run.reconcile(...)` settles it | The framework retries on a transport error, so without the gateway the provider would pay twice |

When all four behave as expected, add the integration to the table in
[README.md](README.md) with its guide and example, and run it in CI like the others
(`./examples/frameworks/run.sh <framework>`).

## What not to do

- Do not give the agent a second route to the same system (a direct SDK client next to
  the governed tool). The gateway cannot govern a call it never sees.
- Do not send one effect through both the in-process route and MCP. They derive
  different operation keys, and the second is refused as a repeated effect.
- Do not cache effectful tools or let the framework deduplicate identical calls.
- Do not budget in a hook that swallows exceptions; budget where a refusal stops the
  call.

A conformance command that drives these four scenarios against an integration
automatically (`ctx adapter-check`) is planned, not built.
