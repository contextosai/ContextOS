# Mastra under ContextOS

This guide puts a Mastra agent under `contextosd`: every tool call is governed by the
gateway, every model call spends the run's budget, refusals reach the model as what they
are, approval pauses become Mastra suspensions, and the run ends with a signed
DecisionRecord. It targets Mastra 1.x (`@mastra/core@1.78`: `Agent`, `createTool`,
processors, workflows with suspend/resume, `@mastra/mcp`). The runnable version is
[examples/frameworks/mastra](../../examples/frameworks/mastra/README.md).

The integration is the tool's `execute` function and one processor. The gateway enforces everything that matters for safety; the seams only make
sure the agent asks it and tells the model the truth.

## 1. Install

```sh
npm install @mastra/core@1.78.0 zod@4.6.7
npm install @mastra/mcp@2.4.1        # only for the MCP route (section 8)
```

`@mastra/core` is large (about 140 MB installed) and includes the model router, so
`model: "openai/gpt-6.1-sol"` needs no provider package. The ContextOS client
(`bindings/node/client.mjs`, published as `@contextos/kernel/client`) has no dependencies.

## 2. Admit a run

Admit one run per agent task, before calling the agent:

```ts
import { Client, governedTool } from "@contextos/kernel/client";

const client = new Client("https://contextos.internal", { token: process.env.CONTEXTOS_TOKEN! });
const run = await client.admit(admissionBody);   // holds the executor generation
```

Use `run.runId` as the Mastra memory thread (section 6), so the two are found together.

## 3. Governed tools

A Mastra tool is `createTool({ id, description, inputSchema, execute })`, with
`execute(inputData, context)`. Make `execute` call a `governedTool` function: the call
goes to `contextosd`, which authorizes, dispatches, records and audits it, and nothing
runs locally.

```ts
import { createTool } from "@mastra/core/tools";
import { z } from "zod";

const refund = governedTool(run, "adp_payments.issue_refund", {
  approvalMode: "destructive",
  idempotencyKey: (a) => `refund:${a.order_id}`,     // one operation, however often it is asked
  toolCallId: (a) => `tc_refund_${a.order_id}`,      // cited by the DecisionRecord
  evidenceRefs: ["kg:order:ord_881#snapshot_kg_2026_05_03_T0930"],
});

const issueRefund = createTool({
  id: "issueRefund",
  description: "Refund an order to its customer, in minor units.",
  inputSchema: z.object({ order_id: z.string(), customer_id: z.string(), amount_minor: z.number().int().min(1) }),
  execute: (input, context) => governed(refund, input, context),   // section 5
});
```

Keep the Zod schema in step with the capability's `input_schema`, which the gateway
enforces (`arguments_invalid`). Derive the idempotency key from the arguments, never
from Mastra's tool call id, so a repeated request is the same operation.

## 4. Budget every model call

Use a processor. `processLLMRequest` runs just before each provider call and
`processLLMResponse` just after it, sharing per-request `state`. With `@mastra/core`
1.78 both run once per attempt, including Mastra's own retries and calls that fail, so
each attempt reserves first and is settled:

```ts
const budget = {
  id: "contextos-budget",
  async processLLMRequest({ state }) {
    state.reservation = await run.reserveUsage("model_call", { tokens: 4000 });   // refusal throws: no call
  },
  async processLLMResponse({ state }) {
    const reservation = state.reservation;
    state.reservation = undefined;
    if (reservation) await run.settleUsage(reservation);
  },
};
const agent = new Agent({ id: "support", name: "Support", instructions, model: "openai/gpt-6.1-sol", tools, inputProcessors: [budget] });
```

A reservation that does not fit is refused with `budget_exhausted`; the error propagates
out of `generate()`/`stream()` before the provider is contacted, so the loop stops
whatever the model wants. The processor works with model router strings and with AI SDK
model objects alike. Processors passed to `generate()` replace the agent's array for
that call, so include `budget` whenever you override `inputProcessors`.

If you prefer to budget below Mastra, wrap the AI SDK model object instead (Mastra
accepts AI SDK v4-specification models): a wrapper whose `doGenerate`/`doStream` reserve
before delegating and settle in `finally` or in the stream's `flush`/`cancel`, as in
[the AI SDK guide](vercel-ai-sdk.md#4-budget-every-model-call).

The executor settling charges the whole reservation; to charge measured usage, have
your LLM gateway (holding the `meter` scope) settle it, passing it the reservation id
([GUIDE §6](../GUIDE.md#6-budget-model-calls-and-replans)).

## 5. Map outcomes

Non-success results throw a `ToolOutcome` subclass. Return text the model reads for
refusals, and suspend the tool for pauses that wait on a person:

```ts
import { ToolOutcome, ToolPaused } from "@contextos/kernel/client";

function refusal(error) {
  const reasons = error.reasonCodes.join(", ") || error.status;
  const kind = error instanceof ToolPaused ? error.kind : null;
  if (kind === "duplicate") return `ALREADY REQUESTED (${reasons}): this exact action was submitted before and was not repeated.`;
  if (kind === "unknown_outcome") return `OUTCOME UNKNOWN (${reasons}): the action may have happened and is being reconciled; do not retry it.`;
  return `NOT DONE (${error.status}: ${reasons}). The action did not take effect; do not retry it.`;
}

async function governed(fn, input, context) {
  try {
    return await fn(input);              // on resume this re-sends the same call: same operation key
  } catch (error) {
    if (!(error instanceof ToolOutcome)) throw error;
    if (error instanceof ToolPaused && error.kind === "approval" && context?.agent?.suspend) {
      return await context.agent.suspend({ operation_id: error.operationId, approval_request_id: error.report.approval_request_id });
    }
    return refusal(error);
  }
}
```

Give the tool a `suspendSchema` and `resumeSchema` (for example `{ decided: z.boolean() }`).
`agent.generate()` then returns `finishReason: "suspended"` with a `runId`; when your
approval service has decided, `agent.resumeGenerate({ decided: true }, { runId })` runs
`execute` again, which re-sends the same governed call. It runs only if the approval was
granted and cannot apply twice; if it was denied, the gateway's refusal is what the model
reads. Suspension needs the agent registered on a `Mastra` instance with storage
(`new Mastra({ agents: { support }, storage })`, then `mastra.getAgent("support")`;
`InMemoryStore` from `@mastra/core/storage` for tests, a durable store in production), or
resuming fails with "snapshot not found". The example configures no storage, so it ends
the turn with `stopWhen` instead and leaves the run open.

| Outcome | Mapping |
|---|---|
| `ToolBlocked`, `ToolRejected`, `ToolFailed` | refusal text as the tool result |
| `ToolPaused`, `kind: "duplicate"` (`retry_unsafe`) | "already requested": the operation already exists |
| `ToolPaused`, `kind: "approval"` | `suspend()`, resume after the approval service decides |
| `ToolPaused`, `kind: "input"` | `suspend()` with `paused.inputRequests`; answer with `run.provideInput(...)` |
| `ToolPaused`, `kind: "unknown_outcome"` | end the turn (or `suspend()`); an operator reconciles; never re-send |

`paused.kind` classifies a pause by what it waits on, so `governed` never matches
obligation or reason codes itself.

Mastra's own `requireApproval: true` is a local confirmation before `execute` runs. Use it
as an extra prompt if you like, but it grants nothing: the gateway still decides. Do not
use `declineToolCall` to answer a ContextOS approval; the decision belongs to the
approval service.

## 6. Checkpoints, workflow snapshots and memory

Three kinds of state are in play, and they are not interchangeable:

- **ContextOS checkpoints** (`run.checkpoint(state, expectedRevision)`) hold the
  orchestrator's own position (plan, step, last verdict), are fenced to the current
  executor and are audited by digest. They are what a replacement executor reads after
  `takeOver()`.
- **Mastra snapshots** (agent suspensions, workflow runs) hold Mastra's execution state
  in your Mastra storage. Store the Mastra `runId` in the ContextOS checkpoint, so the
  executor that takes over can `resumeGenerate`, or `workflow.createRun({ runId })` and
  `run.resume({ step, resumeData })`.
- **Mastra memory** (`memory: { thread: run.runId, resource: customerId }`) is
  conversation history. It is context, not evidence: what happened is in the run's
  operation ledgers and audit chain, and a remembered "refund issued" never substitutes
  for the gateway's record.

After a crash:

```ts
const resumed = await (await client.attach(runId, traceId, principalChain)).takeOver();
const { state } = await resumed.latestCheckpoint();       // the old executor is now fenced
// rebuild tools and the budget processor on `resumed`, then resume Mastra from state.mastraRunId
```

In a workflow, put each governed effect in its own step and checkpoint after it: a step
that re-runs on resume re-sends the same operation key, so the effect is reconciled or
refused (`retry_unsafe`), never repeated.

## 7. Multi-agent: delegate to child runs

Mastra supervisors call subagents (`agents: { researchAgent }`) as tool calls. Under
ContextOS each subagent works in its own child run, narrowed by an
`AgentDelegationEnvelope` (capabilities, `effect_policy: "read_only"`, `sub_budget`;
see [GUIDE: delegating to child runs](../GUIDE.md#delegating-to-child-runs-subagent-lanes)).
Because the lane's tools must be bound to the lane, the simplest form is a tool that
opens the lane, runs the subagent and closes it:

```ts
const research = createTool({
  id: "research", description: "Research an order (read-only).",
  inputSchema: z.object({ order_id: z.string() }),
  execute: async ({ order_id }) => {
    const lane = await run.delegate(childAdmission, envelope);          // sub-budget reserved from the parent
    const sub = new Agent({
      id: "researcher", name: "Researcher", instructions: "Read only.",
      model: "openai/gpt-6.1-sol",
      inputProcessors: [budgetFor(lane)],                                // spends the lane's budget
      tools: { lookupOrder: createTool({ id: "lookupOrder", inputSchema, execute: (a) => governed(governedTool(lane, "adp_orders.lookup"), a) }) },
    });
    try {
      return (await sub.generate(`Summarize order ${order_id}`, { maxSteps: 5 })).text;
    } finally {
      await run.closeChild(lane, "accept");                              // settles its usage into the parent
    }
  },
});
```

`budgetFor(lane)` is the section 4 processor built for the lane's run. With
`agents: {...}` instead, open the lane in `delegation.onDelegationStart` and close it in
`onDelegationComplete`, resolving the subagent's tools from the request context. A
`read_only` lane surfaces no effectful capability, so a subagent cannot refund whatever
its prompt says (`capability_not_surfaced`). The parent cannot complete with an open
child (`children_unsettled`).

## 8. The MCP alternative

Each run is an MCP server at `POST /v1/runs/{run_id}/mcp`. Mastra's MCP client turns its
tools into Mastra tools:

```ts
import { MCPClient } from "@mastra/mcp";

const mcp = new MCPClient({
  id: run.runId,
  servers: {
    contextos: {
      url: new URL(`https://contextos.internal/v1/runs/${run.runId}/mcp`),
      requestInit: { headers: { Authorization: `Bearer ${token}`, "ContextOS-Executor-Generation": String(run.executorGeneration) } },
    },
  },
});
const agent = new Agent({ ..., tools: await mcp.listTools() });   // contextos_adp_payments.issue_refund, ...
// ... finally: await mcp.disconnect();
```

Effectful calls get an operation key derived from capability and arguments, so a
repeated call is `retry_unsafe`, not a second refund. Mastra's MCP client turns a
refusal (`isError: true`) into a thrown `MCP_CLIENT_TOOL_EXECUTION_FAILED` error whose
message ("ContextOS paused: retry_unsafe. This call had no effect; do not retry it
unchanged. …") the agent loop passes to the model; the `structuredContent` with reason
codes and obligations is lost, so you cannot tell an approval pause from a refusal on
this route. Keep one effect on one route: an explicitly keyed call (section 3) and a
derived-key MCP call are different operations. You still need the budget processor, and after
`takeOver()` the client must be rebuilt with the new generation. Prefer section 3.

## 9. Record the decision and complete

```ts
await run.recordDecision("support.refund.execute", refunded ? "DECIDED" : "REJECTED", {
  ...(refunded ? { outcome: "refund_issued" } : {}),
  toolCalls: refunded ? [{ tool_call_id: "tc_refund_ord_881", operation_id: "refund:ord_881" }] : [],
  rationale: { strategy: result.text.slice(0, 500) },
});
await run.complete();      // 409 while an effect is unknown, a child is open or a call is in flight
```

The gateway verifies each cited tool call against its ledgers (`lineage_unverified`
otherwise) and signs the record into the audit chain. If the loop throws, call
`run.fail()`; a suspended agent's run stays open until it is resumed or cancelled.

## 10. Pitfalls

- **Step limits.** Set `maxSteps` (or `stopWhen`) on `generate()`/`stream()`; the run's
  budget is the hard limit either way.
- **Parallel tool calls.** Mastra runs up to 10 tool calls of a step concurrently, but
  forces sequential execution while a suspend- or approval-capable tool is registered.
  Set `toolCallConcurrency: 1` when ordering matters. Concurrent identical calls are still
  one operation, and the gateway's loop guard stops an agent repeating the same call
  (`loop_detected`).
- **Streaming.** `agent.stream()` goes through the same processor hooks. If you budget
  with a model wrapper instead, settle in the stream's `flush`/`cancel`, so an aborted
  stream still settles.
- **Serverless timeouts.** Never wait for an approval inside `execute`: suspend, return,
  and resume in a later invocation from durable Mastra storage. If the function is killed
  mid-call the operation may be in flight; the next executor takes over and reconciles.
- **Retries.** Mastra retries failed provider calls; the processor budgets each
  attempt. Do not retry governed calls yourself: the client already retries what the
  server did not process (429, 503), and a paused or blocked call must not be re-sent.
- **`suspend()` does not throw.** Write `return await context.agent.suspend(...)`, or
  the code after it runs.

## References

- Mastra: [Agents](https://mastra.ai/docs/agents/overview),
  [Using tools](https://mastra.ai/docs/agents/using-tools),
  [Agent approval and suspension](https://mastra.ai/docs/agents/agent-approval),
  [Processors](https://mastra.ai/docs/agents/processors),
  [Supervisor agents](https://mastra.ai/docs/agents/supervisor-agents),
  [Workflow suspend and resume](https://mastra.ai/docs/workflows/suspend-and-resume),
  [Memory](https://mastra.ai/docs/memory/overview), [MCP](https://mastra.ai/docs/mcp/overview),
  [Models](https://mastra.ai/models)
- ContextOS: [GUIDE §2, the Node client and MCP](../GUIDE.md#2-govern-an-existing-python-agent-over-http),
  [executors and failover](../GUIDE.md#executors-and-failover),
  [§6 budgets and checkpoints](../GUIDE.md#6-budget-model-calls-and-replans)
