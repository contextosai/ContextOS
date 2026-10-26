# Vercel AI SDK under ContextOS

This guide puts an AI SDK agent under `contextosd`: every tool call is governed by the
gateway, every model call spends the run's budget, refusals and pauses reach the model
as what they are, and the run ends with a signed DecisionRecord. It targets AI SDK 7
(`ai@7.0`, `ToolLoopAgent`, `generateText`/`streamText` with `stopWhen`, language-model
middleware). The runnable version is
[examples/frameworks/vercel-ai-sdk](../../examples/frameworks/vercel-ai-sdk/README.md).

The integration is two seams the SDK already has: a tool's `execute` function and a
`wrapLanguageModel` middleware. The gateway enforces everything that matters for
safety; the seams only make sure the agent asks it and tells the model the truth.

## 1. Install

```sh
npm install ai@7.0.150 @ai-sdk/openai@4.0.101 zod@4.6.7   # or any AI SDK provider
npm install @ai-sdk/mcp@2.0.80                           # only for the MCP route (section 8)
```

The ContextOS client (`bindings/node/client.mjs`, published as `@contextos/kernel/client`)
has no dependencies and runs anywhere `fetch` does, including edge and serverless
runtimes.

## 2. Admit a run

Admit one run per agent task, before building the agent:

```ts
import { Client, governedTool } from "@contextos/kernel/client";

const client = new Client("https://contextos.internal", { token: process.env.CONTEXTOS_TOKEN! });
const run = await client.admit(admissionBody);   // holds the executor generation
```

`run.runId` and `run.executorGeneration` are what a later process needs to resume
(section 6); store them with your conversation.

## 3. Governed tools

An AI SDK tool is `tool({ description, inputSchema, execute })`. Make `execute` call a
`governedTool` function: the call goes to `contextosd`, which authorizes, dispatches,
records and audits it, and nothing runs locally.

```ts
import { tool } from "ai";
import { z } from "zod";

const refund = governedTool(run, "adp_payments.issue_refund", {
  approvalMode: "destructive",
  idempotencyKey: (a) => `refund:${a.order_id}`,     // one operation, however often it is asked
  toolCallId: (a) => `tc_refund_${a.order_id}`,      // cited by the DecisionRecord
  evidenceRefs: ["kg:order:ord_881#snapshot_kg_2026_05_03_T0930"],
});

const issueRefund = tool({
  description: "Refund an order to its customer, in minor units.",
  inputSchema: z.object({ order_id: z.string(), customer_id: z.string(), amount_minor: z.number().int().min(1) }),
  execute: (args) => governed(refund, args),           // section 5
});
```

The Zod schema shapes what the model sends; the capability's `input_schema` is what the
gateway enforces (`arguments_invalid`), so keep them in step. Derive the idempotency key
from the arguments, never from the SDK's `toolCallId`: a model that asks again gets a new
`toolCallId`, and only an argument-derived key makes the repeat the same operation.

## 4. Budget every model call

Wrap the model once. `wrapGenerate` and `wrapStream` run around every provider call the
loop makes, including the SDK's own retries (`maxRetries`, default 2), so each attempt
reserves first:

```ts
import { wrapLanguageModel, type LanguageModelMiddleware } from "ai";

const budget: LanguageModelMiddleware = {
  specificationVersion: "v4",
  // Reserves, calls, and settles even when the call throws.
  wrapGenerate: ({ doGenerate }) => run.budgetedModelCall(() => doGenerate(), { tokens: 4000 }),
  async wrapStream({ doStream }) {
    const reservation = await run.reserveUsage("model_call", { tokens: 4000 });
    let settled: Promise<unknown> | undefined;
    const settle = () => (settled ??= run.settleUsage(reservation));
    try {
      const { stream, ...rest } = await doStream();
      // Settle when the stream ends, errors or is cancelled, not when it starts.
      const done = new TransformStream({ flush: () => settle().then(() => {}), cancel: () => settle().then(() => {}) });
      return { ...rest, stream: stream.pipeThrough(done) };
    } catch (error) {
      await settle();
      throw error;
    }
  },
};
const model = wrapLanguageModel({ model: openai("gpt-6.1-sol"), middleware: budget });
```

A reservation that does not fit throws `BudgetExhausted` (from the client) before the
provider is contacted, so the loop stops whatever the model wants. The
executor settling charges the whole reservation. To charge measured usage, route the
provider through an LLM gateway holding the `meter` scope
(`createOpenAI({ baseURL: "https://llm-gateway.internal/v1" })`;
[examples/metering-proxy](../../examples/metering-proxy) is a reference), reserve with
`metered: true`, and send `run.meteringHeaders(reservation)` as the call's `headers`
([GUIDE §6](../GUIDE.md#6-budget-model-calls-and-replans)):

```ts
const withMeter = (params, reservation) => ({ ...params, headers: { ...params.headers, ...run.meteringHeaders(reservation) } });
const metered: LanguageModelMiddleware = {
  specificationVersion: "v4",
  wrapGenerate: ({ model, params }) =>
    run.budgetedModelCall((r) => model.doGenerate(withMeter(params, r)), { tokens: 4000, metered: true }),
  wrapStream: ({ model, params }) =>
    run.budgetedModelCall((r) => model.doStream(withMeter(params, r)), { tokens: 4000, metered: true }),
};
```

Use it in place of `budget`. The gateway settles what the provider reported, a stream
when it ends; if the call throws, a reservation the gateway did not settle is settled
here, charging all of it. One reservation covers one call.

## 5. Map outcomes

Non-success results throw a `ToolOutcome` subclass. Catch them in `execute` and return
text the model reads, so a refusal never looks like a result:

```ts
import { ToolOutcome, ToolPaused } from "@contextos/kernel/client";

const WAITS = ["approval", "input", "unknown_outcome"];   // pauses someone else resolves
const paused: ToolPaused[] = [];

function refusal(error: ToolOutcome): string {
  const reasons = error.reasonCodes.join(", ") || error.status;
  const kind = error instanceof ToolPaused ? error.kind : null;
  if (kind === "duplicate") return `ALREADY REQUESTED (${reasons}): this exact action was submitted before and was not repeated.`;
  if (kind === "unknown_outcome") return `OUTCOME UNKNOWN (${reasons}): the action may have happened and is being reconciled; do not retry it.`;
  return `NOT DONE (${error.status}: ${reasons}). The action did not take effect; do not retry it.`;
}

async function governed(fn: (a: any) => Promise<unknown>, args: any) {
  try {
    return await fn(args);
  } catch (error) {
    if (!(error instanceof ToolOutcome)) throw error;        // transport errors stay errors
    if (error instanceof ToolPaused && WAITS.includes(error.kind)) paused.push(error);
    return refusal(error);
  }
}

const agent = new ToolLoopAgent({
  model, instructions, tools: { lookupOrder, issueRefund },
  toolCallConcurrency: 1,
  stopWhen: [isStepCount(8), () => paused.length > 0],      // a pause ends the loop
});
```

| Outcome | What the model sees | What the application does |
|---|---|---|
| `ToolBlocked` (authority, policy, budget) | the refusal text | nothing; the model explains or changes approach |
| `ToolRejected` (malformed, unsurfaced, key reuse) | the refusal text | fix the schema or capability if it recurs |
| `ToolFailed` (provider did not apply it) | the refusal text | retry only per the capability's recovery policy |
| `ToolPaused`, `kind: "duplicate"` (`retry_unsafe`) | "already requested" | nothing: the operation already exists |
| `ToolPaused`, `kind: "approval"` | the loop stops | resume with an SDK tool approval response once approved (below) |
| `ToolPaused`, `kind: "input"` | the loop stops | answer `paused.inputRequests` with `run.provideInput(...)` |
| `ToolPaused`, `kind: "unknown_outcome"` | "outcome unknown", then the loop stops | an operator reconciles the operation; never re-send |

`paused.kind` classifies a pause by what it waits on (the client reads the obligations
for you), so `governed` never matches obligation or reason codes itself.

Approval in ContextOS is decided by your approval service against the action digest,
not in the SDK. The SDK's `toolApproval` (the newer form of the deprecated
`needsApproval`) decides before `execute` runs, so it cannot raise a pause the gateway
only reports during the call, and it grants nothing. Its resume path fits, though:
record the pause by the call's `toolCallId` (from `execute`'s options) and stop the
loop. Once the approval service has approved, continue the conversation with
`result.responseMessages` (all steps, not `response.messages`), the paused call's
placeholder result removed and a `tool-approval-request` added for it, then an
approving `tool-approval-response`. The SDK executes the approved call with its
identical input, which redeems the exact approval, and the loop goes on.
`./examples/frameworks/run.sh vercel-ai-sdk --approval` runs this:

```ts
const approvals = new Map<string, ToolPaused>();         // toolCallId -> approval pause, set in execute
let messages: ModelMessage[] = [{ role: "user", content: goal }];
let result = await agent.generate({ prompt: goal });      // stopWhen also stops on approvals.size > 0
while (approvals.size > 0) {
  for (const pause of approvals.values()) await askReviewer(pause);   // decided in the approval service
  const id = (callId: string) => approvals.get(callId)?.report.approval_request_id;
  const step = result.responseMessages.map((m) =>
    m.role === "assistant" && typeof m.content !== "string"
      ? { ...m, content: [...m.content, ...m.content.flatMap((p) => p.type === "tool-call" && id(p.toolCallId)
          ? [{ type: "tool-approval-request", approvalId: id(p.toolCallId), toolCallId: p.toolCallId }] : [])] }
      : m.role === "tool" ? { ...m, content: m.content.filter((p) => !(p.type === "tool-result" && id(p.toolCallId))) } : m,
  ).filter((m) => m.role !== "tool" || m.content.length > 0);
  const responses = [...approvals.values()].map((p) => ({
    type: "tool-approval-response", approvalId: p.report.approval_request_id, approved: true }));
  messages = [...messages, ...step, { role: "tool", content: responses }];
  approvals.clear();
  result = await agent.generate({ messages });
}
```

If the approval was not granted, the re-sent call pauses again. In a high-value run the
gate covers every call of the run, so the lookup pauses as well; give read-only tools a
derived key and call id so their re-send redeems too. Never retry a paused call in a
loop of your own.

## 6. Checkpoint and resume

The SDK holds no durable state of its own; the message history is the agent's state.
Save it as a ContextOS checkpoint after every step, so a replacement executor resumes
where this one stopped:

```ts
let revision = 0;
const result = await agent.generate({
  messages,
  onStepEnd: async (step) => {
    revision = (await run.checkpoint({ messages: [...messages, ...step.response.messages] }, revision)).revision;
  },
});
```

A checkpoint is at most 256 KiB, written only by the current executor and optimistic on
the revision (`checkpoint_conflict`). For long histories, store the messages in your own
database and checkpoint a pointer plus its digest. After a crash or a serverless
cold start:

```ts
const resumed = await (await client.attach(runId, traceId, principalChain)).takeOver();
const { state } = await resumed.latestCheckpoint();       // the old executor is now fenced
// rebuild tools and middleware on `resumed`, then agent.generate({ messages: state.messages })
```

`takeOver()` moves the run to a new executor generation; requests from the old process
are refused with `executor_stale`, and an effect it had in flight is reconciled, not
repeated.

## 7. Multi-agent: delegate to child runs

The SDK's subagent pattern is a tool whose `execute` runs another agent. Under
ContextOS, give that subagent its own child run, narrowed by an `AgentDelegationEnvelope`
(capabilities, `effect_policy: "read_only"`, `sub_budget`, `expires_at`; see
[GUIDE: delegating to child runs](../GUIDE.md#delegating-to-child-runs-subagent-lanes)):

```ts
const research = tool({
  description: "Research an order (read-only).",
  inputSchema: z.object({ order_id: z.string() }),
  execute: async ({ order_id }) => {
    const lane = await run.delegate(childAdmission, envelope);          // sub-budget reserved from the parent
    const sub = new ToolLoopAgent({
      model: wrapLanguageModel({ model: base, middleware: budgetFor(lane) }),   // spends the lane's budget
      tools: { lookupOrder: tool({ inputSchema, execute: (a) => governed(governedTool(lane, "adp_orders.lookup"), a) }) },
      stopWhen: isStepCount(5),
    });
    try {
      return (await sub.generate({ prompt: `Summarize order ${order_id}` })).text;
    } finally {
      await run.closeChild(lane, "accept");                              // settles its usage into the parent
    }
  },
});
```

`budgetFor(lane)` is the section 4 middleware built for the lane's run. A `read_only`
lane has no effectful capability surfaced, so a subagent that tries to refund is refused
(`capability_not_surfaced`) whatever its prompt says. Close every lane: the parent
cannot complete with an open child (`children_unsettled`).

## 8. The MCP alternative

Each run is an MCP server at `POST /v1/runs/{run_id}/mcp`. The SDK's MCP client turns its
tools into AI SDK tools:

```ts
import { createMCPClient } from "@ai-sdk/mcp";

const mcp = await createMCPClient({
  transport: {
    type: "http",
    url: `https://contextos.internal/v1/runs/${run.runId}/mcp`,
    headers: { Authorization: `Bearer ${token}`, "ContextOS-Executor-Generation": String(run.executorGeneration) },
  },
});
const agent = new ToolLoopAgent({ model, tools: await mcp.tools(), stopWhen: isStepCount(8) });
// ... finally: await mcp.close();
```

The tools carry the capabilities' reviewed schemas and names (`adp_payments.issue_refund`).
A refusal comes back as a result with `isError: true` and `structuredContent` holding
`status`, `reason_codes` and `obligations`, which the model sees. Effectful calls get an
operation key derived from capability and arguments, so a repeated call is
`retry_unsafe`, not a second refund. Every result's `_meta` names
`io.contextos/toolCallId` and `io.contextos/operationId`, which the DecisionRecord
cites. Keep one effect on one route: an explicitly keyed call (section 3) and a
derived-key MCP call are different operations (the second is refused, `effect_repeated`). You still need the budget middleware, and after a
`takeOver()` the client must be rebuilt with the new generation. Prefer section 3 when
you want your own idempotency keys, evidence refs and outcome mapping.

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
`run.fail()` rather than leaving the run open.

## 10. Pitfalls

- **Step limits.** `generateText`/`streamText` default to `stopWhen: isStepCount(1)`: one
  model call, tools executed, no follow-up. `ToolLoopAgent` defaults to
  `isStepCount(20)`. Set it explicitly; the run's budget is the hard limit either way.
- **Parallel tool calls.** Tool calls in one step run concurrently by default. Set
  `toolCallConcurrency: 1` when ordering matters. Concurrent identical calls are still
  one operation (same key), and the gateway's loop guard stops an agent repeating the
  same call (`loop_detected`).
- **Streaming.** Settle in the stream's `flush`/`cancel`, not after `doStream()` returns;
  an aborted response (`abortSignal`, a client disconnect) must still settle.
- **Serverless timeouts.** Never wait for an approval inside `execute`: end the loop and
  resume in a later invocation (section 6). If the function is killed mid-call, the
  operation may be in flight; the next executor takes over and reconciles rather than
  re-sends. Keep the platform timeout above the capability's `timeout_ms`.
- **Retries.** SDK retries re-call the model, which the middleware budgets per attempt.
  Do not wrap governed calls in your own retry helper: the client already retries what
  the server did not process (429, 503), and a paused or blocked call must not be
  re-sent.
- **Tool errors.** An `execute` that throws becomes a `tool-error` part the model sees.
  Catch `ToolOutcome` so the model gets the explicit "not done" text instead of an
  error string it may treat as transient.

## References

- AI SDK: [Tools and tool calling](https://ai-sdk.dev/docs/ai-sdk-core/tools-and-tool-calling),
  [Language model middleware](https://ai-sdk.dev/docs/ai-sdk-core/middleware),
  [Agents](https://ai-sdk.dev/docs/agents/overview),
  [MCP tools](https://ai-sdk.dev/docs/ai-sdk-core/mcp-tools),
  [Testing](https://ai-sdk.dev/docs/ai-sdk-core/testing)
- ContextOS: [GUIDE §2, the Node client and MCP](../GUIDE.md#2-govern-an-existing-python-agent-over-http),
  [executors and failover](../GUIDE.md#executors-and-failover),
  [§6 budgets and checkpoints](../GUIDE.md#6-budget-model-calls-and-replans)
