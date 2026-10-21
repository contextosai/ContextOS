// The quickstart's refund, run by the Vercel AI SDK's own agent loop (ToolLoopAgent).
// Tools are AI SDK `tool()`s whose execute calls a governed function: contextosd
// authorizes, dispatches, records and audits each call; nothing runs locally. Every
// model call is wrapped by budget middleware that reserves from the run first.
//
//   ./examples/frameworks/run.sh vercel-ai-sdk      (OPENAI_API_KEY set: a real model)
//   ./examples/frameworks/run.sh vercel-ai-sdk --approval
// With --approval the gateway pauses calls for an exact approval; each pause becomes the
// AI SDK's own tool approval request, a scripted reviewer approves it, and the loop
// resumes with the approval response, which re-sends the identical call.
import { ToolLoopAgent, isStepCount, tool, wrapLanguageModel } from "ai";
import type { LanguageModel, LanguageModelMiddleware, ModelMessage } from "ai";
import { MockLanguageModelV4 } from "ai/test";
import { z } from "zod";
import {
  GOAL, INSTRUCTIONS, MODEL_CALL_TOKENS, ToolOutcome, ToolPaused, admit, approve, finish, offline, refusal, tools,
} from "../_shared/demo.mjs";

const { client, run } = await admit("vercel_ai_sdk");
const { lookupOrder, issueRefund } = tools(run);

// Budget: reserve before every provider call, settle after (even when it fails). In
// production send the reservation id to your LLM gateway so it meters the call.
const budget: LanguageModelMiddleware = {
  specificationVersion: "v4",
  async wrapGenerate({ doGenerate }) {
    const reservation = await run.reserveUsage("model_call", { tokens: MODEL_CALL_TOKENS });
    try {
      return await doGenerate();
    } finally {
      await run.settleUsage(reservation);
    }
  },
  async wrapStream({ doStream }) {
    const reservation = await run.reserveUsage("model_call", { tokens: MODEL_CALL_TOKENS });
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

// A non-success outcome becomes a tool result the model reads, saying it did not complete.
// A pause that waits on someone else (an approver, requested input, an unknown effect
// to reconcile) also stops the loop. An approval pause is resumed below through the
// SDK's tool approval flow; any other is resolved out of band, and re-sending the same
// call continues the same operation, which cannot apply twice.
const WAITS = ["approval", "input", "unknown_outcome"];
let refunded = false;
const paused: ToolPaused[] = [];
const approvals = new Map<string, ToolPaused>(); // tool call id -> its approval pause
async function governed(name: string, fn: (args: any) => Promise<unknown>, args: any, toolCallId: string) {
  try {
    const output = await fn(args);
    console.log(`${name} -> ${JSON.stringify(output)}`);
    return output;
  } catch (error) {
    if (!(error instanceof ToolOutcome)) throw error;
    if (error instanceof ToolPaused && error.kind === "approval") {
      approvals.set(toolCallId, error);
      console.log(`${name} -> paused for approval: ${error.report.approval_request_id}`);
      return refusal(error); // replaced by the approval request when the loop resumes
    }
    if (error instanceof ToolPaused && WAITS.includes(error.kind)) paused.push(error);
    console.log(`${name} -> ${refusal(error)}`);
    return refusal(error);
  }
}

const agentTools = {
  lookupOrder: tool({
    description: "Look an order up by id.",
    inputSchema: z.object({ order_id: z.string() }),
    execute: (args, { toolCallId }) => governed("lookupOrder", lookupOrder, args, toolCallId),
  }),
  issueRefund: tool({
    description: "Refund an order to its customer, in minor units.",
    inputSchema: z.object({ order_id: z.string(), customer_id: z.string(), amount_minor: z.number().int().min(1) }),
    execute: async (args, { toolCallId }) => {
      const output = await governed("issueRefund", issueRefund, args, toolCallId);
      if (typeof output !== "string") refunded = true;
      return output;
    },
  }),
};

const model = wrapLanguageModel({ model: await chooseModel(), middleware: budget });
const agent = new ToolLoopAgent({
  model,
  instructions: INSTRUCTIONS,
  tools: agentTools,
  toolCallConcurrency: 1, // effectful calls in one step run in order, not racing
  stopWhen: [isStepCount(8), () => paused.length > 0 || approvals.size > 0],
});
const generate = (call: { prompt: string } | { messages: ModelMessage[] }) => agent.generate(call).catch(async (error) => {
  await run.fail(); // the loop itself failed (model error, budget refused): close the run
  throw error;
});
let messages: ModelMessage[] = [{ role: "user", content: GOAL }];
let result = await generate({ prompt: GOAL });
while (approvals.size > 0) {
  // A real deployment shows the bound action to a reviewer, who decides in ContextOS's
  // approval service; `approve` plays them. The SDK then executes the approved call
  // with its identical input, and the gateway redeems the exact approval.
  for (const pause of approvals.values()) await approve(pause);
  messages = [...messages, ...approvalResponses(result.responseMessages)];
  approvals.clear();
  console.log("resuming with the tool approval response");
  result = await generate({ messages });
}
if (paused.length > 0) {
  // Leave the run open: approve it (or reconcile the effect) and resume this executor.
  console.log(`paused on ${paused.map((p) => `${p.operationId} (${p.kind}: ${p.obligations.join(", ")})`).join("; ")}`);
  process.exit(0);
}
console.log(`agent (${result.steps.length} steps): ${result.text}`);
await finish(client, run, refunded, result.text);

/** The step's messages with each approval-paused call as the SDK's tool approval request
 * (its placeholder result removed), followed by the approving responses. */
function approvalResponses(stepMessages: ModelMessage[]): ModelMessage[] {
  const ids = (id: string) => approvals.get(id)?.report.approval_request_id;
  const out: ModelMessage[] = stepMessages.map((m): ModelMessage => {
    if (m.role === "assistant" && typeof m.content !== "string") {
      const requests = m.content.flatMap((p) => (p.type === "tool-call" && ids(p.toolCallId)
        ? [{ type: "tool-approval-request" as const, approvalId: ids(p.toolCallId)!, toolCallId: p.toolCallId }] : []));
      return { ...m, content: [...m.content, ...requests] };
    }
    if (m.role === "tool") return { ...m, content: m.content.filter((p) => !(p.type === "tool-result" && ids(p.toolCallId))) };
    return m;
  }).filter((m) => m.role !== "tool" || m.content.length > 0);
  const responses = [...approvals.values()].map((p) => ({
    type: "tool-approval-response" as const, approvalId: p.report.approval_request_id, approved: true,
  }));
  return [...out, { role: "tool", content: responses }];
}

/** A real model when OPENAI_API_KEY is set; otherwise a scripted one. */
async function chooseModel(): Promise<LanguageModel> {
  if (!offline("OPENAI_API_KEY")) {
    const { openai } = await import("@ai-sdk/openai");
    return openai(process.env.OPENAI_MODEL ?? "gpt-6.1-sol");
  }
  // Offline: the AI SDK's mock model, scripted from what the tools returned so far.
  return new MockLanguageModelV4({
    doGenerate: async ({ prompt }) => {
      const results = prompt.flatMap((m: any) => (m.role === "tool" ? m.content : []))
        .filter((p: any) => p.type === "tool-result")
        .map((p: any) => p.output?.value);
      const order = results.find((r: any) => r && typeof r === "object" && "amount_minor" in r);
      const refund = { order_id: "ord_881", customer_id: "cus_77", amount_minor: order?.amount_minor };
      const step = [
        call("lookupOrder", { order_id: "ord_881" }),
        call("issueRefund", refund),
        call("issueRefund", refund), // the "retry" the gateway refuses
      ][results.length];
      const content = step ? [step] : [{
        type: "text" as const,
        text: `Refunded ${order?.amount_minor} minor units for ord_881. A second refund was refused: ${results.at(-1)}`,
      }];
      return {
        content,
        finishReason: { unified: step ? "tool-calls" : "stop", raw: undefined },
        usage: { inputTokens: { total: 0, noCache: 0, cacheRead: 0, cacheWrite: 0 }, outputTokens: { total: 0, text: 0, reasoning: 0 } },
        warnings: [],
      };
    },
  });
}

function call(toolName: string, input: unknown) {
  return { type: "tool-call" as const, toolCallId: `call_${toolName}_${Math.random().toString(36).slice(2, 8)}`, toolName, input: JSON.stringify(input) };
}
