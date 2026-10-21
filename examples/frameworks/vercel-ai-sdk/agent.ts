// The quickstart's refund, run by the Vercel AI SDK's own agent loop (ToolLoopAgent).
// Tools are AI SDK `tool()`s whose execute calls a governed function: contextosd
// authorizes, dispatches, records and audits each call; nothing runs locally. Every
// model call is wrapped by budget middleware that reserves from the run first.
//
//   ./examples/frameworks/run.sh vercel-ai-sdk      (OPENAI_API_KEY set: a real model)
import { ToolLoopAgent, isStepCount, tool, wrapLanguageModel } from "ai";
import type { LanguageModel, LanguageModelMiddleware } from "ai";
import { MockLanguageModelV4 } from "ai/test";
import { z } from "zod";
import {
  GOAL, INSTRUCTIONS, MODEL_CALL_TOKENS, ToolOutcome, ToolPaused, admit, finish, offline, refusal, tools,
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
// to reconcile) also stops the loop: the application resolves it out of band and
// re-sends the same call, which continues the same operation and cannot apply twice.
const WAITS = ["approval", "input", "unknown_outcome"];
let refunded = false;
const paused: ToolPaused[] = [];
async function governed(name: string, fn: (args: any) => Promise<unknown>, args: any) {
  try {
    const output = await fn(args);
    console.log(`${name} -> ${JSON.stringify(output)}`);
    return output;
  } catch (error) {
    if (!(error instanceof ToolOutcome)) throw error;
    if (error instanceof ToolPaused && WAITS.includes(error.kind)) paused.push(error);
    console.log(`${name} -> ${refusal(error)}`);
    return refusal(error);
  }
}

const agentTools = {
  lookupOrder: tool({
    description: "Look an order up by id.",
    inputSchema: z.object({ order_id: z.string() }),
    execute: (args) => governed("lookupOrder", lookupOrder, args),
  }),
  issueRefund: tool({
    description: "Refund an order to its customer, in minor units.",
    inputSchema: z.object({ order_id: z.string(), customer_id: z.string(), amount_minor: z.number().int().min(1) }),
    execute: async (args) => {
      const output = await governed("issueRefund", issueRefund, args);
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
  stopWhen: [isStepCount(8), () => paused.length > 0],
});
const result = await agent.generate({ prompt: GOAL }).catch(async (error) => {
  await run.fail(); // the loop itself failed (model error, budget refused): close the run
  throw error;
});
if (paused.length > 0) {
  // Leave the run open: approve it (or reconcile the effect) and resume this executor.
  console.log(`paused on ${paused.map((p) => `${p.operationId} (${p.kind}: ${p.obligations.join(", ")})`).join("; ")}`);
  process.exit(0);
}
console.log(`agent (${result.steps.length} steps): ${result.text}`);
await finish(client, run, refunded, result.text);

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
