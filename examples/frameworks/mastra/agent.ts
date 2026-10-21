// The quickstart's refund, run by a Mastra Agent. Tools are Mastra createTool()s whose
// execute calls a governed function: contextosd authorizes, dispatches, records and
// audits each call; nothing runs locally. A processor reserves from the run's budget
// before every provider call.
//
//   ./examples/frameworks/run.sh mastra      (OPENAI_API_KEY set: a real model)
import { Agent } from "@mastra/core/agent";
import { createTool } from "@mastra/core/tools";
import { z } from "zod";
import {
  GOAL, INSTRUCTIONS, MODEL_CALL_TOKENS, ToolOutcome, ToolPaused, admit, finish, offline, refusal, tools,
} from "../_shared/demo.mjs";

const { client, run } = await admit("mastra");
const { lookupOrder, issueRefund } = tools(run);

// Budget: a processor whose processLLMRequest runs just before every provider call
// (each attempt, retries included) and processLLMResponse just after it, even when the
// call fails. A refused reservation (budget_exhausted) throws, so no call is made.
const budget = {
  id: "contextos-budget",
  async processLLMRequest({ state }: { state: Record<string, unknown> }) {
    state.reservation = await run.reserveUsage("model_call", { tokens: MODEL_CALL_TOKENS });
  },
  async processLLMResponse({ state }: { state: Record<string, unknown> }) {
    const reservation = state.reservation as string | undefined;
    state.reservation = undefined;
    if (reservation) await run.settleUsage(reservation);
  },
};

// A non-success outcome becomes a tool result the model reads, saying it did not complete.
// A pause that waits on someone else (an approver, requested input, an unknown effect to
// reconcile) also ends the agent's turn: resolve it out of band, then re-send the same
// call, which continues the same operation and cannot apply twice.
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

const lookupOrderTool = createTool({
  id: "lookupOrder",
  description: "Look an order up by id.",
  inputSchema: z.object({ order_id: z.string() }),
  execute: (input) => governed("lookupOrder", lookupOrder, input),
});
const issueRefundTool = createTool({
  id: "issueRefund",
  description: "Refund an order to its customer, in minor units.",
  inputSchema: z.object({ order_id: z.string(), customer_id: z.string(), amount_minor: z.number().int().min(1) }),
  execute: async (input) => {
    const output = await governed("issueRefund", issueRefund, input);
    if (typeof output !== "string") refunded = true;
    return output;
  },
});

const agent = new Agent({
  id: "support-agent",
  name: "Support agent",
  instructions: INSTRUCTIONS,
  model: await chooseModel(),
  inputProcessors: [budget],
  tools: { lookupOrder: lookupOrderTool, issueRefund: issueRefundTool },
});
const result = await agent.generate(GOAL, {
  maxSteps: 8,
  toolCallConcurrency: 1, // effectful calls in one step run in order, not racing
  stopWhen: () => paused.length > 0,
}).catch(async (error) => {
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
async function chooseModel(): Promise<any> {
  // Mastra's model router reads OPENAI_API_KEY; any "provider/model" id works.
  if (!offline("OPENAI_API_KEY")) return process.env.MASTRA_MODEL ?? "openai/gpt-6.1-sol";
  // Offline: a minimal AI SDK (v4 specification) model, scripted from what the tools
  // returned so far.
  const next = ({ prompt }: any) => {
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
    const text = `Refunded ${order?.amount_minor} minor units for ord_881. A second refund was refused: ${results.at(-1)}`;
    return { step, text };
  };
  const usage = { inputTokens: { total: 0, noCache: 0, cacheRead: 0, cacheWrite: 0 }, outputTokens: { total: 0, text: 0, reasoning: 0 } };
  return {
    specificationVersion: "v4",
    provider: "scripted",
    modelId: "scripted-refund",
    supportedUrls: {},
    async doGenerate(options: any) {
      const { step, text } = next(options);
      return {
        content: step ? [step] : [{ type: "text", text }],
        finishReason: { unified: step ? "tool-calls" : "stop", raw: undefined },
        usage,
        warnings: [],
      };
    },
    async doStream(options: any) {
      const { step, text } = next(options);
      const parts = step ? [step] : [{ type: "text-start", id: "t" }, { type: "text-delta", id: "t", delta: text }, { type: "text-end", id: "t" }];
      return {
        stream: ReadableStream.from([
          { type: "stream-start", warnings: [] },
          ...parts,
          { type: "finish", finishReason: { unified: step ? "tool-calls" : "stop", raw: undefined }, usage },
        ]),
      };
    },
  };
}

function call(toolName: string, input: unknown) {
  return { type: "tool-call", toolCallId: `call_${toolName}_${Math.random().toString(36).slice(2, 8)}`, toolName, input: JSON.stringify(input) };
}
