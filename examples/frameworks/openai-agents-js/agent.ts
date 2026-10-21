// The OpenAI Agents SDK for TypeScript running its own agent loop (`run`), governed by
// ContextOS. The same design as ../openai-agents/agent.py:
//
// - The run's governed functions become SDK tools; their bodies never run locally.
// - Every model call reserves budget first: a ModelProvider wraps each model the
//   runner resolves, so reservation and settlement bracket the call even if it throws.
// - A refusal reaches the model as `refusal()` text ("NOT DONE", or "ALREADY REQUESTED"
//   for a repeat) through `errorFunction`; the SDK's default tells the model "Please try
//   again". A pause for approval, input or an unknown outcome stops the run instead.
// - The refund needs a human's approval in the SDK too (`needsApproval`); the paused
//   RunState is checkpointed in ContextOS before the run resumes.
//
// Without OPENAI_API_KEY a scripted model (the SDK's ScriptedModel) drives the loop:
// look up, refund, refund again (refused), answer.
//
// Run with: ./examples/frameworks/run.sh openai-agents-js
import { Agent, OpenAIProvider, Runner, ToolCallError, tool } from "@openai/agents";
import type { Model, ModelProvider, ModelRequest } from "@openai/agents";
import { ScriptedModel, assistantMessage, functionCall, modelResponder } from "@openai/agents/testing";
import type { RecordedModelCall } from "@openai/agents/testing";
import { z } from "zod";
import { GOAL, INSTRUCTIONS, MODEL_CALL_TOKENS, ToolOutcome, ToolPaused, admit, budgeted, finish, offline, refusal, tools } from "../_shared/demo.mjs";

const MODEL = process.env.OPENAI_MODEL ?? "gpt-6.1-sol";

/** Reserves run budget before each model call and settles it after, success or not. */
function budgetedModel(run: any, inner: Model): Model {
  return {
    getResponse: (request: ModelRequest) => budgeted(run, () => inner.getResponse(request)),
    async *getStreamedResponse(request: ModelRequest) {
      const reservation = await run.reserveUsage("model_call", { tokens: MODEL_CALL_TOKENS });
      try {
        yield* inner.getStreamedResponse(request);
      } finally {
        await run.settleUsage(reservation);
      }
    },
    getRetryAdvice: (args) => inner.getRetryAdvice?.(args),
  };
}

/** Every agent the runner drives (handoffs included) gets a budgeted model. */
const budgetedProvider = (run: any, inner: ModelProvider): ModelProvider => ({
  getModel: async (name?: string) => budgetedModel(run, await inner.getModel(name)),
});

function outputOf(call: RecordedModelCall, callId: string): string {
  const input = call.request.input as any[];
  const output = input.find((item) => item.type === "function_call_result" && item.callId === callId)?.output;
  return typeof output === "string" ? output : output?.text;
}

function refundArgs(call: RecordedModelCall) {
  const order = JSON.parse(outputOf(call, "call_lookup"));
  return { order_id: "ord_881", customer_id: "cus_77", amount_minor: order.amount_minor };
}

/** The offline stand-in for a model: the steps a model would take. */
const script = (): ModelProvider => {
  const model = new ScriptedModel([
    [functionCall("lookup_order", { order_id: "ord_881" }, { callId: "call_lookup" })],
    modelResponder((call) => [functionCall("issue_refund", refundArgs(call), { callId: "call_refund" })]),
    // A confused model repeating the effect: the gateway refuses it.
    modelResponder((call) => [functionCall("issue_refund", refundArgs(call), { callId: "call_refund_again" })]),
    modelResponder((call) => [assistantMessage(
      `Refunded ord_881 in full. The repeat refund was refused: ${outputOf(call, "call_refund_again")}`)]),
  ]);
  return { getModel: () => model };
};

/** What the model sees when a governed call did not complete. */
function governedFailure(_context: unknown, error: unknown): string {
  const stops = error instanceof ToolPaused && ["approval", "input", "unknown_outcome"].includes(error.kind);
  if (error instanceof ToolOutcome && !stops) {
    // Refused, or a repeat of an operation that already exists (kind "duplicate").
    return refusal(error);
  }
  throw error; // approval pending, input required, unknown outcome, transport error: the run stops
}

const { client, run } = await admit("openai_agents_js");
const { lookupOrder, issueRefund } = tools(run);
const agent = new Agent({
  name: "support",
  instructions: INSTRUCTIONS,
  model: MODEL, // a name, so the runner's provider resolves (and budgets) it
  modelSettings: { parallelToolCalls: false }, // look up before acting
  tools: [
    tool({
      name: "lookup_order",
      description: "Look up an order's status, amount (amount_minor) and refund eligibility.",
      parameters: z.object({ order_id: z.string() }),
      execute: (args) => lookupOrder(args),
      errorFunction: governedFailure,
    }),
    tool({
      name: "issue_refund",
      description: "Issue a refund for an order to its customer, in minor units of the order's currency.",
      parameters: z.object({ order_id: z.string(), customer_id: z.string(), amount_minor: z.number().int() }),
      execute: (args) => issueRefund(args),
      errorFunction: governedFailure,
      needsApproval: true, // every refund is shown to a human first; the gateway still decides
    }),
  ],
});

const scripted = offline("OPENAI_API_KEY");
const runner = new Runner({
  modelProvider: budgetedProvider(run, scripted ? script() : new OpenAIProvider()),
  tracingDisabled: scripted,
  traceIncludeSensitiveData: false,
});
let refunded = false;
runner.on("agent_tool_end", (_context, _agent, calledTool, result) => {
  console.log(`tool ${calledTool.name} -> ${result}`);
  if (calledTool.name === "issue_refund" && String(result).startsWith('{"refund_id"')) refunded = true;
});

let result;
try {
  result = await runner.run(agent, GOAL, { maxTurns: 8 });
  let revision = 0;
  while (result.interruptions.length > 0) {
    const state = result.state;
    for (const item of result.interruptions) {
      console.log(`approval requested: ${item.name}(${item.arguments})`);
      state.approve(item); // a real reviewer decides here
    }
    // Save the approved state with the run: another executor, or this one after a
    // gateway pause, resumes from it and re-sends the same governed call.
    revision = (await run.checkpoint({ sdk_run_state: JSON.parse(state.toString()) }, revision)).revision;
    console.log(`approved; checkpoint revision ${revision}`);
    result = await runner.run(agent, state, { maxTurns: 8 });
  }
} catch (error) {
  const paused = error instanceof ToolCallError ? error.error : error; // the SDK wraps what a tool threw
  if (!(paused instanceof ToolOutcome)) throw error;
  const kind = paused instanceof ToolPaused ? paused.kind : paused.status;
  console.log(`paused (${kind}): ${paused.reasonCodes} ${paused.obligations}; wait for approval, answer input or reconcile, never retry`);
  process.exit(1);
}
console.log(`agent: ${result.finalOutput}`);
await finish(client, run, refunded, String(result.finalOutput));
