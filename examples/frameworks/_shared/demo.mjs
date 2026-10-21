// Shared setup for the TypeScript framework examples; the same run, tools and model-call
// budget as demo.py (see it for the reasoning). Run an example with
// ./examples/frameworks/run.sh <framework>.
import { readFileSync } from "node:fs";
import {
  BudgetExhausted, Client, ToolBlocked, ToolFailed, ToolOutcome, ToolPaused, ToolRejected, governedTool,
} from "../../../bindings/node/client.mjs";

const REQUESTS = new URL("../../support-refund/requests/", import.meta.url);
export const EVIDENCE = ["kg:order:ord_881#snapshot_kg_2026_05_03_T0930"];
export const GOAL =
  "Customer cus_77 reports order ord_881 arrived damaged. Check the order and refund it if it is refundable.";
export const INSTRUCTIONS =
  "You are a support agent. Look the order up before acting. Refund only a refundable order, " +
  "for at most its amount_minor. If a tool reports that an action was refused or paused, " +
  "do not retry it: explain what happened.";
// `--approval`: the pack's high-value rule requires an approval above 3,000 (see demo.py).
export const APPROVAL = process.argv.slice(2).includes("--approval");
// A model call reserves at least `[guards] model_call_min_tokens` (1,000 by default).
export const MODEL_CALL_TOKENS = 1000;
export { BudgetExhausted, ToolOutcome, ToolPaused, ToolBlocked, ToolRejected, ToolFailed };

/** True when none of the provider keys is set: the example then uses a scripted model. */
export const offline = (...envKeys) => !envKeys.some((key) => process.env[key]);

/** Admits a fresh run of the quickstart's support pack for this example. */
export async function admit(name) {
  const client = new Client(process.env.CONTEXTOS_URL ?? "http://127.0.0.1:8080", { token: process.env.CONTEXTOS_TOKEN });
  const runId = `run_${name}_${Date.now()}`;
  const body = JSON.parse(readFileSync(new URL("run.json", REQUESTS), "utf8"));
  body.run_context.run_id = body.contract.run_id = runId;
  body.contract.contract_id = `contract_${runId}`;
  if (APPROVAL) body.request.input.context.refund_amount = 5000;
  const run = await client.admit(body);
  console.log(`admitted ${run.runId} (executor generation ${run.executorGeneration})`);
  return { client, run };
}

/** The run's two governed tools as async functions of named arguments. */
export function tools(run) {
  return {
    // With --approval every call of the run is gated, reads included; keying the lookup
    // makes its re-sent call the same operation, which redeems the approval (see demo.py).
    lookupOrder: governedTool(run, "adp_orders.lookup", APPROVAL
      ? { idempotencyKey: (a) => `lookup:${a.order_id}`, toolCallId: (a) => `tc_lookup_${a.order_id}` }
      : {}),
    issueRefund: governedTool(run, "adp_payments.issue_refund", {
      approvalMode: "destructive",
      idempotencyKey: (a) => `refund:${a.order_id}`,
      toolCallId: (a) => `tc_refund_${a.order_id}`,
      evidenceRefs: EVIDENCE,
    }),
  };
}

/** Reserves budget for one model call around `fn` (`run.budgetedModelCall`); throws
 * BudgetExhausted when the run cannot afford it. In production pass the reservation id
 * to your LLM gateway, which meters the call; settling it here charges all of it. */
export function budgeted(run, fn, tokens = MODEL_CALL_TOKENS) {
  return run.budgetedModelCall(fn, { tokens });
}

/** What the model is told when the gateway did not complete a call (see demo.py). */
export function refusal(outcome) {
  const reasons = outcome.reasonCodes.join(", ") || outcome.status;
  const kind = outcome instanceof ToolPaused ? outcome.kind : null;
  if (kind === "duplicate") return `ALREADY REQUESTED (${reasons}): this exact action was submitted before and was not repeated.`;
  if (kind === "unknown_outcome") {
    return `OUTCOME UNKNOWN (${reasons}): the action may have happened and is being reconciled; do not retry it.`;
  }
  return `NOT DONE (${outcome.status}: ${reasons}). The action did not take effect; do not retry it.`;
}

/** Plays the reviewer: approves the paused call's exact action in the development
 * approval service (see demo.py). */
export async function approve(paused) {
  const requestId = paused.report.approval_request_id;
  const port = process.env.CONTEXTOS_DEV_PORTS.split(",")[2];
  const response = await fetch(`http://127.0.0.1:${port}/`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ op: "approve", approval_request_id: requestId }),
  });
  if (!response.ok) throw new Error(`approval service: ${response.status}`);
  console.log(`reviewer approved ${requestId}`);
}

/** Records the decision, completes the run and prints its evidence. */
export async function finish(client, run, refunded, summary) {
  const toolCalls = refunded ? [{ tool_call_id: "tc_refund_ord_881", operation_id: "refund:ord_881" }] : [];
  const decision = await run.recordDecision("support.refund.execute", refunded ? "DECIDED" : "REJECTED", {
    ...(refunded ? { outcome: "refund_issued" } : {}), toolCalls, rationale: { strategy: summary.slice(0, 500) },
  });
  console.log(`decision ${decision.record.record_id} (${refunded ? "refunded" : "not refunded"})`);
  console.log(`run ${(await run.complete()).status}`);
  const evidence = await run.evidence();
  let entries = 0;
  for await (const _ of client.auditEntries()) entries++;
  console.log(`evidence: budget used ${JSON.stringify(evidence.budget_ledger.used)}, ${entries} signed audit entries`);
}
