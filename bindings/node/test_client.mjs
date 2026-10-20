// End-to-end test of the HTTP client against a real contextosd.
// Run with: cargo build --release -p contextosd && node bindings/node/test_client.mjs
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { Client, ContextOSHTTPError, ToolBlocked, ToolPaused, governedTool } from "./client.mjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const binary = join(root, "target/release/contextosd");
const example = join(root, "examples/support-refund");
const KEY = "dev-key-0123456789abcdef0123456789abcdef";
const JUDGE_KEY = "dev-judge-0123456789abcdef0123456789abcd";
const OPS_KEY = "dev-ops-0123456789abcdef0123456789abcdef";

if (!existsSync(binary)) {
  console.log(`skipped: ${binary} not built`);
  process.exit(0);
}

const freePort = () => new Promise((ok) => {
  const server = createServer().listen(0, "127.0.0.1", () => {
    const { port } = server.address();
    server.close(() => ok(port));
  });
});
const [authority, constraints, approvals, payments, serverPort] = await Promise.all([1, 2, 3, 4, 5].map(freePort));

const services = spawn("python3", [join(example, "dev_services.py")], {
  env: { ...process.env, CONTEXTOS_DEV_PORTS: [authority, constraints, approvals, payments].join(",") },
  stdio: ["ignore", "pipe", "inherit"],
});
await new Promise((ok) => services.stdout.once("data", ok));

let config = readFileSync(join(example, "contextosd.toml"), "utf8")
  .replace("127.0.0.1:8080", `127.0.0.1:${serverPort}`)
  .replace("127.0.0.1:7701", `127.0.0.1:${authority}`)
  .replace("127.0.0.1:7702", `127.0.0.1:${constraints}`)
  .replace("127.0.0.1:7703", `127.0.0.1:${approvals}`)
  .replaceAll("127.0.0.1:7704", `127.0.0.1:${payments}`)
  .replaceAll('"examples/', `"${join(root, "examples")}/`)
  .replace("sha256:REPLACED_BY_RUN_SH", "sha256:" + createHash("sha256").update(KEY).digest("hex"));
const configPath = join(mkdtempSync(join(tmpdir(), "contextosd-")), "contextosd.toml");
writeFileSync(configPath, config);
const server = spawn(binary, ["--config", configPath], {
  env: { ...process.env, CONTEXTOS_AUDIT_SEED: "11".repeat(32) },
  stdio: "ignore",
});
const base = `http://127.0.0.1:${serverPort}`;
for (let i = 0; i < 100; i++) {
  try {
    if ((await fetch(`${base}/readyz`)).ok) break;
  } catch {}
  await new Promise((ok) => setTimeout(ok, 50));
}

try {
  const client = new Client(base, { token: KEY });
  assert.equal(JSON.stringify(client).includes(KEY), false, "the token is never serialized");
  const run = await client.admit(JSON.parse(readFileSync(join(example, "requests/run.json"), "utf8")));
  assert.equal(run.executorGeneration, 2);

  const call = JSON.parse(readFileSync(join(example, "requests/tool_call.json"), "utf8"));
  const options = { approvalMode: "destructive", idempotencyKey: call.idempotency_key, evidenceRefs: call.evidence_refs };
  const output = await run.callTool(call.capability_id, call.args, { ...options, toolCallId: "tc_1" });
  assert.equal(output.refund_id, "rf_ord_881");

  await assert.rejects(run.callTool(call.capability_id, call.args, options), (error) =>
    error instanceof ToolPaused && error.reasonCodes[0] === "retry_unsafe");

  const refund = governedTool(run, call.capability_id, {
    approvalMode: "destructive", evidenceRefs: call.evidence_refs, idempotencyKey: (a) => `refund:${a.order_id}:big`,
  });
  await assert.rejects(refund({ ...call.args, amount_minor: 999_999_999 }), (error) =>
    error instanceof ToolBlocked && error.reasonCodes[0] === "scope_mismatch");

  const decision = await run.recordDecision("support.refund.execute", "DECIDED", {
    outcome: "refund_issued", toolCalls: [{ tool_call_id: "tc_1", operation_id: call.idempotency_key }],
  });
  assert.equal(decision.record.tool_lineage[0].tool_call_id, "tc_1");

  // The orchestrator checkpoints its state after each verdict.
  assert.equal((await run.checkpoint({ step: 1, verdict: "accept" }, 0)).revision, 1);

  // Model calls spend the run's budget; a self-reported settlement charges it all.
  const reservation = await run.reserveUsage("model_call", { tokens: 300 });
  assert.equal((await run.settleUsage(reservation)).charged.tokens, 300);

  // An independent evaluator scores the decision; the executor's key cannot.
  const scores = { evaluatorRef: "evaluator.refund_quality@3", policy: 1, utility: 0.9, safety: 1 };
  await assert.rejects(client.score(run.runId, decision.record.record_id, scores), (error) =>
    error instanceof ContextOSHTTPError && error.status === 403);
  const judge = new Client(client.baseUrl, { token: JUDGE_KEY });
  const scored = await judge.score(run.runId, decision.record.record_id, scores);
  assert.equal(scored.score.scorecard.latency, decision.record.budget_usage.wall_clock_ms);

  // A read-only research lane funded by the run.
  const agent = JSON.parse(readFileSync(join(example, "requests/run.json"), "utf8"));
  const childId = `${run.runId}_lane`;
  const childBody = structuredClone(agent);
  childBody.run_context.run_id = childId;
  childBody.contract.run_id = childId;
  childBody.contract.contract_id = `contract_${childId}`;
  const agentId = agent.run_context.agent.agent_id;
  const lane = await run.delegate(childBody, {
    envelope_version: "contextos.agent_delegation.v1", delegation_id: `dlg_${childId}`, parent_run_id: run.runId,
    child_run_id: childId, trace_id: run.traceId, tenant_id: agent.contract.tenant_id, issuer: agentId, subject: agentId,
    principal_chain: run.principalChain,
    scope: { allowed_intents: [agent.request.input.intent], allowed_capabilities: ["adp_orders.lookup"],
      data_classification_ceiling: "CONFIDENTIAL", output_schema_ref: "schema://x" },
    sub_budget: { total_tokens: 10, bucket_tokens: {}, max_tool_calls: 1, max_replan_attempts: 0, wall_clock_ms: 1000, max_cost_cents: 1 },
    effect_policy: "read_only", issued_at: "2020-01-01T00:00:00Z", expires_at: "2098-01-01T00:00:00Z",
    parent_claim_hash: run.admitted.compiled_context_hash,
  });
  const order = await lane.callTool("adp_orders.lookup", { order_id: "ord_881" });
  assert.equal(order.refundable, true);
  const closed = await run.closeChild(lane);
  assert.equal(closed.usage.tool_calls, 1);

  const replacement = await (await client.attach(run.runId, run.traceId, run.principalChain)).takeOver();
  assert.equal(replacement.executorGeneration, 4);
  const stale = await client.request("POST", `/v1/runs/${run.runId}/tool-calls`, {
    body: run.envelope(call.capability_id, call.args, { ...options, idempotencyKey: "refund:other" }), generation: 2,
  });
  assert.deepEqual(stale.report.reason_codes, ["executor_stale"]);

  // Kill switch: a revoked capability is blocked before it is sent; restored, it runs.
  const ops = new Client(client.baseUrl, { token: OPS_KEY });
  await ops.revoke("capability", "adp_payments.issue_refund", "incident 4711");
  assert.equal((await ops.revocations()).revoked[0].by, "svc_oncall");
  await assert.rejects(
    replacement.callTool(call.capability_id, call.args, { ...options, idempotencyKey: "refund:revoked" }),
    (error) => error instanceof ToolBlocked && error.reasonCodes[0] === "revoked_capability");
  assert.deepEqual((await ops.restore("capability", "adp_payments.issue_refund", "resolved")).revoked, []);

  assert.deepEqual((await replacement.latestCheckpoint()).state, { step: 1, verdict: "accept" });
  assert.equal((await replacement.complete()).status, "completed");
  const sequences = [];
  for await (const entry of client.auditEntries({ page: 2 })) sequences.push(entry.sequence);
  assert.deepEqual(sequences, sequences.map((_, i) => i + 1));
  console.log(`ok: node client end to end (${sequences.length} audit entries)`);
} finally {
  server.kill();
  services.kill();
}
