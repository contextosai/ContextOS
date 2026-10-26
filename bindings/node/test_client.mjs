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
import {
  BudgetExhausted, Client, ContextOSHTTPError, ToolBlocked, ToolPaused, governedTool, taskAuthorization, taskScope,
} from "./client.mjs";

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

  // A run bound to what the user asked: the refund of ord_881 to cus_77, up to INR 1200.
  const scoped = JSON.parse(readFileSync(join(example, "requests/run.json"), "utf8"));
  scoped.run_context.run_id = scoped.contract.run_id = "run_scoped";
  scoped.contract.contract_id = "contract_scoped";
  const user = { principal_id: "usr_771", principal_type: "person", trust_domain: "contextos.dev", tenant_id: "tenant_acme_prod" };
  scoped.task_authorization = taskAuthorization(user, [taskScope("run_scoped", "support.refund", call.capability_id, {
    resources: ["ord_881"], destinations: ["cus_77"], amount: [120_000, "INR"],
  })]);
  const scopedRun = await client.admit(scoped);
  await assert.rejects(
    scopedRun.callTool(call.capability_id, { ...call.args, amount_minor: 480_000 }, { ...options, idempotencyKey: "refund:more" }),
    (error) => error instanceof ToolBlocked && error.reasonCodes.includes("outside_task_authorization")
      && error.reasonCodes.includes("task_scope_amount"));
  // The executor may restrict its own task further; widening is not its call.
  const lower = taskAuthorization(user, [taskScope("run_scoped", "support.refund", call.capability_id, {
    resources: ["ord_881"], destinations: ["cus_77"], amount: [50_000, "INR"],
  })], { maxEffects: 1, amountTotal: { minorUnits: 50_000, currency: "INR" } });
  assert.deepEqual(lower.limits, { max_effects: 1, amount_total: { minor_units: 50_000, currency: "INR" } });
  assert.equal((await client.amendTaskAuthorization("run_scoped", 0, lower)).change, "narrowed");
  await assert.rejects(client.amendTaskAuthorization("run_scoped", 1, scoped.task_authorization), (error) =>
    error instanceof ContextOSHTTPError && error.status === 403);

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

  assert.equal((await run.publishWork("inspect", "Inspect the order", "Record a test report")).task.revision, 1);
  assert.equal((await run.workTasks({ limit: 1 })).tasks[0].task_id, "inspect");
  assert.equal((await run.workTask("inspect")).data_only, true);
  const claimed = await run.updateWork("inspect", { action: "claim", expected_revision: 1, lease_seconds: 30 });
  assert.equal(claimed.task.claim.run_id, run.runId);
  const done = await run.updateWork("inspect", { action: "complete", expected_revision: 2, lease_epoch: 1,
    evidence_refs: [{ artifact_type: "test", artifact_id: "local-report", sha256: `sha256:${"a".repeat(64)}` }] });
  assert.equal(done.task.status, "completed");
  assert.equal(done.evidence_verified, false);
  await assert.rejects(run.updateWork("inspect", { action: "claim", expected_revision: 1, lease_seconds: 30 }),
    (error) => error instanceof ContextOSHTTPError && error.code === "work_conflict");

  // Model calls spend the run's budget; a self-reported settlement charges it all.
  const reservation = await run.reserveUsage("model_call", { tokens: 3000 });
  assert.equal((await run.settleUsage(reservation)).charged.tokens, 3000);
  // A reservation the run cannot afford is refused before the model is called.
  await assert.rejects(run.budgetedModelCall(async () => assert.fail("the model call ran"), { tokens: 1_000_000 }),
    (error) => error instanceof BudgetExhausted && error.status === 409 && error.reasons.length > 0);
  assert.equal(await run.budgetedModelCall(async (id) => id.startsWith("usage:"), { tokens: 1000 }), true);
  // Metered: the headers name the reservation for the gateway; a call that throws first
  // is settled here, so a second settlement finds nothing open.
  let metered;
  await assert.rejects(run.budgetedModelCall(async (id) => {
    metered = id;
    assert.deepEqual(run.meteringHeaders(id), { "ContextOS-Run-Id": run.runId, "ContextOS-Usage-Reservation": id });
    throw new Error("model unreachable");
  }, { tokens: 1000, metered: true }), /model unreachable/);
  await assert.rejects(run.settleUsage(metered), (error) => error instanceof ContextOSHTTPError && error.status === 404);

  // An independent evaluator scores the decision; the executor's key cannot.
  const scores = { evaluatorRef: "evaluator.refund_quality@3", policy: 1, utility: 0.9, safety: 1 };
  await assert.rejects(client.score(run.runId, decision.record.record_id, scores), (error) =>
    error instanceof ContextOSHTTPError && error.status === 403);
  const judge = new Client(client.baseUrl, { token: JUDGE_KEY });
  const scored = await judge.score(run.runId, decision.record.record_id, scores);
  assert.equal(scored.score.scorecard.latency, decision.record.budget_usage.wall_clock_ms);

  // The reviewer files a correction; an operator closes it with evidence.
  const filed = await judge.fileFeedback(run.runId, {
    kind: "correction", targetSurface: "policy", summary: "Refund should have been escalated.",
    decisionRecordId: decision.record.record_id, expectedOutcome: "escalate",
  });
  assert.equal(filed.replay_obligation.case, run.runId);
  assert.equal((await client.openFeedback()).open, 1);
  const resolved = await new Client(client.baseUrl, { token: OPS_KEY }).closeFeedback(filed.feedback_id, "fixed", {
    artifactType: "gate_report", artifactId: "gate_1", sha256: `sha256:${"c".repeat(64)}`,
  });
  assert.equal(resolved.status, "fixed");
  assert.equal((await client.openFeedback()).open, 0);

  // No escalations are open; resolving an unknown one is refused.
  assert.equal((await client.openEscalations()).open, 0);
  await assert.rejects(new Client(client.baseUrl, { token: OPS_KEY }).resolveEscalation("esc_unknown", "handled", "n/a"),
    (error) => error instanceof ContextOSHTTPError && error.status === 404);

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
