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
import { Client, ToolBlocked, ToolPaused, governedTool } from "./client.mjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const binary = join(root, "target/release/contextosd");
const example = join(root, "examples/support-refund");
const KEY = "dev-key-0123456789abcdef0123456789abcdef";

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
  .replace("127.0.0.1:7704", `127.0.0.1:${payments}`)
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

  const replacement = await (await client.attach(run.runId, run.traceId, run.principalChain)).takeOver();
  assert.equal(replacement.executorGeneration, 4);
  const stale = await client.request("POST", `/v1/runs/${run.runId}/tool-calls`, {
    body: run.envelope(call.capability_id, call.args, { ...options, idempotencyKey: "refund:other" }), generation: 2,
  });
  assert.deepEqual(stale.report.reason_codes, ["executor_stale"]);

  assert.equal((await replacement.complete()).status, "completed");
  const sequences = [];
  for await (const entry of client.auditEntries({ page: 2 })) sequences.push(entry.sequence);
  assert.deepEqual(sequences, sequences.map((_, i) => i + 1));
  console.log(`ok: node client end to end (${sequences.length} audit entries)`);
} finally {
  server.kill();
  services.kill();
}
