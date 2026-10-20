// HTTP client for contextosd: govern an agent's tool calls from Node.js or any
// runtime with fetch. No dependencies and no native addon.
//
//   import { Client, ToolPaused, ToolBlocked, governedTool } from "@contextos/kernel/client";
//   const client = new Client("https://contextos.internal", { token: process.env.CONTEXTOS_TOKEN });
//   const run = await client.admit(admissionBody);       // holds the executor generation
//   const output = await run.callTool("adp_payments.issue_refund", args,
//     { approvalMode: "destructive", idempotencyKey: "refund:ord_881", evidenceRefs });
//
// Results that are not plain success throw: ToolPaused (approval, input, or an
// unknown outcome to reconcile — never retry blindly), ToolBlocked, ToolRejected,
// ToolFailed. Only requests the server did not process (429, 503) are retried.

export const GENERATION_HEADER = "ContextOS-Executor-Generation";

export class ContextOSHTTPError extends Error {
  constructor(status, code, message, detail) {
    super(`${status} ${code}: ${message}`);
    this.status = status;
    this.code = code;
    this.detail = detail;
  }
}

export class ToolOutcome extends Error {
  constructor(result, report) {
    const reasons = report.reason_codes ?? [];
    super(`${result.status}: ${reasons.join(", ") || result.error || ""}`);
    this.result = result;
    this.report = report;
    this.status = result.status;
    this.reasonCodes = reasons;
    this.obligations = report.obligations ?? [];
    this.operationId = report.operation_id ?? null;
  }
}
export class ToolPaused extends ToolOutcome {
  get inputRequests() {
    return this.result.output?.result?.inputRequests ?? null;
  }
}
export class ToolBlocked extends ToolOutcome {}
export class ToolRejected extends ToolOutcome {}
export class ToolFailed extends ToolOutcome {}

const OUTCOMES = { paused: ToolPaused, blocked: ToolBlocked, rejected: ToolRejected, failed: ToolFailed };

function outcome(response) {
  const { result, report } = response;
  if (result.status === "ok" || result.status === "completed") return result.output ?? {};
  throw new (OUTCOMES[result.status] ?? ToolOutcome)(result, report);
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const segment = (value) => encodeURIComponent(value);

export class Client {
  #token;

  constructor(baseUrl, { token, timeoutMs = 30_000, maxRetries = 3, fetch: fetchImpl = globalThis.fetch } = {}) {
    if (!token) throw new TypeError("a token is required");
    this.baseUrl = baseUrl.replace(/\/+$/, "");
    this.#token = token;
    this.timeoutMs = timeoutMs;
    this.maxRetries = maxRetries;
    this.fetch = fetchImpl;
  }

  toJSON() {
    return { baseUrl: this.baseUrl }; // never serialize the token
  }

  async request(method, path, { body, generation, query } = {}) {
    let url = this.baseUrl + path;
    if (query) url += "?" + new URLSearchParams(Object.entries(query).map(([k, v]) => [k, String(v)]));
    const headers = { Authorization: `Bearer ${this.#token}`, Accept: "application/json" };
    if (body !== undefined) headers["Content-Type"] = "application/json";
    if (generation !== undefined) headers[GENERATION_HEADER] = String(generation);
    for (let attempt = 0; ; attempt++) {
      const response = await this.fetch(url, {
        method,
        headers,
        body: body === undefined ? undefined : JSON.stringify(body),
        signal: AbortSignal.timeout(this.timeoutMs),
        redirect: "error",
      });
      const text = await response.text();
      const decoded = text ? JSON.parse(text) : null;
      if (response.ok) return decoded;
      // Not processed: safe to retry after the server's hint.
      if ((response.status === 429 || response.status === 503) && attempt < this.maxRetries) {
        const hint = Number(response.headers.get("retry-after"));
        await sleep(Number.isFinite(hint) && hint > 0 ? Math.min(hint, 30) * 1000 : Math.min(200 * 2 ** attempt, 5000));
        continue;
      }
      const failure = decoded?.error;
      if (failure && typeof failure === "object") {
        throw new ContextOSHTTPError(response.status, failure.code ?? "error", failure.message ?? "", failure.detail);
      }
      throw new ContextOSHTTPError(response.status, "refused", text, decoded);
    }
  }

  /** Admits a run (POST /v1/runs) and returns a handle that owns it. */
  async admit(body, { principalChain } = {}) {
    const admitted = await this.request("POST", "/v1/runs", { body });
    const context = body.run_context ?? {};
    const agent = context.agent?.agent_id;
    return new Run(this, admitted.run_id, context.trace_id ?? "", admitted.executor_generation,
      principalChain ?? (agent ? [{ kind: "agent", id: agent }] : []), admitted);
  }

  /** A handle on an existing run at its current generation (no takeover). */
  async attach(runId, traceId, principalChain) {
    const status = await this.request("GET", `/v1/runs/${segment(runId)}`);
    return new Run(this, runId, traceId, status.executor_generation, principalChain, status);
  }

  /** Yields the tenant's signed audit entries in order. */
  async *auditEntries({ from = 1, page = 500 } = {}) {
    let cursor = from;
    while (cursor != null) {
      const batch = await this.request("GET", "/v1/audit/entries", { query: { from: cursor, limit: page } });
      yield* batch.entries;
      cursor = batch.next;
    }
  }
}

export class Run {
  constructor(client, runId, traceId, executorGeneration, principalChain, admitted = {}) {
    Object.assign(this, { client, runId, traceId, executorGeneration, principalChain, admitted });
  }

  #path(suffix = "") {
    return `/v1/runs/${segment(this.runId)}${suffix}`;
  }

  #post(suffix, body = {}) {
    return this.client.request("POST", this.#path(suffix), { body, generation: this.executorGeneration });
  }

  envelope(capabilityId, args, { approvalMode = "read_only", idempotencyKey = null, evidenceRefs = [], toolCallId } = {}) {
    return {
      envelope_version: "contextos.tool_call.v1",
      tool_call_id: toolCallId ?? `tc_${globalThis.crypto.randomUUID().replaceAll("-", "")}`,
      run_id: this.runId, trace_id: this.traceId, capability_id: capabilityId, args,
      principal_chain: this.principalChain, approval_mode_requested: approvalMode,
      approval_mode_effective: approvalMode, approval_mode_highest: approvalMode,
      evidence_refs: evidenceRefs, idempotency_key: idempotencyKey,
    };
  }

  /** Governs and dispatches one tool call; resolves to its output or throws a ToolOutcome. */
  async callTool(capabilityId, args, options = {}) {
    return outcome(await this.#post("/tool-calls", this.envelope(capabilityId, args, options)));
  }

  async provideInput(paused, envelope, responses) {
    return outcome(await this.#post(`/operations/${segment(paused.operationId ?? "")}/input`,
      { tool_call: envelope, input_responses: responses }));
  }

  /** Resolves an unknown effect: by provider query, or by asserting `outcome` with evidence. */
  reconcile(operationId, { outcome: asserted, evidenceRef } = {}) {
    const body = asserted === undefined ? { source: "provider" }
      : { source: "operator", outcome: asserted, evidence_ref: evidenceRef };
    return this.#post(`/operations/${segment(operationId)}/reconcile`, body);
  }

  recordDecision(decisionKey, status, { decisionVersion = "1", toolCalls = [], ...fields } = {}) {
    return this.#post("/decisions", { decision_key: decisionKey, decision_version: decisionVersion, status,
      tool_calls: toolCalls, ...fields });
  }

  status() {
    return this.client.request("GET", this.#path());
  }

  /** Takes the run over; the previous executor's generation becomes stale. */
  async takeOver() {
    const { executor_generation: current } = await this.status();
    const taken = await this.client.request("POST", this.#path("/takeover"), { body: { expected_generation: current } });
    this.executorGeneration = taken.executor_generation;
    return this;
  }

  complete() { return this.#post("/complete"); }
  fail() { return this.#post("/fail"); }
  cancel() { return this.client.request("POST", this.#path("/cancel"), { body: {} }); }
  evidence() { return this.client.request("GET", this.#path("/evidence")); }
}

/**
 * Wraps a capability as an async tool function taking named arguments. Register the
 * result with any framework that accepts async functions (Vercel AI SDK, LangChain.js,
 * OpenAI Agents SDK). `idempotencyKey` derives the operation key from the arguments.
 */
export function governedTool(run, capabilityId, { approvalMode = "read_only", idempotencyKey, evidenceRefs = [] } = {}) {
  return (args) => run.callTool(capabilityId, args, {
    approvalMode, evidenceRefs, idempotencyKey: idempotencyKey ? idempotencyKey(args) : null,
  });
}
