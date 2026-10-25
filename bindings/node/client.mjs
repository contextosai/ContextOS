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
// On a model request, these tell a metering LLM gateway which reservation to settle with
// the usage it measures (see examples/metering-proxy).
export const RUN_HEADER = "ContextOS-Run-Id";
export const RESERVATION_HEADER = "ContextOS-Usage-Reservation";

export class ContextOSHTTPError extends Error {
  constructor(status, code, message, detail) {
    super(`${status} ${code}: ${message}`);
    this.status = status;
    this.code = code;
    this.detail = detail;
  }
}

/** The run's budget cannot fit a model-call or replan reservation; `reasons` says which
 * limit. Stop the loop: retrying the same reservation cannot succeed. */
export class BudgetExhausted extends ContextOSHTTPError {
  get reasons() {
    return Array.isArray(this.detail) ? this.detail : [];
  }
}
const HTTP_ERRORS = { budget_exhausted: BudgetExhausted };

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
  /** What the pause waits on; see client.d.ts. */
  get kind() {
    const { obligations: o, reasonCodes: r } = this;
    if (o.includes("await_approval")) return "approval";
    if (o.includes("provide_requested_input")) return "input";
    if (o.includes("reconcile_effect_before_retry")) return "unknown_outcome";
    if (r.includes("retry_unsafe") || o.includes("reconcile_existing_operation")) return "duplicate";
    return "other";
  }
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
const segment = (value) => {
  if (value === "" || value === "." || value === "..") throw new TypeError(`invalid path segment ${JSON.stringify(value)}`);
  return encodeURIComponent(value);
};

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
        const code = failure.code ?? "error";
        throw new (HTTP_ERRORS[code] ?? ContextOSHTTPError)(response.status, code, failure.message ?? "", failure.detail);
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

  /**
   * Scores a recorded decision as an independent evaluator (a client whose token has
   * only the `evaluate` scope). The runtime adds the measured cost and latency.
   */
  /**
   * Corrects what a run's principal authorized. Narrowing is open to the executor;
   * widening needs an `authorize` token that does not run tasks, the principal's
   * `confirmation_ref` and the same `issued_by`. Resolves to the new revision.
   */
  amendTaskAuthorization(runId, expectedRevision, task) {
    return this.request("PUT", `/v1/runs/${segment(runId)}/task-authorization`, {
      body: { expected_revision: expectedRevision, task_authorization: task },
    });
  }

  score(runId, recordId, { evaluatorRef, policy, utility, safety }) {
    return this.request("POST", `/v1/runs/${segment(runId)}/decisions/${segment(recordId)}/scores`, {
      body: { evaluator_ref: evaluatorRef, policy, utility, safety },
    });
  }

  /**
   * Files an operator correction or override against a run as an independent reviewer
   * (`evaluate` scope); the run's replay case becomes its replay obligation.
   */
  fileFeedback(runId, { kind, targetSurface, summary, decisionRecordId, expectedOutcome }) {
    const body = { kind, target_surface: targetSurface, summary };
    if (decisionRecordId !== undefined) body.decision_record_id = decisionRecordId;
    if (expectedOutcome !== undefined) body.expected_outcome = expectedOutcome;
    return this.request("POST", `/v1/runs/${segment(runId)}/feedback`, { body });
  }

  /** The tenant's open policy escalations, oldest first (`audit:read`). */
  openEscalations({ limit = 500 } = {}) {
    return this.request("GET", "/v1/escalations", { query: { limit } });
  }

  /**
   * Records how a human resolved an escalation, `handled` or `dismissed` (`control`).
   * Grants nothing: an action the human approves is retried through policy.
   */
  resolveEscalation(escalationId, resolution, reason) {
    return this.request("POST", `/v1/escalations/${segment(escalationId)}/resolve`, { body: { resolution, reason } });
  }

  /** The tenant's open feedback, oldest first: the replay corpus a change must pass. */
  openFeedback({ limit = 500 } = {}) {
    return this.request("GET", "/v1/feedback", { query: { limit } });
  }

  /**
   * Closes feedback as `fixed`, `still_failing`, `invalid` or `superseded`, with a
   * reference to the evidence (`control` scope).
   */
  closeFeedback(feedbackId, status, { artifactType, artifactId, sha256 }) {
    return this.request("POST", `/v1/feedback/${segment(feedbackId)}/close`, {
      body: { status, evidence_ref: { artifact_type: artifactType, artifact_id: artifactId, sha256 } },
    });
  }

  /**
   * Kill switch (token with the `control` scope): revokes a `tenant`, `pack`, `agent`,
   * `adapter` or `capability` from the next dispatch and admission.
   */
  revoke(kind, target, reason) {
    return this.request("POST", "/v1/revocations", { body: { kind, target, reason } });
  }

  /** Restores a revoked target. */
  restore(kind, target, reason) {
    return this.request("POST", "/v1/revocations/restore", { body: { kind, target, reason } });
  }

  /** The tenant's revoked targets. */
  revocations() {
    return this.request("GET", "/v1/revocations");
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

  /**
   * Admits a child run in a narrowed lane (AgentDelegationEnvelope). Its budget is
   * reserved from this run, which must hold the current generation.
   */
  async delegate(childAdmission, envelope) {
    const admitted = await this.client.request("POST", "/v1/runs", {
      body: { ...childAdmission, delegation: envelope }, generation: this.executorGeneration,
    });
    return new Run(this.client, admitted.run_id, childAdmission.run_context?.trace_id ?? this.traceId,
      admitted.executor_generation, this.principalChain, admitted);
  }

  /** Closes a delegated child (`accept` or `reject`), settling its spend into this run. */
  closeChild(child, decision = "accept") {
    return this.client.request("POST", `/v1/runs/${segment(child.runId)}/close`, {
      body: { decision }, generation: this.executorGeneration,
    });
  }

  /** Saves the orchestrator's state as the next checkpoint revision. */
  checkpoint(state, expectedRevision) {
    return this.#post("/checkpoint", { expected_revision: expectedRevision, state });
  }

  /** The latest checkpoint (`state`, `revision`), e.g. after taking the run over. */
  latestCheckpoint() {
    return this.client.request("GET", this.#path("/checkpoint"), { generation: this.executorGeneration });
  }

  /** Reserves budget for a `model_call` or a `replan`; resolves to the reservation id. */
  async reserveUsage(kind, { tokens = 0, costCents = 0 } = {}) {
    return (await this.#post("/usage/reserve", { kind, tokens, cost_cents: costCents })).reservation_id;
  }

  /**
   * Settles a reservation as the executor: the whole reservation is charged. Pass the
   * id to your metering gateway instead to settle measured usage.
   */
  settleUsage(reservationId) {
    return this.#post("/usage/settle", { reservation_id: reservationId });
  }

  /** Headers for a model request that a metering LLM gateway settles with the usage it
   * measures (`budgetedModelCall(fn, { metered: true })`). */
  meteringHeaders(reservationId) {
    return { [RUN_HEADER]: this.runId, [RESERVATION_HEADER]: reservationId };
  }

  /** Reserves budget for one model call around `fn(reservationId)` and settles it
   * afterwards, even if `fn` throws. Throws BudgetExhausted before calling `fn` when the
   * run cannot afford it. `metered: true` leaves settlement to a metering LLM gateway
   * (send `meteringHeaders(id)`); if `fn` throws, a reservation the gateway did not
   * settle is settled here, charging all of it. */
  async budgetedModelCall(fn, { tokens, costCents = 0, metered = false }) {
    const reservation = await this.reserveUsage("model_call", { tokens, costCents });
    let result;
    try {
      result = await fn(reservation);
    } catch (error) {
      await (metered ? this.#settleOpen(reservation) : this.settleUsage(reservation));
      throw error;
    }
    if (!metered) await this.settleUsage(reservation);
    return result;
  }

  async #settleOpen(reservationId) {
    try {
      await this.settleUsage(reservationId);
    } catch (error) {
      if (!(error instanceof ContextOSHTTPError && error.status === 404)) throw error; // settled by the gateway
    }
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
 * OpenAI Agents SDK). `idempotencyKey` derives the operation key from the arguments,
 * and `toolCallId` the call's id, so a DecisionRecord can cite it.
 */
export function governedTool(run, capabilityId, { approvalMode = "read_only", idempotencyKey, evidenceRefs = [], toolCallId } = {}) {
  return (args) => run.callTool(capabilityId, args, {
    approvalMode, evidenceRefs, idempotencyKey: idempotencyKey ? idempotencyKey(args) : null,
    toolCallId: toolCallId ? toolCallId(args) : undefined,
  });
}

/**
 * One `AuthorityGrant` scope for a task authorization: this capability, on these
 * resources, to these destinations, up to `amount` = `[minorUnits, currency]`.
 */
export function taskScope(rootRunId, purposeId, capabilityId, {
  resources = [], destinations = [], classification = "CONFIDENTIAL", amount, argumentConstraints = [],
} = {}) {
  const scope = {
    root_run_id: rootRunId, purpose_ids: [purposeId], capability_ids: [capabilityId],
    resource_ids: [...resources], destination_ids: [...destinations], classification_labels: [classification],
    argument_constraints: [...argumentConstraints],
  };
  if (amount) scope.amount_ceiling = { minor_units: amount[0], currency: amount[1] };
  return scope;
}

/**
 * What the principal authorized for a run, for `admit(body)` as
 * `body.task_authorization`. Effects outside every scope are refused
 * (`outOfScope: "deny"`) or wait for an exact approval (`"ask"`, thrown as
 * `ToolPaused` with `kind === "approval"`).
 */
export function taskAuthorization(issuedBy, scopes, { outOfScope = "deny", readOnly = "allow", confirmationRef, maxEffects, amountTotal } = {}) {
  const task = { issued_by: issuedBy, scopes, out_of_scope: outOfScope, read_only: readOnly };
  if (confirmationRef) task.confirmation_ref = confirmationRef;
  // Bounds on the task as a whole, across all its effects.
  const limits = {};
  if (maxEffects !== undefined) limits.max_effects = maxEffects;
  if (amountTotal) limits.amount_total = { minor_units: amountTotal.minorUnits, currency: amountTotal.currency };
  if (Object.keys(limits).length) task.limits = limits;
  return task;
}
