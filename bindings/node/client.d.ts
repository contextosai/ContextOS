export declare const GENERATION_HEADER: "ContextOS-Executor-Generation";

export type ApprovalMode = "read_only" | "local_write" | "network" | "delegated" | "destructive";
export type DecisionStatus = "DECIDED" | "DEFERRED" | "REJECTED" | "ESCALATED" | "IN_FLIGHT" | "CLOSED";
export type Json = null | boolean | number | string | Json[] | { [key: string]: Json };

export type RevocationKind = "tenant" | "pack" | "agent" | "adapter" | "capability";
export interface Revocations {
  revoked: { kind: RevocationKind; target: string; reason: string; by: string; at: string }[];
}

export interface DispatchReport {
  status: string;
  action_digest: string | null;
  operation_id: string | null;
  attempt_id: string | null;
  reason_codes: string[];
  obligations: string[];
  approval_request_id: string | null;
  audit_sequences: number[];
}

export declare const RUN_HEADER: string;
export declare const RESERVATION_HEADER: string;

export declare class ContextOSHTTPError extends Error {
  readonly status: number;
  readonly code: string;
  readonly detail: unknown;
}

/** A model-call or replan reservation the run's budget cannot fit; stop the loop. */
export declare class BudgetExhausted extends ContextOSHTTPError {
  readonly reasons: string[];
}

export declare class ToolOutcome extends Error {
  readonly result: Record<string, Json>;
  readonly report: DispatchReport;
  readonly status: string;
  readonly reasonCodes: string[];
  readonly obligations: string[];
  readonly operationId: string | null;
}
/** Approval pending, input required, or an unknown outcome to reconcile. Never retry blindly. */
export declare class ToolPaused extends ToolOutcome {
  /**
   * What the pause waits on: `approval` (re-send the same call once approved), `input`
   * (answer with provideInput), `unknown_outcome` (the effect may have happened:
   * reconcile), `duplicate` (already requested; not repeated) or `other`.
   */
  readonly kind: "approval" | "input" | "unknown_outcome" | "duplicate" | "other";
  readonly inputRequests: Record<string, Json> | null;
}
/** Authority, policy, constraints or budget refused the call. */
export declare class ToolBlocked extends ToolOutcome {}
/** Malformed, not surfaced to this run, or incompatible reuse of an operation key. */
export declare class ToolRejected extends ToolOutcome {}
/** The provider definitively did not apply the effect. */
export declare class ToolFailed extends ToolOutcome {}

export interface CallOptions {
  approvalMode?: ApprovalMode;
  idempotencyKey?: string | null;
  evidenceRefs?: string[];
  toolCallId?: string;
}

export declare class Client {
  constructor(baseUrl: string, options: { token: string; timeoutMs?: number; maxRetries?: number; fetch?: typeof fetch });
  readonly baseUrl: string;
  request<T = any>(method: string, path: string, options?: { body?: unknown; generation?: number; query?: Record<string, string | number> }): Promise<T>;
  admit(body: Record<string, any>, options?: { principalChain?: { kind: string; id: string }[] }): Promise<Run>;
  attach(runId: string, traceId: string, principalChain: { kind: string; id: string }[]): Promise<Run>;
  /** Scores a recorded decision as an independent evaluator (token with only `evaluate`). */
  score(runId: string, recordId: string, scores: { evaluatorRef: string; policy: number; utility: number; safety: number }): Promise<{ score: Record<string, any>; audit_sequence: number }>;
  /** Files an operator correction or override against a run (token with `evaluate`, independent of the run). */
  fileFeedback(runId: string, feedback: { kind: "correction" | "override" | "approval_verdict"; targetSurface: FeedbackSurface; summary: string; decisionRecordId?: string; expectedOutcome?: string }): Promise<Feedback>;
  /** The tenant's open policy escalations, oldest first. */
  openEscalations(options?: { limit?: number }): Promise<{ open: number; escalations: Record<string, Json>[] }>;
  /** Records how a human resolved an escalation (token with `control`); grants nothing. */
  resolveEscalation(escalationId: string, resolution: "handled" | "dismissed", reason: string): Promise<Record<string, Json>>;
  /** The tenant's open feedback, oldest first. */
  openFeedback(options?: { limit?: number }): Promise<{ open: number; feedback: Feedback[] }>;
  /** Closes feedback with a reference to the evidence (token with `control`). */
  closeFeedback(feedbackId: string, status: "fixed" | "still_failing" | "invalid" | "superseded", evidence: { artifactType: string; artifactId: string; sha256: string }): Promise<Feedback>;
  /** Kill switch (token with the `control` scope). */
  revoke(kind: RevocationKind, target: string, reason: string): Promise<Revocations>;
  restore(kind: RevocationKind, target: string, reason: string): Promise<Revocations>;
  revocations(): Promise<Revocations>;
  auditEntries(options?: { from?: number; page?: number }): AsyncGenerator<Record<string, Json>>;
}

export type FeedbackSurface = "run_context" | "pack" | "policy" | "tool" | "memory" | "skill" | "evaluator" | "unknown";

export interface Feedback {
  feedback_id: string;
  run_id: string;
  trace_id: string;
  decision_record_id: string | null;
  kind: string;
  target_surface: FeedbackSurface;
  summary: string;
  expected_outcome: string | null;
  reporter: string;
  filed_at: string;
  status: "open" | "fixed" | "still_failing" | "invalid" | "superseded";
  replay_obligation: { case: string; replay_case: string };
  closed_at?: string;
  closed_by?: string;
  evidence_ref?: { artifact_type: string; artifact_id: string; sha256: string };
}

export declare class Run {
  readonly client: Client;
  readonly runId: string;
  readonly traceId: string;
  executorGeneration: number;
  readonly principalChain: { kind: string; id: string }[];
  envelope(capabilityId: string, args: Record<string, Json>, options?: CallOptions): Record<string, Json>;
  callTool(capabilityId: string, args: Record<string, Json>, options?: CallOptions): Promise<Record<string, Json>>;
  provideInput(paused: ToolPaused, envelope: Record<string, Json>, responses: Record<string, Json>): Promise<Record<string, Json>>;
  reconcile(operationId: string, options?: { outcome?: "confirmed" | "not_applied" | "partial"; evidenceRef?: Record<string, string> }): Promise<any>;
  recordDecision(decisionKey: string, status: DecisionStatus, options?: { decisionVersion?: string; outcome?: string; toolCalls?: { tool_call_id: string; operation_id: string }[]; [field: string]: unknown }): Promise<{ record: any; replay_packet: any }>;
  delegate(childAdmission: Record<string, any>, envelope: Record<string, any>): Promise<Run>;
  closeChild(child: Run, decision?: "accept" | "reject"): Promise<{ status: string; usage: Record<string, number> | null; reason_codes: string[] }>;
  checkpoint(state: Json, expectedRevision: number): Promise<{ run_id: string; revision: number; digest: string; executor_generation: number; saved_at: string }>;
  latestCheckpoint(): Promise<{ revision: number; digest: string; state: Json; executor_generation: number; saved_at: string }>;
  reserveUsage(kind: "model_call" | "replan", options?: { tokens?: number; costCents?: number }): Promise<string>;
  settleUsage(reservationId: string): Promise<{ reservation_id: string; charged: Record<string, number>; verified: boolean }>;
  /** Headers for a model request that a metering LLM gateway settles with the usage it measures. */
  meteringHeaders(reservationId: string): Record<string, string>;
  /**
   * Reserves budget around one model call and settles it afterwards; throws BudgetExhausted first if it
   * cannot fit. `metered` leaves settlement to a metering LLM gateway unless the call throws.
   */
  budgetedModelCall<T>(
    fn: (reservationId: string) => Promise<T>,
    options: { tokens: number; costCents?: number; metered?: boolean },
  ): Promise<T>;
  status(): Promise<{ run_id: string; status: string; executor_generation: number }>;
  takeOver(): Promise<Run>;
  complete(): Promise<any>;
  fail(): Promise<any>;
  cancel(): Promise<any>;
  evidence(): Promise<any>;
}

export declare function governedTool<A extends Record<string, Json>>(
  run: Run,
  capabilityId: string,
  options?: {
    approvalMode?: ApprovalMode;
    idempotencyKey?: (args: A) => string;
    evidenceRefs?: string[];
    toolCallId?: (args: A) => string;
  },
): (args: A) => Promise<Record<string, Json>>;
