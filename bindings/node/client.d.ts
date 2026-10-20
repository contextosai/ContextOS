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

export declare class ContextOSHTTPError extends Error {
  readonly status: number;
  readonly code: string;
  readonly detail: unknown;
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
  /** Kill switch (token with the `control` scope). */
  revoke(kind: RevocationKind, target: string, reason: string): Promise<Revocations>;
  restore(kind: RevocationKind, target: string, reason: string): Promise<Revocations>;
  revocations(): Promise<Revocations>;
  auditEntries(options?: { from?: number; page?: number }): AsyncGenerator<Record<string, Json>>;
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
  options?: { approvalMode?: ApprovalMode; idempotencyKey?: (args: A) => string; evidenceRefs?: string[] },
): (args: A) => Promise<Record<string, Json>>;
