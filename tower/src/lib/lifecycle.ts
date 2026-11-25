// Agent lifecycle stages and the moves between them, as towerd allows them
// (crates/towerd/src/ops/lifecycle.rs).

export const STAGES = ["proposed", "approved", "pilot", "production", "deprecated", "suspended", "retired"] as const;

const NEXT: Record<string, string[]> = {
  proposed: ["approved", "retired"],
  approved: ["pilot", "production", "retired"],
  pilot: ["production", "deprecated", "suspended", "retired"],
  production: ["deprecated", "suspended", "retired"],
  deprecated: ["production", "suspended", "retired"],
  suspended: ["pilot", "production", "deprecated", "retired"],
};

/** The stages an agent at `stage` may be moved to. */
export function nextStages(stage: string): string[] {
  return NEXT[stage] ?? [];
}

/** `pilot`, `production` and `deprecated` are stages of an active agent. */
export function lifecycleState(stage: string): string {
  return ["pilot", "production", "deprecated"].includes(stage) ? "active" : stage;
}

/** Whether moving to `stage` revokes the agent on the runtimes. */
export function stops(stage: string): boolean {
  return stage === "suspended" || stage === "retired";
}

export interface LifecycleRequest {
  id: string;
  agent: string;
  from: string;
  to: string;
  reason: string;
  status: "requested" | "approved" | "applied" | "rejected" | "cancelled" | "expired" | "failed";
  requested_by: string;
  requested_at: string;
  expires_at: string;
  decided_by?: string;
  results?: { source: string | null; ok: boolean; skipped?: boolean; error?: string }[];
}

/** Who may decide `r`: a risk reviewer who is not its requester (and, to approve, not
 *  the agent's owner or declarer); towerd checks the same. */
export function mayDecide(r: LifecycleRequest, me: { principal_id: string; roles: string[] } | undefined, owner: string, declaredBy: string, approve: boolean): boolean {
  if (!me || !(me.roles.includes("risk") || me.roles.includes("admin"))) return false;
  if (r.requested_by === me.principal_id) return false;
  return !approve || (me.principal_id !== owner && me.principal_id !== declaredBy);
}
