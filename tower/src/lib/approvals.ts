/** Approval quality, from `GET /api/approvals`. */
export interface ApprovalStats {
  requested: number;
  redeemed: number;
  /** One count per `buckets_seconds` entry, then slower. */
  decision_seconds: number[];
  untimed: number;
  refused_too_fast: number;
  refused_step_up: number;
  within_ten_seconds: number;
}

export interface ApprovalRow extends ApprovalStats {
  capability_id?: string;
  approver?: string;
}

export interface ApprovalsReport {
  buckets_seconds: number[];
  capabilities: ApprovalRow[];
  approvers: ApprovalRow[];
}

/** Labels of the decision-time buckets: "≤10s", …, then "slower". */
export function bucketLabels(bounds: number[]): string[] {
  const label = (s: number) => (s >= 3600 ? `${s / 3600}h` : s >= 60 ? `${s / 60}m` : `${s}s`);
  return [...bounds.map((b) => `≤${label(b)}`), `>${label(bounds[bounds.length - 1] ?? 0)}`];
}

/** The share of timed redemptions decided within ten seconds, or undefined with none. */
export function rubberStampShare(row: ApprovalStats): number | undefined {
  const timed = row.decision_seconds.reduce((a, b) => a + b, 0);
  return timed === 0 ? undefined : row.within_ten_seconds / timed;
}

/** The bucket label holding the median timed redemption. */
export function medianBucket(row: ApprovalStats, labels: string[]): string | undefined {
  const timed = row.decision_seconds.reduce((a, b) => a + b, 0);
  if (timed === 0) return undefined;
  let seen = 0;
  for (let i = 0; i < row.decision_seconds.length; i++) {
    seen += row.decision_seconds[i] ?? 0;
    if (seen * 2 >= timed) return labels[i];
  }
  return labels[labels.length - 1];
}
