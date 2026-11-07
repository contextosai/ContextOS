import type { Me } from "./api";
import type { Provenance, RestoreRequest, Revocation } from "./types";

/** One target revoked on one or more sources, the unit an operator restores. */
export interface RevokedTarget {
  kind: string;
  target: string;
  rows: Revocation[];
  affected: string[];
  refusals: number;
  mismatch: boolean;
  /** The most recent revocation of it on any source. */
  latest: Revocation;
}

/** Groups per-source revocations by target, most recent first. */
export function byTarget(rows: Revocation[]): RevokedTarget[] {
  const groups = new Map<string, RevokedTarget>();
  for (const r of rows) {
    const key = `${r.kind}:${r.target}`;
    const g = groups.get(key);
    if (!g) {
      groups.set(key, { kind: r.kind, target: r.target, rows: [r], affected: [...r.affected], refusals: r.refusals, mismatch: r.mismatch, latest: r });
      continue;
    }
    g.rows.push(r);
    for (const a of r.affected) if (!g.affected.includes(a)) g.affected.push(a);
    g.refusals += r.refusals;
    g.mismatch ||= r.mismatch;
    if ((r.at ?? "") > (g.latest.at ?? "")) g.latest = r;
  }
  return [...groups.values()].sort((a, b) => (b.latest.at ?? "").localeCompare(a.latest.at ?? ""));
}

export const provenanceLabel: Record<Provenance, [string, "ok" | "warn" | "bad" | "info"]> = {
  verified: ["verified", "ok"],
  runtime_only: ["not yet in chain", "warn"],
  chain_only: ["not in force on runtime", "bad"],
  chain: ["from audit chain", "info"],
};

/** Who did it: the Tower user when the change came through Tower, else the runtime principal. */
export function actor(r: Revocation): string {
  return r.via_tower ?? r.by ?? "unknown";
}

/** Why `me` may not approve `request`, or null when they may. Mirrors towerd's checks. */
export function approveBlocked(me: Me | undefined, request: RestoreRequest, can: (me: Me | undefined, role: string) => boolean): string | null {
  if (request.status !== "requested") return "No longer waiting for approval.";
  if (!can(me, "operator")) return "Needs the operator role.";
  if (me?.principal_id === request.requested_by) return "Approved by an operator other than the requester.";
  return null;
}

/** The waiting restore request for a target, if any. */
export function pendingFor(requests: RestoreRequest[], kind: string, target: string): RestoreRequest | undefined {
  return requests.find((r) => r.status === "requested" && r.kind === kind && r.target === target);
}
