import { describe, expect, it } from "vitest";
import { can } from "./api";
import { actor, approveBlocked, byTarget, pendingFor } from "./revocations";
import type { RestoreRequest, Revocation } from "./types";

const row = (over: Partial<Revocation>): Revocation => ({
  source: "eu",
  kind: "capability",
  target: "pay.send",
  reason: "INC-1",
  by: "svc_tower_control",
  via_tower: null,
  at: "2026-11-07T10:00:00.000000Z",
  sequence: 4,
  provenance: "verified",
  mismatch: false,
  affected: [],
  refusals: 0,
  ...over,
});

const request = (over: Partial<RestoreRequest>): RestoreRequest => ({
  id: "r1",
  kind: "capability",
  target: "pay.send",
  sources: null,
  reason: "fix deployed",
  status: "requested",
  requested_by: "oncall-a",
  requested_at: "2026-11-07T11:00:00.000000Z",
  expires_at: "2026-11-08T11:00:00.000000Z",
  ...over,
});

describe("byTarget", () => {
  it("merges a target revoked on several sources and keeps the newest first", () => {
    const groups = byTarget([
      row({ source: "eu", affected: ["t/a"], refusals: 2 }),
      row({ source: "us", affected: ["t/a", "t/b"], refusals: 1, provenance: "runtime_only", mismatch: true, at: "2026-11-07T12:00:00.000000Z" }),
      row({ kind: "agent", target: "agt_x", at: "2026-11-06T09:00:00.000000Z" }),
    ]);
    expect(groups.map((g) => `${g.kind}:${g.target}`)).toEqual(["capability:pay.send", "agent:agt_x"]);
    expect(groups[0]!.rows.length).toBe(2);
    expect(groups[0]!.affected).toEqual(["t/a", "t/b"]);
    expect(groups[0]!.refusals).toBe(3);
    expect(groups[0]!.mismatch).toBe(true);
    expect(groups[0]!.latest.source).toBe("us");
  });
});

describe("actor", () => {
  it("prefers the Tower user over the runtime principal", () => {
    expect(actor(row({ via_tower: "oncall-a" }))).toBe("oncall-a");
    expect(actor(row({}))).toBe("svc_tower_control");
    expect(actor(row({ by: null }))).toBe("unknown");
  });
});

describe("approveBlocked", () => {
  const me = (principal_id: string, roles: string[]) => ({ principal_id, roles, teams: [], intelligence: null });
  it("mirrors the server's separation of duties", () => {
    expect(approveBlocked(me("oncall-b", ["operator"]), request({}), can)).toBeNull();
    expect(approveBlocked(me("oncall-a", ["operator"]), request({}), can)).toMatch(/other than the requester/);
    expect(approveBlocked(me("ciso", ["viewer"]), request({}), can)).toMatch(/operator role/);
    expect(approveBlocked(me("oncall-b", ["operator"]), request({ status: "restored" }), can)).toMatch(/No longer/);
  });
  it("finds the waiting request for a target", () => {
    const list = [request({ id: "old", status: "cancelled" }), request({ id: "open" })];
    expect(pendingFor(list, "capability", "pay.send")?.id).toBe("open");
    expect(pendingFor(list, "agent", "pay.send")).toBeUndefined();
  });
});
