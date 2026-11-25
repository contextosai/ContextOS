import { describe, expect, it } from "vitest";
import { lifecycleState, mayDecide, nextStages, stops, type LifecycleRequest } from "./lifecycle";

const request = { id: "1", agent: "a", from: "production", to: "suspended", reason: "r", status: "requested", requested_by: "maya", requested_at: "", expires_at: "" } as LifecycleRequest;

describe("lifecycle", () => {
  it("follows towerd's moves", () => {
    expect(nextStages("proposed")).toEqual(["approved", "retired"]);
    expect(nextStages("retired")).toEqual([]);
    expect(nextStages("suspended")).toContain("production");
    expect(nextStages("approved")).not.toContain("suspended");
  });
  it("groups stages into states", () => {
    expect(lifecycleState("pilot")).toBe("active");
    expect(lifecycleState("suspended")).toBe("suspended");
    expect(stops("retired") && stops("suspended") && !stops("deprecated")).toBe(true);
  });
  it("keeps the decision with a second person", () => {
    const risk = (id: string) => ({ principal_id: id, roles: ["risk"] });
    expect(mayDecide(request, risk("maya"), "ana", "ana", true)).toBe(false);
    expect(mayDecide(request, risk("rita"), "rita", "ana", true)).toBe(false);
    expect(mayDecide(request, risk("rita"), "rita", "ana", false)).toBe(true);
    expect(mayDecide(request, risk("rita"), "ana", "ana", true)).toBe(true);
    expect(mayDecide(request, { principal_id: "rita", roles: ["viewer"] }, "ana", "ana", true)).toBe(false);
  });
});
