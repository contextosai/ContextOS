import { describe, expect, it } from "vitest";
import { facets, resolvable, urgency, waited } from "./inbox";
import type { InboxItem } from "./types";

const item = (over: Partial<InboxItem>): InboxItem => ({
  source: "eu",
  escalation_id: "esc_1",
  kind: "policy",
  run_id: "r1",
  opened_at: "2026-10-21T10:00:00Z",
  age_seconds: 10,
  reopened: 0,
  agent: "t/a",
  agent_id: "a",
  owner: null,
  team: null,
  declared: false,
  can_resolve: true,
  ...over,
});

describe("waited", () => {
  it("reads like a duration", () => {
    expect(waited(42)).toBe("42s");
    expect(waited(17 * 60)).toBe("17m");
    expect(waited(5 * 3600 + 3 * 60)).toBe("5h 3m");
    expect(waited(3600)).toBe("1h");
    expect(waited(3 * 86_400 + 4 * 3600)).toBe("3d 4h");
    expect(waited(null)).toBe("—");
  });
});

describe("urgency", () => {
  it("escalates with age, and an unknown age needs attention", () => {
    expect(urgency(59)).toBe("ok");
    expect(urgency(3600)).toBe("warn");
    expect(urgency(86_400)).toBe("bad");
    expect(urgency(null)).toBe("warn");
  });
});

describe("facets", () => {
  it("counts per source and team, most first", () => {
    const f = facets([item({ source: "us", team: "ops" }), item({ source: "eu", team: "ops" }), item({ source: "eu" })]);
    expect(f.sources).toEqual([
      ["eu", 2],
      ["us", 1],
    ]);
    expect(f.teams).toEqual([
      ["ops", 2],
      ["undeclared", 1],
    ]);
  });
});

describe("resolvable", () => {
  it("mirrors the server's owner and control-key rules", () => {
    expect(resolvable(item({}), "risk-a")).toBe(true);
    expect(resolvable(item({ owner: "risk-a" }), "risk-a")).toBe(false);
    expect(resolvable(item({ can_resolve: false }), "risk-a")).toBe(false);
    expect(resolvable(item({}), undefined)).toBe(false);
  });
});
