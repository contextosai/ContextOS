import { describe, expect, it } from "vitest";
import { isShadow, matches, type InventoryItem } from "./inventory";

const item = (over: Partial<InventoryItem>): InventoryItem => ({
  kind: "capability",
  id: "crm.delete_customer",
  first_seen: "2026-10-21T10:00:00Z",
  last_seen: "2026-10-21T10:05:00Z",
  environments: ["production"],
  sources: ["eu"],
  risk_tier: null,
  owner_teams: ["support-ai"],
  agents: ["acme/agt_support"],
  declared: false,
  ...over,
});

describe("inventory", () => {
  it("calls a row shadow only when it ran undeclared", () => {
    expect(isShadow(item({}))).toBe(true);
    expect(isShadow(item({ declared: true }))).toBe(false);
    expect(isShadow(item({ last_seen: null, first_seen: null }))).toBe(false);
  });
  it("matches ids, teams, agents and environments", () => {
    expect(matches(item({}), "CRM")).toBe(true);
    expect(matches(item({}), "support-ai")).toBe(true);
    expect(matches(item({}), "production")).toBe(true);
    expect(matches(item({}), "billing")).toBe(false);
    expect(matches(item({}), "  ")).toBe(true);
  });
});
