// The inventory view (GET /api/inventory): agents, capabilities, adapters, models and
// owning teams, declared or seen in verified evidence.

import { download } from "./api";

export const KINDS = ["agent", "capability", "adapter", "model", "owner"] as const;
export type Kind = (typeof KINDS)[number];

export interface InventoryItem {
  kind: Kind;
  id: string;
  first_seen: string | null;
  last_seen: string | null;
  environments: string[];
  sources: string[];
  risk_tier: string | null;
  owner_teams: string[];
  agents: string[];
  declared: boolean;
  lifecycle?: string;
}

/** Seen in traffic and accounted for by no declaration or pin. */
export function isShadow(item: InventoryItem): boolean {
  return !item.declared && item.last_seen !== null;
}

/** Rows matching `needle` in their id, teams, agents or environments. */
export function matches(item: InventoryItem, needle: string): boolean {
  const q = needle.trim().toLowerCase();
  if (!q) return true;
  return [item.id, ...item.owner_teams, ...item.agents, ...item.environments].some((v) => v.toLowerCase().includes(q));
}

/** Downloads the inventory CSV towerd renders. */
export function downloadCsv(kind: Kind | "all", shadow: boolean): Promise<void> {
  const params = new URLSearchParams({ format: "csv" });
  if (kind !== "all") params.set("kind", kind);
  if (shadow) params.set("shadow", "true");
  return download(`/api/inventory?${params}`, "inventory.csv");
}
