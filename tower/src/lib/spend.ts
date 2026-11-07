// Model spend helpers. Costs arrive in hundredths of a cent (`cost_units`), the unit
// the runtime's budget ledger uses.

import type { ModelUsage, SpendUsage } from "./types";

/** `$1.24` from hundredths of a cent, rounded up to the cent (as the runtime charges). */
export function money(costUnits: number | undefined | null): string {
  if (costUnits === undefined || costUnits === null || Number.isNaN(costUnits)) return "—";
  const cents = Math.ceil(costUnits / 100);
  const dollars = Math.floor(cents / 100);
  return `$${dollars.toLocaleString("en-US")}.${String(cents % 100).padStart(2, "0")}`;
}

/** Compact token counts: 950, 12.3k, 4M. */
export function tokens(v: number | undefined | null): string {
  if (v === undefined || v === null || Number.isNaN(v)) return "—";
  if (v < 1_000) return String(v);
  if (v < 1_000_000) return `${trim(v / 1_000)}k`;
  if (v < 1_000_000_000) return `${trim(v / 1_000_000)}M`;
  return `${trim(v / 1_000_000_000)}B`;
}

function trim(x: number): string {
  return x >= 100 ? x.toFixed(0) : x.toFixed(1).replace(/\.0$/, "");
}

/** Share of charged tokens a metering gateway measured, or undefined with no spend. */
export function measuredShare(u: Pick<SpendUsage, "tokens" | "verified_tokens">): number | undefined {
  return u.tokens > 0 ? u.verified_tokens / u.tokens : undefined;
}

/** How much of a usage figure was measured, for a badge. */
export function metering(u: Pick<SpendUsage | ModelUsage, "tokens" | "verified_tokens">): "measured" | "mixed" | "self-reported" | "none" {
  if (u.tokens === 0) return "none";
  if (u.verified_tokens === u.tokens) return "measured";
  if (u.verified_tokens === 0) return "self-reported";
  return "mixed";
}

/** A series bucket's label: an hour index (hours since the epoch) as local time. */
export function bucketLabel(hour: number, bucketHours: number): string {
  const d = new Date(hour * 3_600_000);
  return bucketHours >= 24
    ? d.toLocaleDateString(undefined, { month: "short", day: "numeric" })
    : d.toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}

export const WINDOWS: [number, string][] = [
  [24, "24 hours"],
  [168, "7 days"],
  [720, "30 days"],
];
