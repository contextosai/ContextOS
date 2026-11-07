// Pure helpers for the approvals inbox: how long an item has waited and how urgent
// that is, and the facets the queue can be narrowed by.

import type { InboxItem } from "./types";

/** "42s", "17m", "5h 3m", "3d 4h"; "—" when the runtime's time was unreadable. */
export function waited(seconds: number | null | undefined): string {
  if (seconds === null || seconds === undefined || Number.isNaN(seconds) || seconds < 0) return "—";
  if (seconds < 60) return `${Math.floor(seconds)}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m`;
  if (seconds < 86_400) {
    const m = Math.floor((seconds % 3600) / 60);
    return `${Math.floor(seconds / 3600)}h${m ? ` ${m}m` : ""}`;
  }
  const h = Math.floor((seconds % 86_400) / 3600);
  return `${Math.floor(seconds / 86_400)}d${h ? ` ${h}h` : ""}`;
}

/** Waiting over an hour needs attention; over a day is overdue. */
export function urgency(seconds: number | null | undefined): "ok" | "warn" | "bad" {
  if (seconds === null || seconds === undefined) return "warn";
  if (seconds >= 86_400) return "bad";
  if (seconds >= 3600) return "warn";
  return "ok";
}

export interface Facets {
  sources: [string, number][];
  teams: [string, number][];
}

/** Item counts per source and per owning team (undeclared agents under "undeclared"), most first. */
export function facets(items: InboxItem[]): Facets {
  const count = (key: (i: InboxItem) => string): [string, number][] => {
    const m = new Map<string, number>();
    for (const i of items) m.set(key(i), (m.get(key(i)) ?? 0) + 1);
    return [...m.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
  };
  return { sources: count((i) => i.source), teams: count((i) => i.team ?? "undeclared") };
}

/** Whether `principal` may resolve the item: the server refuses the agent's owner
 *  (and its declarer, which only the server knows), and runtimes Tower holds no
 *  control key for. */
export function resolvable(item: InboxItem, principal: string | undefined): boolean {
  if (!item.can_resolve || !principal) return false;
  return principal !== item.owner;
}
