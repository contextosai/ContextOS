// Runtime sources as the console manages them: health rows from
// `GET /api/sources/health`, and the definition an admin proposes. Keys are only ever
// referenced (an environment variable on the Tower host, or a mounted secret file);
// the console never asks for, sends or shows a key.

import type { Tone } from "../components/ui";

export type SourceState = "current" | "starting" | "stale" | "error" | "stopped" | "broken" | "paused" | "unavailable";

export interface KeyRefs {
  token_env: string | null;
  token_file: string | null;
  control_token_env: string | null;
  control_token_file: string | null;
}

export interface SourceHealthRow {
  id: string;
  url: string;
  origin: "config" | "console";
  state: SourceState;
  paused: boolean;
  collecting: boolean;
  tenant_id: string | null;
  verified_to: number;
  head: number;
  lag: number;
  last_sync: string | null;
  last_sync_age_seconds: number | null;
  last_error: string | null;
  broken: { sequence: number; reason: string } | null;
  unattributed: number;
  can_revoke: boolean;
  business_unit: string | null;
  region: string | null;
  environment: string | null;
  added_by: string | null;
  added_at: string | null;
  last_change: { by: string | null; at: string | null; reason: string | null } | null;
  /** Only for admins. */
  keys?: KeyRefs;
}

export interface SourceHealth {
  sources: SourceHealthRow[];
  reconciled_at: string | null;
  reconcile_error: string | null;
  stale_after_seconds: number;
}

export interface ProbeResult {
  id: string;
  url: string;
  tenant_id: string;
  principal_id: string;
  scopes: string[];
  mode: string | null;
  packs: number;
  supported_controls: number;
  can_revoke: boolean;
  warnings: string[];
}

export const STATE_TEXT: Record<SourceState, [Tone, string]> = {
  current: ["ok", "current"],
  starting: ["info", "starting"],
  stale: ["warn", "stale"],
  error: ["warn", "unreachable"],
  stopped: ["warn", "stopped"],
  broken: ["bad", "chain broken"],
  paused: ["", "paused"],
  unavailable: ["bad", "keys unavailable"],
};

export function stateBadge(state: string): [Tone, string] {
  return STATE_TEXT[state as SourceState] ?? ["", state];
}

/** Sources needing someone, most urgent first, then by id. */
export function attentionOrder(rows: SourceHealthRow[]): SourceHealthRow[] {
  const rank: Record<string, number> = { broken: 0, unavailable: 1, error: 2, stopped: 3, stale: 4, starting: 5, paused: 6, current: 7 };
  return [...rows].sort((a, b) => (rank[a.state] ?? 9) - (rank[b.state] ?? 9) || a.id.localeCompare(b.id));
}

/** What the admin can do to a source in its current state. */
export function actionsFor(row: SourceHealthRow): ("pause" | "resume" | "retry" | "reload" | "remove")[] {
  const out: ("pause" | "resume" | "retry" | "reload" | "remove")[] = [row.paused ? "resume" : "pause"];
  if (row.state === "broken") out.push("retry");
  if (row.state !== "unavailable") out.push("reload");
  if (row.origin === "console") out.push("remove");
  return out;
}

export interface SourceForm {
  id: string;
  url: string;
  readKind: "env" | "file";
  read: string;
  controlKind: "none" | "env" | "file";
  control: string;
  business_unit: string;
  region: string;
  environment: string;
}

export const EMPTY_FORM: SourceForm = {
  id: "",
  url: "",
  readKind: "file",
  read: "",
  controlKind: "none",
  control: "",
  business_unit: "",
  region: "",
  environment: "",
};

const ENV = /^[A-Z_][A-Z0-9_]{0,127}$/;
const ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

function refError(kind: "env" | "file", value: string, what: string): string | null {
  if (!value) return `Name the ${what}.`;
  if (kind === "env" && !ENV.test(value)) return `The ${what} variable must be uppercase letters, digits and _.`;
  if (kind === "file" && (!value.startsWith("/") || value.split("/").includes(".."))) return `The ${what} file must be an absolute path without "..".`;
  return null;
}

/** The definition `POST /api/sources/probe` takes, or the first problem with the form
 *  (towerd checks the same and more). */
export function definition(form: SourceForm): { ok: true; value: Record<string, string> } | { ok: false; error: string } {
  const f = Object.fromEntries(Object.entries(form).map(([k, v]) => [k, typeof v === "string" ? v.trim() : v])) as SourceForm;
  if (!ID.test(f.id)) return { ok: false, error: "The id must be 1-64 letters, digits, '.', '_' or '-'." };
  let url: URL;
  try {
    url = new URL(f.url);
  } catch {
    return { ok: false, error: "The URL is not valid." };
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") return { ok: false, error: "The URL must use https." };
  if (url.username || url.password || url.search || url.hash) return { ok: false, error: "The URL must not carry credentials, a query or a fragment." };
  const read = refError(f.readKind, f.read, "audit:read key");
  if (read) return { ok: false, error: read };
  const value: Record<string, string> = { id: f.id, url: f.url };
  value[f.readKind === "env" ? "token_env" : "token_file"] = f.read;
  if (f.controlKind !== "none") {
    const control = refError(f.controlKind, f.control, "control key");
    if (control) return { ok: false, error: control };
    value[f.controlKind === "env" ? "control_token_env" : "control_token_file"] = f.control;
  }
  for (const k of ["business_unit", "region", "environment"] as const) if (f[k]) value[k] = f[k];
  return { ok: true, value };
}

export function syncText(row: SourceHealthRow): string {
  if (row.last_sync_age_seconds === null) return "never";
  const s = row.last_sync_age_seconds;
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  return `${Math.floor(s / 3600)}h ago`;
}

export function keyText(refs: KeyRefs | undefined, control: boolean): string {
  if (!refs) return "—";
  const env = control ? refs.control_token_env : refs.token_env;
  const file = control ? refs.control_token_file : refs.token_file;
  return env ? `$${env}` : file ? file : "—";
}
