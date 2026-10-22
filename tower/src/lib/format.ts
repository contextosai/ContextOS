export function ago(iso: string | number | undefined, now = Date.now()): string {
  if (iso === undefined) return "—";
  const t = typeof iso === "number" ? iso : Date.parse(iso);
  if (Number.isNaN(t)) return String(iso);
  const s = Math.round((now - t) / 1000);
  if (s < 0) return "just now";
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

export function time(iso: string | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "medium" });
}

export function clock(iso: string): string {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleTimeString(undefined, { hour12: false }) + `.${String(d.getMilliseconds()).padStart(3, "0")}`;
}

export function duration(fromIso: string, toIso: string): string {
  const ms = Date.parse(toIso) - Date.parse(fromIso);
  if (Number.isNaN(ms)) return "—";
  if (ms < 1000) return `${ms} ms`;
  if (ms < 60_000) return `${(ms / 1000).toFixed(1)} s`;
  if (ms < 3_600_000) return `${Math.floor(ms / 60_000)}m ${Math.round((ms % 60_000) / 1000)}s`;
  return `${(ms / 3_600_000).toFixed(1)} h`;
}

export const n = (v: number | undefined | null, digits = 0) =>
  v === undefined || v === null || Number.isNaN(v) ? "—" : v.toLocaleString(undefined, { maximumFractionDigits: digits });

/** `sha256:abcdef…1234` */
export function short(digest: string | undefined, keep = 10): string {
  if (!digest) return "—";
  const body = digest.startsWith("sha256:") ? digest.slice(7) : digest;
  return body.length <= keep + 4 ? digest : `${digest.startsWith("sha256:") ? "sha256:" : ""}${body.slice(0, keep)}…${body.slice(-4)}`;
}

export const pct = (v: number | undefined) => (v === undefined ? "—" : `${Math.round(v * 100)}%`);
