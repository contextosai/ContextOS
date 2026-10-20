// Deterministic structural mutations for validator parity corpora.
export function rng(seed: number) {
  return () => { seed |= 0; seed = (seed + 0x6d2b79f5) | 0; let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t; return ((t ^ (t >>> 14)) >>> 0) / 4294967296; };
}

type Path = (string | number)[];
function paths(value: unknown, prefix: Path = [], out: Path[] = []): Path[] {
  out.push(prefix);
  if (Array.isArray(value)) value.forEach((v, i) => paths(v, [...prefix, i], out));
  else if (value && typeof value === "object") for (const [k, v] of Object.entries(value)) paths(v, [...prefix, k], out);
  return out;
}
function get(root: any, path: Path) { return path.reduce((v, k) => v?.[k], root); }
function set(root: any, path: Path, value: unknown) {
  const parent = get(root, path.slice(0, -1)); parent[path[path.length - 1]] = value;
}

const TIMES = ["2026-01-01T00:00:00Z", "2026-10-20T10:00:00Z", "2026-10-20T10:00:00.5Z", "2030-01-01T00:00:00Z",
  "2026-02-30T00:00:00Z", "2026-10-20T10:00:60Z", "not-a-time"];

export function mutate<T>(input: T, rand: () => number, count = 1 + Math.floor(rand() * 3)): T {
  const root: any = structuredClone(input);
  for (let n = 0; n < count; n++) {
    const all = paths(root).filter((p) => p.length > 0);
    if (!all.length) break;
    const path = all[Math.floor(rand() * all.length)];
    const value = get(root, path);
    const parent = get(root, path.slice(0, -1));
    const r = rand();
    if (r < 0.12 && !Array.isArray(parent)) { delete parent[path[path.length - 1]]; continue; }
    if (r < 0.18 && value && typeof value === "object" && !Array.isArray(value)) { value.extra_field = 1; continue; }
    if (r < 0.3 && Array.isArray(value)) {
      const s = rand();
      if (s < 0.3) value.pop(); else if (s < 0.6 && value.length) value.push(structuredClone(value[0]));
      else if (value.length > 1) value.reverse(); else value.length = 0;
      continue;
    }
    if (typeof value === "string") {
      const s = rand();
      if (s < 0.2) set(root, path, ""); else if (s < 0.45) set(root, path, value + "_x");
      else if (s < 0.6) set(root, path, TIMES[Math.floor(rand() * TIMES.length)]);
      else if (s < 0.7) set(root, path, "x".repeat(300));
      else if (s < 0.85) set(root, path, value.startsWith("sha256:") ? "sha256:" + "f".repeat(64) : value.toUpperCase());
      else set(root, path, 7);
      continue;
    }
    if (typeof value === "number") {
      const s = rand();
      set(root, path, s < 0.25 ? value + 1 : s < 0.5 ? Math.max(0, value - 1) : s < 0.65 ? -1 : s < 0.8 ? 1.5 : s < 0.9 ? 0 : "1");
      continue;
    }
    if (typeof value === "boolean") { set(root, path, rand() < 0.8 ? !value : null); continue; }
    const replacements = [null, 0, "", [], {}, true];
    set(root, path, replacements[Math.floor(rand() * replacements.length)]);
  }
  return root;
}
