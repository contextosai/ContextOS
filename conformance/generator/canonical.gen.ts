import { test } from "vitest";
import { writeFileSync } from "node:fs";
import path from "node:path";
import { canonicalizeJson, sha256Canonical } from "@ref/canonical-json";

const out = path.resolve(import.meta.dirname, "../vectors");

function stableStringify(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`;
  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, v]) => v !== undefined)
    .sort(([a], [b]) => a.localeCompare(b));
  return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${stableStringify(v)}`).join(",")}}`;
}

const inputs: unknown[] = [
  null, true, 0, -0, 1, -1.5, 0.1, 1e21, 1e-7, 123456789012345680000, 5e-324, 1.7976931348623157e308,
  "", "plain", "quote\"back\\slash", "\u0000\u0001\u001f\u007f  ", "é漢字😀",
  [], [1, [2, [3]]], {},
  { b: 1, a: 2, A: 3, _z: 4, "1": 5, "10": 6, "2": 7, a_b: 8, ab: 9, "a-b": 10, "a.b": 11, "a b": 12 },
  { "�": 1, "\u{1f600}": 2, é: 3, e: 4, f: 5, E: 6, "ß": 7, ss: 8 },
  { compiled_prompt: { system: "s", task: "t", context_blocks: [] }, budget_report: { tokens_allocated: { business: 1, policy: 2 } } },
  { tokens_used_by_bucket: { session: 1, evidence: 2, memory: 3, tool: 4, policy: 5, business: 6 } },
];

test("canonical vectors", () => {
  const vectors = inputs.map((input) => ({
    input,
    jcs: canonicalizeJson(input),
    jcs_sha256: sha256Canonical(input),
    legacy: stableStringify(input),
  }));
  writeFileSync(path.join(out, "canonical.json"), JSON.stringify(vectors, null, 2) + "\n");
});
