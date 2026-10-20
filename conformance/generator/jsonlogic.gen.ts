import { test } from "vitest";
import { writeFileSync } from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";

const require = createRequire(path.join(process.env.CONTEXTOS_SPEC ?? "/opt/contextosai", "package.json"));
const jsonLogic = require("json-logic-js");
const out = path.resolve(import.meta.dirname, "../vectors");

// mulberry32: deterministic corpus.
function rng(seed: number) {
  return () => { seed |= 0; seed = (seed + 0x6d2b79f5) | 0; let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t; return ((t ^ (t >>> 14)) >>> 0) / 4294967296; };
}
const rand = rng(20261020);
const pick = <T>(xs: readonly T[]): T => xs[Math.floor(rand() * xs.length)];

const DATA = { a: 1, b: "2", c: [1, "x", null, true], d: { e: { f: "deep" }, g: [] }, s: "Springfield", z: 0, n: null,
  t: true, f: false, empty: "", neg: -3.5, big: 12345678901, list: [{ v: 1 }, { v: 2 }, { v: 3 }], nums: [3, 1, 2],
  role: "support_agent", amount: 4200, "": "blank", "k.dot": 9 };
const PATHS = ["a", "b", "c", "c.0", "c.1", "c.9", "c.length", "d.e.f", "d.g", "d.e", "s", "s.0", "s.length", "z", "n", "n.x",
  "t", "f", "empty", "neg", "big", "list", "list.1.v", "nums", "role", "amount", "missing", "missing.deep", "", "k", "a.b", "d.g.length"];
const LEAVES: unknown[] = [0, 1, -1, 2, 1.5, -0.5, 3000, 1e21, "", "0", "1", "2", " 12 ", "abc", "a", "Spring", "0x10", "1e3",
  "-", ".", "Infinity", true, false, null, [], [1], [1, 2], ["a", "b"], [null], [[1], [2]]];
const BINARY = ["==", "===", "!=", "!==", ">", ">=", "<", "<=", "%", "/", "-", "in", "substr"];
const NARY = ["+", "*", "cat", "min", "max", "merge", "and", "or", "if", "<", "<=", "missing", "?:"];
const UNARY = ["!", "!!", "-", "log"];

function gen(depth: number): unknown {
  const r = rand();
  if (depth <= 0 || r < 0.25) return rand() < 0.4 ? { var: pick(PATHS) } : pick(LEAVES);
  if (r < 0.32) return { var: [pick(PATHS), gen(depth - 1)] };
  if (r < 0.5) return { [pick(BINARY)]: [gen(depth - 1), gen(depth - 1)] };
  if (r < 0.62) return { [pick(UNARY)]: [gen(depth - 1)] };
  if (r < 0.66) return { [pick(UNARY)]: gen(depth - 1) };
  if (r < 0.8) { const n = Math.floor(rand() * 4); return { [pick(NARY)]: Array.from({ length: n }, () => gen(depth - 1)) }; }
  if (r < 0.86) return { [pick(["map", "filter", "all", "none", "some"])]: [pick([{ var: "list" }, { var: "nums" }, { var: "c" }, [1, 2, 0], { var: "a" }]),
    pick([{ var: "v" }, { ">": [{ var: "" }, 1] }, { var: "" }, { "!": { var: "" } }, gen(1)])] };
  if (r < 0.9) return { reduce: [pick([{ var: "nums" }, { var: "list" }, [1, 2, 3], { var: "s" }]),
    pick([{ "+": [{ var: "current" }, { var: "accumulator" }] }, { cat: [{ var: "accumulator" }, { var: "current.v" }] }, { var: "current" }]),
    pick([0, "", undefined, { var: "a" }])] };
  if (r < 0.93) return { missing_some: [pick([0, 1, 2, "1"]), pick([["a", "missing"], ["a", "b", "empty"], "a"])] };
  if (r < 0.96) return { substr: [gen(depth - 1), pick([0, 1, -2, "1", 10]), pick([undefined, 2, -1, "-1", 0])].filter((x) => x !== undefined) };
  return pick([{ a: 1, b: 2 }, { unknown_op: [1] }, {}, { "if": [] }]);
}

function encode(v: any): unknown {
  if (v === undefined) return { t: "undefined" };
  if (typeof v === "number") {
    if (Number.isNaN(v)) return { t: "nan" };
    if (v === Infinity) return { t: "inf" };
    if (v === -Infinity) return { t: "-inf" };
    if (Object.is(v, -0)) return { t: "-0" };
    return { t: "value", v };
  }
  if (typeof v === "function") return { t: "function" };
  if (typeof v === "object" && v !== null) {
    let bad = false;
    JSON.stringify(v, (_k, x) => { if (typeof x === "function" || (typeof x === "number" && !Number.isFinite(x)) || x === undefined) bad = true; return x; });
    if (bad) return { t: "json", v: JSON.parse(JSON.stringify(v) ?? "null") };
  }
  return { t: "value", v };
}

test("jsonlogic parity corpus", () => {
  const cases = [];
  const seen = new Set<string>();
  while (cases.length < 6000) {
    const logic = gen(4);
    const key = JSON.stringify(logic);
    if (seen.has(key)) continue;
    seen.add(key);
    let expected;
    try { expected = encode(jsonLogic.apply(logic, DATA)); } catch (e: any) { expected = { t: "error", message: String(e.message) }; }
    cases.push({ logic, expected });
  }
  writeFileSync(path.join(out, "jsonlogic.json"), JSON.stringify({ data: DATA, cases }) + "\n");
});
