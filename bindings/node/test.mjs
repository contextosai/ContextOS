// CONTEXTOS_NATIVE=/path/to/contextos.node node bindings/node/test.mjs
import { readFile } from "node:fs/promises";
import assert from "node:assert/strict";
import { kernel, ContextOSError } from "./index.mjs";

const vectors = JSON.parse(await readFile(new URL("../../conformance/vectors/compiler.json", import.meta.url)));
const results = await Promise.all(vectors.cases.slice(0, 10).map((c) =>
  kernel.call("compile", { pack: c.pack, request: c.request, run_context: c.run_context, deps: c.deps })));
results.forEach((compiled, i) =>
  assert.equal(compiled.context_ledger.compiled_context_hash, vectors.cases[i].expected.context_ledger.compiled_context_hash));
assert.equal(kernel.callSync("canonicalize", { b: 1, a: 2 }).canonical, '{"a":2,"b":1}');
await assert.rejects(kernel.call("jsonlogic", { logic: { no_such_op: [1] }, data: null }), ContextOSError);
assert.equal(kernel.callSync("validate", { schema: "execution-contract", def: "ControlRef", instance: { control_id: "x", control_version: "1", z: 1 } }).valid, false);
console.log("node binding ok");
