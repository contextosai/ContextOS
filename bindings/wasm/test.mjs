// node bindings/wasm/test.mjs <path-to-contextos_wasm.wasm>
import { readFile } from "node:fs/promises";
import assert from "node:assert/strict";
import { load, ContextOSError } from "./contextos.mjs";

const wasm = await readFile(process.argv[2]);
const module = await WebAssembly.compile(wasm);
assert.deepEqual(WebAssembly.Module.imports(module), [], "the module must import nothing");

const ctx = await load(wasm);
assert.equal(ctx.call("canonicalize", { b: 1, a: [2, 1.0] }).canonical, '{"a":[2,1],"b":1}');

const vectors = JSON.parse(await readFile(new URL("../../conformance/vectors/compiler.json", import.meta.url)));
for (const c of vectors.cases.slice(0, 10)) {
  const compiled = ctx.call("compile", { pack: c.pack, request: c.request, run_context: c.run_context, deps: c.deps });
  assert.equal(compiled.context_ledger.compiled_context_hash, c.expected.context_ledger.compiled_context_hash, c.name);
}
assert.throws(() => ctx.call("jsonlogic", { logic: { no_such_op: [1] }, data: null }), ContextOSError);
assert.equal(ctx.call("compose_policy", []).verdict, "deny");
console.log("wasm binding ok");
