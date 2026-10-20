// ContextOS kernel for any WebAssembly host (Node, browsers, edge workers).
// The module imports nothing: no clock, no randomness, no network.
//
//   import { load } from "./contextos.mjs";
//   const ctx = await load(await fs.readFile("contextos_wasm.wasm"));
//   const compiled = ctx.call("compile", { pack, request, run_context, deps });

const encoder = new TextEncoder();
const decoder = new TextDecoder();

export class ContextOSError extends Error {
  constructor(code, message, detail) {
    super(message);
    this.code = code;
    this.detail = detail;
  }
}

export async function load(source) {
  const { instance } = await WebAssembly.instantiate(source, {});
  const { memory, ctx_alloc, ctx_free, ctx_call } = instance.exports;

  const write = (bytes) => {
    const ptr = ctx_alloc(bytes.length);
    new Uint8Array(memory.buffer, ptr, bytes.length).set(bytes);
    return ptr;
  };

  /** Runs one kernel operation. Throws ContextOSError for unusable input. */
  function call(operation, input) {
    const op = encoder.encode(operation);
    const body = encoder.encode(JSON.stringify(input ?? {}));
    const opPtr = write(op);
    const inPtr = write(body);
    try {
      const result = BigInt.asUintN(64, ctx_call(opPtr, op.length, inPtr, body.length));
      const ptr = Number(result >> 32n);
      const len = Number(result & 0xffffffffn);
      const text = decoder.decode(new Uint8Array(memory.buffer, ptr, len).slice());
      ctx_free(ptr, len);
      const response = JSON.parse(text);
      if (response.error) throw new ContextOSError(response.error.code, response.error.message, response.error.detail);
      return response.ok;
    } finally {
      ctx_free(opPtr, op.length);
      ctx_free(inPtr, body.length);
    }
  }

  return { call };
}
