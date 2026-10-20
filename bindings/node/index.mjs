// ContextOS kernel for Node.js, in-process.
//
//   import { kernel } from "@contextos/kernel";
//   const compiled = await kernel.call("compile", { pack, request, run_context });
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const native = require(process.env.CONTEXTOS_NATIVE ?? "./contextos.node");

export class ContextOSError extends Error {
  constructor(code, message, detail) {
    super(`${code}: ${message}`);
    this.code = code;
    this.detail = detail;
  }
}

function unwrap(text) {
  const response = JSON.parse(text);
  if (response.error) throw new ContextOSError(response.error.code, response.error.message, response.error.detail);
  return response.ok;
}

export const kernel = {
  /** Runs one operation on the libuv thread pool. */
  async call(operation, input) {
    return unwrap(await native.call(operation, JSON.stringify(input ?? {})));
  },
  /** Runs one operation on the calling thread. */
  callSync(operation, input) {
    return unwrap(native.callSync(operation, JSON.stringify(input ?? {})));
  },
};
