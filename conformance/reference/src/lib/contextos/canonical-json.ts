import { createHash } from "node:crypto";
import { types } from "node:util";

const MAX_DEPTH = 64;
const MAX_VALUES = 10_000;
const MAX_BYTES = 1_048_576;

function invalidJson(): never {
  throw new TypeError("Input is not a complete plain JSON value");
}

function resourceLimit(): never {
  throw new RangeError("Canonical JSON exceeds reference resource limits");
}

function validateString(value: string): void {
  if (value.length > MAX_BYTES) resourceLimit();
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) invalidJson();
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) invalidJson();
  }
}

/** RFC 8785 JCS for plain JSON inputs; does not alter legacy compiler hashes. */
export function canonicalizeJson(value: unknown): string {
  let values = 0;
  let bytes = 0;
  const output: string[] = [];
  const ancestors = new Set<object>();
  const emit = (text: string): void => {
    bytes += Buffer.byteLength(text, "utf8");
    if (bytes > MAX_BYTES) resourceLimit();
    output.push(text);
  };
  const visit = (input: unknown, depth: number): void => {
    values += 1;
    if (depth > MAX_DEPTH || values > MAX_VALUES) resourceLimit();
    if (input === null) return emit("null");
    if (typeof input === "string") {
      validateString(input);
      return emit(JSON.stringify(input));
    }
    if (typeof input === "boolean") return emit(input ? "true" : "false");
    if (typeof input === "number") {
      if (!Number.isFinite(input)) invalidJson();
      return emit(JSON.stringify(input));
    }
    if (typeof input !== "object" || types.isProxy(input)) invalidJson();
    if (ancestors.has(input)) invalidJson();
    const array = Array.isArray(input);
    const prototype = Object.getPrototypeOf(input);
    if (prototype !== null && prototype !== (array ? Array.prototype : Object.prototype)) invalidJson();
    if (array && input.length > MAX_VALUES - values) resourceLimit();
    const keys = Reflect.ownKeys(input);
    if (keys.some((key) => typeof key !== "string")) invalidJson();
    if (array ? keys.length !== input.length + 1 : keys.length > MAX_VALUES - values) {
      if (array) invalidJson();
      resourceLimit();
    }
    ancestors.add(input);
    try {
      emit(array ? "[" : "{");
      const ordered = array
        ? Array.from({ length: input.length }, (_, index) => String(index))
        : (keys as string[]).sort();
      ordered.forEach((key, index) => {
        const descriptor = Object.getOwnPropertyDescriptor(input, key);
        if (!descriptor || !("value" in descriptor) || (!array && !descriptor.enumerable)) invalidJson();
        if (index > 0) emit(",");
        if (!array) {
          validateString(key);
          emit(JSON.stringify(key));
          emit(":");
        }
        visit(descriptor.value, depth + 1);
      });
      emit(array ? "]" : "}");
    } finally {
      ancestors.delete(input);
    }
  };
  visit(value, 0);
  return output.join("");
}

export function sha256Canonical(value: unknown): string {
  return `sha256:${createHash("sha256")
    .update(canonicalizeJson(value), "utf8").digest("hex")}`;
}
