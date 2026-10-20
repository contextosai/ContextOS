// Runs vector generators against the spec repo's TypeScript reference.
// Usage (from the repo root):
//   CONTEXTOS_SPEC=/opt/contextosai $CONTEXTOS_SPEC/node_modules/.bin/vitest run --config conformance/generator/vitest.config.mts
// No package imports here: the config is loaded from outside the spec repo's node_modules.
import path from "node:path";

const here = import.meta.dirname;
const spec = process.env.CONTEXTOS_SPEC ?? "/opt/contextosai";
export default {
  root: here,
  resolve: { alias: { "@ref": path.join(spec, "src/lib/contextos"), "@fixtures": path.join(spec, "tests/fixtures"), "@/": path.join(spec, "src") + "/" } },
  server: { fs: { allow: [spec, path.resolve(here, "../..")] } },
  test: { include: ["*.gen.ts"], environment: "node" },
};
