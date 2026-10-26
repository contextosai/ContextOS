// Generate vectors from the committed, pinned reference snapshot by default.
// CONTEXTOS_SPEC optionally selects an upstream checkout for a reviewed spec update.
// Usage (from the repo root): npm test --prefix conformance
import path from "node:path";

const here = import.meta.dirname;
const spec = path.resolve(process.env.CONTEXTOS_SPEC ?? path.join(here, "../reference"));
export default {
  root: here,
  resolve: { alias: { "@ref": path.join(spec, "src/lib/contextos"), "@fixtures": path.join(spec, "tests/fixtures"), "@/": path.join(spec, "src") + "/" } },
  server: { fs: { allow: [spec, path.resolve(here, "../..")] } },
  test: { include: ["*.gen.ts"], environment: "node" },
};
