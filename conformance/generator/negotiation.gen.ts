import { test } from "vitest";
import { writeFileSync } from "node:fs";
import { gzipSync } from "node:zlib";
import path from "node:path";
import { negotiateExecutionContract } from "@ref/execution-contract";
import { STANDARD_PROFILE_REGISTRY } from "@ref/profiles";
import { bindRegistry, coreFixture, standardProfileFixture } from "@fixtures/execution-contract";
import { mutate, rng } from "./mutate";

const out = path.resolve(import.meta.dirname, "../vectors");
const FEATURES = ["arbitrary_code", "external_network", "persistent_memory", "external_effects", "delegation",
  "checkpoint_resume", "proactive_triggers", "sensitive_data"] as const;

test("negotiation vectors", () => {
  const rand = rng(4242);
  const cases: unknown[] = [];
  const run = (name: string, live: any) => {
    // Vectors must be plain JSON: fixture helpers can leave `undefined` fields behind.
    const f = JSON.parse(JSON.stringify(live));
    let expected: unknown;
    try { expected = negotiateExecutionContract(f.contract, f.support, f.registry, f.features); }
    catch (e: any) { expected = { throws: String(e.message) }; }
    cases.push({ name, input: f, expected });
  };
  run("core", coreFixture());
  for (const p of STANDARD_PROFILE_REGISTRY.profiles) {
    for (let mask = 0; mask < 256; mask += 37) {
      const f = standardProfileFixture(p.profile.profile_id);
      FEATURES.forEach((k, i) => { (f.features as any)[k] = ((mask >> i) & 1) === 1; });
      run(`standard:${p.profile.profile_id}:${mask}`, f);
    }
  }
  const partial = standardProfileFixture("contextos.enterprise");
  partial.support.supported_controls = partial.support.supported_controls.slice(0, 6);
  partial.contract.optional_controls = [{ control_id: "unknown.control", control_version: "1" }, { control_id: "release.pinned", control_version: "1" }];
  run("partial_support", partial);
  const multi = standardProfileFixture("contextos.core");
  multi.contract.profiles.push({ profile_id: "contextos.durable-delegated", profile_version: "1" }, { profile_id: "contextos.core", profile_version: "2" });
  run("conflicting_profiles", multi);
  const cycle: any = standardProfileFixture("contextos.core");
  cycle.registry.profiles[0].includes = [{ profile_id: "contextos.high-assurance", profile_version: "1" }];
  bindRegistry(cycle.registry);
  run("include_cycle", cycle);
  const deep: any = coreFixture();
  for (let d = 1; d <= 10; d++) deep.registry.profiles.push({ profile: { profile_id: `test.p${d}`, profile_version: "1" },
    includes: [{ profile_id: d === 1 ? "test.core" : `test.p${d - 1}`, profile_version: "1" }], mandatory_controls: [],
    conditional_controls: [], definition_ref: { ...deep.registry.profiles[0].definition_ref } });
  bindRegistry(deep.registry);
  run("include_depth", deep);
  const dupControl: any = coreFixture();
  dupControl.registry.controls.push({ ...structuredClone(dupControl.registry.controls[0]), evidence_obligations: ["other"] });
  bindRegistry(dupControl.registry);
  run("duplicate_control_definition", dupControl);
  const extraReq: any = coreFixture();
  extraReq.contract.required_controls = [{ control_id: "test.policy", control_version: "2" }, { control_id: "nope", control_version: "1" }];
  extraReq.contract.release_refs = [{ artifact_type: "a", artifact_id: "r", version: "1", sha256: "sha256:" + "a".repeat(64) },
    { artifact_type: "a", artifact_id: "r", version: "2", sha256: "sha256:" + "a".repeat(64) }];
  run("extra_required_and_release_conflict", extraReq);
  for (let i = 0; i < 3000; i++) {
    const base = i % 3 === 0 ? coreFixture() : standardProfileFixture(STANDARD_PROFILE_REGISTRY.profiles[i % 5].profile.profile_id);
    const mutated: any = mutate(base, rand);
    if (i % 2 === 1) { try { bindRegistry(mutated.registry); } catch { /* malformed registry stays unbound */ } }
    run(`mutation:${i}`, mutated);
  }
  writeFileSync(path.join(out, "negotiation.json.gz"), gzipSync(JSON.stringify({ registry: STANDARD_PROFILE_REGISTRY, cases }) + "\n", { level: 9 }));
});
