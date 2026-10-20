import { test } from "vitest";
import { writeFileSync } from "node:fs";
import { gzipSync } from "node:zlib";
import path from "node:path";
import { assessConformanceReport } from "@ref/conformance";
import { conformanceFixture, bindConformanceEvidence, fixtureArtifact } from "@fixtures/execution-contract";
import { mutate, rng } from "./mutate";

const out = path.resolve(import.meta.dirname, "../vectors");
const json = <T>(v: T): T => JSON.parse(JSON.stringify(v));
function call(fn: () => unknown) { try { return fn(); } catch (e: any) { return { throws: String(e.message) }; } }

test("conformance vectors", () => {
  const rand = rng(2718);
  const cases: unknown[] = [];
  const run = (name: string, f: any) => { const x = json(f); cases.push({ name, input: x, expected: call(() => assessConformanceReport(json(x))) }); };
  run("base", conformanceFixture());
  const semantic: [string, (f: any) => void, boolean][] = [
    ["synthetic_evidence", (f) => { f.report_verification.evidence_kind = "synthetic"; }, false],
    ["synthetic_case", (f) => { f.evidence_observations[3].evidence_kind = "synthetic"; }, false],
    ["control_failed", (f) => { f.report.control_results[0].status = "failed"; f.report.outcome = "failed"; }, true],
    ["case_failed", (f) => { f.report.control_results[1].case_results[0].status = "failed"; }, true],
    ["missing_negative_case", (f) => { f.report.control_results[2].case_results.pop(); }, true],
    ["missing_control_row", (f) => { f.report.control_results.pop(); }, true],
    ["evidence_hash_drift", (f) => { f.evidence_observations[0].actual_sha256 = "sha256:" + "e".repeat(64); }, false],
    ["report_stale", (f) => { f.evaluation_time = "2026-10-16T09:00:00Z"; }, false],
    ["untrusted_assessor", (f) => { f.trusted_assessors = [{ ...f.trusted_assessors[0], principal_id: "other" }]; }, false],
    ["scope_release", (f) => { f.scope.release_refs = [fixtureArtifact("release", "other")]; }, true],
    ["scope_workflow", (f) => { f.scope.workflow_id = "other_workflow"; }, true],
    ["utility_missing", (f) => { f.scope.required_utility_case_ids = ["owner_scheduling.useful", "other.useful"]; }, true],
    ["utility_failed", (f) => { f.report.utility_results[0].status = "failed"; }, true],
    ["declared_insufficient", (f) => { f.report.outcome = "insufficient_evidence"; }, true],
    ["extra_optional_result", (f) => { f.contract.optional_controls = [{ control_id: "release.pinned", control_version: "1" }];
      f.report.control_results.push({ control: { control_id: "release.pinned", control_version: "1" }, status: "not_evaluated", case_results: [],
        evidence_refs: [], reason_codes: [], limitations: ["not_run_in_synthetic_env"] }); }, true],
    ["unselected_result", (f) => { f.report.control_results.push({ control: { control_id: "memory.lifecycle", control_version: "1" }, status: "passed",
      case_results: [], evidence_refs: [], reason_codes: [], limitations: [] }); }, true],
    ["limitations", (f) => { f.report.control_results[0].limitations = ["b_limit", "a_limit", "b_limit"]; }, true],
    ["duplicate_rows", (f) => { f.report.utility_results.push(structuredClone(f.report.utility_results[0])); }, true],
    ["unsupported_contract", (f) => { f.support.supported_controls = []; }, true],
    ["feature_requires_more", (f) => { f.features.external_effects = true; }, true],
  ];
  for (const [n, edit, rebind] of semantic) { const f: any = conformanceFixture(); edit(f); if (rebind) bindConformanceEvidence(f); run(`semantic:${n}`, f); }
  for (let i = 0; i < 300; i++) {
    const f: any = mutate(conformanceFixture(), rand);
    if (i % 2) call(() => bindConformanceEvidence(f));
    run(`mutation:${i}`, f);
  }
  writeFileSync(path.join(out, "conformance.json.gz"), gzipSync(JSON.stringify({ cases }) + "\n", { level: 9 }));
});
