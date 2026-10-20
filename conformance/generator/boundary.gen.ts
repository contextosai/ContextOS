import { test } from "vitest";
import { writeFileSync } from "node:fs";
import { gzipSync } from "node:zlib";
import path from "node:path";
import { sha256Canonical } from "@ref/canonical-json";
import { evaluateBoundaryReadiness, evaluateDataFlow, validateMemoryLifecycle } from "@ref/execution-boundary";
import { boundaryFixture, sandboxBoundaryFixture, dataFlowFixture, fixtureArtifact } from "@fixtures/execution-contract";
import { mutate, rng } from "./mutate";

const out = path.resolve(import.meta.dirname, "../vectors");
const json = <T>(v: T): T => JSON.parse(JSON.stringify(v));
function call(fn: () => unknown) { try { return fn(); } catch (e: any) { return { throws: String(e.message) }; } }

function intentDigest(record: any): string {
  const { review: _r, propagation_entries: _e, propagation_status: _s, ...intent } = record;
  return sha256Canonical({ domain: "contextos.memory_lifecycle_intent.v1", intent });
}
function memoryFixture(): any {
  const f: any = dataFlowFixture();
  f.request.stage = "memory"; f.request.destination_id = "memory:support";
  f.request.processor_observation.destination_id = "memory:support";
  f.policy.allowed_flows[0].destination_id = "memory:support";
  const context = { tenant_id: "tenant_acme_prod", owner_id: "usr_771", namespace: "support",
    purpose_id: "support.refund", allowed_readers: ["usr_771", "agt_support"], allowed_operations: ["propose", "promote", "correct", "delete"],
    requires_review: ["promote", "correct"], maximum_retention_expires_at: "2026-11-16T00:00:00Z",
    retention_exception: "none", trusted_observers: f.policy.trusted_observers,
    access_observation: { tenant_id: "tenant_acme_prod", owner_id: "usr_771", namespace: "support", purpose_id: "support.refund",
      verification_status: "verified", observer: f.policy.trusted_observers[0], evidence_ref: fixtureArtifact("memory_access", "owner_771"),
      observed_at: "2026-10-16T07:59:59Z", valid_until: "2026-10-16T08:05:00Z" },
    data_flow_request: f.request, data_policy: f.policy, known_derived_copy_refs: [] as any[], derived_inventory_status: "verified_complete" };
  const record: any = { record_id: "memory_lifecycle_771", memory_ref: fixtureArtifact("memory", "memory_771"),
    contract_id: f.request.contract_id, run_id: f.request.run_id, operation_id: f.request.operation_id, action_digest: f.request.action_digest,
    tenant_id: "tenant_acme_prod", owner_id: "usr_771", namespace: "support", purpose_id: "support.refund",
    source_refs: f.request.source_artifacts.map((s: any) => s.artifact_ref), readers: ["usr_771"], operation: "promote",
    policy_ref: f.policy.policy_ref, retention_expires_at: "2026-10-23T00:00:00Z", review: null, derived_copy_refs: [],
    propagation_entries: [], propagation_status: "pending" };
  record.review = { record_digest: intentDigest(record), decision: "approved", verification_status: "verified",
    observer: context.trusted_observers[0], evidence_ref: fixtureArtifact("memory_review", "review_771"),
    observed_at: "2026-10-16T07:59:59Z", valid_until: "2026-10-16T08:05:00Z" };
  return { record, context, evaluation_time: f.evaluation_time };
}
function propagate(f: any, copies: number, statuses: string[]) {
  const r = f.record;
  r.derived_copy_refs = Array.from({ length: copies }, (_, i) => fixtureArtifact("memory_copy", `copy_${i}`));
  f.context.known_derived_copy_refs = structuredClone(r.derived_copy_refs);
  const digest = intentDigest(r);
  r.review.record_digest = digest;
  const targets = [r.memory_ref, ...r.derived_copy_refs];
  r.propagation_entries = targets.map((t: any, i: number) => ({ artifact_ref: t, status: statuses[i % statuses.length],
    record_id: r.record_id, operation_id: r.operation_id, record_digest: digest, verification_status: "verified",
    observer: f.context.trusted_observers[0], evidence_ref: fixtureArtifact("propagation", `p_${i}`),
    observed_at: "2026-10-16T07:59:59Z", valid_until: "2026-10-16T08:05:00Z" }));
}

// Mirrors the reference network-grant predicate for origin parity.
function originValid(origin: string): boolean {
  if (origin.length === 0 || origin.length > 512 || [...origin].length > 256 || origin.includes("*")) return false;
  try { const url = new URL(origin);
    return ["https:", "http:", "wss:", "ws:"].includes(url.protocol) && !url.username && !url.password
      && url.origin === origin && url.pathname === "/" && !url.search && !url.hash; } catch { return false; }
}

test("boundary, data-flow and memory vectors", () => {
  const rand = rng(9090);
  const boundary: unknown[] = [], dataflow: unknown[] = [], memory: unknown[] = [];
  const runB = (name: string, f: any) => { const x = json(f);
    boundary.push({ name, input: x, expected: call(() => evaluateBoundaryReadiness(json(x.requirement), json(x.observation), x.evaluation_time)) }); };
  const runD = (name: string, f: any) => { const x = json(f);
    dataflow.push({ name, input: x, expected: call(() => evaluateDataFlow(json(x.request), json(x.policy), x.evaluation_time)) }); };
  const runM = (name: string, f: any) => { const x = json(f);
    memory.push({ name, input: x, expected: call(() => validateMemoryLifecycle(json(x.record), json(x.context), x.evaluation_time)) }); };

  runB("broker", boundaryFixture()); runB("sandbox", sandboxBoundaryFixture());
  const bSemantic: [string, (f: any) => void][] = [
    ["no_observation", (f) => { f.observation = null; }],
    ["terminated", (f) => { f.observation.lifecycle_state = "terminated"; }],
    ["unavailable", (f) => { f.observation.lifecycle_state = "unavailable"; }],
    ["stale_age", (f) => { f.evaluation_time = "2026-10-16T08:00:09.9999999Z"; f.observation.observed_at = "2026-10-16T07:59:59.5Z"; }],
    ["age_exact", (f) => { f.evaluation_time = "2026-10-16T08:00:09Z"; }],
    ["age_over", (f) => { f.evaluation_time = "2026-10-16T08:00:09.000000001Z"; }],
    ["config_mismatch", (f) => { f.observation.actual_configuration_sha256 = "sha256:" + "a".repeat(64); }],
    ["trust_domain", (f) => { f.observation.trust_domain = "other.domain"; }],
    ["observer", (f) => { f.observation.observer.principal_id = "someone"; }],
    ["control_missing", (f) => { f.observation.active_controls = []; }],
    ["control_failed", (f) => { f.observation.failed_controls = [{ control_id: "network.mediated", control_version: "1" }]; }],
    ["network_unenforced", (f) => { f.observation.enforcement.network = false; }],
    ["child_processes", (f) => { f.requirement.process_restrictions.allow_child_processes = true; }],
    ["fs_grant_broker", (f) => { f.requirement.filesystem_grants = [{ root: "/data", path_format: "posix", access: "read" }]; }],
    ["fs_grant_relative", (f) => { f.requirement.filesystem_grants = [{ root: "data", path_format: "posix", access: "read" }]; }],
    ["fs_grant_dotdot", (f) => { f.requirement.filesystem_grants = [{ root: "/data/../etc", path_format: "posix", access: "read" }]; }],
    ["fs_grant_windows", (f) => { f.requirement.filesystem_grants = [{ root: "C:\\work", path_format: "windows", access: "read" }]; }],
    ["fs_grant_windows_slash", (f) => { f.requirement.filesystem_grants = [{ root: "C:/work", path_format: "windows", access: "read" }]; }],
    ["fs_grant_unc", (f) => { f.requirement.filesystem_grants = [{ root: "\\\\server\\share\\x", path_format: "windows", access: "read" }]; }],
    ["net_grant_ok", (f) => { f.requirement.network_grants = [{ origin: "https://api.example.com" }]; }],
    ["net_grant_port", (f) => { f.requirement.network_grants = [{ origin: "https://api.example.com:8443" }]; }],
    ["net_grant_default_port", (f) => { f.requirement.network_grants = [{ origin: "https://api.example.com:443" }]; }],
    ["net_grant_path", (f) => { f.requirement.network_grants = [{ origin: "https://api.example.com/v1" }]; }],
    ["net_grant_upper", (f) => { f.requirement.network_grants = [{ origin: "https://API.example.com" }]; }],
    ["net_grant_ftp", (f) => { f.requirement.network_grants = [{ origin: "ftp://example.com" }]; }],
    ["no_isolation_control", (f) => { f.requirement.required_controls = []; }],
    ["duplicate_control_revision", (f) => { f.requirement.required_controls.push({ control_id: "isolation.required", control_version: "2" }); }],
    ["zero_cpu", (f) => { f.requirement.resource_ceilings.cpu_ms = 0; }],
    ["mode_mismatch", (f) => { f.observation.isolation_mode = "dedicated_environment"; }],
    ["bad_time", (f) => { f.evaluation_time = "2026-10-16 08:00:00"; }],
  ];
  for (const base of [boundaryFixture, sandboxBoundaryFixture]) for (const [n, edit] of bSemantic) {
    const f: any = base(); edit(f); runB(`semantic:${base.name}:${n}`, f);
  }
  for (let i = 0; i < 600; i++) runB(`mutation:${i}`, mutate(i % 2 ? sandboxBoundaryFixture() : boundaryFixture(), rand));

  runD("base", dataFlowFixture());
  const transformed = () => { const f: any = dataFlowFixture(); const res = fixtureArtifact("evidence_snapshot", "order_881_redacted");
    f.request.requested_classification = "PUBLIC";
    f.request.transformation = { transformation_id: "redact_order", source_refs: f.request.source_artifacts.map((s: any) => s.artifact_ref),
      result_ref: res, result_classification: "PUBLIC", policy_ref: f.policy.policy_ref, purpose_id: f.request.purpose_id,
      destination_id: f.request.destination_id, release_status: "approved", approval_ref: fixtureArtifact("release_approval", "redaction"),
      destination_tenant_id: f.request.destination_tenant_id, destination_trust_domain: f.request.destination_trust_domain,
      operation_id: f.request.operation_id, action_digest: f.request.action_digest, processor_id: f.request.processor_id, stage: f.request.stage,
      verification_status: "verified", observer: f.policy.trusted_observers[0], evidence_ref: fixtureArtifact("transformation", "redaction"),
      observed_at: "2026-10-16T07:59:59Z", valid_until: "2026-10-16T08:05:00Z" };
    return f; };
  const combined = () => { const f: any = dataFlowFixture(); const second = fixtureArtifact("evidence_snapshot", "customer_77");
    f.request.source_artifacts.push({ artifact_ref: second, classification: "INTERNAL" });
    f.policy.source_observations.push({ ...structuredClone(f.policy.source_observations[0]), artifact_ref: second, classification: "INTERNAL" });
    f.policy.label_combinations = [{ inputs: ["INTERNAL", "CONFIDENTIAL"], output: "CONFIDENTIAL" }];
    return f; };
  runD("transformed", transformed()); runD("combined", combined());
  const dSemantic: [string, (f: any) => void][] = [
    ["destination", (f) => { f.request.destination_id = "elsewhere"; f.request.processor_observation.destination_id = "elsewhere"; }],
    ["purpose", (f) => { f.request.purpose_id = "marketing"; }],
    ["stage", (f) => { f.policy.allowed_flows[0].stages = ["inference"]; }],
    ["downgrade_without_transform", (f) => { f.request.requested_classification = "PUBLIC"; }],
    ["unknown_label", (f) => { f.request.requested_classification = "SECRET"; }],
    ["residency", (f) => { f.request.processor_observation.residency_region = "region_x"; }],
    ["processor_unverified", (f) => { f.request.processor_observation.verification_status = "unavailable"; }],
    ["source_stale", (f) => { f.policy.source_observations[0].observed_at = "2026-10-16T07:59:40Z"; }],
    ["source_label_mismatch", (f) => { f.request.source_artifacts[0].classification = "INTERNAL"; }],
    ["policy_expired", (f) => { f.evaluation_time = "2026-10-17T00:00:00Z"; }],
    ["policy_ref", (f) => { f.request.policy_ref = fixtureArtifact("data_flow_policy", "other"); }],
    ["tenant", (f) => { f.request.tenant_id = "other_tenant"; }],
    ["duplicate_source", (f) => { f.request.source_artifacts.push(structuredClone(f.request.source_artifacts[0])); }],
    ["dup_combination", (f) => { f.policy.label_combinations = [{ inputs: ["A"], output: "PUBLIC" }]; }],
  ];
  for (const [n, edit] of dSemantic) { const f: any = dataFlowFixture(); edit(f); runD(`semantic:${n}`, f); }
  const tSemantic: [string, (f: any) => void][] = [
    ["not_approved", (f) => { f.request.transformation.release_status = "unknown"; }],
    ["wrong_digest", (f) => { f.request.transformation.action_digest = "sha256:" + "b".repeat(64); }],
    ["result_is_source", (f) => { f.request.transformation.result_ref = f.request.source_artifacts[0].artifact_ref; }],
    ["unlisted_transform", (f) => { f.request.transformation.transformation_id = "anything"; }],
    ["stage", (f) => { f.request.transformation.stage = "export"; }],
  ];
  for (const [n, edit] of tSemantic) { const f: any = transformed(); edit(f); runD(`transform:${n}`, f); }
  const comboSemantic: [string, (f: any) => void][] = [
    ["no_combination", (f) => { f.policy.label_combinations = []; }],
  ];
  for (const [n, edit] of comboSemantic) { const f: any = combined(); edit(f); runD(`combined:${n}`, f); }
  for (let i = 0; i < 500; i++) runD(`mutation:${i}`, mutate([dataFlowFixture, transformed, combined][i % 3](), rand));

  runM("base", memoryFixture());
  for (const [n, copies, statuses, inv] of [["confirmed", 2, ["confirmed"], "verified_complete"], ["pending", 1, ["pending"], "verified_complete"],
    ["failed", 2, ["confirmed", "failed"], "verified_complete"], ["external", 1, ["external_unknown"], "verified_complete"],
    ["incomplete_inventory", 1, ["confirmed"], "incomplete"], ["external_inventory", 0, ["confirmed"], "external_unknown"],
    ["max_copies", 128, ["confirmed"], "verified_complete"]] as const) {
    for (const claimed of ["pending", "confirmed", "failed", "external_unknown"]) {
      const f = memoryFixture(); propagate(f, copies, [...statuses]); f.context.derived_inventory_status = inv;
      f.record.propagation_status = claimed; runM(`propagation:${n}:${claimed}`, f);
    }
  }
  const mSemantic: [string, (f: any) => void][] = [
    ["no_review", (f) => { f.record.review = null; }],
    ["review_denied", (f) => { f.record.review.decision = "denied"; }],
    ["review_stale_digest", (f) => { f.record.readers.push("agt_support"); }],
    ["reader_not_allowed", (f) => { f.record.readers.push("stranger"); f.record.review.record_digest = intentDigest(f.record); }],
    ["operation_not_allowed", (f) => { f.context.allowed_operations = ["propose"]; }],
    ["retention_escalation", (f) => { f.context.retention_exception = "requires_escalation"; }],
    ["retention_expired", (f) => { f.record.retention_expires_at = "2026-10-16T08:00:00Z"; f.record.review.record_digest = intentDigest(f.record); }],
    ["retention_too_long", (f) => { f.record.retention_expires_at = "2027-01-01T00:00:00Z"; f.record.review.record_digest = intentDigest(f.record); }],
    ["delete_past_retention", (f) => { f.record.operation = "delete"; f.record.retention_expires_at = "2026-01-01T00:00:00Z"; f.record.review = null; }],
    ["access_unverified", (f) => { f.context.access_observation.verification_status = "invalid"; }],
    ["scope_owner", (f) => { f.context.owner_id = "usr_other"; }],
    ["flow_stage", (f) => { f.context.data_flow_request.stage = "tool_input"; }],
    ["copy_untracked", (f) => { f.context.known_derived_copy_refs = [fixtureArtifact("memory_copy", "ghost")]; }],
  ];
  for (const [n, edit] of mSemantic) { const f = memoryFixture(); edit(f); runM(`semantic:${n}`, f); }
  for (let i = 0; i < 500; i++) { const f = memoryFixture(); if (i % 3 === 0) propagate(f, 2, ["confirmed", "pending"]); runM(`mutation:${i}`, mutate(f, rand)); }

  const pathCorpus: unknown[] = [];
  const atoms = ["/", "\\", "a", "b", ".", "..", "C:", "c:", "//", "\\\\", "srv", "share", "x y", ":", "CON", "~", "é"];
  for (let i = 0; i < 4000; i++) {
    const n = 1 + Math.floor(rand() * 7);
    let p = ""; for (let j = 0; j < n; j++) p += atoms[Math.floor(rand() * atoms.length)];
    pathCorpus.push({ p, posix_abs: path.posix.isAbsolute(p), posix_norm: path.posix.normalize(p),
      win_abs: path.win32.isAbsolute(p), win_norm: path.win32.normalize(p) });
  }
  const origins = ["https://api.example.com", "http://a.b", "https://API.example.com", "https://api.example.com/", "https://api.example.com:443",
    "https://api.example.com:8443", "wss://x.y", "ws://x.y:80", "ws://x.y:81", "ftp://x.y", "https://u:p@x.y", "https://x.y?q", "https://x.y#h",
    "https://xn--bcher-kva.example", "https://bücher.example", "https://127.0.0.1", "https://[::1]", "https://[::1]:8443", "https://0x7f.1",
    "https://x.y.", "https:x.y", "HTTPS://x.y", "https://x..y", "http://localhost:0", "https://x.y:65535", "https://x.y:65536", " https://x.y",
    "https://x_y.z", "https://%41.com", "https://a.com:", "http://1.2.3", "https://exa mple.com", "https://x.y:080", "https://*.x.y"];
  const originCorpus = origins.map((o) => ({ origin: o, valid: originValid(o) }));
  writeFileSync(path.join(out, "boundary.json.gz"), gzipSync(JSON.stringify({ boundary, dataflow, memory, paths: pathCorpus, origins: originCorpus }) + "\n", { level: 9 }));
});
