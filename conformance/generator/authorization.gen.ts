import { test } from "vitest";
import { writeFileSync } from "node:fs";
import { gzipSync } from "node:zlib";
import path from "node:path";
import { sha256Canonical } from "@ref/canonical-json";
import { composePolicyOutcomes, digestActionBinding, evaluateAuthorization, transitionApprovalRedemption,
  validateApprovalBinding, validateAuthority } from "@ref/authorization";
import { actionFixture, approvalFixture, authorityFixture, authorizationFixture, refreshApprovalObservations,
  refreshGrantObservations, fixtureArtifact } from "@fixtures/execution-contract";
import { mutate, rng } from "./mutate";

const out = path.resolve(import.meta.dirname, "../vectors");
const json = <T>(v: T): T => JSON.parse(JSON.stringify(v));
function call(fn: () => unknown) { try { return fn(); } catch (e: any) { return { throws: String(e.message) }; } }

/** Leaf grant delegated from a root grant; the child run is linked to the root run. */
function delegatedAuthority(childRun = true) {
  const input: any = authorityFixture();
  const root = input.grants[0];
  const broker = { ...input.binding.actor, principal_id: "parent_agent" };
  root.grant_id = "grant_root"; root.subject = broker; root.verification_ref = fixtureArtifact("authority_grant", "grant_root");
  const leaf = structuredClone(root);
  leaf.grant_id = "grant_leaf"; leaf.issuer = broker; leaf.subject = input.binding.actor;
  leaf.delegation_depth_remaining = 3; leaf.parent_grant_ref = { grant_id: "grant_root", grant_revision: "1" };
  leaf.scope.argument_constraints = [{ pointer: "/order_id", kind: "one_of", values: ["ord_881"] },
    { pointer: "/amount_inr", kind: "max_integer", maximum: 4500 }];
  leaf.scope.amount_ceiling = { currency: "INR", minor_units: 4500 };
  leaf.verification_ref = fixtureArtifact("authority_grant", "grant_leaf");
  input.grants = [leaf, root]; input.leaf_grant_ref = { grant_id: "grant_leaf", grant_revision: "1" };
  if (childRun) {
    input.binding.run_id = "run_child"; input.authenticated.run_id = "run_child";
    input.run_links = [{ parent_run_id: input.authenticated.root_run_id, child_run_id: "run_child",
      root_run_id: input.authenticated.root_run_id, tenant_id: input.binding.tenant_id, subject: input.binding.actor,
      observer: input.authenticated.trusted_observers[0], verification_status: "verified",
      verification_ref: fixtureArtifact("run_link", "run_child"), observed_at: "2026-10-16T07:00:00Z", valid_until: "2026-10-16T09:00:00Z" }];
  }
  refreshGrantObservations(input);
  return input;
}
function personDirected() {
  const input: any = authorityFixture();
  const person = { ...input.binding.actor, principal_id: "usr_771", principal_type: "person" };
  input.authenticated.mandate_kind = "person_directed"; input.authenticated.mandating_person = person;
  input.authenticated.trusted_issuers = [person]; input.grants[0].issuer = person;
  input.binding.action_risk.authority = "user_delegated";
  refreshGrantObservations(input);
  return input;
}

test("authorization vectors", () => {
  const rand = rng(777);
  const authority: unknown[] = [], approval: unknown[] = [], redemption: unknown[] = [], authorization: unknown[] = [],
    policy: unknown[] = [], digest: unknown[] = [];
  const bases = [() => authorityFixture(), () => delegatedAuthority(true), () => delegatedAuthority(false), () => personDirected()];
  for (const [i, make] of bases.entries()) authority.push({ name: `base:${i}`, input: json(make()), expected: call(() => validateAuthority(json(make()))) });
  for (let i = 0; i < 500; i++) {
    const input: any = mutate(bases[i % bases.length](), rand);
    if (i % 2 === 0) call(() => refreshGrantObservations(input));
    const f = json(input);
    authority.push({ name: `mutation:${i}`, input: f, expected: call(() => validateAuthority(json(f))) });
  }
  const semantic: [string, (x: any) => void, boolean][] = [
    ["revoked", (x) => { x.observations[0].revocation_status = "revoked"; }, false],
    ["revocation_unknown", (x) => { x.observations[0].revocation_status = "unknown"; }, false],
    ["observation_unavailable", (x) => { x.observations[0].verification_status = "unavailable"; }, false],
    ["observation_stale", (x) => { x.observations[0].valid_until = "2026-10-16T07:30:00Z"; }, false],
    ["grant_expired", (x) => { x.evaluation_time = "2026-10-17T00:00:00Z"; x.authenticated.valid_until = "2026-10-18T00:00:00Z"; }, true],
    ["grant_not_yet_valid", (x) => { x.grants[0].not_before = "2026-10-16T08:00:00.000001Z"; }, true],
    ["auth_unverified", (x) => { x.authenticated.verification_status = "invalid"; }, false],
    ["auth_person_principal", (x) => { x.authenticated.principal.principal_type = "person"; }, false],
    ["tenant_mismatch", (x) => { x.binding.actor.tenant_id = "other"; x.authenticated.principal.tenant_id = "other"; x.grants[0].subject.tenant_id = "other"; }, true],
    ["scope_amount_over", (x) => { x.binding.amount.minor_units = 6000; }, false],
    ["scope_amount_currency", (x) => { x.binding.amount.currency = "USD"; }, false],
    ["scope_argument_over", (x) => { x.binding.arguments.amount_inr = 5001; }, false],
    ["scope_argument_missing", (x) => { delete x.binding.arguments.order_id; }, false],
    ["scope_destination", (x) => { x.binding.destination_ids.push("someone_else"); }, false],
    ["scope_purpose", (x) => { x.binding.purpose_id = "marketing"; }, false],
    ["scope_classification", (x) => { x.binding.action_risk.data_scope = "RESTRICTED"; }, false],
    ["audience", (x) => { x.authenticated.audience = "other.gateway"; }, false],
    ["untrusted_issuer", (x) => { x.authenticated.trusted_issuers = [x.authenticated.trusted_observers[0]]; }, false],
    ["untrusted_observer", (x) => { x.authenticated.trusted_observers = [x.authenticated.trusted_issuers[0]]; }, false],
    ["user_delegated_by_workload", (x) => { x.binding.action_risk.authority = "user_delegated"; }, true],
    ["extra_grant", (x) => { x.grants.push({ ...structuredClone(x.grants[0]), grant_id: "unused" }); }, true],
    ["authority_ref_mismatch", (x) => { x.binding.authority_refs = [fixtureArtifact("authority_grant", "other")]; }, false],
  ];
  for (const [mi, make] of bases.entries()) for (const [name, edit, refresh] of semantic) {
    const x: any = make();
    try { edit(x); } catch { continue; }
    if (refresh) refreshGrantObservations(x);
    const f = json(x);
    authority.push({ name: `semantic:${mi}:${name}`, input: f, expected: call(() => validateAuthority(json(f))) });
  }
  const dl: any = delegatedAuthority(true);
  const widen = [
    ["child_wider_amount", (x: any) => { x.grants[0].scope.amount_ceiling.minor_units = 6000; }],
    ["child_extra_purpose", (x: any) => { x.grants[0].scope.purpose_ids.push("other"); }],
    ["child_depth_not_reduced", (x: any) => { x.grants[0].delegation_depth_remaining = 15; }],
    ["parent_depth_zero", (x: any) => { x.grants[1].delegation_depth_remaining = 0; x.grants[0].delegation_depth_remaining = 0; }],
    ["child_outlives_parent", (x: any) => { x.grants[0].expires_at = "2026-10-18T00:00:00Z"; }],
    ["child_issuer_not_parent_subject", (x: any) => { x.grants[0].issuer = x.grants[1].issuer; }],
    ["child_drops_constraint", (x: any) => { x.grants[0].scope.argument_constraints = []; }],
    ["child_one_of_outside", (x: any) => { x.grants[0].scope.argument_constraints[0].values = ["ord_881", "ord_999"]; }],
    ["run_link_missing", (x: any) => { x.run_links = []; }],
    ["run_link_unverified", (x: any) => { x.run_links[0].verification_status = "invalid"; }],
    ["run_link_wrong_root", (x: any) => { x.run_links[0].root_run_id = "other_root"; }],
    // A scope without amount_ceiling admits no amount: a child may neither add nor drop one.
    ["child_adds_ceiling", (x: any) => { delete x.grants[1].scope.amount_ceiling; delete x.binding.amount; }],
    ["neither_has_ceiling", (x: any) => { delete x.grants[0].scope.amount_ceiling; delete x.grants[1].scope.amount_ceiling; delete x.binding.amount; }],
    ["child_drops_ceiling", (x: any) => { delete x.grants[0].scope.amount_ceiling; delete x.binding.amount; }],
  ] as const;
  for (const [name, edit] of widen) {
    const x: any = structuredClone(dl); edit(x); refreshGrantObservations(x);
    const f = json(x);
    authority.push({ name: `delegation:${name}`, input: f, expected: call(() => validateAuthority(json(f))) });
  }
  const approvalSemantic: [string, (x: any) => void][] = [
    ["denied", (x) => { x.decisions[0].decision = "denied"; }],
    ["self_approval", (x) => { x.decisions[0].approver = x.binding.actor; x.request.eligible_approvers = [x.binding.actor]; x.entitlements[0].approver = x.binding.actor; }],
    ["quorum_two", (x) => { x.request.required_approvals = 2; }],
    ["duplicate_approver", (x) => { x.request.required_approvals = 2; x.decisions.push({ ...structuredClone(x.decisions[0]), approval_id: "approval_dup" }); }],
    ["second_approver", (x) => { x.request.required_approvals = 2; const p = { ...x.decisions[0].approver, principal_id: "cfo" };
      x.request.eligible_approvers.push(p); x.decisions.push({ ...structuredClone(x.decisions[0]), approval_id: "approval_2", approver: p });
      x.entitlements.push({ ...structuredClone(x.entitlements[0]), approver: p }); }],
    ["no_entitlement", (x) => { x.entitlements = []; }],
    ["wrong_role", (x) => { x.entitlements[0].role_id = "intern"; }],
    ["expired", (x) => { x.evaluation_time = "2026-10-16T09:00:00Z"; }],
    ["decided_in_future", (x) => { x.decisions[0].decided_at = "2026-10-16T08:30:00Z"; }],
    ["consumed_other_op", (x) => { x.redemption_state.operation_id = "op_other"; x.redemption_state.action_digest = x.proposal.action_digest; }],
    ["consumed_same_op", (x) => { x.redemption_state.operation_id = x.binding.operation_id; x.redemption_state.action_digest = x.proposal.action_digest; }],
    ["proposal_digest_mismatch", (x) => { x.binding.arguments.amount_inr = 4300; }],
    ["request_outlives_proposal", (x) => { x.request.expires_at = "2026-10-16T10:00:00Z"; }],
    ["untrusted_observer", (x) => { x.trusted_observers = [x.binding.actor]; }],
  ];
  for (const [name, edit] of approvalSemantic) {
    const x: any = approvalFixture(); edit(x); refreshApprovalObservations(x);
    const f = json(x);
    approval.push({ name: `semantic:${name}`, input: f, expected: call(() => validateApprovalBinding(json(f))) });
    for (const rev of [0, 1]) {
      const r = json({ approval: x, expected_revision: rev });
      redemption.push({ input: r, expected: call(() => transitionApprovalRedemption(json(r))) });
    }
  }
  const authSemantic: [string, (x: any) => void][] = [
    ["human_approved_without_approval", (x) => { x.approval = null; x.policy_outcomes[0].verdict = "allow"; x.authority.binding.action_risk.authority = "human_approved"; }],
    ["allow_without_approval", (x) => { x.approval = null; x.policy_outcomes[0].verdict = "allow"; }],
    ["guardrail_deny", (x) => { x.policy_outcomes.push({ ...x.policy_outcomes[0], category: "guardrail", verdict: "deny", rule_id: "g" }); }],
    ["escalate", (x) => { x.policy_outcomes[0].verdict = "escalate"; }],
    ["constraint_missing", (x) => { x.constraint_observations = []; }],
    ["constraint_conflict", (x) => { x.required_constraints.push({ control_id: "isolation.required", control_version: "2" }); }],
    ["constraint_denied", (x) => { x.constraint_observations[0].verdict = "deny"; }],
    ["policy_ref_mismatch", (x) => { x.policy_outcomes[0].bundle_ref = fixtureArtifact("policy_bundle", "other"); }],
    ["approval_time_mismatch", (x) => { x.approval.evaluation_time = "2026-10-16T08:00:01Z"; }],
    ["self_approval_by_mandating_person", (x) => { const p = x.approval.decisions[0].approver; x.authority.authenticated.mandate_kind = "person_directed";
      x.authority.authenticated.mandating_person = p; x.authority.authenticated.trusted_issuers = [p]; x.authority.grants[0].issuer = p;
      refreshGrantObservations(x.authority); }],
  ];
  for (const [name, edit] of authSemantic) {
    const x: any = authorizationFixture(); edit(x);
    const f = json(x);
    authorization.push({ name: `semantic:${name}`, input: f, expected: call(() => evaluateAuthorization(json(f))) });
  }
  digest.push({ input: json(actionFixture()), expected: call(() => digestActionBinding(json(actionFixture()))) });
  for (let i = 0; i < 300; i++) {
    const f = json(mutate(actionFixture(), rand));
    digest.push({ input: f, expected: call(() => digestActionBinding(json(f))) });
  }
  const outcomeBase = () => {
    const ref = fixtureArtifact("policy_bundle", "refund_policy"), other = fixtureArtifact("policy_bundle", "guard");
    return [
      { category: "business", priority: 10, verdict: "require_approval", rule_id: "refund_approval", bundle_ref: ref, obligations: ["audit"] },
      { category: "business", priority: 5, verdict: "allow", rule_id: "refund_allow", bundle_ref: ref, obligations: ["notify", "audit"] },
      { category: "guardrail", priority: 0, verdict: "allow", rule_id: "no_pii", bundle_ref: other, obligations: [] },
    ];
  };
  const verdicts = ["allow", "deny", "require_approval", "escalate", "error"];
  for (let i = 0; i < 800; i++) {
    let o: any[] = outcomeBase();
    if (i % 3 === 0) o = mutate(o, rand);
    else o.forEach((x, j) => { x.verdict = verdicts[Math.floor(rand() * 5)]; x.priority = Math.floor(rand() * 3) * 5;
      if (rand() < 0.2) o[j].category = rand() < 0.5 ? "guardrail" : "business"; });
    if (i % 7 === 0) o = o.slice(0, Math.floor(rand() * 3));
    const f = json(o);
    policy.push({ input: f, expected: call(() => composePolicyOutcomes(json(f))) });
  }
  approval.push({ name: "base", input: json(approvalFixture()), expected: call(() => validateApprovalBinding(json(approvalFixture()))) });
  for (let i = 0; i < 400; i++) {
    const input: any = mutate(approvalFixture(), rand);
    if (i % 2 === 0) call(() => refreshApprovalObservations(input));
    const f = json(input);
    approval.push({ name: `mutation:${i}`, input: f, expected: call(() => validateApprovalBinding(json(f))) });
  }
  for (let i = 0; i < 200; i++) {
    const base: any = i % 4 === 0 ? mutate(approvalFixture(), rand) : approvalFixture();
    if (i % 4 === 1) { base.redemption_state.revision = 3; }
    if (i % 4 === 2) { base.redemption_state.operation_id = base.binding.operation_id; base.redemption_state.action_digest = digestActionBinding(base.binding); }
    if (i % 4 === 0) call(() => refreshApprovalObservations(base));
    const input = json({ approval: base, expected_revision: [0, 3, 1, 9007199254740991][Math.floor(rand() * 4)] });
    redemption.push({ input, expected: call(() => transitionApprovalRedemption(json(input))) });
  }
  const authBase = () => {
    const f: any = authorizationFixture();
    return f;
  };
  authorization.push({ name: "base", input: json(authBase()), expected: call(() => evaluateAuthorization(json(authBase()))) });
  const noApproval: any = authBase(); noApproval.approval = null;
  authorization.push({ name: "no_approval", input: json(noApproval), expected: call(() => evaluateAuthorization(json(noApproval))) });
  for (let i = 0; i < 300; i++) {
    const input: any = mutate(authBase(), rand);
    if (i % 2 === 0) { call(() => refreshGrantObservations(input.authority)); if (input.approval) call(() => refreshApprovalObservations(input.approval)); }
    if (i % 5 === 0) input.approval = null;
    if (i % 5 === 1 && Array.isArray(input.policy_outcomes) && input.policy_outcomes[0]) input.policy_outcomes[0].verdict = verdicts[i % 5];
    const f = json(input);
    authorization.push({ name: `mutation:${i}`, input: f, expected: call(() => evaluateAuthorization(json(f))) });
  }
  writeFileSync(path.join(out, "authorization.json.gz"), gzipSync(JSON.stringify({ digest, authority, policy, approval, redemption, authorization }) + "\n", { level: 9 }));
});
