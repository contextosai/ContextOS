import { canonicalizeJson, sha256Canonical } from "./canonical-json";
import { hasExactKeys, isArtifactRef, isContractIdentifier, isContractTimestamp, isControlRef,
  compareContractTimes, isWithinContractInterval } from "./contract-validation";
import type { ArtifactRef, ControlRef } from "./execution-contract-types";
import type { ActionRisk } from "./types";

export interface PrincipalRef {
  principal_id: string;
  principal_type: "person" | "workload" | "agent";
  trust_domain: string;
  tenant_id: string;
}
export interface MonetaryAmount { minor_units: number; currency: string }
export interface ActionBinding {
  binding_version: "contextos.action_binding.v1";
  contract_id: string;
  run_id: string;
  tenant_id: string;
  operation_id: string;
  proposal_id: string;
  actor: PrincipalRef;
  authority_refs: ArtifactRef[];
  purpose_id: string;
  capability_id: string;
  capability_version: string;
  arguments: Record<string, unknown>;
  resource_ids: string[];
  destination_ids: string[];
  evidence_refs: ArtifactRef[];
  policy_refs: ArtifactRef[];
  profile_refs: ArtifactRef[];
  release_refs: ArtifactRef[];
  action_risk: ActionRisk;
  amount?: MonetaryAmount;
}

function validPrincipal(value: unknown): value is PrincipalRef {
  return hasExactKeys(value, ["principal_id", "principal_type", "trust_domain", "tenant_id"])
    && isContractIdentifier(value.principal_id) && isContractIdentifier(value.trust_domain)
    && isContractIdentifier(value.tenant_id) && ["person", "workload", "agent"].includes(value.principal_type as string);
}
function validAmount(value: unknown): value is MonetaryAmount {
  return hasExactKeys(value, ["minor_units", "currency"])
    && Number.isSafeInteger(value.minor_units) && (value.minor_units as number) >= 0
    && typeof value.currency === "string" && /^[A-Z]{3}$/.test(value.currency);
}
function validRisk(value: unknown): value is ActionRisk {
  if (value === null || typeof value !== "object") return false;
  const keys = ["effect", "authority", "reversibility", "interaction", "data_scope"];
  if (Object.hasOwn(value, "decision_ttl_seconds")) keys.push("decision_ttl_seconds");
  return hasExactKeys(value, keys)
    && ["none", "local_state", "external_state", "physical_world"].includes(value.effect as string)
    && ["agent", "service", "user_delegated", "human_approved"].includes(value.authority as string)
    && ["read_only", "reversible", "compensatable", "irreversible"].includes(value.reversibility as string)
    && ["api", "browser", "computer", "agent_to_agent", "human_handoff"].includes(value.interaction as string)
    && ["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"].includes(value.data_scope as string)
    && (!Object.hasOwn(value, "decision_ttl_seconds") || (Number.isSafeInteger(value.decision_ttl_seconds)
      && (value.decision_ttl_seconds as number) >= 0));
}
const refs = (value: unknown, min = 0): value is ArtifactRef[] =>
  Array.isArray(value) && value.length >= min && value.length <= 128 && value.every(isArtifactRef);
const ids = (value: unknown): value is string[] =>
  Array.isArray(value) && value.length <= 128 && value.every(isContractIdentifier);

function validBinding(binding: unknown): binding is ActionBinding {
  if (binding === null || typeof binding !== "object") return false;
  const keys = ["binding_version", "contract_id", "run_id", "tenant_id", "operation_id", "proposal_id", "actor",
    "authority_refs", "purpose_id", "capability_id", "capability_version", "arguments", "resource_ids",
    "destination_ids", "evidence_refs", "policy_refs", "profile_refs", "release_refs", "action_risk"];
  if (Object.hasOwn(binding, "amount")) keys.push("amount");
  if (!hasExactKeys(binding, keys)) return false;
  return binding.binding_version === "contextos.action_binding.v1"
    && [binding.contract_id, binding.run_id, binding.tenant_id, binding.operation_id, binding.proposal_id,
      binding.purpose_id, binding.capability_id, binding.capability_version].every(isContractIdentifier)
    && validPrincipal(binding.actor) && refs(binding.authority_refs, 1)
    && ids(binding.resource_ids) && ids(binding.destination_ids) && refs(binding.evidence_refs)
    && refs(binding.policy_refs, 1) && refs(binding.profile_refs, 1) && refs(binding.release_refs, 1)
    && binding.arguments !== null && typeof binding.arguments === "object" && !Array.isArray(binding.arguments)
    && validRisk(binding.action_risk) && (!Object.hasOwn(binding, "amount") || validAmount(binding.amount));
}

/** A digest binds complete proposal data; it does not establish permission or authenticity. */
export function digestActionBinding(binding: ActionBinding): string {
  canonicalizeJson(binding); // Reject unsafe traversal/coercion before reading any property.
  if (!validBinding(binding)) throw new TypeError("Invalid action binding");
  return sha256Canonical({ domain: "contextos.action_binding.v1", binding });
}

export type ArgumentConstraint = { pointer: string } & (
  | { kind: "equals"; value: unknown }
  | { kind: "one_of"; values: unknown[] }
  | { kind: "max_integer"; maximum: number });
export interface AuthorityScope {
  root_run_id: string;
  purpose_ids: string[];
  capability_ids: string[];
  resource_ids: string[];
  destination_ids: string[];
  classification_labels: ActionRisk["data_scope"][];
  argument_constraints: ArgumentConstraint[];
  amount_ceiling?: MonetaryAmount;
}
export interface GrantRef { grant_id: string; grant_revision: string }
export interface AuthorityGrant extends GrantRef {
  issuer: PrincipalRef;
  subject: PrincipalRef;
  audience: string;
  scope: AuthorityScope;
  not_before: string;
  expires_at: string;
  delegation_depth_remaining: number;
  parent_grant_ref?: GrantRef;
  verification_ref: ArtifactRef;
}
export type VerificationStatus = "verified" | "invalid" | "unavailable";
export interface GrantObservation extends GrantRef {
  grant_digest: string;
  verification_ref: ArtifactRef;
  verification_status: VerificationStatus;
  observed_at: string;
  valid_until: string;
  revocation_status: "active" | "revoked" | "unknown";
  observer: PrincipalRef;
}
export interface AuthenticatedPrincipalContext {
  principal: PrincipalRef;
  audience: string;
  root_run_id: string;
  run_id: string;
  mandate_kind: "workload" | "person_directed";
  mandating_person?: PrincipalRef;
  trusted_issuers: PrincipalRef[];
  trusted_observers: PrincipalRef[];
  verification_status: VerificationStatus;
  verification_ref: ArtifactRef;
  observed_at: string;
  valid_until: string;
}
export interface VerifiedRunLink {
  parent_run_id: string;
  child_run_id: string;
  root_run_id: string;
  tenant_id: string;
  subject: PrincipalRef;
  observer: PrincipalRef;
  verification_status: VerificationStatus;
  verification_ref: ArtifactRef;
  observed_at: string;
  valid_until: string;
}
export interface AuthorityValidationInput {
  binding: ActionBinding;
  authenticated: AuthenticatedPrincipalContext;
  leaf_grant_ref: GrantRef;
  grants: AuthorityGrant[];
  observations: GrantObservation[];
  run_links: VerifiedRunLink[];
  evaluation_time: string;
}
export type AuthorityReasonCode = "identity_unverified" | "tenant_mismatch" | "grant_invalid"
  | "grant_expired" | "grant_revoked" | "revocation_unknown" | "delegation_scope_expanded"
  | "scope_mismatch" | "precondition_stale" | "verification_unavailable";
export interface AuthorityValidationResult {
  allowed: boolean;
  action_digest: string | null;
  grant_refs: ArtifactRef[];
  reason_codes: AuthorityReasonCode[];
}

const list = <T>(value: unknown, guard: (item: unknown) => item is T, max = 128): value is T[] =>
  Array.isArray(value) && value.length <= max && value.every(guard);
const verificationStatus = (value: unknown): value is VerificationStatus =>
  value === "verified" || value === "invalid" || value === "unavailable";
const sameJson = (a: unknown, b: unknown) => canonicalizeJson(a) === canonicalizeJson(b);
const grantKey = (ref: GrantRef) => JSON.stringify([ref.grant_id, ref.grant_revision]);
const validGrantRef = (value: unknown): value is GrantRef => hasExactKeys(value, ["grant_id", "grant_revision"])
  && isContractIdentifier(value.grant_id) && isContractIdentifier(value.grant_revision);
const safeInteger = (value: unknown): value is number => Number.isSafeInteger(value) && (value as number) >= 0;
function validPointer(value: unknown): value is string {
  return typeof value === "string" && value.length <= 256 && (value === "" || value.startsWith("/")) && !/~(?![01])/u.test(value);
}
function validConstraint(value: unknown): value is ArgumentConstraint {
  if (value === null || typeof value !== "object" || !("kind" in value)) return false;
  const constraint = value as Record<string, unknown>;
  if (constraint.kind === "equals") return hasExactKeys(constraint, ["pointer", "kind", "value"]) && validPointer(constraint.pointer);
  if (constraint.kind === "one_of") return hasExactKeys(constraint, ["pointer", "kind", "values"])
    && validPointer(constraint.pointer) && Array.isArray(constraint.values) && constraint.values.length > 0 && constraint.values.length <= 128;
  return constraint.kind === "max_integer" && hasExactKeys(constraint, ["pointer", "kind", "maximum"])
    && validPointer(constraint.pointer) && safeInteger(constraint.maximum);
}
function validScope(value: unknown): value is AuthorityScope {
  if (value === null || typeof value !== "object") return false;
  const keys = ["root_run_id", "purpose_ids", "capability_ids", "resource_ids", "destination_ids", "classification_labels", "argument_constraints"];
  if (Object.hasOwn(value, "amount_ceiling")) keys.push("amount_ceiling");
  return hasExactKeys(value, keys) && isContractIdentifier(value.root_run_id)
    && [value.purpose_ids, value.capability_ids, value.resource_ids, value.destination_ids].every(ids)
    && list(value.classification_labels, (label): label is ActionRisk["data_scope"] =>
      ["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"].includes(label as string))
    && list(value.argument_constraints, validConstraint)
    && new Set(value.argument_constraints.map(c => c.pointer)).size === value.argument_constraints.length
    && (!Object.hasOwn(value, "amount_ceiling") || validAmount(value.amount_ceiling));
}
function validGrant(value: unknown): value is AuthorityGrant {
  if (value === null || typeof value !== "object") return false;
  const keys = ["grant_id", "grant_revision", "issuer", "subject", "audience", "scope", "not_before", "expires_at",
    "delegation_depth_remaining", "verification_ref"];
  if (Object.hasOwn(value, "parent_grant_ref")) keys.push("parent_grant_ref");
  return hasExactKeys(value, keys) && isContractIdentifier(value.grant_id) && isContractIdentifier(value.grant_revision)
    && validPrincipal(value.issuer) && validPrincipal(value.subject) && isContractIdentifier(value.audience)
    && validScope(value.scope) && isContractTimestamp(value.not_before) && isContractTimestamp(value.expires_at)
    && safeInteger(value.delegation_depth_remaining) && value.delegation_depth_remaining <= 16
    && isArtifactRef(value.verification_ref) && (!Object.hasOwn(value, "parent_grant_ref") || validGrantRef(value.parent_grant_ref));
}
function validObservation(value: unknown): value is GrantObservation {
  return hasExactKeys(value, ["grant_id", "grant_revision", "grant_digest", "verification_ref", "verification_status",
    "observed_at", "valid_until", "revocation_status", "observer"])
    && isContractIdentifier(value.grant_id) && isContractIdentifier(value.grant_revision)
    && typeof value.grant_digest === "string" && /^sha256:[a-f0-9]{64}$/.test(value.grant_digest)
    && isArtifactRef(value.verification_ref) && verificationStatus(value.verification_status)
    && isContractTimestamp(value.observed_at) && isContractTimestamp(value.valid_until)
    && ["active", "revoked", "unknown"].includes(value.revocation_status as string) && validPrincipal(value.observer);
}
function validAuthenticated(value: unknown): value is AuthenticatedPrincipalContext {
  if (value === null || typeof value !== "object") return false;
  const keys = ["principal", "audience", "root_run_id", "run_id", "mandate_kind", "trusted_issuers", "trusted_observers",
    "verification_status", "verification_ref", "observed_at", "valid_until"];
  if (Object.hasOwn(value, "mandating_person")) keys.push("mandating_person");
  if (!hasExactKeys(value, keys)) return false;
  return validPrincipal(value.principal) && [value.audience, value.root_run_id, value.run_id].every(isContractIdentifier)
    && list(value.trusted_issuers, validPrincipal) && list(value.trusted_observers, validPrincipal)
    && verificationStatus(value.verification_status) && isArtifactRef(value.verification_ref)
    && isContractTimestamp(value.observed_at) && isContractTimestamp(value.valid_until)
    && ((value.mandate_kind === "workload" && !Object.hasOwn(value, "mandating_person"))
      || (value.mandate_kind === "person_directed" && validPrincipal(value.mandating_person)
        && value.mandating_person.principal_type === "person"));
}
function validRunLink(value: unknown): value is VerifiedRunLink {
  return hasExactKeys(value, ["parent_run_id", "child_run_id", "root_run_id", "tenant_id", "subject", "observer",
    "verification_status", "verification_ref", "observed_at", "valid_until"])
    && [value.parent_run_id, value.child_run_id, value.root_run_id, value.tenant_id].every(isContractIdentifier)
    && validPrincipal(value.subject) && validPrincipal(value.observer) && verificationStatus(value.verification_status)
    && isArtifactRef(value.verification_ref) && isContractTimestamp(value.observed_at) && isContractTimestamp(value.valid_until);
}
function pointerValue(argumentsValue: unknown, pointer: string): { found: boolean; value?: unknown } {
  let value = argumentsValue;
  if (pointer === "") return { found: true, value };
  for (const segment of pointer.slice(1).split("/")) {
    if (value === null || typeof value !== "object") return { found: false };
    const key = segment.replace(/~1/g, "/").replace(/~0/g, "~");
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !("value" in descriptor)) return { found: false };
    value = descriptor.value;
  }
  return { found: true, value };
}
function satisfies(value: unknown, constraint: ArgumentConstraint): boolean {
  if (constraint.kind === "equals") return sameJson(value, constraint.value);
  if (constraint.kind === "one_of") return constraint.values.some(candidate => sameJson(value, candidate));
  return safeInteger(value) && value <= constraint.maximum;
}
function constraintNarrows(child: ArgumentConstraint, parent: ArgumentConstraint): boolean {
  if (child.kind === "equals") return satisfies(child.value, parent);
  if (child.kind === "one_of") return child.values.every(value => satisfies(value, parent));
  return parent.kind === "max_integer" && child.maximum <= parent.maximum;
}
function scopeNarrows(child: AuthorityScope, parent: AuthorityScope): boolean {
  return child.root_run_id === parent.root_run_id
    && (["purpose_ids", "capability_ids", "resource_ids", "destination_ids", "classification_labels"] as const)
      .every(key => child[key].every(value => (parent[key] as readonly string[]).includes(value)))
    && parent.argument_constraints.every(required => child.argument_constraints.some(candidate =>
      candidate.pointer === required.pointer && constraintNarrows(candidate, required)))
    // A scope without a ceiling admits no amount (inScope), so a child may not add one.
    && (parent.amount_ceiling
      ? !!child.amount_ceiling && child.amount_ceiling.currency === parent.amount_ceiling.currency
        && child.amount_ceiling.minor_units <= parent.amount_ceiling.minor_units
      : !child.amount_ceiling);
}
function inScope(binding: ActionBinding, scope: AuthorityScope): boolean {
  return scope.purpose_ids.includes(binding.purpose_id) && scope.capability_ids.includes(binding.capability_id)
    && binding.resource_ids.every(id => scope.resource_ids.includes(id))
    && binding.destination_ids.every(id => scope.destination_ids.includes(id))
    && scope.classification_labels.includes(binding.action_risk.data_scope)
    && scope.argument_constraints.every(constraint => {
      const value = pointerValue(binding.arguments, constraint.pointer);
      return value.found && satisfies(value.value, constraint);
    })
    && (!binding.amount || (!!scope.amount_ceiling && binding.amount.currency === scope.amount_ceiling.currency
      && binding.amount.minor_units <= scope.amount_ceiling.minor_units));
}

/** Consumes authenticated adapter facts; never verifies caller assertions, signatures or live revocation itself. */
export function validateAuthority(input: AuthorityValidationInput): AuthorityValidationResult {
  const reasons = new Set<AuthorityReasonCode>();
  let actionDigest: string | null = null;
  let grantRefs: ArtifactRef[] = [];
  const finish = (): AuthorityValidationResult => ({ allowed: reasons.size === 0, action_digest: actionDigest,
    grant_refs: grantRefs, reason_codes: [...reasons].sort() });
  try { canonicalizeJson(input); } catch { reasons.add("grant_invalid"); return finish(); }
  if (!hasExactKeys(input, ["binding", "authenticated", "leaf_grant_ref", "grants", "observations", "run_links", "evaluation_time"])
    || !validBinding(input.binding) || !validAuthenticated(input.authenticated) || !validGrantRef(input.leaf_grant_ref)
    || !list(input.grants, validGrant, 16) || !list(input.observations, validObservation, 16)
    || !list(input.run_links, validRunLink, 16) || !isContractTimestamp(input.evaluation_time)) {
    reasons.add("grant_invalid"); return finish();
  }
  const { binding, authenticated: auth, evaluation_time: time } = input;
  actionDigest = digestActionBinding(binding);
  if (auth.verification_status !== "verified" || auth.principal.principal_type === "person"
    || !sameJson(auth.principal, binding.actor) || auth.run_id !== binding.run_id) reasons.add("identity_unverified");
  if (binding.actor.tenant_id !== binding.tenant_id || auth.principal.tenant_id !== binding.tenant_id) reasons.add("tenant_mismatch");
  if (!isWithinContractInterval(time, auth.observed_at, auth.valid_until)) reasons.add("precondition_stale");
  const grants = new Map(input.grants.map(grant => [grantKey(grant), grant]));
  if (grants.size !== input.grants.length) reasons.add("grant_invalid");
  const chain: AuthorityGrant[] = [], visited = new Set<string>();
  let next: GrantRef | undefined = input.leaf_grant_ref;
  while (next) {
    const key = grantKey(next), grant = grants.get(key);
    if (!grant || visited.has(key) || chain.length >= 16) { reasons.add("grant_invalid"); break; }
    chain.push(grant); visited.add(key); next = grant.parent_grant_ref;
  }
  if (chain.length === 0 || chain.length !== input.grants.length) reasons.add("grant_invalid");
  const leaf = chain[0], root = chain.at(-1);
  if (!leaf || !root) return finish();
  if (!sameJson(leaf.subject, binding.actor)) reasons.add("identity_unverified");
  if (!auth.trusted_issuers.some(issuer => sameJson(issuer, root.issuer))) reasons.add("identity_unverified");
  if (auth.mandate_kind === "person_directed" && !sameJson(root.issuer, auth.mandating_person)) reasons.add("identity_unverified");
  if (auth.mandate_kind === "workload" && root.issuer.principal_type === "person") reasons.add("identity_unverified");
  if (binding.action_risk.authority === "user_delegated" && auth.mandate_kind !== "person_directed") reasons.add("identity_unverified");
  grantRefs = chain.map(grant => ({ ...grant.verification_ref }));
  const expectedRefs = new Set(grantRefs.map(ref => canonicalizeJson(ref)));
  if (expectedRefs.size !== chain.length || binding.authority_refs.length !== expectedRefs.size
    || new Set(binding.authority_refs.map(ref => canonicalizeJson(ref))).size !== expectedRefs.size
    || binding.authority_refs.some(ref => !expectedRefs.has(canonicalizeJson(ref)))) reasons.add("grant_invalid");
  if (input.observations.length !== chain.length) reasons.add("grant_invalid");
  for (const grant of chain) {
    if (grant.subject.tenant_id !== binding.tenant_id || grant.issuer.tenant_id !== binding.tenant_id) reasons.add("tenant_mismatch");
    if (grant.audience !== auth.audience || grant.scope.root_run_id !== auth.root_run_id) reasons.add("scope_mismatch");
    if (!isWithinContractInterval(time, grant.not_before, grant.expires_at)) reasons.add("grant_expired");
    if (!inScope(binding, grant.scope)) reasons.add("scope_mismatch");
    const matches = input.observations.filter(observation => grantKey(observation) === grantKey(grant));
    const observation = matches[0];
    if (matches.length !== 1 || !observation) { reasons.add("verification_unavailable"); continue; }
    if (observation.verification_status !== "verified" || !sameJson(observation.verification_ref, grant.verification_ref)
      || observation.grant_digest !== sha256Canonical({ domain: "contextos.authority_grant.v1", grant })
      || observation.observer.tenant_id !== binding.tenant_id
      || !auth.trusted_observers.some(observer => sameJson(observer, observation.observer))) reasons.add("verification_unavailable");
    if (!isWithinContractInterval(time, observation.observed_at, observation.valid_until)) reasons.add("precondition_stale");
    if (observation.revocation_status === "revoked") reasons.add("grant_revoked");
    if (observation.revocation_status === "unknown") reasons.add("revocation_unknown");
  }
  for (let index = 0; index < chain.length - 1; index += 1) {
    const child = chain[index], parent = chain[index + 1];
    if (!sameJson(child.issuer, parent.subject) || child.audience !== parent.audience || !scopeNarrows(child.scope, parent.scope)
      || parent.delegation_depth_remaining === 0 || child.delegation_depth_remaining >= parent.delegation_depth_remaining
      || compareContractTimes(child.not_before, parent.not_before) === -1
      || compareContractTimes(child.expires_at, parent.expires_at) === 1) reasons.add("delegation_scope_expanded");
  }
  if (binding.run_id !== auth.root_run_id) {
    let run = binding.run_id, depth = 0;
    const seen = new Set<string>();
    while (run !== auth.root_run_id) {
      const matches = input.run_links.filter(link => link.child_run_id === run), link = matches[0];
      if (seen.has(run) || depth >= 16 || matches.length !== 1 || !link || depth >= chain.length - 1) {
        reasons.add("grant_invalid"); break;
      }
      seen.add(run);
      if (link.verification_status !== "verified" || !auth.trusted_observers.some(observer => sameJson(observer, link.observer))
        || link.observer.tenant_id !== binding.tenant_id || !sameJson(link.subject, chain[depth].subject)) reasons.add("verification_unavailable");
      if (link.tenant_id !== binding.tenant_id || link.root_run_id !== auth.root_run_id) reasons.add("tenant_mismatch");
      if (!isWithinContractInterval(time, link.observed_at, link.valid_until)) reasons.add("precondition_stale");
      run = link.parent_run_id; depth += 1;
    }
  }
  return finish();
}

export type AuthorizationVerdict = "allow" | "deny" | "require_approval" | "escalate" | "error";
export interface NormalizedPolicyOutcome {
  category: "guardrail" | "business";
  priority: number;
  verdict: AuthorizationVerdict;
  rule_id: string;
  bundle_ref: ArtifactRef;
  obligations: string[];
}
export interface ComposedPolicyOutcome {
  verdict: AuthorizationVerdict;
  reason_codes: string[];
  obligations: string[];
  policy_refs: ArtifactRef[];
  rule_ids: string[];
}
function validPolicyOutcome(value: unknown): value is NormalizedPolicyOutcome {
  return hasExactKeys(value, ["category", "priority", "verdict", "rule_id", "bundle_ref", "obligations"])
    && (value.category === "guardrail" || value.category === "business") && Number.isSafeInteger(value.priority)
    && ["allow", "deny", "require_approval", "escalate", "error"].includes(value.verdict as string)
    && isContractIdentifier(value.rule_id) && isArtifactRef(value.bundle_ref) && ids(value.obligations);
}

/** Compose normalized applicable results; DSL execution and authenticity are adapter obligations. */
export function composePolicyOutcomes(outcomes: NormalizedPolicyOutcome[]): ComposedPolicyOutcome {
  const error = (code: string): ComposedPolicyOutcome =>
    ({ verdict: "error", reason_codes: [code], obligations: [], policy_refs: [], rule_ids: [] });
  try { canonicalizeJson(outcomes); } catch { return error("policy_invalid"); }
  if (!list(outcomes, validPolicyOutcome)) return error("policy_invalid");
  const normalized = new Map<string, NormalizedPolicyOutcome>(), bundles = new Map<string, string>();
  for (const outcome of outcomes) {
    const ref = outcome.bundle_ref, bundleKey = JSON.stringify([ref.artifact_type, ref.artifact_id]);
    const encoded = canonicalizeJson(ref), key = JSON.stringify([bundleKey, outcome.rule_id]);
    if ((bundles.has(bundleKey) && bundles.get(bundleKey) !== encoded)
      || (normalized.has(key) && !sameJson(normalized.get(key), outcome))) return error("policy_outcome_conflict");
    bundles.set(bundleKey, encoded); normalized.set(key, outcome);
  }
  const all = [...normalized.values()], guardrails = all.filter(o => o.category === "guardrail");
  const business = all.filter(o => o.category === "business");
  const priority = business.length ? Math.max(...business.map(o => o.priority)) : undefined;
  const winning = business.filter(o => o.priority === priority);
  const obligations = [...new Set(all.flatMap(o => o.obligations))].sort();
  if (obligations.length > 128) return error("policy_invalid");
  let verdict: AuthorizationVerdict = "allow";
  const reasons: string[] = [];
  if (all.some(o => o.verdict === "error")) { verdict = "error"; reasons.push("policy_eval_error"); }
  else if (guardrails.some(o => o.verdict === "deny")) { verdict = "deny"; reasons.push("guardrail_denied"); }
  else if (!business.length || winning.some(o => o.verdict === "deny")) { verdict = "deny"; reasons.push("business_policy_denied"); }
  else if ([...guardrails, ...winning].some(o => o.verdict === "escalate")) { verdict = "escalate"; reasons.push("escalation_required"); }
  else if ([...guardrails, ...winning].some(o => o.verdict === "require_approval")) { verdict = "require_approval"; reasons.push("approval_required"); }
  return { verdict, reason_codes: reasons, obligations,
    policy_refs: [...new Map(all.map(o => [canonicalizeJson(o.bundle_ref), { ...o.bundle_ref }])).entries()]
      .sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0).map(([, ref]) => ref),
    rule_ids: [...new Set(all.map(o => o.rule_id))].sort() };
}

export interface StoredActionProposal {
  request_id: string; proposal_id: string; run_id: string; tenant_id: string; operation_id: string;
  action_digest: string; policy_refs: ArtifactRef[]; authority_refs: ArtifactRef[];
  not_before: string; expires_at: string;
}
export interface ApprovalRequestRecord extends StoredActionProposal {
  approval_request_id: string; requester: PrincipalRef; eligible_approvers: PrincipalRef[];
  eligible_approver_roles: string[]; required_approvals: number; prohibit_self_approval: boolean;
  verification_ref: ArtifactRef;
}
export interface ApprovalBinding extends StoredActionProposal {
  approval_id: string; approval_request_id: string; approver: PrincipalRef;
  decision: "approved" | "denied"; decided_at: string; verification_ref: ArtifactRef;
}
export interface ApprovalVerificationObservation {
  approval_id: string; decision_digest: string; verification_ref: ArtifactRef;
  verification_status: VerificationStatus; observer: PrincipalRef; observed_at: string; valid_until: string;
}
export interface ApproverEntitlementObservation {
  approver: PrincipalRef; role_id: string; approval_request_id: string; action_digest: string;
  observer: PrincipalRef; verification_status: VerificationStatus; verification_ref: ArtifactRef;
  observed_at: string; valid_until: string;
}
export interface ApprovalRedemptionState {
  approval_request_id: string; revision: number; operation_id: string | null; action_digest: string | null;
}
export interface ApprovalValidationInput {
  binding: ActionBinding; proposal: StoredActionProposal; request: ApprovalRequestRecord;
  decisions: ApprovalBinding[]; verification_observations: ApprovalVerificationObservation[];
  entitlements: ApproverEntitlementObservation[]; trusted_observers: PrincipalRef[];
  redemption_state: ApprovalRedemptionState; evaluation_time: string;
}
export interface ApprovalValidationResult { allowed: boolean; action_digest: string | null; approval_refs: ArtifactRef[]; reason_codes: string[] }
export interface ApprovalRedemptionInput { approval: ApprovalValidationInput; expected_revision: number }
export type ApprovalRedemptionResult = { expected_revision: number | null; permits_new_effect: false; reason_codes: string[] } & (
  | { status: "redeem" | "existing"; state: ApprovalRedemptionState }
  | { status: "rejected"; state: ApprovalRedemptionState | null });
/** Trusted admission supplies requirements; model-provided lists/verification flags are not authenticated facts. */
export interface ConstraintObservation {
  control: ControlRef; action_digest: string; policy_refs: ArtifactRef[]; verdict: "allow" | "deny" | "unknown";
  verification_status: VerificationStatus; verification_ref: ArtifactRef; observer: PrincipalRef;
  observed_at: string; valid_until: string;
}
export interface AuthorizationInput {
  decision_id: string; authority: AuthorityValidationInput; policy_outcomes: NormalizedPolicyOutcome[];
  approval: ApprovalValidationInput | null; required_constraints: ControlRef[]; constraint_observations: ConstraintObservation[];
}
export interface AuthorizationDecision {
  decision_id: string; contract_id: string; run_id: string; operation_id: string; action_digest: string | null;
  evaluation_time: string; policy_refs: ArtifactRef[]; grant_refs: ArtifactRef[]; approval_refs: ArtifactRef[];
  reason_codes: string[]; obligations: string[]; verdict: AuthorizationVerdict;
}
export type AuthorizationOutcome = { verdict: "allow"; decision: AuthorizationDecision }
  | { verdict: "deny" | "require_approval" | "escalate" | "error"; decision: AuthorizationDecision };

const PROPOSAL_KEYS = ["request_id", "proposal_id", "run_id", "tenant_id", "operation_id", "action_digest",
  "policy_refs", "authority_refs", "not_before", "expires_at"];
const digestString = (value: unknown): value is string => typeof value === "string" && /^sha256:[a-f0-9]{64}$/.test(value);
function proposalFields(value: Record<string, unknown>): boolean {
  return [value.request_id, value.proposal_id, value.run_id, value.tenant_id, value.operation_id].every(isContractIdentifier)
    && digestString(value.action_digest) && refs(value.policy_refs, 1) && refs(value.authority_refs, 1)
    && isContractTimestamp(value.not_before) && isContractTimestamp(value.expires_at);
}
function validProposal(value: unknown): value is StoredActionProposal {
  return hasExactKeys(value, PROPOSAL_KEYS) && proposalFields(value);
}
function validApprovalRequest(value: unknown): value is ApprovalRequestRecord {
  return hasExactKeys(value, [...PROPOSAL_KEYS, "approval_request_id", "requester", "eligible_approvers",
    "eligible_approver_roles", "required_approvals", "prohibit_self_approval", "verification_ref"])
    && proposalFields(value) && isContractIdentifier(value.approval_request_id) && validPrincipal(value.requester)
    && list(value.eligible_approvers, validPrincipal) && ids(value.eligible_approver_roles) && value.eligible_approver_roles.length > 0
    && safeInteger(value.required_approvals) && value.required_approvals > 0 && value.required_approvals <= 128
    && typeof value.prohibit_self_approval === "boolean" && isArtifactRef(value.verification_ref);
}
function validApproval(value: unknown): value is ApprovalBinding {
  return hasExactKeys(value, [...PROPOSAL_KEYS, "approval_id", "approval_request_id", "approver", "decision", "decided_at", "verification_ref"])
    && proposalFields(value) && isContractIdentifier(value.approval_id) && isContractIdentifier(value.approval_request_id)
    && validPrincipal(value.approver) && (value.decision === "approved" || value.decision === "denied")
    && isContractTimestamp(value.decided_at) && isArtifactRef(value.verification_ref);
}
function validApprovalObservation(value: unknown): value is ApprovalVerificationObservation {
  return hasExactKeys(value, ["approval_id", "decision_digest", "verification_ref", "verification_status", "observer", "observed_at", "valid_until"])
    && isContractIdentifier(value.approval_id) && digestString(value.decision_digest) && isArtifactRef(value.verification_ref)
    && verificationStatus(value.verification_status) && validPrincipal(value.observer)
    && isContractTimestamp(value.observed_at) && isContractTimestamp(value.valid_until);
}
function validEntitlement(value: unknown): value is ApproverEntitlementObservation {
  return hasExactKeys(value, ["approver", "role_id", "approval_request_id", "action_digest", "observer", "verification_status",
    "verification_ref", "observed_at", "valid_until"])
    && validPrincipal(value.approver) && isContractIdentifier(value.role_id) && isContractIdentifier(value.approval_request_id)
    && digestString(value.action_digest) && validPrincipal(value.observer) && verificationStatus(value.verification_status)
    && isArtifactRef(value.verification_ref) && isContractTimestamp(value.observed_at) && isContractTimestamp(value.valid_until);
}
function validRedemption(value: unknown): value is ApprovalRedemptionState {
  return hasExactKeys(value, ["approval_request_id", "revision", "operation_id", "action_digest"])
    && isContractIdentifier(value.approval_request_id) && safeInteger(value.revision)
    && ((value.operation_id === null && value.action_digest === null)
      || (isContractIdentifier(value.operation_id) && digestString(value.action_digest)));
}
function sameReferenceSet(left: unknown[], right: unknown[]): boolean {
  const l = new Set(left.map(ref => canonicalizeJson(ref))), r = new Set(right.map(ref => canonicalizeJson(ref)));
  return l.size === left.length && r.size === right.length && l.size === r.size && [...l].every(key => r.has(key));
}
function proposalMatches(record: StoredActionProposal, proposal: StoredActionProposal, binding: ActionBinding, digest: string): boolean {
  return record.request_id === proposal.request_id && record.proposal_id === binding.proposal_id
    && record.run_id === binding.run_id && record.tenant_id === binding.tenant_id && record.operation_id === binding.operation_id
    && record.action_digest === digest && sameReferenceSet(record.policy_refs, binding.policy_refs)
    && sameReferenceSet(record.authority_refs, binding.authority_refs);
}

/** Validates trusted stored records plus post-verification observations; performs no signature/store I/O. */
export function validateApprovalBinding(input: ApprovalValidationInput): ApprovalValidationResult {
  const reasons = new Set<string>(), approvalRefs: ArtifactRef[] = [];
  let digest: string | null = null;
  const finish = (): ApprovalValidationResult => ({ allowed: reasons.size === 0, action_digest: digest,
    approval_refs: approvalRefs, reason_codes: [...reasons].sort() });
  try { canonicalizeJson(input); } catch { reasons.add("approval_binding_mismatch"); return finish(); }
  if (!hasExactKeys(input, ["binding", "proposal", "request", "decisions", "verification_observations", "entitlements",
    "trusted_observers", "redemption_state", "evaluation_time"]) || !validBinding(input.binding)
    || !validProposal(input.proposal) || !validApprovalRequest(input.request) || !list(input.decisions, validApproval)
    || !list(input.verification_observations, validApprovalObservation) || !list(input.entitlements, validEntitlement)
    || !list(input.trusted_observers, validPrincipal) || !validRedemption(input.redemption_state)
    || !isContractTimestamp(input.evaluation_time)) { reasons.add("approval_binding_mismatch"); return finish(); }
  const { binding, proposal, request, redemption_state: state, evaluation_time: time } = input;
  digest = digestActionBinding(binding);
  for (const record of [proposal, request, ...input.decisions]) {
    if (!proposalMatches(record, proposal, binding, digest)) reasons.add("approval_binding_mismatch");
    if (!isWithinContractInterval(time, record.not_before, record.expires_at)) reasons.add("approval_expired");
  }
  if (compareContractTimes(request.not_before, proposal.not_before) === -1
    || compareContractTimes(request.expires_at, proposal.expires_at) === 1) reasons.add("approval_binding_mismatch");
  if (state.approval_request_id !== request.approval_request_id) reasons.add("approval_binding_mismatch");
  if (state.operation_id !== null && (state.operation_id !== binding.operation_id || state.action_digest !== digest)) reasons.add("approval_consumed");
  if (request.requester.tenant_id !== binding.tenant_id || request.eligible_approvers.some(p => p.tenant_id !== binding.tenant_id)) reasons.add("tenant_mismatch");
  const trusted = (observer: PrincipalRef) => observer.tenant_id === binding.tenant_id
    && input.trusted_observers.some(candidate => sameJson(candidate, observer));
  const distinct = new Set<string>(), approvalIds = new Set<string>();
  if (input.verification_observations.length !== input.decisions.length) reasons.add("verification_unavailable");
  for (const decision of input.decisions) {
    approvalRefs.push({ ...decision.verification_ref });
    const key = canonicalizeJson(decision.approver);
    if (distinct.has(key) || approvalIds.has(decision.approval_id)) reasons.add("approval_approver_duplicate");
    distinct.add(key); approvalIds.add(decision.approval_id);
    if (decision.approval_request_id !== request.approval_request_id || decision.approver.tenant_id !== binding.tenant_id
      || !request.eligible_approvers.some(candidate => sameJson(candidate, decision.approver))) reasons.add("approval_binding_mismatch");
    if (request.prohibit_self_approval && (sameJson(decision.approver, binding.actor)
      || sameJson(decision.approver, request.requester))) reasons.add("approval_self_denied");
    if (decision.decision !== "approved") reasons.add("approval_denied");
    if (!isWithinContractInterval(decision.decided_at, request.not_before, request.expires_at)
      || compareContractTimes(decision.decided_at, time) === 1
      || compareContractTimes(decision.not_before, request.not_before) === -1
      || compareContractTimes(decision.expires_at, request.expires_at) === 1) reasons.add("approval_binding_mismatch");
    const observations = input.verification_observations.filter(o => o.approval_id === decision.approval_id), observed = observations[0];
    if (observations.length !== 1 || !observed || observed.verification_status !== "verified" || !trusted(observed.observer)
      || !sameJson(observed.verification_ref, decision.verification_ref)
      || observed.decision_digest !== sha256Canonical({ domain: "contextos.approval_decision.v1", decision })) reasons.add("verification_unavailable");
    if (observed && (!isWithinContractInterval(time, observed.observed_at, observed.valid_until)
      || compareContractTimes(observed.observed_at, decision.decided_at) === -1)) reasons.add("precondition_stale");
    const entitled = input.entitlements.some(e => sameJson(e.approver, decision.approver)
      && e.approval_request_id === request.approval_request_id && e.action_digest === digest
      && request.eligible_approver_roles.includes(e.role_id) && e.verification_status === "verified" && trusted(e.observer)
      && isWithinContractInterval(time, e.observed_at, e.valid_until));
    if (!entitled) reasons.add("approval_entitlement_missing");
  }
  if (distinct.size < request.required_approvals) reasons.add("approval_required");
  return finish();
}

/** Intended CAS only. Neither an existing redemption nor this transition permits a new external effect. */
export function transitionApprovalRedemption(input: ApprovalRedemptionInput): ApprovalRedemptionResult {
  try { canonicalizeJson(input); } catch {
    return { status: "rejected", state: null, expected_revision: null, permits_new_effect: false, reason_codes: ["approval_binding_mismatch"] };
  }
  if (!hasExactKeys(input, ["approval", "expected_revision"]) || !safeInteger(input.expected_revision)) {
    return { status: "rejected", state: null, expected_revision: null, permits_new_effect: false, reason_codes: ["approval_binding_mismatch"] };
  }
  const validation = validateApprovalBinding(input.approval);
  const state = validRedemption(input.approval?.redemption_state) ? { ...input.approval.redemption_state } : null;
  const common = { expected_revision: input.expected_revision, permits_new_effect: false as const };
  if (!validation.allowed || !state) return { ...common, status: "rejected", state, reason_codes: validation.reason_codes };
  if (state.revision !== input.expected_revision) return { ...common, status: "rejected", state, reason_codes: ["approval_revision_conflict"] };
  if (state.operation_id) return { ...common, status: "existing", state, reason_codes: [] };
  if (!Number.isSafeInteger(state.revision + 1)) return { ...common, status: "rejected", state, reason_codes: ["approval_revision_conflict"] };
  return { ...common, status: "redeem", reason_codes: [], state: { ...state, revision: state.revision + 1,
    operation_id: input.approval.binding.operation_id, action_digest: validation.action_digest } };
}

function validConstraintObservation(value: unknown): value is ConstraintObservation {
  return hasExactKeys(value, ["control", "action_digest", "policy_refs", "verdict", "verification_status", "verification_ref",
    "observer", "observed_at", "valid_until"]) && isControlRef(value.control) && digestString(value.action_digest)
    && refs(value.policy_refs, 1) && ["allow", "deny", "unknown"].includes(value.verdict as string)
    && verificationStatus(value.verification_status) && isArtifactRef(value.verification_ref) && validPrincipal(value.observer)
    && isContractTimestamp(value.observed_at) && isContractTimestamp(value.valid_until);
}

/** Conjunctive reference decision over trusted normalized inputs, not a production dispatch service. */
export function evaluateAuthorization(input: AuthorizationInput): AuthorizationOutcome {
  const invalid = (): AuthorizationOutcome => ({ verdict: "error", decision: { decision_id: "invalid", contract_id: "invalid",
    run_id: "invalid", operation_id: "invalid", action_digest: null, evaluation_time: "invalid", policy_refs: [], grant_refs: [],
    approval_refs: [], reason_codes: ["authorization_invalid"], obligations: [], verdict: "error" } });
  try { canonicalizeJson(input); } catch { return invalid(); }
  if (!hasExactKeys(input, ["decision_id", "authority", "policy_outcomes", "approval", "required_constraints", "constraint_observations"])
    || !isContractIdentifier(input.decision_id) || !list(input.required_constraints, isControlRef)
    || !list(input.constraint_observations, validConstraintObservation)) return invalid();
  const authority = validateAuthority(input.authority), policy = composePolicyOutcomes(input.policy_outcomes);
  if (!authority.action_digest) return invalid();
  const { binding, authenticated, evaluation_time: time } = input.authority;
  const reasons = new Set([...authority.reason_codes, ...policy.reason_codes]);
  let verdict = policy.verdict;
  let approvalRefs: ArtifactRef[] = [];
  if (!authority.allowed) verdict = "deny";
  if (!sameReferenceSet(policy.policy_refs, binding.policy_refs)) { verdict = "error"; reasons.add("policy_binding_mismatch"); }
  const required = new Map<string, string>();
  for (const control of input.required_constraints) {
    if (required.has(control.control_id) && required.get(control.control_id) !== control.control_version) {
      reasons.add("constraint_conflict"); verdict = "deny";
    }
    required.set(control.control_id, control.control_version);
    const matches = input.constraint_observations.filter(o => sameJson(o.control, control)), observed = matches[0];
    if (matches.length !== 1 || !observed || observed.verdict !== "allow" || observed.verification_status !== "verified"
      || observed.action_digest !== authority.action_digest || !sameReferenceSet(observed.policy_refs, binding.policy_refs)
      || observed.observer.tenant_id !== binding.tenant_id
      || !authenticated.trusted_observers.some(observer => sameJson(observer, observed.observer))
      || !isWithinContractInterval(time, observed.observed_at, observed.valid_until)) {
      verdict = "deny"; reasons.add("required_constraint_failed");
    }
  }
  const needsApproval = policy.verdict === "require_approval" || binding.action_risk.authority === "human_approved";
  if (input.approval !== null) {
    const approval = validateApprovalBinding(input.approval);
    const selfApproval = approval.allowed && input.approval.request.prohibit_self_approval && authenticated.mandating_person
      && input.approval.decisions?.some(decision => sameJson(decision.approver, authenticated.mandating_person));
    if (!approval.allowed || approval.action_digest !== authority.action_digest
      || compareContractTimes(input.approval.evaluation_time, time) !== 0
      || !sameReferenceSet(input.approval.trusted_observers, authenticated.trusted_observers) || selfApproval) {
      verdict = "deny"; approval.reason_codes.forEach(code => reasons.add(code)); reasons.add("approval_binding_mismatch");
      if (selfApproval) reasons.add("approval_self_denied");
    } else {
      approvalRefs = approval.approval_refs;
      if (verdict === "require_approval" && authority.allowed) { verdict = "allow"; reasons.delete("approval_required"); }
    }
  } else if (needsApproval && verdict === "allow") { verdict = "require_approval"; reasons.add("approval_required"); }
  // Any independent failure stays blocking, including after an approval resolves the business gate.
  if (!authority.allowed || reasons.has("required_constraint_failed") || reasons.has("constraint_conflict")) verdict = "deny";
  const decision: AuthorizationDecision = { decision_id: input.decision_id, contract_id: binding.contract_id,
    run_id: binding.run_id, operation_id: binding.operation_id, action_digest: authority.action_digest, evaluation_time: time,
    policy_refs: policy.policy_refs, grant_refs: authority.grant_refs, approval_refs: approvalRefs,
    reason_codes: [...reasons].sort(), obligations: policy.obligations, verdict };
  return verdict === "allow" ? { verdict, decision } : { verdict, decision };
}
