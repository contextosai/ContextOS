import { canonicalizeJson, sha256Canonical } from "./canonical-json";
import { hasExactKeys, isArtifactRef, isContractIdentifier, isControlRef, isProfileSelection } from "./contract-validation";
import type { ArtifactRef, ControlRef, ProfileSelection, ControlDefinition, ProfileDefinition,
  ExecutionContractEnvelope, RuntimeSupportDeclaration, ProfileRegistrySnapshot, WorkflowFeatureSet,
  ContractNegotiationResult, ContractNegotiationReason, ContractNegotiationReasonCode } from "./execution-contract-types";

const FEATURES: readonly (keyof WorkflowFeatureSet)[] = ["arbitrary_code", "external_network", "persistent_memory",
  "external_effects", "delegation", "checkpoint_resume", "proactive_triggers", "sensitive_data"];
const order = (a: string, b: string) => a === b ? 0 : a < b ? -1 : 1;
const controlKey = (ref: ControlRef) => `${ref.control_id}@${ref.control_version}`;
const profileKey = (ref: ProfileSelection) => `${ref.profile_id}@${ref.profile_version}`;
// Tuple keys cannot collide when an identifier itself contains '@'.
const exactControlKey = (ref: ControlRef) => JSON.stringify([ref.control_id, ref.control_version]);
const exactProfileKey = (ref: ProfileSelection) => JSON.stringify([ref.profile_id, ref.profile_version]);
const boundedArray = <T>(value: unknown, guard: (entry: unknown) => entry is T, max: number, min = 0): value is T[] =>
  Array.isArray(value) && value.length >= min && value.length <= max && value.every(guard);
const identifiers = (value: unknown): value is string[] => boundedArray(value, isContractIdentifier, 128, 1);

function validContract(value: unknown): value is ExecutionContractEnvelope {
  return hasExactKeys(value, ["envelope_version", "contract_id", "run_id", "trace_id", "tenant_id", "profiles",
    "required_controls", "optional_controls", "release_refs"])
    && value.envelope_version === "contextos.execution_contract.v1"
    && [value.contract_id, value.run_id, value.trace_id, value.tenant_id].every(isContractIdentifier)
    && boundedArray(value.profiles, isProfileSelection, 16, 1)
    && boundedArray(value.required_controls, isControlRef, 128)
    && boundedArray(value.optional_controls, isControlRef, 128)
    && boundedArray(value.release_refs, isArtifactRef, 128);
}
function validSupport(value: unknown): value is RuntimeSupportDeclaration {
  return hasExactKeys(value, ["implementation_id", "implementation_version", "supported_profiles", "supported_controls"])
    && isContractIdentifier(value.implementation_id) && isContractIdentifier(value.implementation_version)
    && boundedArray(value.supported_profiles, isProfileSelection, 128)
    && boundedArray(value.supported_controls, isControlRef, 128);
}
function validControl(value: unknown): value is ControlDefinition {
  return hasExactKeys(value, ["control", "definition_ref", "evidence_obligations", "positive_cases", "negative_cases"])
    && isControlRef(value.control) && isArtifactRef(value.definition_ref)
    && identifiers(value.evidence_obligations) && identifiers(value.positive_cases) && identifiers(value.negative_cases);
}
function validProfile(value: unknown): value is ProfileDefinition {
  return hasExactKeys(value, ["profile", "includes", "mandatory_controls", "conditional_controls", "definition_ref"])
    && isProfileSelection(value.profile) && isArtifactRef(value.definition_ref)
    && boundedArray(value.includes, isProfileSelection, 16)
    && boundedArray(value.mandatory_controls, isControlRef, 128)
    && boundedArray(value.conditional_controls, (condition): condition is ProfileDefinition["conditional_controls"][number] =>
      hasExactKeys(condition, ["feature", "equals", "control"])
      && FEATURES.includes(condition.feature as keyof WorkflowFeatureSet)
      && typeof condition.equals === "boolean" && isControlRef(condition.control), 128);
}
function validRegistry(value: unknown): value is ProfileRegistrySnapshot {
  return hasExactKeys(value, ["registry_ref", "profiles", "controls"]) && isArtifactRef(value.registry_ref)
    && boundedArray(value.profiles, validProfile, 128, 1) && boundedArray(value.controls, validControl, 128, 1);
}
function unionExactRefs(...groups: ControlRef[][]): ControlRef[] {
  return [...new Map(groups.flat().map(ref => [exactControlKey(ref), { ...ref }])).values()]
    .sort((a, b) => order(a.control_id, b.control_id) || order(a.control_version, b.control_version));
}
function hasExactSupport(support: RuntimeSupportDeclaration, ref: ControlRef): boolean {
  return support.supported_controls.some(item => item.control_id === ref.control_id && item.control_version === ref.control_version);
}

/** Pure compatibility negotiation. Callers authenticate the registry and derive features at admission. */
export function negotiateExecutionContract(contract: ExecutionContractEnvelope, support: RuntimeSupportDeclaration,
  registry: ProfileRegistrySnapshot, features: WorkflowFeatureSet): ContractNegotiationResult {
  const reasons: ContractNegotiationReason[] = [];
  const reason = (code: ContractNegotiationReasonCode, identifier: string) => { reasons.push({ code, identifier }); };
  const result: Omit<ContractNegotiationResult, "status"> = { contract_id: "invalid", registry_ref: null,
    feature_set_digest: null, selected_profiles: [], effective_required_controls: [], supported_controls: [],
    unsupported_optional: [], reasons: [] };
  const finish = (): ContractNegotiationResult => {
    result.reasons = [...new Map(reasons.map(r => [JSON.stringify([r.code, r.identifier]), r])).values()]
      .sort((a, b) => order(a.code, b.code) || order(a.identifier, b.identifier));
    return { ...result, status: result.reasons.length ? "rejected" : "accepted" };
  };
  // Reject accessors, proxies, hidden fields and traversal exhaustion before reading input properties.
  for (const [name, input] of [["contract", contract], ["support", support], ["registry", registry], ["features", features]] as const) {
    try { canonicalizeJson(input); } catch { reason(name === "features" ? "feature_state_invalid" : "invalid_contract", name); }
  }
  if (reasons.length) return finish();
  if (!validContract(contract)) reason("invalid_contract", "contract");
  if (!validSupport(support)) reason("invalid_contract", "support");
  if (!validRegistry(registry)) reason("invalid_contract", "registry");
  if (!hasExactKeys(features, FEATURES) || FEATURES.some(key => typeof features[key] !== "boolean")) {
    reason("feature_state_invalid", "features");
  }
  if (reasons.length) return finish();
  result.contract_id = contract.contract_id;
  result.registry_ref = { ...registry.registry_ref };
  result.feature_set_digest = sha256Canonical({ domain: "contextos.workflow_features.v1", payload: features });
  result.selected_profiles = [...new Map(contract.profiles.map(p => [exactProfileKey(p), { ...p }])).values()]
    .sort((a, b) => order(a.profile_id, b.profile_id) || order(a.profile_version, b.profile_version));

  const conflicts = <T>(refs: T[], id: (ref: T) => string, version: (ref: T) => string): void => {
    const seen = new Map<string, string>();
    for (const ref of refs) {
      if (seen.has(id(ref)) && seen.get(id(ref)) !== version(ref)) reason("conflicting_reference", id(ref));
      seen.set(id(ref), version(ref));
    }
  };
  conflicts(contract.profiles, p => p.profile_id, p => p.profile_version);
  conflicts(support.supported_profiles, p => p.profile_id, p => p.profile_version);
  conflicts(support.supported_controls, c => c.control_id, c => c.control_version);
  const releases = new Map<string, string>();
  for (const ref of contract.release_refs) {
    const key = JSON.stringify([ref.artifact_type, ref.artifact_id]), encoded = canonicalizeJson(ref);
    if (releases.has(key) && releases.get(key) !== encoded) reason("conflicting_reference", ref.artifact_id);
    releases.set(key, encoded);
  }
  const integrity = (ref: ArtifactRef, type: string, id: string, version: string, domain: string, payload: unknown): void => {
    if (ref.artifact_type !== type || ref.artifact_id !== id || ref.version !== version
      || ref.sha256 !== sha256Canonical({ domain, payload })) reason("artifact_binding_invalid", id);
  };
  const controls = new Map<string, ControlDefinition>(), profiles = new Map<string, ProfileDefinition>();
  for (const definition of registry.controls) {
    const { definition_ref, ...payload } = definition, ref = definition.control, key = exactControlKey(ref);
    integrity(definition_ref, "control_definition", ref.control_id, ref.control_version, "contextos.control_definition.v1", payload);
    if (controls.has(key) && canonicalizeJson(controls.get(key)) !== canonicalizeJson(definition)) reason("conflicting_reference", controlKey(ref));
    controls.set(key, definition);
  }
  for (const definition of registry.profiles) {
    const { definition_ref, ...payload } = definition, ref = definition.profile, key = exactProfileKey(ref);
    integrity(definition_ref, "profile_definition", ref.profile_id, ref.profile_version, "contextos.profile_definition.v1", payload);
    if (profiles.has(key) && canonicalizeJson(profiles.get(key)) !== canonicalizeJson(definition)) reason("conflicting_reference", profileKey(ref));
    profiles.set(key, definition);
  }
  const { registry_ref, ...registryPayload } = registry;
  integrity(registry_ref, "profile_registry", registry_ref.artifact_id, registry_ref.version,
    "contextos.profile_registry.v1", registryPayload);
  const resolveProfile = (ref: ProfileSelection): ProfileDefinition | undefined => {
    const definition = profiles.get(exactProfileKey(ref));
    if (!definition) reason(registry.profiles.some(p => p.profile.profile_id === ref.profile_id)
      ? "profile_version_unsupported" : "profile_unknown", profileKey(ref));
    return definition;
  };
  const resolveControl = (ref: ControlRef): void => {
    if (!controls.has(exactControlKey(ref))) reason(registry.controls.some(c => c.control.control_id === ref.control_id)
      ? "control_version_unsupported" : "control_unknown", controlKey(ref));
  };
  // Memoized expansion bounds work by registry nodes/edges, even for highly shared include graphs.
  const expandedProfiles = new Map<string, { height: number; controls: ControlRef[]; profiles: ProfileSelection[] }>();
  const visiting = new Set<string>();
  const expand = (ref: ProfileSelection): { height: number; controls: ControlRef[]; profiles: ProfileSelection[] } => {
    const key = exactProfileKey(ref);
    const cached = expandedProfiles.get(key);
    if (cached) return cached;
    const empty = { height: 0, controls: [], profiles: [] };
    if (visiting.has(key) || visiting.size >= 8) { reason("registry_expansion_invalid", profileKey(ref)); return empty; }
    const definition = resolveProfile(ref);
    if (!definition) return empty;
    visiting.add(key);
    let required = [...definition.mandatory_controls], height = 1;
    let reachedProfiles = [ref];
    for (const control of definition.mandatory_controls) resolveControl(control);
    for (const condition of definition.conditional_controls) {
      resolveControl(condition.control);
      if (features[condition.feature] === condition.equals) required.push(condition.control);
    }
    for (const included of definition.includes) {
      const child = expand(included);
      height = Math.max(height, child.height + 1);
      required = unionExactRefs(required, child.controls);
      reachedProfiles = [...new Map([...reachedProfiles, ...child.profiles].map(p => [exactProfileKey(p), p])).values()];
    }
    visiting.delete(key);
    if (height > 8) reason("registry_expansion_invalid", profileKey(ref));
    const expanded = { height, controls: unionExactRefs(required), profiles: reachedProfiles };
    expandedProfiles.set(key, expanded);
    return expanded;
  };
  // Check relationships in inactive registry branches as well as selected profiles.
  for (const definition of registry.profiles) expand(definition.profile);
  if (reasons.length) return finish();
  const expanded: ControlRef[] = [];
  const reachedProfiles: ProfileSelection[] = [];
  for (const ref of result.selected_profiles) {
    const resolved = expand(ref);
    expanded.push(...resolved.controls);
    reachedProfiles.push(...resolved.profiles);
    if (!support.supported_profiles.some(p => p.profile_id === ref.profile_id && p.profile_version === ref.profile_version)) {
      reason("profile_version_unsupported", profileKey(ref));
    }
  }
  conflicts(reachedProfiles, p => p.profile_id, p => p.profile_version);
  result.effective_required_controls = unionExactRefs(expanded, contract.required_controls);
  if (result.effective_required_controls.length > 128) reason("registry_expansion_invalid", "effective_controls");
  conflicts([...result.effective_required_controls, ...contract.optional_controls], c => c.control_id, c => c.control_version);
  for (const ref of result.effective_required_controls) {
    resolveControl(ref);
    if (!hasExactSupport(support, ref)) reason("required_control_unsupported", controlKey(ref));
  }
  result.supported_controls = unionExactRefs(result.effective_required_controls, contract.optional_controls)
    .filter(ref => controls.has(exactControlKey(ref)) && hasExactSupport(support, ref));
  result.unsupported_optional = unionExactRefs(contract.optional_controls)
    .filter(ref => !controls.has(exactControlKey(ref)) || !hasExactSupport(support, ref));
  return finish();
}
