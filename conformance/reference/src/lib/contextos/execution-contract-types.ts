export interface ControlRef { control_id: string; control_version: string }
export interface ArtifactRef { artifact_type: string; artifact_id: string; version: string; sha256: string }
export interface ProfileSelection { profile_id: string; profile_version: string }
export interface WorkflowFeatureSet {
  arbitrary_code: boolean;
  external_network: boolean;
  persistent_memory: boolean;
  external_effects: boolean;
  delegation: boolean;
  checkpoint_resume: boolean;
  proactive_triggers: boolean;
  sensitive_data: boolean;
}
export interface ConditionalControlRequirement {
  feature: keyof WorkflowFeatureSet;
  equals: boolean;
  control: ControlRef;
}
export interface ControlDefinition {
  control: ControlRef;
  definition_ref: ArtifactRef;
  evidence_obligations: string[];
  positive_cases: string[];
  negative_cases: string[];
}
export interface ProfileDefinition {
  profile: ProfileSelection;
  includes: ProfileSelection[];
  mandatory_controls: ControlRef[];
  conditional_controls: ConditionalControlRequirement[];
  definition_ref: ArtifactRef;
}
export interface ProfileRegistrySnapshot {
  registry_ref: ArtifactRef;
  profiles: ProfileDefinition[];
  controls: ControlDefinition[];
}
export interface ExecutionContractEnvelope {
  envelope_version: "contextos.execution_contract.v1";
  contract_id: string;
  run_id: string;
  trace_id: string;
  tenant_id: string;
  profiles: ProfileSelection[];
  required_controls: ControlRef[];
  optional_controls: ControlRef[];
  release_refs: ArtifactRef[];
}
export interface RuntimeSupportDeclaration {
  implementation_id: string;
  implementation_version: string;
  supported_profiles: ProfileSelection[];
  supported_controls: ControlRef[];
}
export type ContractNegotiationReasonCode = "invalid_contract" | "feature_state_invalid"
  | "profile_unknown" | "profile_version_unsupported" | "control_unknown"
  | "control_version_unsupported" | "required_control_unsupported" | "conflicting_reference"
  | "artifact_binding_invalid" | "registry_expansion_invalid";
export interface ContractNegotiationReason { code: ContractNegotiationReasonCode; identifier: string }
interface NegotiationDetail {
  contract_id: string;
  registry_ref: ArtifactRef | null;
  feature_set_digest: string | null;
  selected_profiles: ProfileSelection[];
  effective_required_controls: ControlRef[];
  supported_controls: ControlRef[];
  unsupported_optional: ControlRef[];
  reasons: ContractNegotiationReason[];
}
/** Compatibility evidence only. Neither status grants execution authority. */
export type ContractNegotiationResult = NegotiationDetail & ({ status: "accepted" } | { status: "rejected" });
