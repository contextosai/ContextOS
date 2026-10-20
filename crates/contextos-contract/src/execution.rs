//! Additive execution-contract types (`execution-contract.v1.schema.json`).
//!
//! The envelope is externally bound to an invocation; it is not an implicit field of
//! the legacy `RunContext`. Profile support and negotiation are compatibility evidence
//! only and never grant execution authority.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ControlRef {
    pub control_id: String,
    pub control_version: String,
}

impl ControlRef {
    pub fn new(id: &str, version: &str) -> Self {
        Self {
            control_id: id.into(),
            control_version: version.into(),
        }
    }

    /// `id@version`, used in reason identifiers.
    pub fn key(&self) -> String {
        format!("{}@{}", self.control_id, self.control_version)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ArtifactRef {
    pub artifact_type: String,
    pub artifact_id: String,
    pub version: String,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ProfileSelection {
    pub profile_id: String,
    pub profile_version: String,
}

impl ProfileSelection {
    pub fn new(id: &str, version: &str) -> Self {
        Self {
            profile_id: id.into(),
            profile_version: version.into(),
        }
    }

    pub fn key(&self) -> String {
        format!("{}@{}", self.profile_id, self.profile_version)
    }
}

/// Workflow features that conditionally require controls.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkflowFeature {
    ArbitraryCode,
    ExternalNetwork,
    PersistentMemory,
    ExternalEffects,
    Delegation,
    CheckpointResume,
    ProactiveTriggers,
    SensitiveData,
}

impl WorkflowFeature {
    pub const ALL: [WorkflowFeature; 8] = [
        WorkflowFeature::ArbitraryCode,
        WorkflowFeature::ExternalNetwork,
        WorkflowFeature::PersistentMemory,
        WorkflowFeature::ExternalEffects,
        WorkflowFeature::Delegation,
        WorkflowFeature::CheckpointResume,
        WorkflowFeature::ProactiveTriggers,
        WorkflowFeature::SensitiveData,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            WorkflowFeature::ArbitraryCode => "arbitrary_code",
            WorkflowFeature::ExternalNetwork => "external_network",
            WorkflowFeature::PersistentMemory => "persistent_memory",
            WorkflowFeature::ExternalEffects => "external_effects",
            WorkflowFeature::Delegation => "delegation",
            WorkflowFeature::CheckpointResume => "checkpoint_resume",
            WorkflowFeature::ProactiveTriggers => "proactive_triggers",
            WorkflowFeature::SensitiveData => "sensitive_data",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct WorkflowFeatureSet {
    pub arbitrary_code: bool,
    pub external_network: bool,
    pub persistent_memory: bool,
    pub external_effects: bool,
    pub delegation: bool,
    pub checkpoint_resume: bool,
    pub proactive_triggers: bool,
    pub sensitive_data: bool,
}

impl WorkflowFeatureSet {
    pub fn get(&self, feature: WorkflowFeature) -> bool {
        match feature {
            WorkflowFeature::ArbitraryCode => self.arbitrary_code,
            WorkflowFeature::ExternalNetwork => self.external_network,
            WorkflowFeature::PersistentMemory => self.persistent_memory,
            WorkflowFeature::ExternalEffects => self.external_effects,
            WorkflowFeature::Delegation => self.delegation,
            WorkflowFeature::CheckpointResume => self.checkpoint_resume,
            WorkflowFeature::ProactiveTriggers => self.proactive_triggers,
            WorkflowFeature::SensitiveData => self.sensitive_data,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConditionalControlRequirement {
    pub feature: WorkflowFeature,
    pub equals: bool,
    pub control: ControlRef,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlDefinition {
    pub control: ControlRef,
    pub definition_ref: ArtifactRef,
    pub evidence_obligations: Vec<String>,
    pub positive_cases: Vec<String>,
    pub negative_cases: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileDefinition {
    pub profile: ProfileSelection,
    pub includes: Vec<ProfileSelection>,
    pub mandatory_controls: Vec<ControlRef>,
    pub conditional_controls: Vec<ConditionalControlRequirement>,
    pub definition_ref: ArtifactRef,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileRegistrySnapshot {
    pub registry_ref: ArtifactRef,
    pub profiles: Vec<ProfileDefinition>,
    pub controls: Vec<ControlDefinition>,
}

pub const EXECUTION_CONTRACT_VERSION: &str = "contextos.execution_contract.v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionContractEnvelope {
    pub envelope_version: String,
    pub contract_id: String,
    pub run_id: String,
    pub trace_id: String,
    pub tenant_id: String,
    pub profiles: Vec<ProfileSelection>,
    pub required_controls: Vec<ControlRef>,
    pub optional_controls: Vec<ControlRef>,
    pub release_refs: Vec<ArtifactRef>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeSupportDeclaration {
    pub implementation_id: String,
    pub implementation_version: String,
    pub supported_profiles: Vec<ProfileSelection>,
    pub supported_controls: Vec<ControlRef>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContractNegotiationReasonCode {
    InvalidContract,
    FeatureStateInvalid,
    ProfileUnknown,
    ProfileVersionUnsupported,
    ControlUnknown,
    ControlVersionUnsupported,
    RequiredControlUnsupported,
    ConflictingReference,
    ArtifactBindingInvalid,
    RegistryExpansionInvalid,
}

impl ContractNegotiationReasonCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidContract => "invalid_contract",
            Self::FeatureStateInvalid => "feature_state_invalid",
            Self::ProfileUnknown => "profile_unknown",
            Self::ProfileVersionUnsupported => "profile_version_unsupported",
            Self::ControlUnknown => "control_unknown",
            Self::ControlVersionUnsupported => "control_version_unsupported",
            Self::RequiredControlUnsupported => "required_control_unsupported",
            Self::ConflictingReference => "conflicting_reference",
            Self::ArtifactBindingInvalid => "artifact_binding_invalid",
            Self::RegistryExpansionInvalid => "registry_expansion_invalid",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ContractNegotiationReason {
    pub code: ContractNegotiationReasonCode,
    pub identifier: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NegotiationStatus {
    Accepted,
    Rejected,
}

/// Compatibility evidence only. Neither status grants execution authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractNegotiationResult {
    pub contract_id: String,
    pub registry_ref: Option<ArtifactRef>,
    pub feature_set_digest: Option<String>,
    pub selected_profiles: Vec<ProfileSelection>,
    pub effective_required_controls: Vec<ControlRef>,
    pub supported_controls: Vec<ControlRef>,
    pub unsupported_optional: Vec<ControlRef>,
    pub reasons: Vec<ContractNegotiationReason>,
    pub status: NegotiationStatus,
}
