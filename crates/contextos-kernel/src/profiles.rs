//! The standard immutable profile registry (`contextos.standard`, version 1).
//!
//! Profiles are exact obligation sets. Selecting one neither authenticates admission
//! facts nor activates enforcement, and a profile name is not a certification.

use std::sync::LazyLock;

use contextos_contract::canonical::domain_digest;
use contextos_contract::execution::{
    ArtifactRef, ConditionalControlRequirement, ControlDefinition, ControlRef, ProfileDefinition,
    ProfileRegistrySnapshot, ProfileSelection, WorkflowFeature,
};
use serde_json::json;

pub const CONTROL_DEFINITION_DOMAIN: &str = "contextos.control_definition.v1";
pub const PROFILE_DEFINITION_DOMAIN: &str = "contextos.profile_definition.v1";
pub const PROFILE_REGISTRY_DOMAIN: &str = "contextos.profile_registry.v1";

/// Control id and its evidence obligations.
const EVIDENCE: &[(&str, &[&str])] = &[
    (
        "identity.authenticated",
        &["Verified principal, workload, trust-domain and tenant binding; reject spoofed or mismatched identity."],
    ),
    (
        "authority.scoped",
        &[
            "Current purpose, capability, resource, argument and destination mandate; intersect every delegation ancestor.",
        ],
    ),
    (
        "authority.revocation",
        &[
            "Bounded-freshness revocation observations from trusted brokers; unknown or unavailable required authority blocks.",
        ],
    ),
    (
        "policy.fail_visible",
        &[
            "Structured non-success for applicable evaluation errors; explicit business priority and independent guardrail composition.",
        ],
    ),
    (
        "approval.bound",
        &[
            "Exact stored proposal, action and request binding, expiry, eligible approvers, quorum and controlled redemption.",
            "Policy may permit a standing grant without a per-action click; any required approval still binds exactly.",
        ],
    ),
    (
        "context.integrity",
        &[
            "Pinned artifact provenance and integrity; untrusted retrieved, tool and message content cannot become trusted instructions.",
        ],
    ),
    (
        "isolation.required",
        &[
            "Current verified active boundary appropriate to enabled execution, filesystem, process, resource and trust-domain requirements.",
        ],
    ),
    (
        "credentials.brokered",
        &[
            "Scoped credentials issued and revoked by a trusted broker outside model-visible state; evidence of actual runtime mediation.",
        ],
    ),
    (
        "network.mediated",
        &[
            "Enforced destination, DNS resolution and redirect restrictions independent of business authority; denied egress evidence.",
        ],
    ),
    (
        "data.flow_policy",
        &[
            "Purpose, classification, actual recipient, processor and residency checks across inference, tools, telemetry and other flow stages.",
        ],
    ),
    (
        "memory.lifecycle",
        &[
            "Owned namespace, source provenance, governed promotion, retention and correction/deletion propagation receipts with external-copy limits.",
        ],
    ),
    (
        "effects.reconciled",
        &[
            "Stable operation identity, provider-specific retry safety and recorded confirmed, partial, not-applied or unknown outcomes.",
        ],
    ),
    (
        "execution.checkpointed",
        &[
            "Verified artifact pins and current authority/budget checks on resume; bounded recovery, executor ownership and target fencing limitations.",
        ],
    ),
    (
        "delegation.attenuated",
        &[
            "Child identities, authority intersection and output boundaries; ancestor revocation and cancellation propagation evidence.",
        ],
    ),
    (
        "budget.aggregate",
        &[
            "Parent/root/child/retry/replan accounting, exact cost units, bounded reservations, verified settlement and inherited absolute deadline.",
        ],
    ),
    (
        "audit.correlated",
        &[
            "Run, trace, operation, decision and control evidence correlation with minimization, retention and restricted access.",
        ],
    ),
    (
        "release.pinned",
        &[
            "Versioned evaluated artifact set, admitted extensions, protected changes, rollback limits and release-specific evidence.",
        ],
    ),
    (
        "operations.stop_recover",
        &[
            "Owned stop, escalation and reconciliation paths; tested dependency failure behavior, cancellation and recovery drills.",
        ],
    ),
    (
        "governance.separation",
        &[
            "Independent approver and control roles; protected policy and release administration where the workflow requires separation.",
        ],
    ),
    (
        "assurance.fault_evidence",
        &[
            "Authorized fault and abuse tests, observed recovery results and a release/environment/workflow-specific assurance argument.",
        ],
    ),
];

/// Workflow feature → controls it requires when enabled.
const CONDITIONAL: &[(WorkflowFeature, &[&str])] = &[
    (WorkflowFeature::ExternalNetwork, &["network.mediated"]),
    (WorkflowFeature::PersistentMemory, &["memory.lifecycle"]),
    (
        WorkflowFeature::ExternalEffects,
        &["effects.reconciled", "approval.bound"],
    ),
    (
        WorkflowFeature::Delegation,
        &["delegation.attenuated", "budget.aggregate"],
    ),
    (WorkflowFeature::CheckpointResume, &["execution.checkpointed"]),
    (WorkflowFeature::ArbitraryCode, &["isolation.required"]),
    (WorkflowFeature::SensitiveData, &["data.flow_policy"]),
    (
        WorkflowFeature::ProactiveTriggers,
        &[
            "authority.revocation",
            "approval.bound",
            "budget.aggregate",
            "operations.stop_recover",
        ],
    ),
];

/// Profile id → mandatory controls.
const MANDATORY: &[(&str, &[&str])] = &[
    (
        "contextos.core",
        &[
            "identity.authenticated",
            "authority.scoped",
            "policy.fail_visible",
            "context.integrity",
            "audit.correlated",
        ],
    ),
    (
        "contextos.personal-proactive",
        &[
            "authority.revocation",
            "approval.bound",
            "isolation.required",
            "credentials.brokered",
            "data.flow_policy",
            "budget.aggregate",
            "operations.stop_recover",
        ],
    ),
    (
        "contextos.enterprise",
        &[
            "authority.revocation",
            "approval.bound",
            "isolation.required",
            "credentials.brokered",
            "data.flow_policy",
            "budget.aggregate",
            "release.pinned",
            "governance.separation",
            "operations.stop_recover",
        ],
    ),
    (
        "contextos.durable-delegated",
        &[
            "authority.revocation",
            "approval.bound",
            "isolation.required",
            "effects.reconciled",
            "execution.checkpointed",
            "delegation.attenuated",
            "budget.aggregate",
            "operations.stop_recover",
        ],
    ),
    ("contextos.high-assurance", &["assurance.fault_evidence"]),
];

fn control(id: &str) -> ControlRef {
    ControlRef::new(id, "1")
}

fn profile(id: &str) -> ProfileSelection {
    ProfileSelection::new(id, "1")
}

fn artifact(artifact_type: &str, artifact_id: &str, domain: &str, payload: &serde_json::Value) -> ArtifactRef {
    ArtifactRef {
        artifact_type: artifact_type.into(),
        artifact_id: artifact_id.into(),
        version: "1".into(),
        sha256: domain_digest(domain, payload).expect("static registry payloads are canonical JSON"),
    }
}

fn build() -> ProfileRegistrySnapshot {
    let controls: Vec<ControlDefinition> = EVIDENCE
        .iter()
        .map(|(id, obligations)| {
            let obligations: Vec<String> = obligations.iter().map(|s| (*s).to_owned()).collect();
            let positive = vec![format!("{id}.useful")];
            let negative = vec![format!("{id}.denied")];
            let payload = json!({
                "control": control(id),
                "evidence_obligations": obligations,
                "positive_cases": positive,
                "negative_cases": negative,
            });
            ControlDefinition {
                control: control(id),
                definition_ref: artifact("control_definition", id, CONTROL_DEFINITION_DOMAIN, &payload),
                evidence_obligations: obligations,
                positive_cases: positive,
                negative_cases: negative,
            }
        })
        .collect();
    let conditional: Vec<ConditionalControlRequirement> = CONDITIONAL
        .iter()
        .flat_map(|(feature, ids)| {
            ids.iter().map(|id| ConditionalControlRequirement {
                feature: *feature,
                equals: true,
                control: control(id),
            })
        })
        .collect();
    let profiles: Vec<ProfileDefinition> = MANDATORY
        .iter()
        .map(|(id, required)| {
            let includes = match *id {
                "contextos.core" => vec![],
                "contextos.high-assurance" => vec![
                    profile("contextos.core"),
                    profile("contextos.enterprise"),
                    profile("contextos.durable-delegated"),
                ],
                _ => vec![profile("contextos.core")],
            };
            let mandatory: Vec<ControlRef> = required.iter().map(|c| control(c)).collect();
            let payload = json!({
                "profile": profile(id),
                "includes": includes,
                "mandatory_controls": mandatory,
                "conditional_controls": conditional,
            });
            ProfileDefinition {
                profile: profile(id),
                includes,
                mandatory_controls: mandatory,
                conditional_controls: conditional.clone(),
                definition_ref: artifact("profile_definition", id, PROFILE_DEFINITION_DOMAIN, &payload),
            }
        })
        .collect();
    let registry_payload = json!({ "profiles": profiles, "controls": controls });
    ProfileRegistrySnapshot {
        registry_ref: artifact(
            "profile_registry",
            "contextos.standard",
            PROFILE_REGISTRY_DOMAIN,
            &registry_payload,
        ),
        profiles,
        controls,
    }
}

/// The standard registry, built once with content-addressed definition refs.
pub static STANDARD_PROFILE_REGISTRY: LazyLock<ProfileRegistrySnapshot> = LazyLock::new(build);
