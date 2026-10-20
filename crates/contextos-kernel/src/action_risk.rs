//! Native multidimensional action risk and its lossy v1 approval-mode projection.
//!
//! Dimensions are evaluated independently and conjunctively; they are never collapsed
//! into a score. The approval-mode projection exists only for v1 compatibility.

use contextos_contract::types::{
    ActionAuthority, ActionEffect, ActionInteraction, ActionReversibility, ActionRisk, ActionRiskEvaluation,
    ActionRiskPolicy, ActionRiskViolation, AllowDeny, ApprovalMode,
};
use serde_json::Value;

fn effect_projection(effect: ActionEffect) -> ApprovalMode {
    match effect {
        ActionEffect::None => ApprovalMode::ReadOnly,
        ActionEffect::LocalState => ApprovalMode::LocalWrite,
        ActionEffect::ExternalState => ApprovalMode::Network,
        ActionEffect::PhysicalWorld => ApprovalMode::Destructive,
    }
}

fn authority_projection(authority: ActionAuthority) -> ApprovalMode {
    match authority {
        ActionAuthority::Agent | ActionAuthority::Service => ApprovalMode::ReadOnly,
        ActionAuthority::UserDelegated => ApprovalMode::Delegated,
        ActionAuthority::HumanApproved => ApprovalMode::Destructive,
    }
}

fn reversibility_projection(reversibility: ActionReversibility) -> ApprovalMode {
    match reversibility {
        ActionReversibility::ReadOnly => ApprovalMode::ReadOnly,
        ActionReversibility::Reversible => ApprovalMode::LocalWrite,
        ActionReversibility::Compensatable => ApprovalMode::Network,
        ActionReversibility::Irreversible => ApprovalMode::Destructive,
    }
}

fn interaction_projection(interaction: ActionInteraction) -> ApprovalMode {
    match interaction {
        ActionInteraction::Api => ApprovalMode::ReadOnly,
        ActionInteraction::Browser => ApprovalMode::Network,
        ActionInteraction::Computer => ApprovalMode::LocalWrite,
        ActionInteraction::AgentToAgent | ActionInteraction::HumanHandoff => ApprovalMode::Delegated,
    }
}

/// Deterministic projection of native risk onto the v1 ladder: the most restrictive
/// mode implied by any dimension. Data scope does not project.
pub fn project_action_risk(risk: &ActionRisk) -> ApprovalMode {
    [
        effect_projection(risk.effect),
        authority_projection(risk.authority),
        reversibility_projection(risk.reversibility),
        interaction_projection(risk.interaction),
    ]
    .into_iter()
    .max()
    .unwrap_or(ApprovalMode::Destructive)
}

/// Evaluates every dimension against `policy`. Violations are emitted in stable
/// dimension order for replay and hashing.
pub fn evaluate_action_risk(risk: &ActionRisk, policy: Option<&ActionRiskPolicy>) -> ActionRiskEvaluation {
    let mut violations = Vec::new();
    if let Some(policy) = policy {
        if !policy.allowed_effects.contains(&risk.effect) {
            violations.push(ActionRiskViolation::EffectNotAllowed);
        }
        if !policy.allowed_authorities.contains(&risk.authority) {
            violations.push(ActionRiskViolation::AuthorityNotAllowed);
        }
        if !policy.allowed_reversibility.contains(&risk.reversibility) {
            violations.push(ActionRiskViolation::ReversibilityNotAllowed);
        }
        if !policy.allowed_interactions.contains(&risk.interaction) {
            violations.push(ActionRiskViolation::InteractionNotAllowed);
        }
        if risk.data_scope > policy.data_scope_ceiling {
            violations.push(ActionRiskViolation::DataScopeExceedsCeiling);
        }
        if let Some(max) = policy.max_decision_ttl_seconds {
            match risk.decision_ttl_seconds {
                None => violations.push(ActionRiskViolation::DecisionTtlRequired),
                Some(ttl) if ttl > max => violations.push(ActionRiskViolation::DecisionTtlExceedsMaximum),
                Some(_) => {}
            }
        }
    }
    ActionRiskEvaluation {
        verdict: if violations.is_empty() {
            AllowDeny::Allow
        } else {
            AllowDeny::Deny
        },
        policy_applied: policy.is_some(),
        approval_mode_projection: project_action_risk(risk),
        violations,
    }
}

/// Evaluates untyped declarations, failing closed: a risk or policy that does not
/// parse into the closed vocabulary is denied with an `unsupported_*` violation and
/// projects to `destructive`.
pub fn evaluate_action_risk_json(risk: &Value, policy: Option<&Value>) -> ActionRiskEvaluation {
    let typed_risk = parse_risk(risk);
    let typed_policy = policy.map(parse_policy);
    let mut violations = Vec::new();
    if typed_risk.is_none() {
        violations.push(ActionRiskViolation::UnsupportedActionRisk);
    }
    if matches!(typed_policy, Some(None)) {
        violations.push(ActionRiskViolation::UnsupportedActionRiskPolicy);
    }
    match (typed_risk, violations.is_empty()) {
        (Some(risk), true) => evaluate_action_risk(&risk, typed_policy.flatten().as_ref()),
        (risk, _) => ActionRiskEvaluation {
            verdict: AllowDeny::Deny,
            policy_applied: policy.is_some(),
            approval_mode_projection: risk.as_ref().map_or(ApprovalMode::Destructive, project_action_risk),
            violations,
        },
    }
}

/// Parses an `ActionRisk`, rejecting anything outside the closed vocabulary.
pub fn parse_risk(value: &Value) -> Option<ActionRisk> {
    if !value.is_object() {
        return None;
    }
    serde_json::from_value(value.clone()).ok()
}

/// Parses an `ActionRiskPolicy`, rejecting anything outside the closed vocabulary.
pub fn parse_policy(value: &Value) -> Option<ActionRiskPolicy> {
    if !value.is_object() {
        return None;
    }
    serde_json::from_value(value.clone()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use contextos_contract::types::DataClassification;

    fn risk() -> ActionRisk {
        ActionRisk {
            effect: ActionEffect::ExternalState,
            authority: ActionAuthority::HumanApproved,
            reversibility: ActionReversibility::Compensatable,
            interaction: ActionInteraction::Api,
            data_scope: DataClassification::Confidential,
            decision_ttl_seconds: Some(300),
        }
    }

    #[test]
    fn projection_takes_most_restrictive_dimension() {
        assert_eq!(project_action_risk(&risk()), ApprovalMode::Destructive);
        let mut read = risk();
        read.authority = ActionAuthority::Service;
        read.effect = ActionEffect::None;
        read.reversibility = ActionReversibility::ReadOnly;
        assert_eq!(project_action_risk(&read), ApprovalMode::ReadOnly);
    }

    #[test]
    fn unsupported_values_fail_closed() {
        let evaluation = evaluate_action_risk_json(&serde_json::json!({"effect": "teleport"}), None);
        assert_eq!(evaluation.verdict, AllowDeny::Deny);
        assert_eq!(evaluation.approval_mode_projection, ApprovalMode::Destructive);
        assert_eq!(evaluation.violations, vec![ActionRiskViolation::UnsupportedActionRisk]);
    }
}
