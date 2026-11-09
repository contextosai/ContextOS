//! Review notes on one capability manifest: declarations the loader accepts but a
//! reviewer should look at again before pinning it. `ctx manifest` prints them with
//! its verdict; contextosd logs the first two kinds at startup.
//!
//! - An effectful capability that declares no `amount` or no `resource_pointers`: a
//!   task's amount and resource limits do not bound it.
//! - A tool named like a destructive call (`delete`, `drop`, `replace`, ...) declared
//!   reversible or read only, or approved below `destructive`.
//! - An effectful capability that is not `repeatable` and declares no `intent` key: the
//!   same request redelivered into another run is applied again.

use contextos_contract::types::{ActionEffect, ActionReversibility, ApprovalMode};

use crate::manifest::{CapabilityManifest, destructive_verb};

fn text<T: serde::Serialize>(value: T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_else(|| "?".into())
}

/// The note on an effectful capability with no amount or no resources, if any.
#[must_use]
pub fn unbounded_note(m: &CapabilityManifest) -> Option<String> {
    if m.action_risk.effect == ActionEffect::None {
        return None;
    }
    let missing: Vec<&str> = [
        ("amount", m.amount.is_none()),
        ("resource_pointers", m.resource_pointers.is_empty()),
    ]
    .into_iter()
    .filter_map(|(name, absent)| absent.then_some(name))
    .collect();
    (!missing.is_empty()).then(|| {
        format!(
            "{} is effectful and declares no {}: task amount and resource limits do not bound it",
            m.capability_id,
            missing.join(" or ")
        )
    })
}

/// The note on a tool named like a destructive call but not declared as one, if any.
#[must_use]
pub fn destructive_name_note(m: &CapabilityManifest) -> Option<String> {
    let verb = destructive_verb(&m.protocol_tool).or_else(|| destructive_verb(m.capability_name()))?;
    let reversible = matches!(
        m.action_risk.reversibility,
        ActionReversibility::ReadOnly | ActionReversibility::Reversible
    );
    (reversible || m.approval_mode < ApprovalMode::Destructive).then(|| {
        format!(
            "{} is named like a destructive call (\"{verb}\") but is declared {} with approval_mode {}: check the review",
            m.capability_id,
            text(m.action_risk.reversibility),
            text(m.approval_mode),
        )
    })
}

/// The note on an effectful, non-repeatable capability without an intent key, if any.
#[must_use]
pub fn intent_note(m: &CapabilityManifest) -> Option<String> {
    (m.action_risk.effect != ActionEffect::None && !m.repeatable && m.intent.is_none()).then(|| {
        format!(
            "{} declares no intent key: the same request redelivered into another run is applied again (declare intent.key_pointers)",
            m.capability_id
        )
    })
}

/// Every review note on `m`.
#[must_use]
pub fn review_notes(m: &CapabilityManifest) -> Vec<String> {
    [unbounded_note(m), destructive_name_note(m), intent_note(m)]
        .into_iter()
        .flatten()
        .collect()
}
