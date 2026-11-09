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

use serde_json::Value;

use crate::manifest::CapabilityManifest;

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

/// Words in a tool or capability name that usually mean the call destroys or replaces
/// something. A naming hint for reviewers, never a decision: `ctx init-tool` offers
/// it, and startup notes a capability so named that is declared reversible or
/// approved below `destructive`.
const DESTRUCTIVE_VERBS: &[&str] = &[
    "delete",
    "drop",
    "destroy",
    "terminate",
    "purge",
    "truncate",
    "wipe",
    "erase",
    "remove",
    "rm",
    "reset",
    "replace",
    "overwrite",
    "deprovision",
    "decommission",
    "kill",
    "shutdown",
    "format",
];

/// The destructive verb `name` contains as a word (split on `_`, `-`, `.`, `/` and
/// lower-to-upper case changes), if any.
#[must_use]
pub fn destructive_verb(name: &str) -> Option<&'static str> {
    let mut words = Vec::new();
    let mut word = String::new();
    let mut previous_lower = false;
    for c in name.chars() {
        if (!c.is_ascii_alphanumeric() || (c.is_ascii_uppercase() && previous_lower)) && !word.is_empty() {
            words.push(std::mem::take(&mut word));
        }
        if c.is_ascii_alphanumeric() {
            word.push(c.to_ascii_lowercase());
        }
        previous_lower = c.is_ascii_lowercase();
    }
    words.push(word);
    DESTRUCTIVE_VERBS
        .iter()
        .copied()
        .find(|verb| words.iter().any(|w| w == verb))
}

/// Marks a field of a drafted manifest (`ctx init-tool`) that a person must decide.
pub const REVIEW_MARKER: &str = "REVIEW:";

/// JSON pointers of every string in a manifest document that still starts with
/// [`REVIEW_MARKER`]. Loaders refuse a manifest while any remain, so a draft cannot
/// be pinned before review even where its placeholder would otherwise parse (a
/// description, a pointer).
#[must_use]
pub fn unreviewed(document: &Value) -> Vec<String> {
    fn walk(value: &Value, pointer: &mut String, found: &mut Vec<String>) {
        match value {
            Value::String(s) if s.trim_start().starts_with(REVIEW_MARKER) => found.push(pointer.clone()),
            Value::Array(items) => {
                for (index, item) in items.iter().enumerate() {
                    let len = pointer.len();
                    pointer.push('/');
                    pointer.push_str(&index.to_string());
                    walk(item, pointer, found);
                    pointer.truncate(len);
                }
            }
            Value::Object(fields) => {
                for (key, item) in fields {
                    let len = pointer.len();
                    pointer.push('/');
                    pointer.push_str(&key.replace('~', "~0").replace('/', "~1"));
                    walk(item, pointer, found);
                    pointer.truncate(len);
                }
            }
            _ => {}
        }
    }
    let mut found = Vec::new();
    walk(document, &mut String::new(), &mut found);
    found
}

#[cfg(test)]
mod review_tests {
    use super::unreviewed;
    use serde_json::json;

    #[test]
    fn finds_every_marked_string_by_pointer() {
        let draft = json!({
            "purpose_id": "REVIEW: a purpose",
            "description": "  REVIEW: upstream says hi",
            "resource_pointers": ["/order_id", "REVIEW: more?"],
            "action_risk": {"effect": "REVIEW: none|external_state", "authority": "service"},
            "a/b": "REVIEW: escaped",
            "note": "not a REVIEW: marker",
        });
        let mut found = unreviewed(&draft);
        found.sort();
        assert_eq!(
            found,
            [
                "/action_risk/effect",
                "/a~1b",
                "/description",
                "/purpose_id",
                "/resource_pointers/1"
            ]
        );
        assert_eq!(
            unreviewed(&json!({"purpose_id": "support.refund"})),
            Vec::<String>::new()
        );
    }
}
