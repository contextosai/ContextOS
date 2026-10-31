//! Pack intents: a run must declare an intent its Context Pack governs.
//!
//! The compiler evaluates a rule scoped to an intent (`applies_to.intent`) only for
//! runs that declare that intent, and the intent is the caller's to declare. A pack
//! whose refund rules are scoped to `support.refund` therefore restricts nothing for a
//! run that declares `general.query`, while its tools are still surfaced. So a run's
//! intent (as the compiler resolved it) must be one the pack's rules name, when they
//! name any:
//!
//! - `required` refuses any other intent (`422 intent_not_governed`). The default for
//!   deployments that declare the `contextos.enterprise` profile.
//! - `observe` admits it, counts it (`contextos_pack_intent_mismatches_total`) and
//!   records `governed: false` in `run_admitted`. The default otherwise.
//! - `off` checks nothing.
//!
//! This does not stop a run declaring one governed intent to avoid the rules of
//! another in the same pack; `--check-config` names every pack where that is possible
//! (more than one governed intent, and a restrictive rule scoped to one of them).

use std::collections::BTreeSet;

use contextos_contract::types::{ContextPack, PolicyRule};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::Config;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PackIntents {
    Required,
    Observe,
    Off,
}

impl PackIntents {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Required => "required",
            Self::Observe => "observe",
            Self::Off => "off",
        }
    }
}

/// `[guards] pack_intents`, or the default for the declared profiles.
#[must_use]
pub fn mode(config: &Config) -> PackIntents {
    config.guards.pack_intents.unwrap_or_else(|| {
        if config.support.profiles.iter().any(|p| p == "contextos.enterprise") {
            PackIntents::Required
        } else {
            PackIntents::Observe
        }
    })
}

fn rules(pack: &ContextPack) -> impl Iterator<Item = &PolicyRule> {
    pack.policy_layer
        .policy_bundles
        .iter()
        .flat_map(|bundle| &bundle.policy_dsl.rules)
}

/// The intents the pack's rules are scoped to.
#[must_use]
pub fn governed(pack: &ContextPack) -> BTreeSet<&str> {
    rules(pack)
        .filter_map(|rule| rule.applies_to.intent.as_deref())
        .filter(|intent| !intent.is_empty())
        .collect()
}

/// Whether a rule restricts what it applies to rather than only allowing it.
fn restrictive(rule: &PolicyRule) -> bool {
    let then = &rule.then;
    !then.allow
        || then.prohibits.as_ref().is_some_and(|p| !p.is_empty())
        || then.requires.as_ref().is_some_and(|r| !r.is_empty())
        || then.approval_gate().is_some_and(|g| !g.is_empty())
        || then.arg_constraints.as_ref().is_some_and(|c| !c.is_empty())
        || rule.otherwise.as_ref().is_some_and(|o| !o.allow)
}

/// A `--check-config` warning when the pack governs more than one intent and scopes
/// a restrictive rule to any of them: a run may declare another governed intent, and
/// it is not held to that rule.
#[must_use]
pub fn spread(pack_ref: &str, pack: &ContextPack) -> Option<String> {
    let governed = governed(pack);
    let restricted: BTreeSet<&str> = rules(pack)
        .filter(|rule| restrictive(rule))
        .filter_map(|rule| rule.applies_to.intent.as_deref())
        .filter(|intent| !intent.is_empty())
        .collect();
    (governed.len() > 1 && !restricted.is_empty()).then(|| {
        format!(
            "{pack_ref} governs {} intents ({}) and scopes restrictive rules to {}: a run declaring \
             one intent is not held to another's rules",
            governed.len(),
            governed.into_iter().collect::<Vec<_>>().join(", "),
            restricted.into_iter().collect::<Vec<_>>().join(", ")
        )
    })
}

/// What admission decided about the run's intent.
#[derive(Debug, Clone, PartialEq)]
pub struct Verdict {
    /// Recorded in `run_admitted` as `pack_intent`.
    pub record: Value,
    /// The intent is not one the pack governs.
    pub outside: bool,
    /// Admission must refuse (`required` and outside).
    pub refuse: bool,
}

#[must_use]
pub fn evaluate(mode: PackIntents, pack: &ContextPack, intent: &str) -> Verdict {
    let governed = governed(pack);
    if mode == PackIntents::Off || governed.is_empty() {
        return Verdict {
            record: json!({"mode": mode.as_str()}),
            outside: false,
            refuse: false,
        };
    }
    let inside = governed.contains(intent);
    Verdict {
        record: json!({"mode": mode.as_str(), "governed": inside}),
        outside: !inside,
        refuse: !inside && mode == PackIntents::Required,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pack(rules: Value) -> ContextPack {
        let mut pack: Value = serde_json::from_str(include_str!("../../../examples/support-refund/pack.json")).unwrap();
        pack["policy_layer"]["policy_bundles"][0]["policy_dsl"]["rules"] = rules;
        serde_json::from_value(pack).unwrap()
    }

    fn rule(id: &str, intent: Option<&str>, then: Value) -> Value {
        json!({"rule_id": id, "applies_to": {"intent": intent}, "if": true, "then": then})
    }

    #[test]
    fn only_required_refuses_and_only_a_governed_intent_is_inside() {
        let refunds = pack(json!([rule("R1", Some("support.refund"), json!({"allow": false}))]));
        for (mode, intent, refuse, outside) in [
            (PackIntents::Required, "support.refund", false, false),
            (PackIntents::Required, "general.query", true, true),
            (PackIntents::Observe, "general.query", false, true),
            (PackIntents::Off, "general.query", false, false),
        ] {
            let verdict = evaluate(mode, &refunds, intent);
            assert_eq!(
                (verdict.refuse, verdict.outside),
                (refuse, outside),
                "{mode:?} {intent}"
            );
        }
        // A pack without intent-scoped rules governs every intent alike.
        let unscoped = pack(json!([rule("R1", None, json!({"allow": false}))]));
        assert!(!evaluate(PackIntents::Required, &unscoped, "anything").refuse);
    }

    #[test]
    fn a_restriction_that_another_governed_intent_escapes_is_reported() {
        // A run declaring general.query is admitted and not held to R1.
        let escapable = pack(json!([
            rule("R1", Some("support.refund"), json!({"allow": false})),
            rule("R2", Some("general.query"), json!({"allow": true})),
        ]));
        let warning = spread("p@1", &escapable).unwrap();
        assert!(
            warning.contains("governs 2 intents (general.query, support.refund)"),
            "{warning}"
        );
        assert!(warning.contains("restrictive rules to support.refund"), "{warning}");
        // One governed intent, or no restriction at all: nothing to escape.
        let single = pack(json!([rule("R1", Some("support.refund"), json!({"allow": false}))]));
        assert_eq!(spread("p@1", &single), None);
        let permissive = pack(json!([
            rule("R1", Some("support.refund"), json!({"allow": true})),
            rule("R2", Some("general.query"), json!({"allow": true})),
        ]));
        assert_eq!(spread("p@1", &permissive), None);
    }
}
