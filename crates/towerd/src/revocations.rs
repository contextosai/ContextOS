//! What is switched off right now, everywhere: each source's revocations, reconciled
//! between the runtime's live list and Tower's verified copy of its audit chain, with
//! the agents each one stops.
//!
//! The runtime's list (read with its `control` key) is what it enforces. The chain is
//! what Tower has verified, and it names who revoked and when. The two disagree only
//! briefly (a change not yet collected) or when something is wrong (a chain Tower has
//! stopped reading, a store edited behind the runtime's back), so a disagreement is
//! shown, never resolved silently.

use std::collections::BTreeMap;

use serde::Serialize;
use serde_json::Value;

use crate::fleet::Revoked;
use crate::governance::AgentView;

/// Where a revocation in the list was seen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Provenance {
    /// In force on the runtime and recorded in its verified chain.
    Verified,
    /// In force on the runtime, not (yet) in the chain Tower verified.
    RuntimeOnly,
    /// In the verified chain, but the runtime does not list it.
    ChainOnly,
    /// From the verified chain; Tower cannot read this runtime's live list.
    Chain,
}

/// One revocation on one source.
#[derive(Debug, Clone, Serialize)]
pub struct Active {
    pub source: String,
    pub kind: String,
    pub target: String,
    pub reason: String,
    pub by: Option<String>,
    /// The Tower user who acted, when the change was made through Tower (its runtime
    /// operator is then Tower's control key).
    pub via_tower: Option<String>,
    pub at: Option<String>,
    /// The chain entry that recorded it, when Tower has verified one.
    pub sequence: Option<u64>,
    pub provenance: Provenance,
    /// Agents on this source whose runs it stops (keys into the inventory).
    pub affected: Vec<String>,
    /// Refusals for this kind of revocation (`revoked_<kind>`) recorded against the
    /// affected agents in Tower's activity window.
    pub refusals: u64,
}

impl Active {
    #[must_use]
    pub fn mismatch(&self) -> bool {
        matches!(self.provenance, Provenance::RuntimeOnly | Provenance::ChainOnly)
    }
}

/// The Tower principal in a reason Tower wrote: `… (via Tower, <principal>)`.
#[must_use]
pub fn via_tower(reason: &str) -> Option<String> {
    const MARK: &str = " (via Tower, ";
    let rest = reason.strip_suffix(')')?;
    let who = &rest[rest.rfind(MARK)? + MARK.len()..];
    (!who.is_empty() && !who.contains(['(', ')', ','])).then(|| who.to_owned())
}

fn key(kind: &str, target: &str) -> String {
    format!("{kind}:{target}")
}

fn text(v: &Value, k: &str) -> Option<String> {
    v[k].as_str().map(str::to_owned)
}

/// Reconciles one source's chain-derived revocations with its live list. `live` is
/// `None` when the live list could not be read; then the chain stands alone.
#[must_use]
pub fn reconcile(source: &str, chain: &BTreeMap<String, Revoked>, live: Option<&Value>) -> Vec<Active> {
    let base = |kind: String, target: String| Active {
        source: source.to_owned(),
        kind,
        target,
        reason: String::new(),
        by: None,
        via_tower: None,
        at: None,
        sequence: None,
        provenance: Provenance::Chain,
        affected: Vec::new(),
        refusals: 0,
    };
    let from_chain = |r: &Revoked, provenance| Active {
        reason: r.reason.clone(),
        by: r.by.clone(),
        at: Some(r.at.clone()),
        sequence: Some(r.sequence),
        provenance,
        ..base(r.kind.clone(), r.target.clone())
    };
    let Some(list) = live.and_then(|l| l["revoked"].as_array()) else {
        return chain.values().map(|r| from_chain(r, Provenance::Chain)).collect();
    };
    let mut out = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for item in list {
        let (Some(kind), Some(target)) = (text(item, "kind"), text(item, "target")) else {
            continue;
        };
        let k = key(&kind, &target);
        if !seen.insert(k.clone()) {
            continue;
        }
        out.push(match chain.get(&k) {
            Some(r) => from_chain(r, Provenance::Verified),
            None => Active {
                reason: text(item, "reason").unwrap_or_default(),
                by: text(item, "by"),
                at: text(item, "at"),
                provenance: Provenance::RuntimeOnly,
                ..base(kind, target)
            },
        });
    }
    out.extend(
        chain
            .iter()
            .filter(|(k, _)| !seen.contains(*k))
            .map(|(_, r)| from_chain(r, Provenance::ChainOnly)),
    );
    for a in &mut out {
        a.via_tower = via_tower(&a.reason);
    }
    out.sort_by(|a, b| (&a.kind, &a.target).cmp(&(&b.kind, &b.target)));
    out
}

/// Whether a revocation of `kind:target` on `source` stops the agent's runs there.
#[must_use]
pub fn stops(view: &AgentView, source: &str, kind: &str, target: &str) -> bool {
    let a = &view.activity;
    if !a.sources.contains(source) {
        return false;
    }
    match kind {
        "tenant" => a.tenants.contains(target),
        "agent" => a.agent_id == target,
        "principal" => a.admitted_by.contains(target),
        "pack" => a.source_packs.contains(&(source.to_owned(), target.to_owned())),
        "capability" => {
            a.capabilities.contains_key(target)
                || a.surfaced.contains(target)
                || view.graph.iter().any(|c| c.id == target)
        }
        "adapter" => view.graph.iter().any(|c| c.adapter == target),
        _ => false,
    }
}

/// Fills in the agents each revocation stops and the refusals it has caused them.
pub fn attribute(active: &mut [Active], views: &[AgentView]) {
    for r in active {
        let reason = format!("revoked_{}", r.kind);
        for view in views.iter().filter(|v| stops(v, &r.source, &r.kind, &r.target)) {
            r.affected.push(view.key.clone());
            r.refusals += view.activity.refusals.get(&reason).copied().unwrap_or(0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn revoked(kind: &str, target: &str, seq: u64) -> (String, Revoked) {
        (
            key(kind, target),
            Revoked {
                kind: kind.into(),
                target: target.into(),
                reason: "INC-7".into(),
                by: Some("oncall".into()),
                at: "2026-11-07T10:00:00.000000Z".into(),
                sequence: seq,
            },
        )
    }

    #[test]
    fn the_chain_stands_alone_without_a_live_list() {
        let chain = BTreeMap::from([revoked("agent", "agt_a", 4)]);
        let list = reconcile("eu", &chain, None);
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].via_tower, None);
        assert_eq!(list[0].provenance, Provenance::Chain);
        assert_eq!(list[0].by.as_deref(), Some("oncall"));
        assert!(!list[0].mismatch());
    }

    #[test]
    fn live_and_chain_are_reconciled_and_disagreements_flagged() {
        let chain = BTreeMap::from([revoked("agent", "agt_a", 4), revoked("pack", "p@1", 9)]);
        let live = json!({"revoked": [
            {"kind": "agent", "target": "agt_a", "reason": "INC-7", "by": "oncall", "at": "x"},
            {"kind": "capability", "target": "pay.send", "reason": "new", "by": "ops", "at": "y"},
            {"kind": "capability", "target": "pay.send", "reason": "dup"},
            {"kind": "capability"}
        ]});
        let list = reconcile("eu", &chain, Some(&live));
        let by: BTreeMap<_, _> = list.iter().map(|a| (key(&a.kind, &a.target), a)).collect();
        assert_eq!(list.len(), 3);
        assert_eq!(by["agent:agt_a"].provenance, Provenance::Verified);
        assert_eq!(by["agent:agt_a"].sequence, Some(4));
        assert_eq!(by["capability:pay.send"].provenance, Provenance::RuntimeOnly);
        assert_eq!(by["capability:pay.send"].reason, "new");
        assert_eq!(by["pack:p@1"].provenance, Provenance::ChainOnly);
        assert!(by["pack:p@1"].mismatch() && by["capability:pay.send"].mismatch());
    }

    #[test]
    fn the_tower_user_is_read_from_the_reason_tower_wrote() {
        assert_eq!(via_tower("INC-1 (via Tower, oncall-a)").as_deref(), Some("oncall-a"));
        assert_eq!(via_tower("x (via Tower, a) (via Tower, b)").as_deref(), Some("b"));
        assert_eq!(via_tower("INC-1"), None);
        assert_eq!(via_tower("INC-1 (via Tower, )"), None);
        assert_eq!(via_tower("fix (via Tower, requested by a, approved by b)"), None);
    }
}
