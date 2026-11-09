//! Approval quality: how approvals of each capability are decided, and by whom,
//! folded from the runtime's approval events.
//!
//! An approval step that people click through looks the same as one that works until
//! someone measures it. The runtime audits when it asked for an approval and when one
//! was redeemed, with the decision time, and refuses decisions faster than a review
//! floor or without a required step-up. Tower keeps, per capability and per approver,
//! how many approvals were requested and redeemed, how long decisions took (in
//! buckets), and how many were refused as too fast or without step-up, so a risk lead
//! can see whether oversight is real.
//!
//! | Event | Fields used |
//! |---|---|
//! | `approval_requested` | `capability_id` |
//! | `approval_redeemed` | `capability_id`, `approvers`, `decision_seconds` |
//! | `approval_review_too_fast` | `capability_id` |
//! | `approval_step_up_refused` | `capability_id` |
//! | `approval_timed_out` | `capability_id` |
//!
//! Memory is bounded: at most [`MAX_KEYS`] capabilities and approvers are tracked;
//! the rest are counted under [`OTHER`].

use std::collections::BTreeMap;

use contextos_audit::AuditEntry;
use serde::Serialize;

/// Upper bounds (seconds, inclusive) of the decision-time buckets; the last bucket is
/// everything slower.
pub const BUCKETS: [u64; 6] = [10, 30, 60, 300, 1800, 3600];
/// Capabilities, and approvers, tracked by name at most.
pub const MAX_KEYS: usize = 256;
/// Where names past [`MAX_KEYS`] are counted.
pub const OTHER: &str = "(other)";

/// How approvals of one capability, or by one approver, were decided.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct Stats {
    pub requested: u64,
    pub redeemed: u64,
    /// Redemptions by decision time: one count per [`BUCKETS`] entry, then slower.
    pub decision_seconds: [u64; BUCKETS.len() + 1],
    /// Redemptions without a usable decision time.
    pub untimed: u64,
    pub refused_too_fast: u64,
    pub refused_step_up: u64,
    /// Requests nobody decided before the approval timeout.
    pub timed_out: u64,
}

impl Stats {
    fn timed(&mut self, seconds: Option<u64>) {
        match seconds {
            Some(s) => self.decision_seconds[BUCKETS.iter().position(|b| s <= *b).unwrap_or(BUCKETS.len())] += 1,
            None => self.untimed += 1,
        }
    }

    /// Redemptions decided within the first bucket (ten seconds).
    #[must_use]
    pub fn within_first_bucket(&self) -> u64 {
        self.decision_seconds[0]
    }
}

/// The fleet's approval quality.
#[derive(Debug, Default)]
pub struct Approvals {
    pub capabilities: BTreeMap<String, Stats>,
    pub approvers: BTreeMap<String, Stats>,
}

/// Whether the event is one this module folds.
#[must_use]
pub fn is_approval(kind: &str) -> bool {
    matches!(
        kind,
        "approval_requested"
            | "approval_redeemed"
            | "approval_review_too_fast"
            | "approval_step_up_refused"
            | "approval_timed_out"
    )
}

fn slot<'a>(map: &'a mut BTreeMap<String, Stats>, name: &str) -> &'a mut Stats {
    let name = if map.contains_key(name) || map.len() < MAX_KEYS {
        name
    } else {
        OTHER
    };
    map.entry(name.to_owned()).or_default()
}

impl Approvals {
    pub fn apply(&mut self, entry: &AuditEntry) {
        let p = &entry.payload;
        let capability = p["capability_id"].as_str().unwrap_or("unknown");
        let stats = slot(&mut self.capabilities, capability);
        match entry.kind.as_str() {
            "approval_requested" => stats.requested += 1,
            "approval_redeemed" => {
                let seconds = p["decision_seconds"].as_u64();
                stats.redeemed += 1;
                stats.timed(seconds);
                for approver in p["approvers"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|a| a.as_str())
                {
                    let by = slot(&mut self.approvers, approver);
                    by.redeemed += 1;
                    by.timed(seconds);
                }
            }
            "approval_review_too_fast" => stats.refused_too_fast += 1,
            "approval_step_up_refused" => stats.refused_step_up += 1,
            "approval_timed_out" => stats.timed_out += 1,
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn entry(kind: &str, payload: Value) -> AuditEntry {
        crate::fleet::tests::entry(1, kind, payload)
    }

    #[test]
    fn folds_requests_redemptions_and_refusals() {
        let mut a = Approvals::default();
        let refund = json!({"capability_id": "pay.refund"});
        a.apply(&entry("approval_requested", refund.clone()));
        a.apply(&entry("approval_requested", refund.clone()));
        a.apply(&entry("approval_review_too_fast", refund.clone()));
        a.apply(&entry("approval_timed_out", refund.clone()));
        a.apply(&entry(
            "approval_redeemed",
            json!({"capability_id": "pay.refund",
            "approvers": ["fin_lead"], "decision_seconds": 4}),
        ));
        a.apply(&entry(
            "approval_redeemed",
            json!({"capability_id": "pay.refund",
            "approvers": ["fin_lead", "ops_lead"], "decision_seconds": 900}),
        ));
        let s = &a.capabilities["pay.refund"];
        assert_eq!((s.requested, s.redeemed, s.refused_too_fast, s.timed_out), (2, 2, 1, 1));
        assert_eq!(s.decision_seconds, [1, 0, 0, 0, 1, 0, 0]);
        assert_eq!(s.within_first_bucket(), 1);
        assert_eq!(a.approvers["fin_lead"].redeemed, 2);
        assert_eq!(a.approvers["ops_lead"].decision_seconds[4], 1);
        assert!(is_approval("approval_step_up_refused") && !is_approval("usage_settled"));
    }

    #[test]
    fn names_past_the_bound_share_one_row() {
        let mut a = Approvals::default();
        for i in 0..=MAX_KEYS {
            a.apply(&entry("approval_requested", json!({"capability_id": format!("c.{i}")})));
        }
        assert_eq!(a.capabilities.len(), MAX_KEYS + 1);
        assert_eq!(a.capabilities[OTHER].requested, 1);
    }
}
