//! The governance dashboard's numbers: what is held, refused, waiting for a person,
//! close to a shared ceiling, and whether the evidence is intact. Folded from the fleet
//! model and Tower's records on every read; the ceilings are read live from each
//! runtime (`GET /v1/guarantees`, `…/holds`) with Tower's read-only key.
//!
//! Users: the on-call engineer (what is stuck or stopped right now) and the compliance
//! lead (is oversight working, is the evidence whole). Every number links to where it
//! comes from: a finding, an agent, an approval row or a source.

use std::collections::BTreeMap;

use serde_json::{Value, json};

use crate::fleet::Fleet;
use crate::governance::Finding;

/// Rows of each ranked list.
pub const TOP: usize = 10;

/// Approvals asked for and not yet redeemed, denied or timed out, per capability. An
/// estimate from audit events: a request redeemed by a later run counts once.
#[must_use]
pub fn approvals_backlog(fleet: &Fleet) -> Vec<Value> {
    let mut rows: Vec<Value> = fleet
        .approvals
        .capabilities
        .iter()
        .map(|(capability, s)| {
            let decided = s.redeemed + s.denied + s.timed_out;
            json!({"capability_id": capability, "waiting": s.requested.saturating_sub(decided),
                "requested": s.requested, "timed_out": s.timed_out})
        })
        .filter(|r| r["waiting"].as_u64() > Some(0))
        .collect();
    rows.sort_by_key(|r| std::cmp::Reverse(r["waiting"].as_u64().unwrap_or(0)));
    rows.truncate(TOP);
    rows
}

/// Everything but the live ceilings.
#[must_use]
pub fn dashboard(fleet: &Fleet, findings: &[Finding], waivers: &Value, now: &str) -> Value {
    let mut held: Vec<(String, u64)> = fleet
        .agents
        .values()
        .map(|a| (a.key.clone(), a.unresolved_effects()))
        .filter(|(_, n)| *n > 0)
        .collect();
    held.sort_by_key(|(_, n)| std::cmp::Reverse(*n));
    let mut denials: BTreeMap<String, u64> = BTreeMap::new();
    for a in fleet.agents.values() {
        for (reason, n) in &a.refusals {
            *denials.entry(reason.clone()).or_default() += n;
        }
    }
    let mut denials: Vec<(String, u64)> = denials.into_iter().collect();
    denials.sort_by_key(|(_, n)| std::cmp::Reverse(*n));
    let open: Vec<&Finding> = findings.iter().filter(|f| f.waiver.is_none()).collect();
    let drift = open
        .iter()
        .filter(|f| {
            matches!(
                f.rule.as_str(),
                "authority_drift" | "pack_version_conflict" | "lifecycle_not_enforced"
            )
        })
        .count();
    let active_waivers: Vec<&Value> = waivers
        .as_array()
        .into_iter()
        .flatten()
        .filter(|w| w["status"] == "approved" && w["expires_at"].as_str().is_some_and(|e| e > now))
        .collect();
    let chains: Vec<Value> = fleet
        .sources
        .values()
        .map(|s| {
            json!({"source": s.id, "verified_to": s.verified_to, "head": s.head,
                "behind": s.head.saturating_sub(s.verified_to), "broken": s.broken.is_some(), "last_sync": s.last_sync})
        })
        .collect();
    let backlog = approvals_backlog(fleet);
    json!({
        "generated_at": now,
        "held_effects": {"total": held.iter().map(|(_, n)| n).sum::<u64>(),
            "agents": held.iter().take(TOP).map(|(k, n)| json!({"agent": k, "held": n})).collect::<Vec<_>>()},
        "denials": {"total": denials.iter().map(|(_, n)| n).sum::<u64>(),
            "by_reason": denials.iter().take(TOP).map(|(r, n)| json!({"reason": r, "count": n})).collect::<Vec<_>>()},
        "approvals_backlog": {"waiting": backlog.iter().filter_map(|r| r["waiting"].as_u64()).sum::<u64>(), "by_capability": backlog},
        "waivers": {"active": active_waivers.len()},
        "policy_drift": drift,
        "break_glass_unreviewed": open.iter().filter(|f| f.rule == "break_glass_unreviewed").count(),
        "findings": {"critical": open.iter().filter(|f| f.severity == "critical").count(),
            "high": open.iter().filter(|f| f.severity == "high").count()},
        "evidence": {"sources": chains.len(), "broken": chains.iter().filter(|c| c["broken"] == true).count(),
            "chains": chains},
    })
}

/// One guarantee's utilisation from its holds listing: resources with held capacity
/// and the fullest one, as `(committed + held) / limit`.
#[must_use]
pub fn utilisation(source: &str, guarantee: &Value, holds: &Value) -> Value {
    let limit = guarantee["limit"].as_u64().unwrap_or(0);
    let rows = holds["resources"].as_array().cloned().unwrap_or_default();
    let used = |r: &Value| r["committed"].as_u64().unwrap_or(0) + r["held"].as_u64().unwrap_or(0);
    let fullest = rows.iter().map(used).max().unwrap_or(0);
    let share = fullest
        .min(limit)
        .checked_mul(1000)
        .and_then(|permille| permille.checked_div(limit))
        .map_or(Value::Null, |permille| {
            json!(f64::from(u32::try_from(permille).unwrap_or(1000)) / 1000.0)
        });
    json!({"source": source, "guarantee": guarantee["id"], "unit": guarantee["unit"], "limit": limit,
        "resources_held": rows.len(), "fullest": fullest, "fullest_share": share})
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fleet::tests::entry;

    #[test]
    fn held_denied_and_waiting_are_counted() {
        let mut fleet = Fleet::new(10, 48);
        fleet.apply(
            "eu",
            &entry(
                1,
                "run_admitted",
                json!({"run_id": "r1", "agent_id": "agt_a", "trace_id": "t"}),
            ),
        );
        fleet.apply(
            "eu",
            &entry(
                2,
                "operation_claim",
                json!({"run_id": "r1", "operation_id": "op", "attempt_id": "a1", "capability_id": "pay.refund"}),
            ),
        );
        fleet.apply(
            "eu",
            &entry(
                3,
                "effect_observation",
                json!({"run_id": "r1", "attempt_id": "a1", "outcome": "unknown", "finality": "provisional"}),
            ),
        );
        fleet.apply(
            "eu",
            &entry(
                4,
                "revocation_refusal",
                json!({"run_id": "r1", "capability_id": "x.y", "reason_codes": ["revoked_agent"]}),
            ),
        );
        for _ in 0..3 {
            fleet
                .approvals
                .apply(&entry(5, "approval_requested", json!({"capability_id": "pay.refund"})));
        }
        fleet.approvals.apply(&entry(
            6,
            "approval_redeemed",
            json!({"capability_id": "pay.refund", "approvers": ["a"]}),
        ));
        fleet.approvals.apply(&entry(
            7,
            "approval_denied",
            json!({"capability_id": "pay.refund", "approvers": ["b"]}),
        ));
        let d = dashboard(&fleet, &[], &json!([]), "2026-10-21T11:00:00Z");
        assert_eq!(d["held_effects"]["total"], 1);
        assert_eq!(d["held_effects"]["agents"][0]["agent"], "acme/agt_a");
        assert_eq!(
            d["denials"]["by_reason"][0],
            json!({"reason": "revoked_agent", "count": 1})
        );
        assert_eq!(d["approvals_backlog"]["waiting"], 1);
        assert_eq!(d["evidence"]["sources"], 1);
    }

    #[test]
    fn utilisation_reports_the_fullest_resource() {
        let g = json!({"id": "refunds-per-order", "limit": 100_000, "unit": "INR_minor"});
        let holds = json!({"resources": [{"committed": 30_000, "held": 50_000}, {"committed": 10_000, "held": 0}]});
        let u = utilisation("eu", &g, &holds);
        assert_eq!(
            (u["resources_held"].as_u64(), u["fullest"].as_u64()),
            (Some(2), Some(80_000))
        );
        assert_eq!(u["fullest_share"], 0.8);
        assert_eq!(utilisation("eu", &g, &json!({}))["fullest"], 0);
    }
}
