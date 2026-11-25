//! Access reviews: which agents hold which capabilities, which of those they have not
//! used, which delegations have gone stale, which agents are dormant, and which waivers
//! and reviews are about to expire. Derived, like the inventory, from verified evidence
//! and Tower's records on every read; a reviewer attests to a review with a signed
//! journal entry citing the report's digest.

use std::collections::BTreeMap;

use contextos_contract::canonical::sha256_canonical;
use serde::Serialize;
use serde_json::{Value, json};

use crate::fleet::hour_index;
use crate::governance::AgentView;

/// Waivers and reviews expiring within this many days are listed.
pub const EXPIRY_HORIZON_DAYS: i64 = 30;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Grant {
    pub agent: String,
    pub owner_team: Option<String>,
    pub capability: String,
    pub adapter: String,
    /// Packs that pin it for the agent (empty when only surfaced at admission).
    pub packs: Vec<String>,
    pub last_used: Option<String>,
    /// `used`, `unused` (not in the window) or `never_used`.
    pub status: &'static str,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct StaleDelegation {
    pub agent: String,
    pub delegate: String,
    pub delegate_last_seen: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Dormant {
    pub agent: String,
    pub lifecycle: String,
    pub last_seen: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct AccessReview {
    pub window_days: i64,
    pub generated_at: String,
    pub grants: Vec<Grant>,
    pub stale_delegations: Vec<StaleDelegation>,
    pub dormant_agents: Vec<Dormant>,
    pub expiring_waivers: Vec<Value>,
    pub expiring_reviews: Vec<Value>,
    pub summary: BTreeMap<&'static str, usize>,
    /// `sha256:` over everything above but the time, so an attestation names the exact
    /// findings it covers.
    pub digest: String,
}

fn within(at: Option<&str>, now_hour: i64, days: i64) -> bool {
    at.filter(|a| !a.is_empty())
        .is_some_and(|a| hour_index(a) >= now_hour - days * 24)
}

fn expiring(at: Option<&str>, now: &str, now_hour: i64) -> bool {
    at.is_some_and(|e| e > now && hour_index(e) <= now_hour + EXPIRY_HORIZON_DAYS * 24)
}

/// The access review over `views` for the last `days` days at `now`.
#[must_use]
pub fn access_review(views: &[AgentView], waivers: &Value, now: &str, days: i64) -> AccessReview {
    let now_hour = hour_index(now);
    let last_seen: BTreeMap<&str, &str> = views
        .iter()
        .map(|v| (v.key.as_str(), v.activity.last_seen.as_str()))
        .collect();
    let mut grants = Vec::new();
    let mut stale = Vec::new();
    let mut dormant = Vec::new();
    let mut reviews = Vec::new();
    for view in views {
        let d = view.declaration.as_ref();
        let team = d.and_then(|d| d["team"].as_str()).map(str::to_owned);
        let lifecycle = d.and_then(|d| d["lifecycle"].as_str()).unwrap_or("undeclared");
        for c in view.graph.iter().filter(|c| !c.packs.is_empty() || c.surfaced) {
            let last = view.activity.seen.get("capability", &c.id).map(|s| s.last.clone());
            let status = match &last {
                None => "never_used",
                Some(l) if within(Some(l), now_hour, days) => "used",
                Some(_) => "unused",
            };
            grants.push(Grant {
                agent: view.key.clone(),
                owner_team: team.clone(),
                capability: c.id.clone(),
                adapter: c.adapter.clone(),
                packs: c.packs.iter().cloned().collect(),
                last_used: last,
                status,
            });
        }
        for delegate in &view.activity.delegates_to {
            let seen = last_seen.get(delegate.as_str()).copied();
            if !within(seen, now_hour, days) {
                stale.push(StaleDelegation {
                    agent: view.key.clone(),
                    delegate: delegate.clone(),
                    delegate_last_seen: seen.filter(|s| !s.is_empty()).map(str::to_owned),
                });
            }
        }
        if matches!(lifecycle, "pilot" | "production") && !within(Some(&view.activity.last_seen), now_hour, days) {
            dormant.push(Dormant {
                agent: view.key.clone(),
                lifecycle: lifecycle.to_owned(),
                last_seen: Some(view.activity.last_seen.clone()).filter(|s| !s.is_empty()),
            });
        }
        if let Some(r) = view.review.as_ref().filter(|r| r["decision"] == "approved")
            && expiring(r["expires_at"].as_str(), now, now_hour)
        {
            reviews.push(json!({"agent": view.key, "expires_at": r["expires_at"], "reviewed_by": r["reviewed_by"]}));
        }
    }
    let expiring_waivers: Vec<Value> = waivers
        .as_array()
        .into_iter()
        .flatten()
        .filter(|w| w["status"] == "approved" && expiring(w["expires_at"].as_str(), now, now_hour))
        .map(|w| json!({"id": w["id"], "agent": w["agent"], "rule": w["rule"], "expires_at": w["expires_at"]}))
        .collect();
    let count = |s: &str| grants.iter().filter(|g| g.status == s).count();
    let summary = BTreeMap::from([
        ("grants", grants.len()),
        ("unused_grants", count("unused") + count("never_used")),
        ("stale_delegations", stale.len()),
        ("dormant_agents", dormant.len()),
        ("expiring_waivers", expiring_waivers.len()),
        ("expiring_reviews", reviews.len()),
    ]);
    let digest = sha256_canonical(&json!({"window_days": days, "grants": grants, "stale": stale,
        "dormant": dormant, "waivers": expiring_waivers, "reviews": reviews}))
    .unwrap_or_default();
    AccessReview {
        window_days: days,
        generated_at: now.to_owned(),
        grants,
        stale_delegations: stale,
        dormant_agents: dormant,
        expiring_waivers,
        expiring_reviews: reviews,
        summary,
        digest,
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::fleet::Fleet;
    use crate::fleet::tests::entry;
    use crate::governance::views;

    #[test]
    fn dormant_agents_stale_delegations_and_expiring_waivers_are_listed() {
        let mut fleet = Fleet::new(10, 48);
        // Entries are timed 2026-10-21T10:MM.
        fleet.apply(
            "eu",
            &entry(
                1,
                "run_admitted",
                json!({"run_id": "p", "agent_id": "agt_parent", "trace_id": "t",
            "surfaced_capabilities": ["adp.read"]}),
            ),
        );
        fleet.apply(
            "eu",
            &entry(
                2,
                "run_admitted",
                json!({"run_id": "c", "agent_id": "agt_child", "trace_id": "t2",
            "parent_run_id": "p"}),
            ),
        );
        fleet.apply(
            "eu",
            &entry(
                3,
                "delegation_admitted",
                json!({"parent_run_id": "p", "child_run_id": "c"}),
            ),
        );
        let declarations = json!({"acme/agt_parent": {"owner": "ana", "team": "ops", "purpose": "p", "users_served": "internal",
            "lifecycle": "production"}});
        let now = "2027-03-01T00:00:00Z";
        let v = views(&fleet, &declarations, &json!({}), now);
        let waivers = json!([
            {"id": "w1", "agent": "acme/agt_parent", "rule": "unreviewed", "status": "approved", "expires_at": "2027-03-10T00:00:00Z"},
            {"id": "w2", "agent": "acme/agt_parent", "rule": "unreviewed", "status": "approved", "expires_at": "2027-09-10T00:00:00Z"},
            {"id": "w3", "agent": "acme/agt_parent", "rule": "unreviewed", "status": "approved", "expires_at": "2027-02-10T00:00:00Z"}
        ]);
        let r = access_review(&v, &waivers, now, 90);
        assert_eq!(
            r.dormant_agents.iter().map(|d| d.agent.as_str()).collect::<Vec<_>>(),
            ["acme/agt_parent"]
        );
        assert_eq!(
            r.expiring_waivers.len(),
            1,
            "only the one expiring within 30 days, not past or later ones"
        );
        assert_eq!(r.expiring_waivers[0]["id"], "w1");
        assert!(
            r.grants
                .iter()
                .any(|g| g.capability == "adp.read" && g.status == "never_used")
        );
        // The child last ran months before `now`: the delegation to it is stale.
        assert_eq!(r.stale_delegations.len(), 1, "{:?}", r.stale_delegations);
        assert_eq!(r.stale_delegations[0].delegate, "acme/agt_child");
        assert_eq!(r.stale_delegations[0].agent, "acme/agt_parent");
        // The digest names the findings, not the moment they were read.
        assert_eq!(r.digest, access_review(&v, &waivers, now, 90).digest);
        assert_ne!(r.digest, access_review(&v, &waivers, now, 30).digest);
    }
}
