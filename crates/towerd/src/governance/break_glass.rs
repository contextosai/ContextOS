//! Break-glass grants need a review after the incident: every grant a runtime's
//! verified chain shows is a `break_glass_unreviewed` finding (high) until a risk
//! reviewer records its review (`POST /api/break-glass/review`).

use serde_json::{Value, json};

use super::Finding;
use crate::fleet::Fleet;

/// The key a grant's review is stored under.
#[must_use]
pub fn review_key(source: &str, grant_id: &str) -> String {
    format!("{source}/{grant_id}")
}

pub fn findings(fleet: &Fleet, reviews: &Value) -> Vec<Finding> {
    let mut out = Vec::new();
    for state in fleet.sources.values() {
        for g in &state.break_glass {
            let id = g["grant_id"].as_str().unwrap_or("?");
            if reviews.get(review_key(&state.id, id)).is_some() {
                continue;
            }
            out.push(Finding {
                id: format!("break_glass_unreviewed:{}:{id}", state.id),
                rule: "break_glass_unreviewed".into(),
                severity: "high",
                agent: None,
                source: Some(state.id.clone()),
                title: format!("Break-glass {id} on {} has not been reviewed", state.id),
                detail: format!(
                    "Opened by {} at {} to lift {} for {}; {} call(s) went through under it. Justification: {}",
                    g["opened_by"].as_str().unwrap_or("?"),
                    g["opened_at"].as_str().unwrap_or("?"),
                    g["lifts"],
                    g["capabilities"],
                    g["calls"].as_u64().unwrap_or(0),
                    g["justification"].as_str().unwrap_or("")
                ),
                remediation: "Review the calls made under the grant and record the review (POST /api/break-glass/review)."
                    .into(),
                evidence: json!({"grant": g}),
                waiver: None,
            });
        }
    }
    out
}
