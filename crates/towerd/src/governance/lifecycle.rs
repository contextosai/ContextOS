//! Findings about lifecycle enforcement: a suspended or retired agent that a runtime
//! it has run on does not revoke (`lifecycle_not_enforced`). The revocation state is
//! read from each source's verified audit chain, not from the runtime's word.

use serde_json::json;

use super::{AgentView, Finding};
use crate::fleet::Fleet;

pub fn findings(fleet: &Fleet, views: &[AgentView]) -> Vec<Finding> {
    let mut out = Vec::new();
    for view in views {
        let Some(stage) = view
            .declaration
            .as_ref()
            .and_then(|d| d["lifecycle"].as_str())
            .filter(|s| matches!(*s, "suspended" | "retired"))
        else {
            continue;
        };
        let target = format!("agent:{}", view.activity.agent_id);
        let open: Vec<&str> = view
            .activity
            .sources
            .iter()
            .filter(|s| {
                fleet
                    .sources
                    .get(s.as_str())
                    .is_some_and(|state| !state.revocations.contains_key(&target))
            })
            .map(String::as_str)
            .collect();
        if open.is_empty() {
            continue;
        }
        out.push(Finding {
            id: format!("lifecycle_not_enforced:{}", view.key),
            rule: "lifecycle_not_enforced".into(),
            severity: "critical",
            agent: Some(view.key.clone()),
            source: None,
            title: format!("{} is {stage} but {} still admit it", view.key, open.join(", ")),
            detail: format!(
                "The agent's lifecycle is {stage}, and the verified audit chain of {} shows no revocation of it. \
                 Its runs and effects are still allowed there.",
                open.join(", ")
            ),
            remediation: "Give Tower a control key for these runtimes and revoke the agent there (fleet kill \
                          switch), or revoke it on each runtime directly."
                .into(),
            evidence: json!({"stage": stage, "sources": open, "target": target}),
            waiver: None,
        });
    }
    out
}
