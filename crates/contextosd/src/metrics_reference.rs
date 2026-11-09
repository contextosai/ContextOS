//! The metric reference (`docs/METRICS.md`), rendered from what `/metrics` exports so it
//! cannot drift: every family appears with a sample of each label, and the reference
//! lists its type, labels and help text.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::time::Duration;

use crate::metrics::Metrics;

/// An exposition with every metric family present and labelled.
#[must_use]
pub fn full_exposition() -> String {
    let metrics = Metrics::default();
    metrics.observe("/v1/runs/{run_id}/dispatch", 200, Duration::from_millis(3));
    metrics.dispatch_outcome("x.y", "blocked", &["shared_guarantee_saturated".into()]);
    metrics.approval("x.y", Some(&contextos_gateway::ApprovalNote::Requested));
    metrics.approval(
        "x.y",
        Some(&contextos_gateway::ApprovalNote::Redeemed {
            decision_seconds: Some(42),
        }),
    );
    metrics.admission("pack");
    metrics.decision("allowed");
    metrics.task_amendment("narrowed");
    metrics.agent_binding_mismatch("observe");
    metrics.user_binding_mismatch("missing");
    metrics.pack_intent_mismatch("observe");
    metrics.over_limit_import("refunds");
    metrics.notification("oncall", "delivered");
    metrics.audit_sink("siem", "accepted");
    metrics.set_governance(Some(crate::governance_sweep::Census::empty_exposition(vec![
        "refunds".into(),
    ])));
    metrics.set_upstream(Some(crate::upstream_check::exposition(
        &[(
            "x.y".to_owned(),
            contextos_gateway::upstream_drift::UpstreamStatus::Drifted,
        )]
        .into(),
    )));
    format!("{}{}", metrics.render(), replicas())
}

fn replicas() -> String {
    crate::metrics::replicas_exposition(1)
}

#[derive(Default)]
struct Family {
    kind: String,
    help: String,
    labels: Vec<String>,
}

/// Label names of one sample line (`name{a="1",b="2"} 3`), without `le`.
fn label_names(sample: &str) -> Vec<String> {
    let Some(open) = sample.find('{') else {
        return Vec::new();
    };
    let close = sample.rfind('}').unwrap_or(sample.len());
    sample[open + 1..close]
        .split("\",")
        .filter_map(|pair| pair.split_once('=').map(|(k, _)| k.trim().to_owned()))
        .filter(|k| k != "le")
        .collect()
}

/// `docs/METRICS.md`.
#[must_use]
pub fn reference() -> String {
    let mut families: BTreeMap<String, Family> = BTreeMap::new();
    for line in full_exposition().lines() {
        if let Some(rest) = line.strip_prefix("# HELP ") {
            let (name, help) = rest.split_once(' ').unwrap_or((rest, ""));
            help.clone_into(&mut families.entry(name.to_owned()).or_default().help);
        } else if let Some(rest) = line.strip_prefix("# TYPE ") {
            let (name, kind) = rest.split_once(' ').unwrap_or((rest, ""));
            kind.clone_into(&mut families.entry(name.to_owned()).or_default().kind);
        } else if !line.starts_with('#') {
            let name = line.split(['{', ' ']).next().unwrap_or_default();
            let family = ["_bucket", "_sum", "_count"]
                .iter()
                .find_map(|s| name.strip_suffix(s).filter(|base| families.contains_key(*base)))
                .unwrap_or(name);
            if let Some(f) = families.get_mut(family)
                && f.labels.is_empty()
            {
                f.labels = label_names(line);
            }
        }
    }
    let mut out = String::from(
        "# contextosd metric reference\n\n\
         Generated from what `GET /metrics` exports by\n\
         `CONTEXTOS_BLESS=1 cargo test -p contextosd --test generated`; do not edit by hand.\n\
         Labels are bounded: capabilities, packs and guarantees are the ones configured at\n\
         startup, and statuses and reason codes are the runtime's own. Tenants are not a\n\
         label; per-tenant evidence is in the audit chain. The governance sweep's gauges\n\
         (`contextos_shared_holds`, `contextos_shared_hold_oldest_seconds`,\n\
         `contextos_shared_receipts_fill_ratio`, `contextos_shared_ledgers_unreadable`,\n\
         `contextos_escalations_open`, `contextos_approvals_timed_out_total` and\n\
         `contextos_governance_sweep_completed_timestamp_seconds`)\n\
         come only from the replica leading the sweep.\n\n\
         | Metric | Type | Labels | Description |\n|---|---|---|---|\n",
    );
    for (name, family) in &families {
        let labels = if family.labels.is_empty() {
            "none".to_owned()
        } else {
            family
                .labels
                .iter()
                .map(|l| format!("`{l}`"))
                .collect::<Vec<_>>()
                .join(", ")
        };
        let _ = writeln!(
            out,
            "| `{name}` | {} | {labels} | {} |",
            family.kind,
            family.help.replace('|', "\\|")
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_family_has_a_type_and_help() {
        let reference = reference();
        assert!(reference.contains("| `contextos_http_request_duration_ms` | histogram | `route` |"));
        assert!(reference.contains("| `contextos_replicas` | gauge | none |"));
        assert!(!reference.contains("|  |"), "a family lacks help or type:\n{reference}");
    }
}
