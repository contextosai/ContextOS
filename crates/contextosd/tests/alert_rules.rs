//! The shipped alerting rules only reference metrics the server exports, so renaming a
//! metric cannot silently disable an alert.

use std::collections::BTreeSet;
use std::time::Duration;

use contextosd::governance_sweep::Census;
use contextosd::metrics::Metrics;

fn rules() -> String {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../deploy/helm/contextosd/files/contextos-rules.yaml"
    );
    std::fs::read_to_string(path).expect("rules file")
}

/// Raw metric names in the rules (`contextos_…`); recording rules (`contextos:…`) are
/// defined by the file itself.
fn referenced(rules: &str) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    let bytes = rules.as_bytes();
    let mut i = 0;
    while let Some(at) = rules[i..].find("contextos_") {
        let start = i + at;
        let boundary = start == 0 || !(bytes[start - 1].is_ascii_alphanumeric() || bytes[start - 1] == b'_');
        let end = rules[start..]
            .find(|c: char| !(c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'))
            .map_or(rules.len(), |n| start + n);
        if boundary {
            names.insert(rules[start..end].to_owned());
        }
        i = end;
    }
    names
}

/// Everything `/metrics` can export, with each labelled family present.
fn exposition() -> String {
    let metrics = Metrics::default();
    metrics.observe("/v1/runs/{run_id}/dispatch", 200, Duration::from_millis(3));
    metrics.dispatch_outcome("x.y", "blocked", &["shared_guarantee_saturated".into()]);
    // The leader's governance gauges.
    metrics.set_governance(Some(Census::empty_exposition(vec!["refunds".into()])));
    // `contextos_replicas` is appended by the `/metrics` handler.
    format!("{}# TYPE contextos_replicas gauge\n", metrics.render())
}

fn assert_exported(names: &BTreeSet<String>, source: &str) {
    let exposition = exposition();
    for name in names {
        assert!(
            exposition.contains(&format!("# TYPE {name} ")),
            "{source} references {name}, which /metrics does not export"
        );
    }
}

#[test]
fn every_metric_in_the_rules_is_exported() {
    let rules = rules();
    let names = referenced(&rules);
    assert!(names.contains("contextos_dispatch_outcomes_total"), "{names:?}");
    assert!(names.contains("contextos_shared_hold_oldest_seconds"), "{names:?}");
    assert_exported(&names, "the alerting rules");
}

#[test]
fn every_metric_on_the_dashboard_is_exported_or_recorded() {
    let dashboard = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../deploy/grafana/contextos-governance.json"
    ))
    .expect("dashboard");
    let names = referenced(&dashboard);
    assert!(names.contains("contextos_shared_holds"), "{names:?}");
    assert_exported(&names, "the dashboard");
    let rules = rules();
    for line in dashboard.lines().filter(|l| l.contains("contextos:")) {
        let start = line.find("contextos:").unwrap();
        let end = line[start..]
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == ':'))
            .map_or(line.len(), |n| start + n);
        let record = &line[start..end];
        assert!(
            rules.contains(&format!("record: {record}\n")),
            "the dashboard uses {record}, which no rule records"
        );
    }
}

#[test]
fn every_alert_links_its_runbook_section() {
    let incident = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs/INCIDENT.md"))
        .expect("incident runbook");
    let rules = rules();
    let alerts: Vec<&str> = rules
        .lines()
        .filter_map(|l| l.trim().strip_prefix("- alert: "))
        .collect();
    assert!(alerts.len() >= 12, "{alerts:?}");
    for alert in alerts {
        let anchor = format!("INCIDENT.md#{}", alert.to_ascii_lowercase());
        assert!(rules.contains(&anchor), "{alert} has no runbook_url to {anchor}");
        assert!(
            incident.contains(&format!("### {alert}\n")),
            "docs/INCIDENT.md has no section for {alert}"
        );
    }
}
