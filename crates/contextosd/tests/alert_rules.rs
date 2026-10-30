//! The shipped alerting rules only reference metrics the server exports, so renaming a
//! metric cannot silently disable an alert.

use std::collections::BTreeSet;
use std::time::Duration;

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

#[test]
fn every_metric_in_the_rules_is_exported() {
    let metrics = Metrics::default();
    metrics.observe("/v1/runs/{run_id}/dispatch", 200, Duration::from_millis(3));
    metrics.dispatch_outcome("x.y", "blocked", &["shared_guarantee_saturated".into()]);
    // `contextos_replicas` is appended by the `/metrics` handler.
    let exposition = format!("{}# TYPE contextos_replicas gauge\n", metrics.render());
    let rules = rules();
    let names = referenced(&rules);
    assert!(names.contains("contextos_dispatch_outcomes_total"), "{names:?}");
    for name in &names {
        assert!(
            exposition.contains(&format!("# TYPE {name} ")),
            "the rules reference {name}, which /metrics does not export"
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
    assert!(alerts.len() >= 6, "{alerts:?}");
    for alert in alerts {
        let anchor = format!("INCIDENT.md#{}", alert.to_ascii_lowercase());
        assert!(rules.contains(&anchor), "{alert} has no runbook_url to {anchor}");
        assert!(
            incident.contains(&format!("### {alert}\n")),
            "docs/INCIDENT.md has no section for {alert}"
        );
    }
}
