//! Live compliance readiness across the fleet, derived from every runtime's verified
//! audit chains and Tower's governance findings.
//!
//! Uses the exact same control definitions as `ctx evidence-pack` (`soc2`, `eu-ai-act`,
//! `iso42001`, `nist-ai-rmf`, `owasp-agentic`). Every control reports its coverage
//! (`covered`, `partial` with what is missing, or `organizational`), live verified event
//! counts, and whether the runtime recorded events in the verified history. This is an
//! evidence index, never a certification or attestation (threat T69).

use std::collections::BTreeMap;
use std::fmt::Write as _;

use contextos_contract::canonical::sha256_canonical;
use serde_json::{Value, json};

use crate::fleet::Fleet;
use crate::governance::Finding;

pub const FRAMEWORKS: [&str; 5] = ["soc2", "eu-ai-act", "iso42001", "nist-ai-rmf", "owasp-agentic"];

const CONTROL_MAP_JSON: &str = include_str!("../../ctx/src/evidence_controls.json");

fn control_map() -> Value {
    serde_json::from_str(CONTROL_MAP_JSON).unwrap_or(Value::Null)
}

/// Evaluates live compliance readiness for `selected` frameworks (or all 5 when empty),
/// optionally scoped to one `source_filter`.
#[must_use]
pub fn evaluate(
    fleet: &Fleet,
    findings: &[Finding],
    selected: &[&str],
    source_filter: Option<&str>,
    generated_at: &str,
) -> Value {
    let mut counts: BTreeMap<String, u64> = BTreeMap::new();
    let mut sources_checked = 0usize;
    let mut verified_sources = 0usize;
    let mut broken_sources = 0usize;
    let mut verified_entries = 0u64;

    for (id, state) in &fleet.sources {
        if source_filter.is_some_and(|s| s != id) {
            continue;
        }
        sources_checked += 1;
        if state.broken.is_some() {
            broken_sources += 1;
        } else if state.verified_to > 0 {
            verified_sources += 1;
        }
        verified_entries += state.verified_to;
        for (kind, n) in &state.event_counts {
            *counts.entry(kind.clone()).or_default() += n;
        }
    }

    let open_findings: Vec<&Finding> = findings
        .iter()
        .filter(|f| f.waiver.is_none())
        .filter(|f| source_filter.is_none_or(|s| f.source.as_deref() == Some(s)))
        .collect();
    let critical = open_findings.iter().filter(|f| f.severity == "critical").count();
    let high = open_findings.iter().filter(|f| f.severity == "high").count();

    let map = control_map();
    let names: Vec<&str> = if selected.is_empty() {
        FRAMEWORKS.to_vec()
    } else {
        selected.to_vec()
    };

    let mut frameworks_out = Vec::new();
    for id in names {
        let fw = &map["frameworks"][id];
        let mut covered = 0usize;
        let mut partial = 0usize;
        let mut organizational = 0usize;
        let mut with_events = 0usize;
        let mut without_events = 0usize;
        let mut controls_out = Vec::new();

        for control in fw["controls"].as_array().into_iter().flatten() {
            let cov = control["coverage"].as_str().unwrap_or("partial");
            match cov {
                "covered" => covered += 1,
                "organizational" => organizational += 1,
                _ => partial += 1,
            }
            let events: Vec<&str> = control["events"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .collect();
            let observed: BTreeMap<&str, u64> = events
                .iter()
                .map(|k| (*k, counts.get(*k).copied().unwrap_or(0)))
                .collect();
            let total_events: u64 = observed.values().sum();
            let status = if events.is_empty() {
                "outside_audit"
            } else if total_events > 0 {
                with_events += 1;
                "events_recorded"
            } else {
                without_events += 1;
                "no_events_in_period"
            };
            controls_out.push(json!({
                "id": control["id"],
                "title": control["title"],
                "runtime": control["runtime"],
                "coverage": cov,
                "missing": control.get("missing").cloned().unwrap_or(Value::Null),
                "note": control.get("note").cloned().unwrap_or(Value::Null),
                "status": status,
                "observed": observed,
                "total_events": total_events,
            }));
        }

        frameworks_out.push(json!({
            "framework": id,
            "title": fw["title"],
            "summary": {
                "controls_total": controls_out.len(),
                "covered": covered,
                "partial": partial,
                "organizational": organizational,
                "with_events": with_events,
                "without_events": without_events,
            },
            "controls": controls_out,
        }));
    }

    let mut body = json!({
        "generated_at": generated_at,
        "certification": false,
        "disclaimer": "Live control index derived from verified runtime audit chains and Tower governance findings. Counts show events recorded, not regulatory certification or control effectiveness; calls bypassing ContextOS gateways are outside coverage.",
        "scope": {
            "source": source_filter,
            "sources_checked": sources_checked,
            "verified_sources": verified_sources,
            "broken_sources": broken_sources,
            "verified_entries": verified_entries,
            "open_critical_findings": critical,
            "open_high_findings": high,
        },
        "frameworks": frameworks_out,
    });
    let digest = sha256_canonical(&body).unwrap_or_default();
    body["digest"] = json!(digest);
    body
}

/// Renders a compliance readiness report as Markdown for auditors without Tower.
#[must_use]
pub fn markdown(report: &Value) -> String {
    let s = |v: &Value| v.as_str().unwrap_or("").replace('|', "/");
    let scope = &report["scope"];
    let mut out = format!(
        "# ContextOS Live Compliance Readiness Report\n\n\
         Generated: `{}` · Sources checked: {} (verified: {}, broken: {}) · Verified audit entries: {} · \
         Open findings: {} critical, {} high.\n\n\
         > **Scope notice:** {}\n",
        s(&report["generated_at"]),
        scope["sources_checked"],
        scope["verified_sources"],
        scope["broken_sources"],
        scope["verified_entries"],
        scope["open_critical_findings"],
        scope["open_high_findings"],
        s(&report["disclaimer"]),
    );

    for fw in report["frameworks"].as_array().into_iter().flatten() {
        let sum = &fw["summary"];
        let _ = write!(
            out,
            "\n## {} (`{}`)\n\n\
             Controls: {} total · {} covered · {} partial · {} organizational · {} with recorded events.\n\n\
             | Control | Coverage | Status | Verified events |\n|---|---|---|---|\n",
            s(&fw["title"]),
            s(&fw["framework"]),
            sum["controls_total"],
            sum["covered"],
            sum["partial"],
            sum["organizational"],
            sum["with_events"],
        );
        for c in fw["controls"].as_array().into_iter().flatten() {
            let cov = match c["missing"].as_str() {
                Some(m) => format!("{}: {}", s(&c["coverage"]), m.replace('|', "/")),
                None => s(&c["coverage"]),
            };
            let obs: Vec<String> = c["observed"]
                .as_object()
                .into_iter()
                .flatten()
                .map(|(k, n)| format!("`{k}` {n}"))
                .collect();
            let detail = if obs.is_empty() { s(&c["note"]) } else { obs.join(", ") };
            let _ = writeln!(
                out,
                "| {} {} | {} | {} | {} |",
                s(&c["id"]),
                s(&c["title"]),
                cov,
                s(&c["status"]).replace('_', " "),
                detail
            );
        }
    }
    let _ = writeln!(
        out,
        "\nReport digest `{}` recorded in Tower's signed journal (`compliance_report_exported`); \
         verify Tower's journal with `ctx audit-verify` against `GET /api/journal/keys`.",
        s(&report["digest"])
    );
    out
}

#[cfg(test)]
mod tests {
    use contextos_audit::{AuditSigner, AuditWriter};
    use contextos_store::MemoryLog;

    use super::*;

    #[tokio::test]
    async fn live_compliance_counts_verified_events_and_never_claims_certification() {
        let writer = AuditWriter::new(MemoryLog::new(), AuditSigner::from_seed("k1", [9u8; 32]));
        let e1 = writer
            .append(
                "tenant_a",
                "run_admitted",
                json!({"run_id": "r1", "trace_id": "t1", "pack_ref": "p@1", "agent": {"principal_id": "agt_1"}}),
                "2026-11-27T10:00:00Z",
            )
            .await
            .unwrap();
        let e2 = writer
            .append(
                "tenant_a",
                "authorization_decision",
                json!({"run_id": "r1", "verdict": "allow"}),
                "2026-11-27T10:00:01Z",
            )
            .await
            .unwrap();
        let mut fleet = Fleet::new(100, 48);
        fleet.apply("eu-prod", &e1);
        fleet.apply("eu-prod", &e2);

        let report = evaluate(&fleet, &[], &["soc2"], None, "2026-11-27T10:05:00Z");
        assert_eq!(report["certification"], false);
        assert_eq!(report["scope"]["verified_sources"], 1);
        assert_eq!(report["scope"]["verified_entries"], 2);
        let cc61 = &report["frameworks"][0]["controls"][0];
        assert_eq!(cc61["id"], "CC6.1");
        assert_eq!(cc61["status"], "events_recorded");
        assert_eq!(cc61["observed"]["run_admitted"], 1);
        assert_eq!(cc61["observed"]["authorization_decision"], 1);

        let md = markdown(&report);
        assert!(md.contains("SOC 2"));
        assert!(md.contains("compliance_report_exported"));
    }
}
