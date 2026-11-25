//! Policy simulation: what a candidate Context Pack would decide differently from the
//! baseline across recorded cases, before it is rolled out.
//!
//! The release gate ([`crate::release_gate`]) answers "may this candidate ship?" and
//! fails on unacknowledged widenings. Simulation answers "what would change?": for every
//! recorded case it reads both packs' decisions exactly as admission does (surfaced
//! capabilities, the composed policy verdict, obligations, applying rules) and reports
//! each difference, then counts them: verdict transitions (`allow -> require_approval`),
//! capabilities newly surfaced or withdrawn, rules that start or stop applying, and
//! cases that stop compiling. It never decides anything itself; the operator reads the
//! report, then stages the rollout (shadow first, then a percentage).

use std::collections::{BTreeMap, BTreeSet};

use contextos_contract::types::ContextPack;
use serde::Serialize;

use crate::ContextPackCompiler;
use crate::pack_observation::{Observed, VERDICTS};
use crate::release_gate::ReplayCase;

/// One pack's reading of one case.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Reading {
    pub compiles: bool,
    /// `deny`, `escalate`, `require_approval` or `allow`; absent when it does not compile.
    pub verdict: Option<&'static str>,
    pub capabilities: BTreeSet<String>,
    pub obligations: BTreeSet<String>,
    pub rules: BTreeSet<String>,
    /// Why it does not compile.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl Reading {
    fn of(result: Result<Observed, String>) -> Self {
        match result {
            Ok(o) => Self {
                compiles: true,
                verdict: Some(VERDICTS[o.verdict]),
                capabilities: o.capabilities,
                obligations: o.obligations,
                rules: o.rules,
                error: None,
            },
            Err(e) => Self {
                compiles: false,
                verdict: None,
                capabilities: BTreeSet::new(),
                obligations: BTreeSet::new(),
                rules: BTreeSet::new(),
                error: Some(e),
            },
        }
    }

    fn rank(&self) -> Option<usize> {
        self.verdict.and_then(|v| VERDICTS.iter().position(|x| *x == v))
    }
}

/// One case under both packs.
#[derive(Debug, Clone, Serialize)]
pub struct CaseDiff {
    pub name: String,
    pub baseline: Reading,
    pub candidate: Reading,
    /// `unchanged`, `widens` (more allowed), `narrows` (less allowed), `mixed`, or
    /// `regression` (the candidate no longer compiles it).
    pub effect: &'static str,
}

/// Counts over every case.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Summary {
    pub cases: usize,
    pub changed: usize,
    pub widens: usize,
    pub narrows: usize,
    pub mixed: usize,
    pub regressions: usize,
    /// `before -> after` verdict to number of cases.
    pub verdict_transitions: BTreeMap<String, usize>,
    /// Capability to the number of cases that newly surface it.
    pub capabilities_added: BTreeMap<String, usize>,
    pub capabilities_removed: BTreeMap<String, usize>,
    /// Rule id to the number of cases it newly applies to, or stops applying to.
    pub rules_added: BTreeMap<String, usize>,
    pub rules_removed: BTreeMap<String, usize>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SimulationReport {
    pub summary: Summary,
    pub cases: Vec<CaseDiff>,
}

fn effect(b: &Reading, c: &Reading) -> &'static str {
    match (b.compiles, c.compiles) {
        (true, false) => return "regression",
        // Admitting a case the baseline refused is new behaviour, whatever it decides.
        (false, true) => return "widens",
        (false, false) => return "unchanged",
        (true, true) => {}
    }
    let (mut wider, mut narrower) = (false, false);
    match (b.rank(), c.rank()) {
        (Some(x), Some(y)) if y > x => wider = true,
        (Some(x), Some(y)) if y < x => narrower = true,
        _ => {}
    }
    wider |= !c.capabilities.is_subset(&b.capabilities) || !b.obligations.is_subset(&c.obligations);
    narrower |= !b.capabilities.is_subset(&c.capabilities) || !c.obligations.is_subset(&b.obligations);
    match (wider, narrower) {
        (true, true) => "mixed",
        (true, false) => "widens",
        (false, true) => "narrows",
        (false, false) if b.rules != c.rules => "mixed",
        (false, false) => "unchanged",
    }
}

fn count<'a>(map: &mut BTreeMap<String, usize>, items: impl Iterator<Item = &'a String>) {
    for i in items {
        *map.entry(i.clone()).or_default() += 1;
    }
}

/// Reads every case under `baseline` and `candidate` and reports the differences.
pub fn simulate(
    baseline: &ContextPack,
    candidate: &ContextPack,
    cases: &[ReplayCase],
) -> Result<SimulationReport, String> {
    if cases.is_empty() {
        return Err("simulation needs at least one recorded case".into());
    }
    let mut names = BTreeSet::new();
    if let Some(case) = cases.iter().find(|c| !names.insert(c.name.as_str())) {
        return Err(format!("case {} appears more than once", case.name));
    }
    let base = ContextPackCompiler::new(baseline.clone()).map_err(|e| format!("baseline: {e}"))?;
    let cand = ContextPackCompiler::new(candidate.clone()).map_err(|e| format!("candidate: {e}"))?;
    let read = |compiler: &ContextPackCompiler, case: &ReplayCase| {
        Reading::of(crate::pack_observation::observe(
            compiler,
            &case.request,
            &case.run_context,
            &case.deps,
        ))
    };
    let mut summary = Summary {
        cases: cases.len(),
        ..Summary::default()
    };
    let mut diffs = Vec::with_capacity(cases.len());
    for case in cases {
        let (b, c) = (read(&base, case), read(&cand, case));
        let effect = effect(&b, &c);
        match effect {
            "widens" => summary.widens += 1,
            "narrows" => summary.narrows += 1,
            "mixed" => summary.mixed += 1,
            "regression" => summary.regressions += 1,
            _ => {}
        }
        if effect != "unchanged" {
            summary.changed += 1;
            let label = |r: &Reading| r.verdict.unwrap_or("does_not_compile");
            if label(&b) != label(&c) {
                *summary
                    .verdict_transitions
                    .entry(format!("{} -> {}", label(&b), label(&c)))
                    .or_default() += 1;
            }
            count(
                &mut summary.capabilities_added,
                c.capabilities.difference(&b.capabilities),
            );
            count(
                &mut summary.capabilities_removed,
                b.capabilities.difference(&c.capabilities),
            );
            count(&mut summary.rules_added, c.rules.difference(&b.rules));
            count(&mut summary.rules_removed, b.rules.difference(&c.rules));
        }
        diffs.push(CaseDiff {
            name: case.name.clone(),
            baseline: b,
            candidate: c,
            effect,
        });
    }
    Ok(SimulationReport { summary, cases: diffs })
}

/// The report as Markdown for a reviewer: the counts, then every changed case.
#[must_use]
pub fn markdown(report: &SimulationReport, baseline: &str, candidate: &str) -> String {
    use std::fmt::Write as _;
    let s = &report.summary;
    let mut out = format!(
        "# Policy simulation: {baseline} -> {candidate}\n\n{} recorded cases, {} would change: {} widen (more allowed), {} narrow, {} mixed, {} no longer compile.\n",
        s.cases, s.changed, s.widens, s.narrows, s.mixed, s.regressions
    );
    let table = |out: &mut String, title: &str, map: &BTreeMap<String, usize>| {
        if map.is_empty() {
            return;
        }
        let _ = write!(out, "\n## {title}\n\n| | Cases |\n|---|---|\n");
        for (k, n) in map {
            let _ = writeln!(out, "| `{k}` | {n} |");
        }
    };
    table(&mut out, "Verdict changes", &s.verdict_transitions);
    table(&mut out, "Capabilities newly surfaced", &s.capabilities_added);
    table(&mut out, "Capabilities withdrawn", &s.capabilities_removed);
    table(&mut out, "Rules that start applying", &s.rules_added);
    table(&mut out, "Rules that stop applying", &s.rules_removed);
    let changed: Vec<&CaseDiff> = report.cases.iter().filter(|c| c.effect != "unchanged").collect();
    if !changed.is_empty() {
        out.push_str("\n## Changed cases\n\n| Case | Effect | Verdict | Detail |\n|---|---|---|---|\n");
        for c in changed {
            let v = |r: &Reading| r.verdict.unwrap_or("does not compile");
            let mut detail = Vec::new();
            let added: Vec<&String> = c.candidate.capabilities.difference(&c.baseline.capabilities).collect();
            let removed: Vec<&String> = c.baseline.capabilities.difference(&c.candidate.capabilities).collect();
            if !added.is_empty() {
                detail.push(format!("surfaces {}", join(&added)));
            }
            if !removed.is_empty() {
                detail.push(format!("withdraws {}", join(&removed)));
            }
            if let Some(e) = &c.candidate.error {
                detail.push(format!("candidate: {}", e.replace('|', "/")));
            }
            let _ = writeln!(
                out,
                "| `{}` | {} | {} -> {} | {} |",
                c.name.replace('|', "/"),
                c.effect,
                v(&c.baseline),
                v(&c.candidate),
                detail.join("; ")
            );
        }
    }
    out.push_str(
        "\nRead from recorded cases only: a case that was never recorded is not simulated. Stage the rollout (shadow, then a percentage) to see live traffic.\n",
    );
    out
}

fn join(items: &[&String]) -> String {
    items.iter().map(|s| format!("`{s}`")).collect::<Vec<_>>().join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reading(verdict: Option<&'static str>, caps: &[&str], obligations: &[&str]) -> Reading {
        let set = |xs: &[&str]| xs.iter().map(|s| (*s).to_owned()).collect();
        Reading {
            compiles: verdict.is_some(),
            verdict,
            capabilities: set(caps),
            obligations: set(obligations),
            rules: BTreeSet::new(),
            error: None,
        }
    }

    #[test]
    fn effects_follow_what_is_allowed() {
        let base = reading(Some("require_approval"), &["a"], &["verify"]);
        assert_eq!(effect(&base, &base.clone()), "unchanged");
        assert_eq!(effect(&base, &reading(Some("allow"), &["a"], &["verify"])), "widens");
        assert_eq!(effect(&base, &reading(Some("deny"), &["a"], &["verify"])), "narrows");
        // Dropping an obligation widens; adding a capability widens.
        assert_eq!(effect(&base, &reading(Some("require_approval"), &["a"], &[])), "widens");
        assert_eq!(
            effect(&base, &reading(Some("require_approval"), &["a", "b"], &["verify"])),
            "widens"
        );
        // Stricter verdict but a new capability: both directions.
        assert_eq!(effect(&base, &reading(Some("deny"), &["a", "b"], &["verify"])), "mixed");
        assert_eq!(effect(&base, &reading(None, &[], &[])), "regression");
        assert_eq!(effect(&reading(None, &[], &[]), &base), "widens");
    }

    #[test]
    fn markdown_escapes_table_cells() {
        let mut c = reading(None, &[], &[]);
        c.error = Some("bad | input".into());
        let report = SimulationReport {
            summary: Summary {
                cases: 1,
                changed: 1,
                regressions: 1,
                ..Summary::default()
            },
            cases: vec![CaseDiff {
                name: "a|b".into(),
                baseline: reading(Some("allow"), &[], &[]),
                candidate: c,
                effect: "regression",
            }],
        };
        let md = markdown(&report, "p@1", "p@2");
        assert!(
            md.contains("| `a/b` | regression | allow -> does not compile | candidate: bad / input |"),
            "{md}"
        );
    }
}
