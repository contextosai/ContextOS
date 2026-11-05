//! `ctx test`: run pack test suites (see `contextos_kernel::pack_test`) and report
//! them as JSON, optionally as JUnit XML for CI.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use contextos_contract::types::ContextPack;
use contextos_kernel::pack_test::{PackTestSuite, SuiteReport, run_pack_tests};
use serde_json::{Map, Value, json};

use crate::{Failure, read, typed};

/// The parts of a case kept from a file named as the base (a replay case exported by
/// `GET /v1/runs/{id}/replay-case`, or an admission body such as `run.json`).
const CASE_KEYS: [&str; 3] = ["request", "run_context", "deps"];

fn relative(suite: &Path, name: &str) -> PathBuf {
    suite.parent().unwrap_or_else(|| Path::new(".")).join(name)
}

/// A base given as a file path, and any of its parts given as file paths, are read
/// relative to the suite file.
fn resolve_base(suite_path: &Path, suite: &mut Value) -> Result<(), Failure> {
    if let Some(name) = suite["base"].as_str() {
        let file = read(&relative(suite_path, name))?;
        let kept: Map<String, Value> = file
            .as_object()
            .into_iter()
            .flatten()
            .filter(|(k, _)| CASE_KEYS.contains(&k.as_str()))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        suite["base"] = Value::Object(kept);
    }
    for key in CASE_KEYS {
        if let Some(name) = suite["base"][key].as_str() {
            suite["base"][key] = read(&relative(suite_path, name))?;
        }
    }
    Ok(())
}

fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn junit(reports: &[SuiteReport]) -> String {
    let total: usize = reports.iter().map(|r| r.tests.len()).sum();
    let failed: usize = reports.iter().map(|r| r.failed).sum();
    let mut xml = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<testsuites name=\"ctx test\" tests=\"{total}\" failures=\"{failed}\">\n"
    );
    for report in reports {
        let errors = report.tests.iter().filter(|t| t.status == "error").count();
        let failures = report.failed - errors;
        let _ = writeln!(
            xml,
            "  <testsuite name=\"{}\" tests=\"{}\" failures=\"{failures}\" errors=\"{errors}\">",
            escape(&report.suite),
            report.tests.len()
        );
        for test in &report.tests {
            let name = escape(&test.name);
            let suite = escape(&report.suite);
            let detail = escape(&test.failures.join("\n"));
            match test.status.as_str() {
                "pass" => {
                    let _ = writeln!(xml, "    <testcase name=\"{name}\" classname=\"{suite}\"/>");
                }
                status => {
                    let element = if status == "error" { "error" } else { "failure" };
                    let message = escape(test.failures.first().map_or("", String::as_str));
                    let _ = writeln!(
                        xml,
                        "    <testcase name=\"{name}\" classname=\"{suite}\">\n      <{element} message=\"{message}\">{detail}</{element}>\n    </testcase>"
                    );
                }
            }
        }
        xml.push_str("  </testsuite>\n");
    }
    xml.push_str("</testsuites>\n");
    xml
}

pub fn run(pack: &PathBuf, suites: &[PathBuf], junit_path: Option<&PathBuf>) -> Result<Value, Failure> {
    let pack: ContextPack = typed(read(pack)?, "pack")?;
    let mut reports = Vec::with_capacity(suites.len());
    for path in suites {
        let mut suite = read(path)?;
        resolve_base(path, &mut suite)?;
        let suite: PackTestSuite = typed(suite, &path.display().to_string())?;
        let report = run_pack_tests(&pack, &suite).map_err(|e| Failure::Usage(format!("{}: {e}", path.display())))?;
        reports.push(report);
    }
    if let Some(out) = junit_path {
        std::fs::write(out, junit(&reports)).map_err(|e| Failure::Usage(format!("{}: {e}", out.display())))?;
    }
    let passed: usize = reports.iter().map(|r| r.passed).sum();
    let failed: usize = reports.iter().map(|r| r.failed).sum();
    let value = json!({
        "verdict": if failed == 0 { "pass" } else { "fail" },
        "passed": passed,
        "failed": failed,
        "suites": reports,
    });
    if failed == 0 {
        Ok(value)
    } else {
        Err(Failure::Rejected(value))
    }
}
