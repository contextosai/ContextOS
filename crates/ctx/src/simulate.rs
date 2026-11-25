//! `ctx simulate`: what a candidate pack would decide differently from the baseline on
//! recorded cases (`GET /v1/runs/{run_id}/replay-case`), as a JSON report and,
//! optionally, a Markdown summary for reviewers (see
//! [`contextos_kernel::simulation`]).

use std::path::{Path, PathBuf};

use contextos_contract::types::ContextPack;
use contextos_kernel::release_gate::ReplayCase;
use contextos_kernel::simulation::{markdown, simulate};
use serde_json::Value;

use crate::{Failure, read, typed};

/// At most this many case files are read from one directory.
const MAX_FILES: usize = 100_000;

pub(crate) struct Options<'a> {
    pub baseline: &'a PathBuf,
    pub candidate: &'a PathBuf,
    pub cases: &'a [PathBuf],
    pub report: Option<&'a PathBuf>,
    pub fail_on_widening: bool,
}

/// Cases from a file holding one case, an array of cases, or `{"cases": [...]}`.
fn cases_in(path: &PathBuf, out: &mut Vec<ReplayCase>) -> Result<(), Failure> {
    let value = read(path)?;
    let list = match value {
        Value::Array(items) => items,
        Value::Object(ref o) if o.get("cases").is_some_and(Value::is_array) => {
            o["cases"].as_array().cloned().unwrap_or_default()
        }
        single => vec![single],
    };
    for item in list {
        out.push(typed(item, &format!("{}: case", path.display()))?);
    }
    Ok(())
}

/// Every case under `paths`: files, or directories of `*.json` files (not recursive),
/// read in name order.
fn load(paths: &[PathBuf]) -> Result<Vec<ReplayCase>, Failure> {
    let mut cases = Vec::new();
    for path in paths {
        if Path::new(path).is_dir() {
            let mut files: Vec<PathBuf> = std::fs::read_dir(path)
                .map_err(|e| Failure::Usage(format!("{}: {e}", path.display())))?
                .filter_map(Result::ok)
                .map(|e| e.path())
                .filter(|p| p.extension().is_some_and(|x| x == "json") && p.is_file())
                .take(MAX_FILES + 1)
                .collect();
            if files.len() > MAX_FILES {
                return Err(Failure::Usage(format!(
                    "{}: more than {MAX_FILES} case files",
                    path.display()
                )));
            }
            files.sort();
            for f in &files {
                cases_in(f, &mut cases)?;
            }
        } else {
            cases_in(path, &mut cases)?;
        }
    }
    Ok(cases)
}

pub(crate) fn run(o: &Options<'_>) -> Result<Value, Failure> {
    let baseline: ContextPack = typed(read(o.baseline)?, "baseline")?;
    let candidate: ContextPack = typed(read(o.candidate)?, "candidate")?;
    let cases = load(o.cases)?;
    let report = simulate(&baseline, &candidate, &cases).map_err(Failure::Usage)?;
    if let Some(path) = o.report {
        let name = |p: &ContextPack| format!("{}@{}", p.pack_meta.pack_id, p.pack_meta.pack_version);
        std::fs::write(path, markdown(&report, &name(&baseline), &name(&candidate)))
            .map_err(|e| Failure::Usage(format!("{}: {e}", path.display())))?;
    }
    let value = serde_json::to_value(&report).unwrap_or(Value::Null);
    let widened = report.summary.widens + report.summary.mixed + report.summary.regressions;
    if o.fail_on_widening && widened > 0 {
        return Err(Failure::Rejected(value));
    }
    Ok(value)
}
