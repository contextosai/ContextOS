//! The trajectory gate's per-case summaries (`ctx trajectory-gate`): what the runs of
//! each case did, from evidence bundles and, when given, the signed audit chain.

use std::path::PathBuf;

use serde_json::{Value, json};

use crate::{Failure, read};

/// What the runs of one case did, across trials.
#[derive(Default)]
pub(crate) struct Trajectory {
    pub(crate) capabilities: std::collections::BTreeSet<String>,
    /// `decision_key=outcome` of every recorded decision, across trials.
    pub(crate) outcomes: std::collections::BTreeSet<String>,
    /// The most effects (applied mutations) and tool calls any one trial made.
    pub(crate) max_effects: usize,
    pub(crate) max_tool_calls: u64,
}

/// Per run, from the audit chain: the capabilities claimed and the effects confirmed.
pub(crate) type Recorded = std::collections::HashMap<String, (std::collections::BTreeSet<String>, usize)>;

pub(crate) fn runs_from_audit(entries: &[Value]) -> Recorded {
    let mut runs = Recorded::new();
    for entry in entries {
        let payload = &entry["payload"];
        let Some(run) = payload["run_id"].as_str() else {
            continue;
        };
        match entry["kind"].as_str() {
            Some("operation_claim") => {
                if let Some(capability) = payload["capability_id"].as_str() {
                    runs.entry(run.to_owned()).or_default().0.insert(capability.to_owned());
                }
            }
            Some("effect_observation") if matches!(payload["outcome"].as_str(), Some("confirmed" | "partial")) => {
                runs.entry(run.to_owned()).or_default().1 += 1;
            }
            _ => {}
        }
    }
    runs
}

pub(crate) fn trajectories(
    paths: &[PathBuf],
    map: &Value,
    recorded: Option<&Recorded>,
) -> Result<std::collections::BTreeMap<String, Trajectory>, Failure> {
    let mut cases: std::collections::BTreeMap<String, Trajectory> = std::collections::BTreeMap::new();
    for path in paths {
        let bundle = read(path)?;
        let Some(run_id) = bundle["run_id"].as_str() else {
            return Err(Failure::Rejected(
                json!({"error": format!("{}: not an evidence bundle", path.display())}),
            ));
        };
        let case = cases
            .entry(map[run_id].as_str().unwrap_or(run_id).to_owned())
            .or_default();
        let mut effects = 0;
        for decision in bundle["decisions"].as_array().into_iter().flatten() {
            let record = &decision["record"];
            case.outcomes.insert(format!(
                "{}={}",
                record["decision_key"].as_str().unwrap_or_default(),
                record["outcome"].as_str().unwrap_or("none")
            ));
            for call in record["tool_lineage"].as_array().into_iter().flatten() {
                if let Some(capability) = call["capability_id"].as_str() {
                    case.capabilities.insert(capability.to_owned());
                }
                effects += call["mutation_refs"].as_array().map_or(0, Vec::len);
            }
        }
        // The signed record, when given, replaces what the decisions reported.
        if let Some(recorded) = recorded {
            let (capabilities, applied) = recorded.get(run_id).cloned().unwrap_or_default();
            case.capabilities.extend(capabilities);
            effects = applied;
        }
        case.max_effects = case.max_effects.max(effects);
        let calls = bundle["budget_ledger"]["used"]["tool_calls"].as_u64().unwrap_or(0);
        case.max_tool_calls = case.max_tool_calls.max(calls);
    }
    Ok(cases)
}
