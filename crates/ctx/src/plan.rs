//! `ctx plan`: a decision plan (see `contextos_kernel::decision_plan`) as JSON.

use std::path::PathBuf;

use contextos_contract::types::{ContextPack, RunContext};
use contextos_kernel::decision_plan::plan_decisions;
use serde_json::Value;

use crate::{Failure, read, typed};

pub fn run(pack: &PathBuf, run: &PathBuf, intent: Option<&str>) -> Result<Value, Failure> {
    let pack: ContextPack = typed(read(pack)?, "pack")?;
    let body = read(run)?;
    // An admission body carries the run context beside the request.
    let run_context = if body.get("run_context").is_some() {
        &body["run_context"]
    } else {
        &body
    };
    let intent = intent
        .map(str::to_owned)
        .or_else(|| run_context["intent"].as_str().map(str::to_owned))
        .or_else(|| body["request"]["input"]["intent"].as_str().map(str::to_owned))
        .filter(|i| !i.is_empty())
        .ok_or_else(|| Failure::Usage("no intent: pass --intent or set run_context.intent".into()))?;
    // The same bound as `POST /v1/plan`.
    if intent.len() > 256 {
        return Err(Failure::Usage("intent is longer than 256 bytes".into()));
    }
    let run_context: RunContext = typed(run_context.clone(), "run context")?;
    let plan =
        plan_decisions(&pack, &run_context, &intent).map_err(|e| Failure::Rejected(serde_json::json!({"error": e})))?;
    serde_json::to_value(plan).map_err(|e| Failure::Usage(e.to_string()))
}
