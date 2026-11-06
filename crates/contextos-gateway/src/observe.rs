//! What each governed call tells operators: one span and one access event per call,
//! whichever entry point ran it (dispatch, MCP, continuation, check, compensation).
//!
//! - The span `contextos.dispatch` carries the OpenTelemetry GenAI conventions for a
//!   tool execution (`gen_ai.operation.name = "execute_tool"`, `gen_ai.tool.name`,
//!   `gen_ai.tool.call.id`), so trace backends that understand agent traces show the
//!   call as a tool step, plus the ContextOS outcome (`contextos.status`,
//!   `contextos.reason_codes`) and where the pipeline stopped (`contextos.stage`).
//! - `contextos.stages` times each pipeline stage the call reached, in milliseconds
//!   (`fence=0.1 surface=0.2 bind=0.4 authorize=3.1 …`), so a slow or refusing stage
//!   is visible without a debugger.
//! - The event on target `contextos::access` is the access log: one JSON line per
//!   governed call with tenant, run, capability, status, reason codes, stage and
//!   duration. A call that fails on infrastructure (the store or the audit chain)
//!   leaves one too, with `status="error"`, the failing dependency as its reason and
//!   an empty stage. Select it with `RUST_LOG=info,contextos::access=info`, or silence it
//!   with `contextos::access=off`. The signed audit chain remains the record of what
//!   happened; this line is for searching and dashboards.

use std::fmt::Write as _;
use std::time::Instant;

/// Pipeline stages, in order.
pub(crate) const STAGES: [&str; 9] = [
    "fence",
    "surface",
    "bind",
    "authorize",
    "reserve",
    "claim",
    "dispatch",
    "settle",
    "result",
];

/// The stages a call reached and how long each took.
#[derive(Debug)]
pub(crate) struct Stages {
    current: &'static str,
    since: Instant,
    timings: Vec<(&'static str, f64)>,
}

impl Stages {
    pub(crate) fn new() -> Self {
        Self {
            current: STAGES[0],
            since: Instant::now(),
            timings: Vec::new(),
        }
    }

    /// Ends the current stage and starts `stage`.
    pub(crate) fn enter(&mut self, stage: &'static str) {
        debug_assert!(STAGES.contains(&stage), "unknown stage {stage}");
        self.close();
        self.current = stage;
    }

    fn close(&mut self) {
        let now = Instant::now();
        let ms = now.duration_since(self.since).as_secs_f64() * 1000.0;
        match self.timings.last_mut() {
            Some((name, total)) if *name == self.current => *total += ms,
            _ => self.timings.push((self.current, ms)),
        }
        self.since = now;
    }

    /// The stage the call ended in.
    pub(crate) fn current(&self) -> &'static str {
        self.current
    }

    /// Ends the last stage; `fence=0.1 surface=0.2 …`.
    pub(crate) fn summary(&mut self) -> String {
        self.close();
        let mut out = String::new();
        for (name, ms) in &self.timings {
            if !out.is_empty() {
                out.push(' ');
            }
            let _ = write!(out, "{name}={ms:.1}");
        }
        out
    }
}

/// What one finished call records on its span and in the access log.
#[derive(Debug)]
pub(crate) struct Finished<'a> {
    pub tenant_id: &'a str,
    pub run_id: &'a str,
    pub capability_id: &'a str,
    pub tool_call_id: &'a str,
    pub operation_id: Option<&'a str>,
    pub action_digest: Option<&'a str>,
    pub status: &'a str,
    pub reason_codes: &'a [String],
    pub stage: &'static str,
    pub stages: &'a str,
    pub duration_ms: f64,
    pub check: bool,
}

/// Records the outcome on the current span (the call's `contextos.dispatch` span) and
/// writes the access event.
pub(crate) fn finished(call: &Finished<'_>) {
    let span = tracing::Span::current();
    let reasons = call.reason_codes.join(",");
    span.record("contextos.status", call.status);
    span.record("contextos.reason_codes", reasons.as_str());
    span.record("contextos.stage", call.stage);
    span.record("contextos.stages", call.stages);
    if let Some(id) = call.operation_id {
        span.record("contextos.operation_id", id);
    }
    if let Some(digest) = call.action_digest {
        span.record("contextos.action_digest", digest);
    }
    if !matches!(call.status, "completed" | "ok" | "paused") {
        // A governance refusal is the system working, not a span error; the reason
        // is the error type trace backends group by.
        span.record(
            "error.type",
            call.reason_codes.first().map_or(call.status, String::as_str),
        );
    }
    tracing::info!(
        target: "contextos::access",
        tenant_id = call.tenant_id,
        run_id = call.run_id,
        capability_id = call.capability_id,
        tool_call_id = call.tool_call_id,
        operation_id = call.operation_id.unwrap_or_default(),
        status = call.status,
        reason_codes = reasons.as_str(),
        stage = call.stage,
        stages = call.stages,
        duration_ms = call.duration_ms,
        check = call.check,
        "governed call"
    );
}

/// A call that failed on infrastructure rather than ending in a governance outcome.
#[derive(Debug)]
pub(crate) struct Failed<'a> {
    pub tenant_id: &'a str,
    pub run_id: &'a str,
    pub capability_id: &'a str,
    pub tool_call_id: &'a str,
    pub error: &'a crate::GatewayError,
    pub duration_ms: f64,
    pub check: bool,
}

/// The reason code an infrastructure failure is logged under.
fn failure_reason(error: &crate::GatewayError) -> &'static str {
    use crate::GatewayError as E;
    match error {
        E::Store(_) => "store_unavailable",
        E::Audit(_) => "audit_unavailable",
        E::Guarantee(_) => "shared_guarantee_failed",
        E::Manifest(_) => "manifest_invalid",
        E::Outcome(_) => "outcome_contract_failed",
    }
}

/// Marks the current span failed and writes the access event with `status="error"`.
pub(crate) fn failed(call: &Failed<'_>) {
    let span = tracing::Span::current();
    let reason = failure_reason(call.error);
    span.record("otel.status_code", "ERROR");
    span.record("error.type", "infrastructure");
    span.record("contextos.status", "error");
    span.record("contextos.reason_codes", reason);
    tracing::info!(
        target: "contextos::access",
        tenant_id = call.tenant_id,
        run_id = call.run_id,
        capability_id = call.capability_id,
        tool_call_id = call.tool_call_id,
        operation_id = "",
        status = "error",
        reason_codes = reason,
        stage = "",
        stages = "",
        duration_ms = call.duration_ms,
        check = call.check,
        "governed call"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stages_are_timed_in_order_and_repeats_merge() {
        let mut stages = Stages::new();
        stages.enter("surface");
        stages.enter("bind");
        stages.enter("bind");
        stages.enter("authorize");
        assert_eq!(stages.current(), "authorize");
        let summary = stages.summary();
        let names: Vec<&str> = summary.split(' ').map(|p| p.split('=').next().unwrap()).collect();
        assert_eq!(names, ["fence", "surface", "bind", "authorize"]);
        assert!(
            summary
                .split(' ')
                .all(|p| p.split('=').nth(1).unwrap().parse::<f64>().is_ok())
        );
    }
}
