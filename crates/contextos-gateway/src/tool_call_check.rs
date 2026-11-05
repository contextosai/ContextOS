//! Checking a tool call without dispatching it (runtime extension).
//!
//! A check runs the same governed pipeline as dispatch, on the same pinned policy,
//! authority, constraint, approval, kill-switch, boundary, loop and data-flow facts,
//! and stops before anything is redeemed, reserved, claimed or sent. Nothing the
//! pipeline would write along the way is written: no intermediate audit entries, no
//! approval request, no escalation, no redemption state. One `tool_call_check` audit
//! entry records that the call was checked and what the check found, so probing which
//! arguments a policy allows stays on the record.
//!
//! A check is advisory. The state it reads can change before the call is dispatched,
//! and the budget reservation, shared-guarantee capacity and operation claim are only
//! decided at dispatch, atomically; `not_evaluated` names them.

use contextos_kernel::authorization::transition_approval_redemption;
use contextos_store::{AppendLog, DocumentStore};
use serde::Serialize;
use serde_json::{Map, Value, json};

use crate::admission::RunAdmission;
use crate::{DispatchOutcome, Gateway, GatewayError, Pipeline};

/// What a check found.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CheckOutcome {
    /// `allowed` (dispatch would proceed to reservation and claim), `approval_required`,
    /// `escalation_required`, `blocked` or `rejected`.
    pub status: String,
    pub capability_id: Value,
    pub operation_id: Option<String>,
    pub action_digest: Option<String>,
    pub reason_codes: Vec<String>,
    pub obligations: Vec<String>,
    /// The message dispatch would return for a call that does not proceed.
    pub message: Option<String>,
    /// An operation with this id already exists in the run: dispatch treats the call as
    /// its retry (duplicate or reconciliation rules apply), not as a new effect.
    pub operation_exists: bool,
    /// Decided only at dispatch.
    pub not_evaluated: Vec<&'static str>,
    /// The `tool_call_check` audit entry.
    pub audit_sequence: u64,
}

/// The end of a checked pipeline that passed authorization and data flow: an exact
/// approval it carries must still be redeemable for this operation.
pub(crate) fn conclude(p: Pipeline<'_>, approval_input: &Value, operation_exists: bool) -> DispatchOutcome {
    let mut p = p;
    if approval_input.is_object() {
        let approval = approval_input.clone();
        let revision = approval["redemption_state"]["revision"].clone();
        let result = transition_approval_redemption(&json!({"approval": approval, "expected_revision": revision}));
        if result.status == "rejected" {
            return p.stop(
                "blocked",
                result.reason_codes,
                "Approval could not be redeemed for this operation.",
            );
        }
        p.risk_tags.push("human_approved".into());
    }
    let mut output = Map::new();
    output.insert("operation_exists".into(), json!(operation_exists));
    p.finish("allowed", output, None, vec![])
}

impl<S: DocumentStore + 'static, L: AppendLog + 'static> Gateway<S, L> {
    /// Checks a tool call as [`Gateway::dispatch_as`] would govern it, without effect
    /// (see the module documentation). With `executor_generation`, a stale executor is
    /// refused as dispatch would refuse it.
    #[tracing::instrument(
        name = "contextos.check",
        skip_all,
        fields(run_id = %admission.run_id, status = tracing::field::Empty)
    )]
    pub async fn check_tool_call(
        &self,
        admission: &RunAdmission,
        envelope: &Value,
        executor_generation: Option<u64>,
    ) -> Result<CheckOutcome, GatewayError> {
        let outcome = self
            .dispatch_inner(admission, envelope, None, executor_generation, None, true)
            .await?;
        let report = outcome.report;
        let capability_id = outcome.result["capability_id"].clone();
        let mut not_evaluated = vec!["budget_reservation", "operation_claim"];
        if capability_id.as_str().is_some_and(|c| self.has_shared_guarantee(c)) {
            not_evaluated.push("shared_guarantee_capacity");
        }
        let now = self.now();
        let entry = self
            .audit
            .append(
                &admission.tenant_id,
                "tool_call_check",
                json!({"run_id": admission.run_id, "capability_id": capability_id,
                    "operation_id": report.operation_id, "action_digest": report.action_digest,
                    "status": report.status, "reason_codes": report.reason_codes}),
                &now,
            )
            .await?;
        tracing::Span::current().record("status", report.status.as_str());
        Ok(CheckOutcome {
            status: report.status,
            capability_id,
            operation_id: report.operation_id,
            action_digest: report.action_digest,
            reason_codes: report.reason_codes,
            obligations: report.obligations,
            message: outcome.result["error"].as_str().map(str::to_owned),
            operation_exists: outcome.result["output"]["operation_exists"] == true,
            not_evaluated,
            audit_sequence: entry.sequence,
        })
    }
}
