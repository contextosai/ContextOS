//! Approval events: when the gateway asked for an approval, and when one was redeemed,
//! on the signed audit chain.
//!
//! Oversight that people click through looks the same as oversight that works until
//! someone measures it. The gateway records `approval_requested` the first time it
//! asks the approval service for a given request, and `approval_redeemed` when an
//! approval is redeemed for an operation, with who approved, when they decided and the
//! decision time (the fastest approver's, from the gateway's own request time). From
//! these an audit consumer (Tower's approvals report, a SIEM) can compute approval
//! rates, decision-time distributions and approvers who decide in seconds, per
//! capability. `decided_at` is the approval service's claim, as everything about a
//! decision is.

use contextos_contract::validation::elapsed_millis;
use contextos_store::{AppendLog, DocKey, DocKind, DocumentStore};
use serde_json::{Value, json};

use crate::admission::RunAdmission;
use crate::{Gateway, GatewayError};

pub(crate) fn requested_key(tenant_id: &str, request_id: &str) -> DocKey {
    DocKey::new(tenant_id, DocKind::ApprovalRequested, request_id)
}

impl<S: DocumentStore + 'static, L: AppendLog + 'static> Gateway<S, L> {
    /// Records when the gateway first asked for approval `request_id`, and audits it
    /// (`approval_requested`); a request asked for again is not recorded twice.
    pub(crate) async fn approval_requested(
        &self,
        admission: &RunAdmission,
        request_id: &str,
        (operation_id, capability_id): (&str, &str),
        now: &str,
    ) -> Result<Option<u64>, GatewayError> {
        let key = requested_key(&admission.tenant_id, request_id);
        match self.store.create(&key, &json!({"requested_at": now})).await {
            Ok(_) => {}
            Err(e) if e.is_conflict() => return Ok(None),
            Err(e) => return Err(e.into()),
        }
        let entry = self
            .audit
            .append(
                &admission.tenant_id,
                "approval_requested",
                json!({"run_id": admission.run_id, "operation_id": operation_id,
                    "capability_id": capability_id, "approval_request_id": request_id}),
                now,
            )
            .await?;
        Ok(Some(entry.sequence))
    }

    /// Audits an approval just redeemed for an operation (`approval_redeemed`): its
    /// approvers, when they decided, and the fastest decision time in seconds.
    pub(crate) async fn approval_redeemed(
        &self,
        admission: &RunAdmission,
        material: &Value,
        (operation_id, capability_id): (&str, &str),
        now: &str,
    ) -> Result<u64, GatewayError> {
        let request_id = material["request"]["approval_request_id"].as_str().unwrap_or_default();
        let recorded = if request_id.is_empty() {
            None
        } else {
            self.store.get(&requested_key(&admission.tenant_id, request_id)).await?
        };
        let requested_at = recorded
            .as_ref()
            .and_then(|r| r.body["requested_at"].as_str().map(str::to_owned))
            .or_else(|| material["request"]["not_before"].as_str().map(str::to_owned));
        let approved: Vec<&Value> = material["decisions"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|d| d["decision"] == "approved")
            .collect();
        let approvers: Vec<&Value> = approved.iter().map(|d| &d["approver"]["principal_id"]).collect();
        let decided_at = approved.iter().filter_map(|d| d["decided_at"].as_str()).max();
        let seconds = requested_at.as_deref().and_then(|from| {
            approved
                .iter()
                .filter_map(|d| d["decided_at"].as_str().and_then(|at| elapsed_millis(from, at)))
                .min()
                .map(|ms| ms / 1000)
        });
        let entry = self
            .audit
            .append(
                &admission.tenant_id,
                "approval_redeemed",
                json!({"run_id": admission.run_id, "operation_id": operation_id, "capability_id": capability_id,
                    "approval_request_id": request_id, "approvers": approvers, "requested_at": requested_at,
                    "decided_at": decided_at, "decision_seconds": seconds}),
                now,
            )
            .await?;
        Ok(entry.sequence)
    }
}
