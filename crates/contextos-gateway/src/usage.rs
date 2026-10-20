//! Budgeted model calls and replans.
//!
//! A run's budget covers more than tool calls: model calls spend tokens and cost, and
//! the planner's replans spend the replan allowance. The orchestrator reserves before
//! each one, from the same ledger tool calls use, so parallel lanes cannot race past a
//! ceiling and resume cannot reset it; a reservation the ledger cannot fit is refused.
//!
//! Settlement depends on who reports the usage. Usage the run's own executor reports
//! is not evidence, so the whole reservation is charged (an agent cannot under-report to
//! stretch its budget). Usage reported by a metering principal (for example an LLM
//! gateway that saw the call) is verified and settles to what it measured, releasing
//! the rest. A reservation never settled stays reserved: unknown usage is never zero.

use contextos_kernel::budget_ledger::{reserve_budget, settle_budget, settlement_intent_digest};
use contextos_store::{AppendLog, Commit, DocKey, DocKind, DocumentStore, transact};
use serde_json::{Value, json};

use crate::admission::RunAdmission;
use crate::revocations::{matching, revocations_key, run_targets};
use crate::{Gateway, GatewayError};

/// What a reservation covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsageKind {
    ModelCall,
    Replan,
}

#[derive(Debug, thiserror::Error)]
pub enum UsageRefusal {
    #[error("the budget cannot fit this reservation: {0:?}")]
    Budget(Vec<String>),
    #[error("revoked: {0}")]
    Revoked(String),
    #[error("no such usage reservation in this run")]
    UnknownReservation,
    #[error(transparent)]
    Gateway(#[from] GatewayError),
}

const PREFIX: &str = "usage:";

impl<S: DocumentStore + 'static, L: AppendLog + 'static> Gateway<S, L> {
    fn budget_key(admission: &RunAdmission) -> DocKey {
        DocKey::new(&admission.tenant_id, DocKind::BudgetLedger, &admission.budget_ledger_id)
    }

    /// Reserves budget for one model call (`tokens`, `cost_cents`) or one replan.
    pub async fn reserve_usage(
        &self,
        admission: &RunAdmission,
        kind: UsageKind,
        tokens: u64,
        cost_cents: u64,
    ) -> Result<String, UsageRefusal> {
        let revocations = self
            .store
            .get(&revocations_key(&admission.tenant_id))
            .await
            .map_err(GatewayError::from)?;
        if let Some(reason) = matching(revocations.as_ref().map(|r| &r.body), &run_targets(admission)) {
            return Err(UsageRefusal::Revoked(reason));
        }
        let now = self.now();
        let reservation_id = format!("{PREFIX}{}", self.ports.ids.new_id("usage"));
        let allocation = match kind {
            UsageKind::ModelCall => {
                json!({"tokens": tokens, "tool_calls": 0, "replans": 0, "cost_units": cost_cents * 100})
            }
            UsageKind::Replan => json!({"tokens": 0, "tool_calls": 0, "replans": 1, "cost_units": 0}),
        };
        let request = json!({
            "ledger_id": admission.budget_ledger_id, "contract_id": admission.contract_id,
            "parent_run_id": admission.run_id, "tenant_id": admission.tenant_id,
            "mutation_id": format!("reserve:{reservation_id}"), "reservation_id": reservation_id, "scope": "run",
            "run_id": admission.run_id, "cost_unit": {"currency": "USD", "units_per_cent": 100}, "allocation": allocation,
            "deadline": admission.deadline, "expected_revision": 0,
            "executor_generation": admission.executor_generation, "evaluation_time": now,
        });
        let commit = transact(self.store.as_ref(), &Self::budget_key(admission), |ledger| {
            let mut request = request.clone();
            request["expected_revision"] = ledger["revision"].clone();
            reserve_budget(ledger, &request)
        })
        .await
        .map_err(GatewayError::from)?;
        match commit {
            Commit::Rejected { reason_codes } => Err(UsageRefusal::Budget(reason_codes)),
            _ => Ok(reservation_id),
        }
    }

    /// Settles a usage reservation. `measured` is `Some` only for usage verified by a
    /// metering principal; otherwise the whole reservation is charged.
    pub async fn settle_usage(
        &self,
        admission: &RunAdmission,
        reservation_id: &str,
        measured: Option<(u64, u64)>,
        reporter: &str,
    ) -> Result<Value, UsageRefusal> {
        if !reservation_id.starts_with(PREFIX) {
            return Err(UsageRefusal::UnknownReservation);
        }
        let key = Self::budget_key(admission);
        let ledger = self
            .store
            .get(&key)
            .await
            .map_err(GatewayError::from)?
            .ok_or(UsageRefusal::UnknownReservation)?;
        let reservation = ledger.body["reservations"]
            .as_array()
            .and_then(|list| {
                list.iter()
                    .find(|r| r["reservation_id"] == reservation_id && r["status"] == "reserved")
                    .cloned()
            })
            .ok_or(UsageRefusal::UnknownReservation)?;
        let allocated = &reservation["allocation"];
        let usage = match measured {
            // Verified: what was measured, never more than was reserved.
            Some((tokens, cost_cents)) => json!({
                "tokens": tokens.min(allocated["tokens"].as_u64().unwrap_or(0)), "tool_calls": 0,
                "replans": allocated["replans"], "cost_units": (cost_cents * 100).min(allocated["cost_units"].as_u64().unwrap_or(0))}),
            // Self-reported: the whole reservation.
            None => allocated.clone(),
        };
        let now = self.now();
        let mut request = json!({
            "ledger_id": admission.budget_ledger_id, "contract_id": admission.contract_id,
            "parent_run_id": admission.run_id, "tenant_id": admission.tenant_id,
            "mutation_id": format!("settle:{reservation_id}"), "reservation_id": reservation_id, "scope": "run",
            "run_id": admission.run_id, "cost_unit": {"currency": "USD", "units_per_cent": 100}, "usage": usage,
            "usage_status": "known", "execution_status": "completed",
            "expected_revision": 0, "executor_generation": admission.executor_generation, "evaluation_time": now,
            "usage_observation": {"intent_digest": "", "verification_status": "verified", "observer": admission.gateway_observer,
                "evidence_ref": {"artifact_type": "usage_report", "artifact_id": reservation_id, "version": "1",
                    "sha256": contextos_contract::canonical::sha256_canonical(&json!({"reporter": reporter, "usage": usage})).unwrap_or_default()},
                "observed_at": now, "valid_until": admission.deadline},
        });
        request["usage_observation"]["intent_digest"] = json!(settlement_intent_digest(&request).unwrap_or_default());
        let commit = transact(self.store.as_ref(), &key, |ledger| {
            let mut request = request.clone();
            request["expected_revision"] = ledger["revision"].clone();
            settle_budget(ledger, &request)
        })
        .await
        .map_err(GatewayError::from)?;
        if let Commit::Rejected { reason_codes } = commit {
            return Err(UsageRefusal::Budget(reason_codes));
        }
        // Keep the ledger small for runs with many model calls, as dispatch does.
        if let Some(current) = self.store.get(&key).await.map_err(GatewayError::from)? {
            self.compact_budget_if_due(admission, &key, current.revision, &current.body, &now)
                .await?;
        }
        Ok(json!({"reservation_id": reservation_id, "charged": usage, "verified": measured.is_some()}))
    }
}
