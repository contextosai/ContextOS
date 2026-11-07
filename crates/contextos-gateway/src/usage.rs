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
//!
//! A metering gateway claims a model-call reservation before it forwards the call
//! ([`Gateway::claim_usage`]), so a forged or reused reservation is refused before the
//! model is called rather than discovered at settlement. Refused reservations, claims
//! and settlements are audited (`usage_refused`, `usage_claimed`, `usage_settled`); the
//! governance plane reports model spend from them.

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
    #[error("the usage values are out of range")]
    Invalid,
    #[error("no such usage reservation in this run")]
    UnknownReservation,
    #[error("the reservation is already claimed")]
    Claimed,
    #[error(transparent)]
    Gateway(#[from] GatewayError),
}

const PREFIX: &str = "usage:";
/// Suffix of the reservation that charges metered usage above a reservation.
const OVERAGE: &str = ":overage";

/// Resource keys of a budget allocation.
const KEYS: [&str; 4] = ["tokens", "tool_calls", "replans", "cost_units"];

impl UsageKind {
    pub fn as_str(self) -> &'static str {
        match self {
            UsageKind::ModelCall => "model_call",
            UsageKind::Replan => "replan",
        }
    }
}

impl<S: DocumentStore + 'static, L: AppendLog + 'static> Gateway<S, L> {
    fn budget_key(admission: &RunAdmission) -> DocKey {
        DocKey::new(&admission.tenant_id, DocKind::BudgetLedger, &admission.budget_ledger_id)
    }

    /// Refuses usage for a run whose tenant, pack, agent or capability is revoked.
    pub(crate) async fn usage_revocation(&self, admission: &RunAdmission) -> Result<(), UsageRefusal> {
        let revocations = self
            .store
            .get(&revocations_key(&admission.tenant_id))
            .await
            .map_err(GatewayError::from)?;
        match matching(revocations.as_ref().map(|r| &r.body), &run_targets(admission)) {
            Some(reason) => Err(UsageRefusal::Revoked(reason)),
            None => Ok(()),
        }
    }

    /// Reserves budget for one model call (`tokens`, `cost_cents`) or one replan. A
    /// model call reserves at least the configured floor (see
    /// [`Gateway::set_model_call_floor`]), so a call can never be reserved, and
    /// self-settled, for nothing. A reservation refused by the budget or a revocation
    /// is audited as `usage_refused`.
    pub async fn reserve_usage(
        &self,
        admission: &RunAdmission,
        kind: UsageKind,
        tokens: u64,
        cost_cents: u64,
    ) -> Result<String, UsageRefusal> {
        let reserved = self.reserve_unaudited(admission, kind, tokens, cost_cents).await;
        let reason_codes = match &reserved {
            Err(UsageRefusal::Budget(codes)) => codes.clone(),
            Err(UsageRefusal::Revoked(_)) => vec!["revoked".to_owned()],
            _ => return reserved,
        };
        self.audit
            .append(
                &admission.tenant_id,
                "usage_refused",
                json!({"run_id": admission.run_id, "kind": kind.as_str(), "tokens": tokens,
                    "cost_cents": cost_cents, "reason_codes": reason_codes}),
                &self.now(),
            )
            .await
            .map_err(GatewayError::from)?;
        reserved
    }

    async fn reserve_unaudited(
        &self,
        admission: &RunAdmission,
        kind: UsageKind,
        tokens: u64,
        cost_cents: u64,
    ) -> Result<String, UsageRefusal> {
        self.usage_revocation(admission).await?;
        let allocation = match kind {
            UsageKind::ModelCall => {
                let cost_units = cost_cents.checked_mul(100).ok_or(UsageRefusal::Invalid)?;
                json!({"tokens": tokens.max(self.model_call_floor), "tool_calls": 0, "replans": 0, "cost_units": cost_units})
            }
            UsageKind::Replan => json!({"tokens": 0, "tool_calls": 0, "replans": 1, "cost_units": 0}),
        };
        let reservation_id = format!("{PREFIX}{}", self.ports.ids.new_id("usage"));
        self.reserve_allocation(admission, &reservation_id, &allocation).await?;
        Ok(reservation_id)
    }

    async fn reserve_allocation(
        &self,
        admission: &RunAdmission,
        reservation_id: &str,
        allocation: &Value,
    ) -> Result<(), UsageRefusal> {
        let request = json!({
            "ledger_id": admission.budget_ledger_id, "contract_id": admission.contract_id,
            "parent_run_id": admission.run_id, "tenant_id": admission.tenant_id,
            "mutation_id": format!("reserve:{reservation_id}"), "reservation_id": reservation_id, "scope": "run",
            "run_id": admission.run_id, "cost_unit": {"currency": "USD", "units_per_cent": 100}, "allocation": allocation,
            "deadline": admission.deadline, "expected_revision": 0,
            "executor_generation": admission.executor_generation, "evaluation_time": self.now(),
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
            _ => Ok(()),
        }
    }

    async fn settle_known(
        &self,
        admission: &RunAdmission,
        reservation_id: &str,
        usage: &Value,
        reporter: &str,
    ) -> Result<(), UsageRefusal> {
        let now = self.now();
        let key = Self::budget_key(admission);
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
        Ok(())
    }

    /// Settles a usage reservation. `measured` is `Some` only for usage verified by a
    /// metering principal; otherwise the whole reservation is charged. Measured usage
    /// above the reservation is charged too, as overage up to the run's remaining
    /// capacity; anything beyond that is audited as uncovered.
    ///
    /// A reservation a metering gateway claimed settles as measured only by that
    /// gateway. Every settlement is audited as `usage_settled`, with the model the
    /// reporter named (an unverified name when the usage is self-reported).
    pub async fn settle_usage(
        &self,
        admission: &RunAdmission,
        reservation_id: &str,
        measured: Option<(u64, u64)>,
        reporter: &str,
        model: Option<&str>,
    ) -> Result<Value, UsageRefusal> {
        let allocated = self.open_reservation(admission, reservation_id).await?;
        if measured.is_some() {
            self.require_claimant(admission, reservation_id, reporter).await?;
        }
        let settled = self
            .settle_allocated(admission, reservation_id, &allocated, measured, reporter)
            .await?;
        let measured = measured
            .map(|(tokens, cost_cents)| json!({"tokens": tokens, "cost_units": cost_cents.saturating_mul(100)}));
        self.audit
            .append(
                &admission.tenant_id,
                "usage_settled",
                json!({"run_id": admission.run_id, "reservation_id": reservation_id, "reporter": reporter,
                    "verified": settled["verified"], "model": model, "charged": settled["charged"],
                    "measured": measured}),
                &self.now(),
            )
            .await
            .map_err(GatewayError::from)?;
        Ok(settled)
    }

    /// The allocation of an open usage reservation of this run (not an overage).
    pub(crate) async fn open_reservation(
        &self,
        admission: &RunAdmission,
        reservation_id: &str,
    ) -> Result<Value, UsageRefusal> {
        if !reservation_id.starts_with(PREFIX) || reservation_id.ends_with(OVERAGE) {
            return Err(UsageRefusal::UnknownReservation);
        }
        let ledger = self
            .store
            .get(&Self::budget_key(admission))
            .await
            .map_err(GatewayError::from)?
            .ok_or(UsageRefusal::UnknownReservation)?;
        ledger.body["reservations"]
            .as_array()
            .and_then(|list| {
                list.iter()
                    .find(|r| r["reservation_id"] == reservation_id && r["status"] == "reserved")
                    .map(|r| r["allocation"].clone())
            })
            .ok_or(UsageRefusal::UnknownReservation)
    }

    async fn settle_allocated(
        &self,
        admission: &RunAdmission,
        reservation_id: &str,
        allocated: &Value,
        measured: Option<(u64, u64)>,
        reporter: &str,
    ) -> Result<Value, UsageRefusal> {
        let allocated = allocated.clone();
        let key = Self::budget_key(admission);
        let get = |v: &Value, k: &str| v[k].as_u64().unwrap_or(0);
        let Some((tokens, cost_cents)) = measured else {
            // Self-reported: the whole reservation.
            self.settle_known(admission, reservation_id, &allocated, reporter)
                .await?;
            return Ok(json!({"reservation_id": reservation_id, "charged": allocated, "verified": false}));
        };
        let cost_units = cost_cents.checked_mul(100).ok_or(UsageRefusal::Invalid)?;
        let within = json!({"tokens": tokens.min(get(&allocated, "tokens")), "tool_calls": 0,
            "replans": allocated["replans"], "cost_units": cost_units.min(get(&allocated, "cost_units"))});
        self.settle_known(admission, reservation_id, &within, reporter).await?;
        let over = json!({"tokens": tokens.saturating_sub(get(&allocated, "tokens")), "tool_calls": 0, "replans": 0,
            "cost_units": cost_units.saturating_sub(get(&allocated, "cost_units"))});
        let mut charged = within;
        if KEYS.iter().any(|k| get(&over, k) > 0) {
            // Charge what the run can still cover; the rest is recorded as uncovered.
            let current = self
                .store
                .get(&key)
                .await
                .map_err(GatewayError::from)?
                .map(|l| l.body)
                .unwrap_or_default();
            let remaining = |k: &str| {
                get(&current["ceiling"], k)
                    .saturating_sub(get(&current["used"], k))
                    .saturating_sub(get(&current["reserved"], k))
            };
            let covered = json!({"tokens": get(&over, "tokens").min(remaining("tokens")), "tool_calls": 0, "replans": 0,
                "cost_units": get(&over, "cost_units").min(remaining("cost_units"))});
            if KEYS.iter().any(|k| get(&covered, k) > 0) {
                let overage_id = format!("{reservation_id}{OVERAGE}");
                self.reserve_allocation(admission, &overage_id, &covered).await?;
                self.settle_known(admission, &overage_id, &covered, reporter).await?;
                for k in ["tokens", "cost_units"] {
                    charged[k] = json!(get(&charged, k) + get(&covered, k));
                }
            }
            self.audit
                .append(
                    &admission.tenant_id,
                    "usage_overage",
                    json!({"run_id": admission.run_id, "reservation_id": reservation_id, "reporter": reporter,
                        "reserved": allocated, "measured": {"tokens": tokens, "cost_units": cost_units},
                        "charged": charged}),
                    &self.now(),
                )
                .await
                .map_err(GatewayError::from)?;
        }
        Ok(json!({"reservation_id": reservation_id, "charged": charged, "verified": true}))
    }
}
