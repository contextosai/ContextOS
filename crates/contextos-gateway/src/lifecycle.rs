//! Completing, failing and cancelling runs.
//!
//! The run state is the kernel's: lifecycle events go through `transition_run`, which
//! advances the executor generation on each one, so every terminal or cancelling event
//! also fences the previous executor. The gateway keeps the two bookkeeping fields the
//! kernel judges by:
//!
//! - `child_run_ids`: delegated children not yet closed (added on delegation, removed
//!   when the child is closed and settled);
//! - `outstanding_effects`: operations whose outcome is unknown or partial (added when
//!   dispatch observes one, removed or updated when reconciliation resolves it).
//!
//! **Complete** requires no unresolved effect, no open child and nothing in flight.
//! **Cancel** first requests cancellation (fencing the executor), cancels and closes
//! every child, and acknowledges once dispatch has stopped: the run's budget ledger
//! holds an open reservation for every effect between reservation and settlement, so
//! no open run-scoped reservation means nothing is in flight. If something is, the run
//! stays `cancel_requested` and cancelling again finishes the job.

use std::future::Future;
use std::pin::Pin;

use contextos_contract::canonical::sha256_canonical;
use contextos_contract::validation::add_contract_seconds;
use contextos_kernel::TransitionResult;
use contextos_kernel::run_state::transition_run;
use contextos_store::{AppendLog, Commit, DocKey, DocKind, DocumentStore, transact};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::admission::RunAdmission;
use crate::ownership::run_state_key;
use crate::{CloseDecision, Gateway, GatewayError, OBSERVATION_VALIDITY_SECONDS};

/// At most this many effects may be unresolved at once in one run (the kernel's
/// bound on `outstanding_effects`); further dispatch waits for reconciliation.
pub const MAX_UNRESOLVED_EFFECTS: usize = 128;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LifecycleOutcome {
    /// The run's status afterwards.
    pub status: String,
    pub reason_codes: Vec<String>,
    pub obligations: Vec<String>,
    pub executor_generation: Option<u64>,
}

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

impl<S: DocumentStore + 'static, L: AppendLog + 'static> Gateway<S, L> {
    /// Applies one kernel lifecycle event. `expected_generation` fences the caller
    /// when given.
    pub(crate) async fn apply_event(
        &self,
        admission: &RunAdmission,
        kind: &str,
        expected_generation: Option<u64>,
        dispatch_stop: Option<(Vec<String>, bool)>,
    ) -> Result<LifecycleOutcome, GatewayError> {
        let key = run_state_key(admission);
        let now = self.now();
        let event_id = self.ports.ids.new_id("run_event");
        let mut obligations = Vec::new();
        let commit = transact(self.store.as_ref(), &key, |state| {
            let generation = state["executor_generation"].as_u64().unwrap_or(0);
            if expected_generation.is_some_and(|g| g != generation) {
                return TransitionResult::rejected(state.clone(), "executor_stale");
            }
            let stop = dispatch_stop.as_ref().map(|(children, stopped)| {
                json!({
                    "run_id": admission.run_id, "tenant_id": admission.tenant_id, "executor_generation": generation,
                    "observer": admission.gateway_observer, "verification_status": "verified",
                    "evidence_ref": {"artifact_type": "dispatch_stop", "artifact_id": event_id, "version": "1",
                        "sha256": sha256_canonical(&json!([admission.run_id, generation, children, stopped])).unwrap_or_default()},
                    "observed_at": now,
                    "valid_until": add_contract_seconds(&now, OBSERVATION_VALIDITY_SECONDS).unwrap_or_else(|| now.clone()),
                    "child_run_ids": children, "dispatch_stopped": stopped, "children_stop_recorded": true,
                })
            });
            let event = json!({
                "event_id": event_id, "run_id": admission.run_id, "tenant_id": admission.tenant_id, "kind": kind,
                "expected_revision": state["revision"], "executor_generation": generation,
                "preconditions": null, "dispatch_stop_ack": stop,
            });
            let result = transition_run(state, &event, &json!(now));
            obligations.clone_from(result.obligations.as_ref().unwrap_or(&Vec::new()));
            result
        })
        .await?;
        let state = self.run_state(admission).await?.unwrap_or(Value::Null);
        let mut out = LifecycleOutcome {
            status: state["status"].as_str().unwrap_or("unknown").to_owned(),
            reason_codes: Vec::new(),
            obligations,
            executor_generation: state["executor_generation"].as_u64(),
        };
        match commit {
            Commit::Rejected { reason_codes } => {
                out.reason_codes = reason_codes;
                out.obligations.clear();
            }
            Commit::Written { .. } | Commit::Unchanged { .. } => {
                self.audit
                    .append(
                        &admission.tenant_id,
                        "run_lifecycle",
                        json!({"run_id": admission.run_id, "event": kind, "event_id": event_id,
                            "status": out.status, "executor_generation": out.executor_generation}),
                        &now,
                    )
                    .await?;
            }
        }
        Ok(out)
    }

    /// Edits the run state's bookkeeping (not a lifecycle event; the generation is
    /// unchanged). A missing run state (an embedder not using lifecycles) is a no-op.
    pub(crate) async fn edit_run_state(
        &self,
        admission: &RunAdmission,
        edit: impl Fn(&mut Value) + Send + Sync,
    ) -> Result<(), GatewayError> {
        let key = run_state_key(admission);
        if self.store.get(&key).await?.is_none() {
            return Ok(());
        }
        transact(self.store.as_ref(), &key, |state| {
            let mut next = state.clone();
            edit(&mut next);
            TransitionResult::accepted(next, vec![])
        })
        .await?;
        Ok(())
    }

    /// Records an operation's outcome in `outstanding_effects`: unresolved outcomes
    /// (`unknown`, `partial`) are listed, anything else is removed.
    pub(crate) async fn note_effect(
        &self,
        admission: &RunAdmission,
        operation_id: &str,
        outcome: &str,
    ) -> Result<(), GatewayError> {
        let unresolved = matches!(outcome, "unknown" | "partial");
        self.edit_run_state(admission, |state| {
            let effects = state["outstanding_effects"].as_array_mut();
            let Some(effects) = effects else { return };
            effects.retain(|e| e["operation_id"] != operation_id);
            if unresolved && effects.len() < MAX_UNRESOLVED_EFFECTS {
                effects.push(json!({"operation_id": operation_id, "outcome": outcome}));
            }
        })
        .await
    }

    /// Effects between reservation and settlement (open run-scoped reservations).
    async fn effects_in_flight(&self, admission: &RunAdmission) -> Result<bool, GatewayError> {
        let key = DocKey::new(&admission.tenant_id, DocKind::BudgetLedger, &admission.budget_ledger_id);
        let closure = format!("closure:{}", admission.run_id);
        Ok(self.store.get(&key).await?.is_some_and(|l| {
            l.body["reservations"]
                .as_array()
                .into_iter()
                .flatten()
                .any(|r| r["scope"] == "run" && r["status"] == "reserved" && r["reservation_id"] != closure.as_str())
        }))
    }

    /// Completes the run. Fenced by the executor's generation.
    pub async fn complete_run(
        &self,
        admission: &RunAdmission,
        executor_generation: u64,
    ) -> Result<LifecycleOutcome, GatewayError> {
        if self.effects_in_flight(admission).await? {
            return self.refusal(admission, "effects_in_flight").await;
        }
        self.apply_event(admission, "complete", Some(executor_generation), None)
            .await
    }

    /// Marks the run failed. Fenced by the executor's generation.
    pub async fn fail_run(
        &self,
        admission: &RunAdmission,
        executor_generation: u64,
    ) -> Result<LifecycleOutcome, GatewayError> {
        self.apply_event(admission, "fail", Some(executor_generation), None)
            .await
    }

    /// Cancels the run and, recursively, its children. Not fenced: stopping is always
    /// allowed to whoever may administer the run. Idempotent; call again while the run
    /// reports `cancel_requested` with `dispatch_in_flight`.
    pub fn cancel_run<'a>(
        &'a self,
        admission: &'a RunAdmission,
        requested_by: &'a str,
    ) -> BoxFuture<'a, Result<LifecycleOutcome, GatewayError>> {
        Box::pin(async move {
            let state = self.run_state(admission).await?.unwrap_or(Value::Null);
            if state.is_null() {
                return self.refusal(admission, "run_not_started").await;
            }
            if state["status"] != "cancel_requested" {
                let requested = self.apply_event(admission, "request_cancel", None, None).await?;
                if !requested.reason_codes.is_empty() {
                    return Ok(requested);
                }
            }
            // Stop every child, then settle it into this run.
            let state = self.run_state(admission).await?.unwrap_or(Value::Null);
            let children: Vec<String> = state["child_run_ids"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|c| c.as_str().map(str::to_owned))
                .collect();
            let mut obligations = Vec::new();
            for child_id in &children {
                let key = DocKey::new(&admission.tenant_id, DocKind::RunAdmission, child_id);
                let Some(child) = self
                    .store
                    .get(&key)
                    .await?
                    .and_then(|r| serde_json::from_value::<RunAdmission>(r.body).ok())
                else {
                    obligations.push(format!("child_admission_missing:{child_id}"));
                    continue;
                };
                let stopped = self.cancel_run(&child, requested_by).await?;
                if stopped.status != "cancelled" {
                    obligations.push(format!("child_cancel_pending:{child_id}"));
                }
                let closed = self
                    .close_delegation(admission, &child, CloseDecision::Reject, requested_by)
                    .await?;
                if closed.status != "closed" {
                    obligations.push(format!("child_settlement_pending:{child_id}"));
                }
            }
            if self.effects_in_flight(admission).await? {
                let mut out = self.refusal(admission, "dispatch_in_flight").await?;
                out.reason_codes.clear();
                out.obligations = vec!["retry_cancel_after_dispatch_settles".into()];
                out.obligations.extend(obligations);
                return Ok(out);
            }
            let state = self.run_state(admission).await?.unwrap_or(Value::Null);
            let remaining: Vec<String> = state["child_run_ids"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|c| c.as_str().map(str::to_owned))
                .collect();
            let mut out = self
                .apply_event(admission, "acknowledge_cancel", None, Some((remaining, true)))
                .await?;
            out.obligations.extend(obligations);
            Ok(out)
        })
    }

    async fn refusal(&self, admission: &RunAdmission, reason: &str) -> Result<LifecycleOutcome, GatewayError> {
        let state = self.run_state(admission).await?.unwrap_or(Value::Null);
        Ok(LifecycleOutcome {
            status: state["status"].as_str().unwrap_or("unknown").to_owned(),
            reason_codes: vec![reason.to_owned()],
            obligations: Vec::new(),
            executor_generation: state["executor_generation"].as_u64(),
        })
    }
}
