//! Executor ownership and failover.
//!
//! Each run has a kernel run-state document. Opening a run applies the kernel's
//! `start` transition; the resulting executor generation is the executor's fencing
//! token. Effectful requests must present the current generation: the gateway checks
//! it on entry and again immediately before the operation is claimed. That re-check is
//! the linearization point. Work claimed before a takeover is durable in the
//! operation ledger, so the new executor sees it (in flight or settled) and reconciles
//! it rather than repeating it; nothing new starts under a stale generation after the
//! takeover commits.
//!
//! A takeover is two kernel transitions under compare-and-swap, `suspend` then
//! `resume`, each advancing the generation. The resume preconditions are observed by
//! the gateway: admission is present, budget has capacity, and authority and boundary
//! are re-evaluated per effect at dispatch (so they are reported ready only in that
//! sense). Target-side fencing is the provider's: adapters forward the generation.

use contextos_contract::canonical::sha256_canonical;
use contextos_contract::validation::add_contract_seconds;
use contextos_kernel::run_state::transition_run;
use contextos_store::{AppendLog, Commit, DocKey, DocKind, DocumentStore, transact};
use serde_json::{Value, json};

use crate::admission::RunAdmission;
use crate::{Gateway, GatewayError, OBSERVATION_VALIDITY_SECONDS};

/// Result of a fencing check or a takeover.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ownership {
    /// The caller owns the run at this generation.
    Current(u64),
    /// Refused, with a reason code (`executor_stale`, `run_not_running`, …).
    Refused(&'static str),
}

/// Fences `generation` against an already-read run state.
pub(crate) fn ownership_in(state: Option<&Value>, generation: u64) -> Ownership {
    let Some(state) = state else {
        return Ownership::Refused("run_not_started");
    };
    if state["executor_generation"].as_u64() != Some(generation) {
        return Ownership::Refused("executor_stale");
    }
    if state["status"] != "running" {
        return Ownership::Refused("run_not_running");
    }
    Ownership::Current(generation)
}

pub(crate) fn run_state_key(admission: &RunAdmission) -> DocKey {
    DocKey::new(&admission.tenant_id, DocKind::RunState, &admission.run_id)
}

fn admission_ref(admission: &RunAdmission) -> Value {
    let digest = serde_json::to_value(admission)
        .ok()
        .and_then(|a| sha256_canonical(&a).ok())
        .unwrap_or_default();
    json!({"artifact_type": "run_admission", "artifact_id": admission.run_id, "version": "1", "sha256": digest})
}

impl<S: DocumentStore + 'static, L: AppendLog + 'static> Gateway<S, L> {
    /// Creates the run's lifecycle state and starts it. Returns the executor
    /// generation the admitting executor must present. Idempotent for a running run.
    pub async fn open_run(&self, admission: &RunAdmission) -> Result<Ownership, GatewayError> {
        let key = run_state_key(admission);
        let initial = json!({
            "contract_id": admission.contract_id, "run_id": admission.run_id, "tenant_id": admission.tenant_id,
            "status": "created", "revision": 0, "executor_generation": 1, "deadline": admission.deadline,
            "admission_ref": admission_ref(admission), "trusted_observer": admission.gateway_observer,
            "outstanding_effects": [], "child_run_ids": [], "dispatch_stop_acknowledged": false, "last_event_id": null,
        });
        match self.store.create(&key, &initial).await {
            Ok(_) => {}
            Err(e) if e.is_conflict() => {}
            Err(e) => return Err(e.into()),
        }
        self.advance(admission, &["start"], None).await
    }

    /// The run's lifecycle state, if it has one.
    pub async fn run_state(&self, admission: &RunAdmission) -> Result<Option<Value>, GatewayError> {
        Ok(self.store.get(&run_state_key(admission)).await?.map(|r| r.body))
    }

    /// Fences `generation` against the run's current executor generation.
    pub async fn check_owner(&self, admission: &RunAdmission, generation: u64) -> Result<Ownership, GatewayError> {
        Ok(ownership_in(self.run_state(admission).await?.as_ref(), generation))
    }

    /// Moves the run to a new executor: `suspend` then `resume`, each fenced by
    /// `expected_generation` (the generation the new executor last observed).
    pub async fn take_over(
        &self,
        admission: &RunAdmission,
        expected_generation: u64,
    ) -> Result<Ownership, GatewayError> {
        self.advance(admission, &["suspend", "resume"], Some(expected_generation))
            .await
    }

    /// Advances a running run's executor generation without expecting one: the
    /// current executor is fenced and must take the run over. `Refused` when the run
    /// is not running (nothing to fence).
    pub(crate) async fn fence_executor(&self, admission: &RunAdmission) -> Result<Ownership, GatewayError> {
        if self
            .run_state(admission)
            .await?
            .is_none_or(|s| s["status"] != "running")
        {
            return Ok(Ownership::Refused("run_not_running"));
        }
        self.advance(admission, &["suspend", "resume"], None).await
    }

    async fn advance(
        &self,
        admission: &RunAdmission,
        kinds: &[&str],
        mut expected_generation: Option<u64>,
    ) -> Result<Ownership, GatewayError> {
        let key = run_state_key(admission);
        for kind in kinds {
            let now = self.now();
            let budget_ready = self.budget_has_capacity(admission).await?;
            // With a boundary controller the boundary is evaluated now. Without one, the
            // run's boundary controls (isolation, mediated network, brokered credentials)
            // are proven per action instead: dispatch requires the constraint provider's
            // attestation of every required control for each action digest.
            let boundary_ready = match self.boundary_readiness(admission, &now).await {
                Some(Err(_)) => "blocked",
                Some(Ok(())) | None => "ready",
            };
            let event_id = self.ports.ids.new_id("run_event");
            let mut refused = None;
            let commit = transact(self.store.as_ref(), &key, |state| {
                let generation = state["executor_generation"].as_u64().unwrap_or(0);
                if *kind == "start" && state["status"] != "created" {
                    // Already started: report the current owner instead of re-starting.
                    refused = Some(if state["status"] == "running" { "already_started" } else { "run_not_running" });
                    return contextos_kernel::TransitionResult::accepted(state.clone(), vec![]);
                }
                if expected_generation.is_some_and(|g| g != generation) {
                    refused = Some("executor_stale");
                    return contextos_kernel::TransitionResult::accepted(state.clone(), vec![]);
                }
                refused = None;
                let preconditions = (*kind == "start" || *kind == "resume").then(|| {
                    json!({
                        "run_id": admission.run_id, "tenant_id": admission.tenant_id, "executor_generation": generation,
                        "observer": admission.gateway_observer, "verification_status": "verified",
                        "evidence_ref": {"artifact_type": "run_preconditions", "artifact_id": event_id, "version": "1",
                            "sha256": sha256_canonical(&json!([admission.run_id, generation, budget_ready, boundary_ready])).unwrap_or_default()},
                        "observed_at": now,
                        "valid_until": add_contract_seconds(&now, OBSERVATION_VALIDITY_SECONDS).unwrap_or_else(|| now.clone()),
                        "admission_ref": state["admission_ref"],
                        "checks": {"admission": "ready", "authority": "ready", "boundary": boundary_ready,
                            "budget": if budget_ready { "ready" } else { "blocked" }},
                    })
                });
                let event = json!({
                    "event_id": event_id, "run_id": admission.run_id, "tenant_id": admission.tenant_id, "kind": kind,
                    "expected_revision": state["revision"], "executor_generation": generation,
                    "preconditions": preconditions, "dispatch_stop_ack": null,
                });
                transition_run(state, &event, &json!(now))
            })
            .await?;
            match (commit, refused) {
                (Commit::Rejected { reason_codes }, _) => {
                    return Ok(Ownership::Refused(match reason_codes.first().map(String::as_str) {
                        Some("budget_exhausted") => "budget_exhausted",
                        Some("deadline_exceeded") => "deadline_exceeded",
                        Some("executor_stale") => "executor_stale",
                        _ => "run_not_running",
                    }));
                }
                (_, Some(reason)) if reason == "already_started" => return Ok(Ownership::Refused(reason)),
                (_, Some(reason)) => return Ok(Ownership::Refused(reason)),
                (Commit::Written { .. } | Commit::Unchanged { .. }, None) => {
                    let state = self.run_state(admission).await?.unwrap_or(Value::Null);
                    expected_generation = state["executor_generation"].as_u64();
                    self.audit
                        .append(
                            &admission.tenant_id,
                            "run_lifecycle",
                            json!({"run_id": admission.run_id, "event": kind, "event_id": event_id,
                                "status": state["status"], "executor_generation": state["executor_generation"]}),
                            &now,
                        )
                        .await?;
                }
            }
        }
        let state = self.run_state(admission).await?.unwrap_or(Value::Null);
        Ok(
            match (state["status"].as_str(), state["executor_generation"].as_u64()) {
                (Some("running"), Some(generation)) => Ownership::Current(generation),
                _ => Ownership::Refused("run_not_running"),
            },
        )
    }

    async fn budget_has_capacity(&self, admission: &RunAdmission) -> Result<bool, GatewayError> {
        let key = DocKey::new(&admission.tenant_id, DocKind::BudgetLedger, &admission.budget_ledger_id);
        Ok(self.store.get(&key).await?.is_some_and(|l| {
            let b = &l.body;
            ["tokens", "tool_calls", "replans", "cost_units"].iter().all(|k| {
                b["ceiling"][*k].as_i64().unwrap_or(0)
                    - b["used"][*k].as_i64().unwrap_or(0)
                    - b["reserved"][*k].as_i64().unwrap_or(0)
                    >= 0
            }) && b["ceiling"]["tool_calls"].as_i64().unwrap_or(0)
                > b["used"]["tool_calls"].as_i64().unwrap_or(0) + b["reserved"]["tool_calls"].as_i64().unwrap_or(0)
        }))
    }
}
