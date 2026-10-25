//! Reconciling unresolved effects.
//!
//! A dispatch whose outcome is unknown (lost response, timeout, an effectful tool
//! error, an MCP task still running) holds its budget reservation and blocks blind
//! retries. Reconciliation resolves the latest attempt with a definitive fact, from
//! one of two sources:
//!
//! - **Provider query** — the adapter asks the provider about the attempt's external
//!   reference (for MCP, `tasks/get` on the task id). Unfinished work stays pending.
//! - **Operator assertion** — an authenticated, authorized principal states the
//!   outcome and cites evidence (a ticket, a provider console record, a ledger
//!   extract). The gateway records it as its own verified observation and the
//!   asserting principal goes into the audit entry.
//!
//! The fact is recorded through the kernel (which refuses conflicting or misbound
//! facts), audited, and the held reservation is settled without further charge.
//! A confirmed effect is never re-dispatched; a definitively unapplied one becomes
//! eligible for retry under the operation's recovery policy.
//!
//! An attempt that was claimed but has no fact (its process crashed between the claim
//! and the provider's answer) is unresolved too. Recording it as not applied first
//! closes its dispatch gate ([`crate::dispatch_gate_key`]): if the dispatch opened the
//! gate first, the effect may be in flight and the assertion is refused
//! (`dispatch_active`); otherwise the stranded dispatch, if it resumes, finds the gate
//! closed and sends nothing.

use std::time::Duration;

use contextos_contract::canonical::sha256_canonical;
use contextos_contract::validation::add_contract_seconds;
use contextos_kernel::operation_ledger::record_effect_observation;
use contextos_store::{AppendLog, Commit, DocKey, DocKind, DocumentStore, transact};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::{
    AdapterCall, AdapterResponse, EffectOutcome, Gateway, GatewayError, OBSERVATION_VALIDITY_SECONDS, RunAdmission,
    later, operation_ledger_key,
};

/// Where the resolving fact comes from.
#[derive(Debug, Clone, PartialEq)]
pub enum Resolution {
    /// Ask the provider about the attempt's external reference.
    Query,
    /// An authorized operator asserts a definitive outcome, citing evidence.
    Assert {
        outcome: EffectOutcome,
        /// `ArtifactRef` for the evidence the operator relied on.
        evidence_ref: Value,
        principal_id: String,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReconcileOutcome {
    /// `resolved`, `pending` (still unknown), `no_change` (nothing to reconcile) or
    /// `rejected`.
    pub status: String,
    pub operation_id: String,
    pub attempt_id: Option<String>,
    /// The operation's outcome after reconciliation.
    pub outcome: Option<String>,
    pub reason_codes: Vec<String>,
    pub obligations: Vec<String>,
    pub output: Map<String, Value>,
    pub audit_sequences: Vec<u64>,
}

impl ReconcileOutcome {
    fn new(operation_id: &str, status: &str) -> Self {
        Self {
            status: status.into(),
            operation_id: operation_id.into(),
            attempt_id: None,
            outcome: None,
            reason_codes: Vec::new(),
            obligations: Vec::new(),
            output: Map::new(),
            audit_sequences: Vec::new(),
        }
    }

    fn rejected(mut self, reason: &str) -> Self {
        "rejected".clone_into(&mut self.status);
        self.reason_codes.push(reason.into());
        self
    }
}

fn artifact_ref(value: &Value) -> bool {
    let text = |k: &str| value[k].as_str().is_some_and(|s| !s.is_empty() && s.len() <= 256);
    let digest = value["sha256"]
        .as_str()
        .and_then(|d| d.strip_prefix("sha256:"))
        .is_some_and(|h| h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()));
    value.as_object().is_some_and(|o| o.len() == 4)
        && text("artifact_type")
        && text("artifact_id")
        && text("version")
        && digest
}

impl<S: DocumentStore + 'static, L: AppendLog + 'static> Gateway<S, L> {
    /// Resolves the latest attempt of an operation whose outcome is unknown.
    #[tracing::instrument(name = "contextos.reconcile", skip_all, fields(run_id = %admission.run_id, operation_id))]
    pub async fn reconcile(
        &self,
        admission: &RunAdmission,
        operation_id: &str,
        resolution: Resolution,
    ) -> Result<ReconcileOutcome, GatewayError> {
        let mut out = ReconcileOutcome::new(operation_id, "no_change");
        let key = operation_ledger_key(admission, operation_id);
        let Some(read) = self.store.get(&key).await? else {
            return Ok(out.rejected("operation_not_found"));
        };
        let Some(op) = read.body["operations"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|op| op["intent"]["operation_id"] == operation_id)
            .cloned()
        else {
            return Ok(out.rejected("operation_not_found"));
        };
        out.outcome = op["outcome"].as_str().map(str::to_owned);
        let shared = self.has_exposure_link(admission, operation_id).await?;
        if shared {
            out.audit_sequences
                .extend(self.settle_shared_exposure(admission, operation_id).await?);
        }
        // A claimed attempt without a definitive fact may or may not have been sent (the
        // process may have crashed on either side of the provider call): it is
        // unresolved, like an unknown outcome.
        let claimed_without_fact = op["attempts"].as_array().and_then(|a| a.last()).is_some_and(|a| {
            a["dispatch_state"] == "claimed"
                && !op["observations"].as_array().into_iter().flatten().any(|o| {
                    o["attempt_id"] == a["attempt_id"] && o["finality"] == "definitive" && o["outcome"] != "unknown"
                })
        });
        if (op["outcome"] != "unknown" && !claimed_without_fact) || op["conflict"] == true {
            if shared
                && let Resolution::Assert {
                    outcome,
                    evidence_ref,
                    principal_id,
                } = &resolution
                && op["outcome"].as_str() != Some(outcome.as_str())
            {
                out.status = "rejected".into();
                out.reason_codes.push("shared_guarantee_attempt_sealed".into());
                out.audit_sequences.push(
                    self.shared_observation_refused(
                        admission,
                        &json!({"operation_id":operation_id,
                    "outcome":outcome.as_str(),"evidence_ref":evidence_ref,"principal_id":principal_id}),
                        &out.reason_codes,
                    )
                    .await?,
                );
                return Ok(out);
            }
            // Only unknown outcomes are reconciled here; conflicts and partial effects
            // need human escalation, and settled outcomes need nothing.
            if op["conflict"] == true {
                out.reason_codes.push("conflicting_effect_evidence".into());
            }
            return Ok(out);
        }
        let Some(attempt) = op["attempts"].as_array().and_then(|a| a.last()).cloned() else {
            return Ok(out.rejected("operation_not_found"));
        };
        let attempt_id = attempt["attempt_id"].as_str().unwrap_or_default().to_owned();
        out.attempt_id = Some(attempt_id.clone());
        let intent = &op["intent"];
        let Some(manifest) = self
            .manifests
            .values()
            .find(|m| serde_json::to_value(&m.capability_ref).ok().as_ref() == Some(&intent["capability_ref"]))
        else {
            return Ok(out.rejected("capability_not_pinned"));
        };
        let now = self.now();

        let (response, source, principal) = match resolution {
            Resolution::Query => {
                let external_ref = op["observations"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .rev()
                    .filter(|o| o["attempt_id"] == attempt_id.as_str())
                    .find_map(|o| o["external_ref"].as_str().map(str::to_owned));
                let (Some(external_ref), Some(adapter)) = (external_ref, self.adapters.get(&manifest.adapter_id))
                else {
                    return Ok(out.rejected("reconcile_requires_operator"));
                };
                let call = AdapterCall {
                    tenant_id: admission.tenant_id.clone(),
                    run_id: admission.run_id.clone(),
                    trace_id: admission.trace_id.clone(),
                    operation_id: operation_id.to_owned(),
                    attempt_id: self.ports.ids.new_id("query"),
                    action_digest: intent["action_digest"].as_str().unwrap_or_default().to_owned(),
                    protocol_tool: manifest.protocol_tool.clone(),
                    arguments: Value::Null,
                    idempotency_key: intent["idempotency_key"].as_str().map(str::to_owned),
                    deadline: add_contract_seconds(&now, manifest.timeout_ms.div_ceil(1000))
                        .unwrap_or_else(|| admission.deadline.clone()),
                    input: None,
                    executor_generation: None,
                };
                let queried = tokio::time::timeout(
                    Duration::from_millis(manifest.timeout_ms),
                    adapter.query(manifest, &call, &external_ref),
                )
                .await
                .unwrap_or_else(|_| Some(AdapterResponse::unknown()));
                let Some(response) = queried else {
                    return Ok(out.rejected("reconcile_requires_operator"));
                };
                (response, "provider", None)
            }
            Resolution::Assert {
                outcome,
                evidence_ref,
                principal_id,
            } => {
                if !matches!(
                    outcome,
                    EffectOutcome::Confirmed | EffectOutcome::NotApplied | EffectOutcome::Partial
                ) || !artifact_ref(&evidence_ref)
                    || principal_id.is_empty()
                {
                    return Ok(out.rejected("reconcile_assertion_invalid"));
                }
                let mut output = Map::new();
                output.insert("evidence_ref".into(), evidence_ref);
                let response = AdapterResponse {
                    outcome,
                    definitive: true,
                    output,
                    external_ref: None,
                    cost_units: None,
                };
                (response, "operator", Some(principal_id))
            }
        };
        out.output.clone_from(&response.output);
        if !response.definitive || response.outcome == EffectOutcome::Unknown {
            "pending".clone_into(&mut out.status);
            out.obligations.push("reconcile_effect_before_retry".into());
            return Ok(out);
        }

        // A rejected assertion/query must not abort a live dispatch. At this point
        // the resolving response and operator evidence have been validated.
        if claimed_without_fact && response.outcome != EffectOutcome::Confirmed && !shared {
            // Close the dispatch gate first: if the attempt's dispatch already opened it,
            // the effect may be in flight and cannot be recorded as not applied.
            let gate = crate::dispatch_gate_key(admission, &attempt_id);
            match self
                .store
                .create(&gate, &json!({"state": "aborted", "operation_id": operation_id}))
                .await
            {
                Ok(_) => {}
                Err(e) if e.is_conflict() => {
                    if self
                        .store
                        .get(&gate)
                        .await?
                        .is_some_and(|g| g.body["state"] == "started")
                    {
                        return Ok(out.rejected("dispatch_active"));
                    }
                }
                Err(e) => return Err(e.into()),
            }
        }
        if claimed_without_fact && response.outcome != EffectOutcome::Confirmed && shared {
            let request = self
                .audit
                .append(
                    &admission.tenant_id,
                    "shared_guarantee_abort_requested",
                    json!({"run_id":admission.run_id,"operation_id":operation_id,"attempt_id":attempt_id,
                    "source":source,"principal_id":principal,"outcome":response.outcome.as_str(),
                    "evidence_ref":response.output.get("evidence_ref")}),
                    &now,
                )
                .await?;
            out.audit_sequences.push(request.sequence);
            if let Err(reasons) = self
                .transition_shared_dispatch(admission, operation_id, &attempt_id, "abort")
                .await?
            {
                out.status = "rejected".into();
                out.reason_codes = reasons;
                out.audit_sequences.push(
                    self.shared_observation_refused(
                        admission,
                        &json!({"operation_id":operation_id,
                    "attempt_id":attempt_id,"kind":"pre_dispatch_resolution"}),
                        &out.reason_codes,
                    )
                    .await?,
                );
                return Ok(out);
            }
        }

        // Record the fact against the original attempt.
        let observed_at = later(now, attempt["started_at"].as_str().unwrap_or_default());
        let valid_until =
            add_contract_seconds(&observed_at, OBSERVATION_VALIDITY_SECONDS).unwrap_or_else(|| observed_at.clone());
        let observation_id = self.ports.ids.new_id("observation");
        let evidence_ref = match response.output.get("evidence_ref") {
            Some(cited) if source == "operator" => cited.clone(),
            _ => json!({"artifact_type": "effect_observation", "artifact_id": observation_id, "version": "1",
                "sha256": sha256_canonical(&serde_json::to_value(&response).unwrap_or(Value::Null)).unwrap_or_default()}),
        };
        let observation = json!({
            "observation_id": observation_id, "contract_id": admission.contract_id, "run_id": admission.run_id,
            "tenant_id": admission.tenant_id, "operation_id": operation_id, "attempt_id": attempt_id,
            "action_digest": intent["action_digest"], "executor_generation": attempt["executor_generation"],
            "outcome": response.outcome.as_str(), "finality": "definitive", "external_ref": response.external_ref,
            "evidence_ref": evidence_ref, "verification_status": "verified", "observer": admission.gateway_observer,
            "observed_at": observed_at, "valid_until": valid_until, "evaluation_time": observed_at,
        });
        let commit = transact(self.store.as_ref(), &key, |ledger| {
            if shared {
                crate::shared_guarantees::record_shared_observation(ledger, &observation)
            } else {
                record_effect_observation(ledger, &observation, &ledger["revision"])
            }
        })
        .await?;
        match commit {
            Commit::Rejected { reason_codes } => {
                if shared {
                    out.audit_sequences.push(
                        self.shared_observation_refused(admission, &observation, &reason_codes)
                            .await?,
                    );
                }
                out.status = "rejected".into();
                out.reason_codes = reason_codes;
                return Ok(out);
            }
            Commit::Written { obligations, .. } | Commit::Unchanged { obligations } => out.obligations = obligations,
        }
        if let Some(op) = self.store.get(&key).await?.and_then(|r| {
            r.body["operations"]
                .as_array()
                .into_iter()
                .flatten()
                .find(|op| op["intent"]["operation_id"] == operation_id)
                .cloned()
        }) {
            out.outcome = op["outcome"].as_str().map(str::to_owned);
        }
        let entry = self
            .audit
            .append(
                &admission.tenant_id,
                "effect_reconciliation",
                json!({"operation_id": operation_id, "attempt_id": attempt_id, "observation_id": observation_id,
                    "outcome": response.outcome.as_str(), "source": source, "principal_id": principal,
                    "evidence_ref": evidence_ref}),
                &observed_at,
            )
            .await?;
        out.audit_sequences.push(entry.sequence);
        out.audit_sequences
            .extend(self.settle_shared_exposure(admission, operation_id).await?);

        // A confirmed claim without a provider observation has no measured usage.
        // Charge its protected original allocation conservatively; an original
        // response sealed out by recovery must not turn this call into free usage.
        let budget_key = DocKey::new(&admission.tenant_id, DocKind::BudgetLedger, &admission.budget_ledger_id);
        let reservation_id = format!("reservation:{attempt_id}");
        let held = self.store.get(&budget_key).await?.and_then(|r| {
            r.body["reservations"]
                .as_array()
                .into_iter()
                .flatten()
                .find(|res| res["reservation_id"] == reservation_id.as_str() && res["status"] != "settled")
                .map(|res| {
                    if claimed_without_fact && response.outcome == EffectOutcome::Confirmed {
                        res["allocation"].clone()
                    } else {
                        res["used"].clone()
                    }
                })
        });
        if let Some(used) = held {
            self.settle(
                admission,
                &budget_key,
                &reservation_id,
                &format!("reconcile:{observation_id}"),
                &observed_at,
                &valid_until,
                &evidence_ref,
                &used,
                true,
            )
            .await?;
        }
        if let Some(outcome) = &out.outcome {
            self.note_effect(admission, operation_id, outcome).await?;
        }
        "resolved".clone_into(&mut out.status);
        Ok(out)
    }
}
