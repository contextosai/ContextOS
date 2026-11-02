//! Outcome contracts: an applied effect is done when its witness says so.
//!
//! A provider confirming a refund call says the call was accepted, not that the refund
//! posted to the right order for the right amount. A capability may declare an
//! `outcome` contract (see [`crate::manifest::OutcomeContract`]): a witness, an
//! `[[evidence_issuers]]` issuer independent of the provider, must attest a named
//! postcondition for the action's resource within a deadline.
//!
//! - **Before dispatch** the contract is recorded for the operation and action, with the
//!   action's resource digests and amount, and indexed for the run and the tenant. A
//!   full index refuses the call (`outcome_index_full`): an effect is never sent that
//!   could not be held to its contract.
//! - **When the effect is applied** (confirmed or partial, at dispatch or by
//!   reconciliation) the record becomes `pending` with `due_at`, audited as
//!   `outcome_pending`. The run cannot complete while any outcome is `pending` or
//!   `missed` (`outcome_pending`).
//! - **The witness's observation** (verified by contextosd: signature, issuer, tenant,
//!   postcondition, validity) is bound here to the effect: its subject must be the
//!   action's resource (the guarantee's canonical resource when the capability has a
//!   shared guarantee), its amount the action's amount when it has one, and it must
//!   have been observed after the effect was applied. Accepted, it is audited
//!   (`outcome_witnessed`) and closes the outcome.
//! - **Past `due_at`**, the governance sweep opens one escalation for the operation
//!   (`reason_codes: ["outcome_missed"]`). The outcome stays open: a late observation
//!   still closes it, and nothing is resolved by waiting.

use contextos_contract::canonical::{sha256_canonical, sha256_text};
use contextos_contract::validation::{add_contract_seconds, compare_contract_times};
use contextos_store::{AppendLog, DocKey, DocKind, DocumentStore};
use serde_json::{Value, json};

use crate::admission::RunAdmission;
use crate::manifest::CapabilityManifest;
use crate::{Gateway, GatewayError, operation_ledger_key};

/// Outcome contracts one run may hold.
pub const MAX_RUN_OUTCOMES: usize = 1024;

/// Open (not yet witnessed or escalated) outcomes a tenant may hold.
pub const MAX_TENANT_OUTCOMES: usize = 10_000;

/// A witness's verified observation, as contextosd hands it over.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WitnessObservation {
    /// The attestation's `iss`.
    pub issuer: String,
    /// The attestation's `sub`: the resource it observed.
    pub subject: String,
    pub observed_at: String,
    pub valid_until: String,
    /// The attestation's `amount`, when it states one.
    pub amount: Option<Value>,
    /// The digest of the attestation token, recorded in place of the token.
    pub attestation_digest: String,
}

fn record_key(tenant: &str, run_id: &str, operation_id: &str, action_digest: &str) -> DocKey {
    let digest = sha256_text(&format!("{run_id}\u{0}{operation_id}\u{0}{action_digest}"));
    DocKey::new(tenant, DocKind::Outcome, format!("rec_{}", &digest[7..39]))
}

fn run_index(admission: &RunAdmission) -> DocKey {
    DocKey::new(
        &admission.tenant_id,
        DocKind::Outcome,
        format!("run:{}", admission.run_id),
    )
}

fn tenant_index(tenant: &str) -> DocKey {
    DocKey::new(tenant, DocKind::Outcome, "open")
}

fn digest(value: &Value) -> Result<String, GatewayError> {
    sha256_canonical(value).map_err(|_| GatewayError::Outcome("outcome digest".into()))
}

fn ids(index: Option<contextos_store::Versioned>) -> Vec<String> {
    index
        .and_then(|i| i.body["keys"].as_array().cloned())
        .unwrap_or_default()
        .iter()
        .filter_map(|v| v.as_str().map(str::to_owned))
        .collect()
}

impl<S: DocumentStore + 'static, L: AppendLog + 'static> Gateway<S, L> {
    /// Records the capability's outcome contract for this operation and action before
    /// it is dispatched. `Ok(Err)` refuses the call.
    pub(crate) async fn register_outcome(
        &self,
        admission: &RunAdmission,
        manifest: &CapabilityManifest,
        operation_id: &str,
        action_digest: &str,
        binding: &Value,
    ) -> Result<Result<(), &'static str>, GatewayError> {
        let Some(contract) = &manifest.outcome else {
            return Ok(Ok(()));
        };
        let key = record_key(&admission.tenant_id, &admission.run_id, operation_id, action_digest);
        if self.store.get(&key).await?.is_some() {
            return Ok(Ok(()));
        }
        if !self
            .note_in_index(run_index(admission), &key.id, MAX_RUN_OUTCOMES)
            .await?
            || !self
                .note_in_index(tenant_index(&admission.tenant_id), &key.id, MAX_TENANT_OUTCOMES)
                .await?
        {
            return Ok(Err("outcome_index_full"));
        }
        let resource_digests = binding["resource_ids"]
            .as_array()
            .into_iter()
            .flatten()
            .map(digest)
            .collect::<Result<Vec<_>, _>>()?;
        let record = json!({
            "run_id": admission.run_id, "operation_id": operation_id, "action_digest": action_digest,
            "capability_id": manifest.capability_id, "witness": contract.witness,
            "postcondition": contract.postcondition, "within_seconds": contract.within_seconds,
            "on_missed": contract.on_missed, "resource_digests": resource_digests,
            "amount": binding.get("amount").cloned().unwrap_or(Value::Null),
            "state": "awaiting_effect", "registered_at": self.now(),
        });
        match self.store.create(&key, &record).await {
            Ok(_) => Ok(Ok(())),
            Err(e) if e.is_conflict() => Ok(Ok(())),
            Err(e) => Err(e.into()),
        }
    }

    /// The outcome record of the action the run's ledger holds for `operation_id`.
    async fn outcome_doc(
        &self,
        admission: &RunAdmission,
        operation_id: &str,
    ) -> Result<Option<contextos_store::Versioned>, GatewayError> {
        let Some(ledger) = self.store.get(&operation_ledger_key(admission, operation_id)).await? else {
            return Ok(None);
        };
        let Some(action_digest) = ledger.body["operations"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|op| op["intent"]["operation_id"] == operation_id)
            .and_then(|op| op["intent"]["action_digest"].as_str())
        else {
            return Ok(None);
        };
        let key = record_key(&admission.tenant_id, &admission.run_id, operation_id, action_digest);
        Ok(self.store.get(&key).await?)
    }

    /// The outcome contract record of an operation, if its capability declares one.
    pub async fn outcome(&self, admission: &RunAdmission, operation_id: &str) -> Result<Option<Value>, GatewayError> {
        Ok(self.outcome_doc(admission, operation_id).await?.map(|d| d.body))
    }

    /// Starts an outcome's deadline once its effect is applied. Idempotent.
    pub(crate) async fn start_outcome(&self, admission: &RunAdmission, operation_id: &str) -> Result<(), GatewayError> {
        if !self.manifests.values().any(|m| m.outcome.is_some()) {
            return Ok(());
        }
        for _ in 0..8 {
            let Some(doc) = self.outcome_doc(admission, operation_id).await? else {
                return Ok(());
            };
            if doc.body["state"] != "awaiting_effect" {
                return Ok(());
            }
            let now = self.now();
            let within = doc.body["within_seconds"].as_u64().unwrap_or(0);
            let mut record = doc.body.clone();
            record["state"] = json!("pending");
            record["effect_at"] = json!(now);
            record["due_at"] = json!(add_contract_seconds(&now, within));
            let key = record_key(
                &admission.tenant_id,
                &admission.run_id,
                operation_id,
                record["action_digest"].as_str().unwrap_or_default(),
            );
            match self.store.compare_and_swap(&key, doc.revision, &record).await {
                Ok(_) => {
                    let payload = json!({"run_id": admission.run_id, "operation_id": operation_id,
                        "capability_id": record["capability_id"], "witness": record["witness"],
                        "postcondition": record["postcondition"], "due_at": record["due_at"]});
                    self.audit
                        .append(&admission.tenant_id, "outcome_pending", payload, &now)
                        .await?;
                    return Ok(());
                }
                Err(e) if e.is_conflict() => {}
                Err(e) => return Err(e.into()),
            }
        }
        Err(GatewayError::Outcome("outcome record contended".into()))
    }

    /// Whether any of the run's applied effects still waits for its witness.
    pub(crate) async fn outcome_unwitnessed(&self, admission: &RunAdmission) -> Result<bool, GatewayError> {
        for id in ids(self.store.get(&run_index(admission)).await?) {
            let key = DocKey::new(&admission.tenant_id, DocKind::Outcome, &id);
            if let Some(doc) = self.store.get(&key).await?
                && matches!(doc.body["state"].as_str(), Some("pending" | "missed"))
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// The run's outcome records, for its evidence bundle.
    pub(crate) async fn run_outcomes(&self, admission: &RunAdmission) -> Result<Vec<Value>, GatewayError> {
        let mut outcomes = Vec::new();
        for id in ids(self.store.get(&run_index(admission)).await?) {
            let key = DocKey::new(&admission.tenant_id, DocKind::Outcome, &id);
            if let Some(doc) = self.store.get(&key).await? {
                outcomes.push(doc.body);
            }
        }
        Ok(outcomes)
    }

    /// Binds a verified witness observation to the operation's effect and closes its
    /// outcome. `Ok(Err)` is the refusal reason; `Ok(Ok)` is the closed record (also for
    /// an outcome already witnessed).
    pub async fn witness_outcome(
        &self,
        admission: &RunAdmission,
        operation_id: &str,
        observation: &WitnessObservation,
    ) -> Result<Result<Value, &'static str>, GatewayError> {
        for _ in 0..8 {
            let Some(doc) = self.outcome_doc(admission, operation_id).await? else {
                return Ok(Err("outcome_not_required"));
            };
            let record = &doc.body;
            match record["state"].as_str() {
                Some("witnessed") => return Ok(Ok(record.clone())),
                Some("pending" | "missed") => {}
                _ => return Ok(Err("outcome_effect_not_applied")),
            }
            if record["witness"] != observation.issuer.as_str() {
                return Ok(Err("outcome_witness_mismatch"));
            }
            let subject = digest(&json!(observation.subject))?;
            let bound = match self.linked_resource_digest(admission, operation_id).await? {
                Some(canonical) => canonical == subject,
                None => record["resource_digests"]
                    .as_array()
                    .is_some_and(|d| d.iter().any(|r| r == subject.as_str())),
            };
            if !bound {
                return Ok(Err("outcome_resource_mismatch"));
            }
            if !record["amount"].is_null() && observation.amount.as_ref() != Some(&record["amount"]) {
                return Ok(Err("outcome_amount_mismatch"));
            }
            let effect_at = record["effect_at"].as_str().unwrap_or_default();
            if matches!(
                compare_contract_times(&observation.observed_at, effect_at),
                None | Some(std::cmp::Ordering::Less)
            ) {
                return Ok(Err("outcome_before_effect"));
            }
            let now = self.now();
            let mut closed = record.clone();
            closed["state"] = json!("witnessed");
            closed["witnessed_at"] = json!(now);
            closed["late"] = json!(record["state"] == "missed");
            closed["observation"] = json!({"issuer": observation.issuer, "subject_digest": subject,
                "observed_at": observation.observed_at, "valid_until": observation.valid_until,
                "attestation_digest": observation.attestation_digest});
            let key = record_key(
                &admission.tenant_id,
                &admission.run_id,
                operation_id,
                record["action_digest"].as_str().unwrap_or_default(),
            );
            // Audited before it counts: no outcome is closed without its entry.
            let payload = json!({"run_id": admission.run_id, "operation_id": operation_id,
                "capability_id": record["capability_id"], "postcondition": record["postcondition"],
                "late": closed["late"], "observation": closed["observation"]});
            self.audit
                .append(&admission.tenant_id, "outcome_witnessed", payload, &now)
                .await?;
            match self.store.compare_and_swap(&key, doc.revision, &closed).await {
                Ok(_) => {
                    self.drop_from(tenant_index(&admission.tenant_id), &key.id).await?;
                    return Ok(Ok(closed));
                }
                Err(e) if e.is_conflict() => {}
                Err(e) => return Err(e.into()),
            }
        }
        Err(GatewayError::Outcome("outcome record contended".into()))
    }

    /// Opens one escalation for each of the tenant's outcomes past due, reading at most
    /// `limit` open outcomes. Returns how many it opened.
    pub async fn escalate_missed_outcomes(&self, tenant: &str, limit: usize) -> Result<usize, GatewayError> {
        let now = self.now();
        let mut opened = 0;
        for id in ids(self.store.get(&tenant_index(tenant)).await?)
            .into_iter()
            .take(limit)
        {
            let key = DocKey::new(tenant, DocKind::Outcome, &id);
            let Some(doc) = self.store.get(&key).await? else {
                self.drop_from(tenant_index(tenant), &id).await?;
                continue;
            };
            let record = &doc.body;
            match record["state"].as_str() {
                Some("pending") => {}
                Some("awaiting_effect") => continue,
                _ => {
                    self.drop_from(tenant_index(tenant), &id).await?;
                    continue;
                }
            }
            let due = record["due_at"].as_str().unwrap_or_default();
            if compare_contract_times(&now, due) == Some(std::cmp::Ordering::Less) {
                continue;
            }
            let run_id = record["run_id"].as_str().unwrap_or_default();
            let Some(admission) = self
                .store
                .get(&DocKey::new(tenant, DocKind::RunAdmission, run_id))
                .await?
                .and_then(|r| serde_json::from_value::<RunAdmission>(r.body).ok())
            else {
                continue;
            };
            let operation_id = record["operation_id"].as_str().unwrap_or_default();
            let facts = json!({"operation_id": operation_id, "capability_id": record["capability_id"],
                "action_digest": record["action_digest"], "witness": record["witness"],
                "postcondition": record["postcondition"], "due_at": due,
                "reason_codes": ["outcome_missed"]});
            let escalation_id = self
                .open_escalation_for(&admission, &format!("outcome:{operation_id}"), facts)
                .await?;
            let mut missed = record.clone();
            missed["state"] = json!("missed");
            missed["escalation_id"] = json!(escalation_id);
            match self.store.compare_and_swap(&key, doc.revision, &missed).await {
                Ok(_) => {
                    opened += 1;
                    self.drop_from(tenant_index(tenant), &id).await?;
                }
                // Witnessed meanwhile: the next pass drops it.
                Err(e) if e.is_conflict() => {}
                Err(e) => return Err(e.into()),
            }
        }
        Ok(opened)
    }
}

impl<S: DocumentStore + 'static, L: AppendLog + 'static> Gateway<S, L> {
    /// Each pinned capability's outcome contract, for startup checks.
    #[must_use]
    pub fn outcome_contracts(&self) -> Vec<(String, crate::manifest::OutcomeContract)> {
        let mut contracts: Vec<_> = self
            .manifests
            .values()
            .filter_map(|m| m.outcome.clone().map(|o| (m.capability_id.clone(), o)))
            .collect();
        contracts.sort_by(|a, b| a.0.cmp(&b.0));
        contracts
    }
}
