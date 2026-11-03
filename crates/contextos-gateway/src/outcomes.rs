//! Outcome contracts: an applied effect is done when its witness says so.
//!
//! A provider confirming a refund call says the call was accepted, not that the refund
//! posted to the right order for the right amount. A capability may declare an
//! `outcome` contract (see [`crate::manifest::OutcomeContract`]): a witness, an
//! `[[evidence_issuers]]` issuer independent of the provider, must attest a named
//! postcondition for the action's resource within a deadline.
//!
//! - **Before dispatch** the contract is recorded for the operation, action and attempt
//!   (`awaiting_effect`), with the action's resource digests and amount, and indexed
//!   for the run and the tenant. A full index refuses the call (`outcome_index_full`):
//!   an effect is never sent that could not be held to its contract. The record is
//!   armed for its attempt after the claim and before the send, which fences it against
//!   retirement and abandonment (see [`crate::outcome_fence`]).
//! - **The operation ledger decides what became of the effect**, not a separate write:
//!   whenever the record is read while `awaiting_effect` (after dispatch, by
//!   reconciliation, by the completion gate, by the sweep), it is brought up to the
//!   ledger. Applied (confirmed or partial) makes it `pending`, with `effect_at` the
//!   ledger's first observation of the effect and `due_at` counted from it, audited as
//!   `outcome_pending`; a crash between the ledger write and this one loses neither the
//!   obligation nor its deadline. The armed attempt definitively not applied (or never
//!   dispatched) retires it (`not_applicable`) and frees its index entries; another
//!   attempt's negative result does not. Unresolved keeps it waiting.
//! - **The run cannot complete** while any outcome is `pending` or `missed`, or
//!   `awaiting_effect` with an effect the ledger has not resolved (`outcome_pending`).
//! - **The witness's observation** (verified by contextosd: signature, issuer, tenant,
//!   postcondition, validity) is bound here to the effect: its subject must be the
//!   action's resource (the guarantee's canonical resource when the capability has a
//!   shared guarantee), its amount the action's amount when it has one, and it must
//!   have been observed after the effect was applied. A contract that `binds` the
//!   `effect` also needs the observation's `receipt` to be the provider's reference the
//!   ledger recorded for the effect, and closes at most one effect per attestation
//!   (`outcome_attestation_reused`); one that binds `state` accepts an observation of
//!   the resource's state for every effect it followed. Accepted, it is audited
//!   (`outcome_witnessed`) and closes the outcome.
//! - **Past `due_at`**, the governance sweep opens one escalation for the operation
//!   (`reason_codes: ["outcome_missed"]`); see [`crate::outcome_sweep`]. The outcome stays
//!   open: a late observation still closes it, and nothing is resolved by waiting.

use contextos_contract::canonical::{sha256_canonical, sha256_text};
use contextos_contract::validation::{add_contract_seconds, compare_contract_times};
use contextos_store::{AppendLog, DocKey, DocKind, DocumentStore, Versioned};
use serde_json::{Value, json};

use crate::admission::RunAdmission;
use crate::manifest::OutcomeBinds;
use crate::outcome_fence::{attempt_not_applied, owed_by};
use crate::{Gateway, GatewayError, operation_ledger_key};

/// Outcome contracts one run may hold.
pub const MAX_RUN_OUTCOMES: usize = 1024;

/// Open (not yet witnessed, escalated or retired) outcomes a tenant may hold.
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
    /// The attestation's `receipt`: the provider's reference for the effect it saw.
    pub receipt: Option<String>,
    /// The digest of the attestation token, recorded in place of the token.
    pub attestation_digest: String,
}

/// What the operation ledger says became of an operation's effect.
#[derive(Debug, Clone, PartialEq, Eq)]
enum LedgerEffect {
    /// Applied, first observed at `at`, with the provider's reference if it gave one.
    Applied { at: String, receipt: Option<String> },
    /// Definitively not applied, or never dispatched.
    NotApplied,
    /// In flight, unknown, or not yet observed.
    Unresolved,
}

fn ledger_effect(op: &Value) -> LedgerEffect {
    let observations = op["observations"].as_array().map_or(&[][..], Vec::as_slice);
    let applied: Vec<&Value> = observations
        .iter()
        .filter(|o| matches!(o["outcome"].as_str(), Some("confirmed" | "partial")))
        .collect();
    let first = applied
        .iter()
        .filter_map(|o| o["observed_at"].as_str())
        .min_by(|a, b| compare_contract_times(a, b).unwrap_or(std::cmp::Ordering::Equal));
    if let Some(at) = first.filter(|_| matches!(op["outcome"].as_str(), Some("confirmed" | "partial"))) {
        let receipt = applied
            .iter()
            .rev()
            .find_map(|o| o["external_ref"].as_str().filter(|r| !r.is_empty()))
            .map(str::to_owned);
        return LedgerEffect::Applied {
            at: at.to_owned(),
            receipt,
        };
    }
    match op["outcome"].as_str() {
        Some("not_applied" | "not_dispatched")
            if observations
                .iter()
                .any(|o| o["finality"] == "definitive" && o["outcome"] == op["outcome"]) =>
        {
            LedgerEffect::NotApplied
        }
        _ => LedgerEffect::Unresolved,
    }
}

pub(crate) fn record_key(tenant: &str, run_id: &str, operation_id: &str, action_digest: &str) -> DocKey {
    let digest = sha256_text(&format!("{run_id}\u{0}{operation_id}\u{0}{action_digest}"));
    DocKey::new(tenant, DocKind::Outcome, format!("rec_{}", &digest[7..39]))
}

fn record_key_of(admission: &RunAdmission, record: &Value) -> DocKey {
    record_key(
        &admission.tenant_id,
        &admission.run_id,
        record["operation_id"].as_str().unwrap_or_default(),
        record["action_digest"].as_str().unwrap_or_default(),
    )
}

/// The claim that an effect contract's attestation closed one outcome.
fn attestation_key(tenant: &str, attestation_digest: &str) -> DocKey {
    let digest = sha256_text(attestation_digest);
    DocKey::new(tenant, DocKind::Outcome, format!("att_{}", &digest[7..39]))
}

pub(crate) fn run_index(admission: &RunAdmission) -> DocKey {
    DocKey::new(
        &admission.tenant_id,
        DocKind::Outcome,
        format!("run:{}", admission.run_id),
    )
}

pub(crate) fn tenant_index(tenant: &str) -> DocKey {
    DocKey::new(tenant, DocKind::Outcome, "open")
}

pub(crate) fn digest(value: &Value) -> Result<String, GatewayError> {
    sha256_canonical(value).map_err(|_| GatewayError::Outcome("outcome digest".into()))
}

pub(crate) fn ids(index: Option<Versioned>) -> Vec<String> {
    index
        .and_then(|i| i.body["keys"].as_array().cloned())
        .unwrap_or_default()
        .iter()
        .filter_map(|v| v.as_str().map(str::to_owned))
        .collect()
}

impl<S: DocumentStore + 'static, L: AppendLog + 'static> Gateway<S, L> {
    /// The outcome record of the action the run's ledger holds for `operation_id`,
    /// with that operation as the ledger has it.
    async fn outcome_doc(
        &self,
        admission: &RunAdmission,
        operation_id: &str,
    ) -> Result<Option<(Versioned, Value)>, GatewayError> {
        let Some(ledger) = self.store.get(&operation_ledger_key(admission, operation_id)).await? else {
            return Ok(None);
        };
        let Some(op) = ledger.body["operations"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|op| op["intent"]["operation_id"] == operation_id)
        else {
            return Ok(None);
        };
        let Some(action_digest) = op["intent"]["action_digest"].as_str() else {
            return Ok(None);
        };
        let key = record_key(&admission.tenant_id, &admission.run_id, operation_id, action_digest);
        Ok(self.store.get(&key).await?.map(|doc| (doc, op.clone())))
    }

    /// The outcome contract record of an operation, if its capability declares one,
    /// brought up to what the operation ledger says of its effect.
    pub async fn outcome(&self, admission: &RunAdmission, operation_id: &str) -> Result<Option<Value>, GatewayError> {
        self.sync_outcome(admission, operation_id).await
    }

    /// Brings an `awaiting_effect` record up to the operation ledger (see the module
    /// documentation). Idempotent; returns the record as it now stands.
    pub(crate) async fn sync_outcome(
        &self,
        admission: &RunAdmission,
        operation_id: &str,
    ) -> Result<Option<Value>, GatewayError> {
        for _ in 0..8 {
            let Some((doc, op)) = self.outcome_doc(admission, operation_id).await? else {
                return Ok(None);
            };
            if doc.body["state"] != "awaiting_effect" {
                return Ok(Some(doc.body));
            }
            let mut record = doc.body.clone();
            match ledger_effect(&op) {
                LedgerEffect::Unresolved => return Ok(Some(doc.body)),
                LedgerEffect::Applied { at, receipt } => {
                    let within = record["within_seconds"].as_u64().unwrap_or(0);
                    record["state"] = json!("pending");
                    record["due_at"] = json!(add_contract_seconds(&at, within));
                    record["effect_at"] = json!(at);
                    // The provider's reference is protected (it may reverse the effect):
                    // the record keeps its digest.
                    record["receipt_digest"] = json!(receipt.as_deref().map(sha256_text));
                }
                LedgerEffect::NotApplied => {
                    // Only the attempt the record is owed by, armed, can retire it.
                    let (attempt, armed) = owed_by(&record, &op);
                    if !armed || !attempt.is_some_and(|a| attempt_not_applied(&op, &a)) {
                        return Ok(Some(doc.body));
                    }
                    record["state"] = json!("not_applicable");
                    record["retired_at"] = json!(self.now());
                }
            }
            let key = record_key_of(admission, &record);
            match self.store.compare_and_swap(&key, doc.revision, &record).await {
                Ok(_) => {
                    if record["state"] == "pending" {
                        let payload = json!({"run_id": admission.run_id, "operation_id": operation_id,
                            "capability_id": record["capability_id"], "witness": record["witness"],
                            "postcondition": record["postcondition"], "effect_at": record["effect_at"],
                            "due_at": record["due_at"]});
                        self.audit
                            .append(&admission.tenant_id, "outcome_pending", payload, &self.now())
                            .await?;
                    } else {
                        // Never applied: it holds neither the run's nor the tenant's capacity.
                        self.drop_from(tenant_index(&admission.tenant_id), &key.id).await?;
                        self.drop_from(run_index(admission), &key.id).await?;
                    }
                    return Ok(Some(record));
                }
                Err(e) if e.is_conflict() => {}
                Err(e) => return Err(e.into()),
            }
        }
        Err(GatewayError::Outcome("outcome record contended".into()))
    }

    /// Whether any of the run's effects still waits for its witness: an outcome that is
    /// `pending` or `missed`, or one whose effect the ledger has not resolved.
    pub(crate) async fn outcome_unwitnessed(&self, admission: &RunAdmission) -> Result<bool, GatewayError> {
        for id in ids(self.store.get(&run_index(admission)).await?) {
            let key = DocKey::new(&admission.tenant_id, DocKind::Outcome, &id);
            let Some(doc) = self.store.get(&key).await? else {
                // Left by an older version (records are written before their entries).
                self.drop_from(run_index(admission), &id).await?;
                continue;
            };
            let record = if doc.body["state"] == "awaiting_effect" {
                let operation_id = doc.body["operation_id"].as_str().unwrap_or_default().to_owned();
                let synced = self.sync_outcome(admission, &operation_id).await?;
                if synced.as_ref().is_none_or(|r| r["state"] == "awaiting_effect")
                    && self.abandon_stale_outcome(&key).await?
                {
                    continue;
                }
                match synced {
                    Some(record) => record,
                    // No operation in the ledger: nothing was ever sent.
                    None => continue,
                }
            } else {
                doc.body
            };
            if matches!(record["state"].as_str(), Some("pending" | "missed" | "awaiting_effect")) {
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
            if self.sync_outcome(admission, operation_id).await?.is_none() {
                return Ok(Err("outcome_not_required"));
            }
            let Some((doc, _)) = self.outcome_doc(admission, operation_id).await? else {
                return Ok(Err("outcome_not_required"));
            };
            let record = &doc.body;
            match record["state"].as_str() {
                Some("witnessed") => return Ok(Ok(record.clone())),
                Some("pending" | "missed") => {}
                _ => return Ok(Err("outcome_effect_not_applied")),
            }
            if let Err(reason) = self
                .bind_observation(admission, operation_id, record, observation)
                .await?
            {
                return Ok(Err(reason));
            }
            let now = self.now();
            let mut closed = record.clone();
            closed["state"] = json!("witnessed");
            closed["witnessed_at"] = json!(now);
            closed["late"] = json!(record["state"] == "missed");
            closed["observation"] = json!({"issuer": observation.issuer,
                "subject_digest": digest(&json!(observation.subject))?,
                "observed_at": observation.observed_at, "valid_until": observation.valid_until,
                "attestation_digest": observation.attestation_digest});
            let key = record_key_of(admission, record);
            // Audited before it counts: no outcome is closed without its entry.
            let payload = json!({"run_id": admission.run_id, "operation_id": operation_id,
                "capability_id": record["capability_id"], "postcondition": record["postcondition"],
                "binds": record["binds"], "late": closed["late"], "observation": closed["observation"]});
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

    /// Whether `observation` establishes this record's effect; for an effect contract,
    /// also claims the attestation for this outcome alone.
    async fn bind_observation(
        &self,
        admission: &RunAdmission,
        operation_id: &str,
        record: &Value,
        observation: &WitnessObservation,
    ) -> Result<Result<(), &'static str>, GatewayError> {
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
        if serde_json::from_value::<OutcomeBinds>(record["binds"].clone()).ok() != Some(OutcomeBinds::Effect) {
            return Ok(Ok(()));
        }
        let Some(expected) = record["receipt_digest"].as_str() else {
            return Ok(Err("outcome_receipt_missing"));
        };
        if observation.receipt.as_deref().map(sha256_text).as_deref() != Some(expected) {
            return Ok(Err("outcome_receipt_mismatch"));
        }
        // One attestation establishes one effect: claim it for this outcome.
        let claim = attestation_key(&admission.tenant_id, &observation.attestation_digest);
        let holder = json!({"run_id": admission.run_id, "operation_id": operation_id,
            "action_digest": record["action_digest"]});
        match self.store.create(&claim, &holder).await {
            Ok(_) => Ok(Ok(())),
            Err(e) if e.is_conflict() => {
                let held = self.store.get(&claim).await?.map(|d| d.body);
                Ok(if held.as_ref() == Some(&holder) {
                    Ok(())
                } else {
                    Err("outcome_attestation_reused")
                })
            }
            Err(e) => Err(e.into()),
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn op(outcome: &str, observations: &[(&str, &str, &str, Option<&str>)]) -> Value {
        json!({"outcome": outcome, "observations": observations.iter().map(|(o, f, at, r)| json!({
            "outcome": o, "finality": f, "observed_at": at, "external_ref": r})).collect::<Vec<_>>()})
    }

    #[test]
    fn the_ledger_decides_what_became_of_the_effect() {
        let t1 = "2026-11-02T10:00:00.000000Z";
        let t2 = "2026-11-02T10:05:00.000000Z";
        assert_eq!(
            ledger_effect(&op(
                "confirmed",
                &[
                    ("unknown", "provisional", t1, None),
                    ("confirmed", "definitive", t2, Some("rf_1"))
                ]
            )),
            LedgerEffect::Applied {
                at: t2.into(),
                receipt: Some("rf_1".into())
            }
        );
        // The first observation of the effect starts the clock.
        assert_eq!(
            ledger_effect(&op(
                "confirmed",
                &[
                    ("partial", "provisional", t1, None),
                    ("confirmed", "definitive", t2, Some("rf_2"))
                ]
            )),
            LedgerEffect::Applied {
                at: t1.into(),
                receipt: Some("rf_2".into())
            }
        );
        assert_eq!(
            ledger_effect(&op("not_applied", &[("not_applied", "definitive", t1, None)])),
            LedgerEffect::NotApplied
        );
        assert_eq!(
            ledger_effect(&op("not_dispatched", &[("not_dispatched", "definitive", t1, None)])),
            LedgerEffect::NotApplied
        );
        assert_eq!(
            ledger_effect(&op("unknown", &[("unknown", "provisional", t1, None)])),
            LedgerEffect::Unresolved
        );
        assert_eq!(ledger_effect(&op("unknown", &[])), LedgerEffect::Unresolved);
        assert_eq!(ledger_effect(&json!({})), LedgerEffect::Unresolved);
    }
}
