//! Fencing an outcome contract to the attempt that may apply its effect.
//!
//! An outcome record is owed by one attempt at a time. It is registered for the
//! attempt about to be claimed (`attempt_id`, unarmed), and armed by a compare-and-swap
//! after the operation claim commits and before anything is sent. Every transition
//! that gives the record up goes through the same document, so it is ordered against
//! arming:
//!
//! - **Retirement** (`not_applicable`, see [`crate::outcomes`]) needs the record armed
//!   and its own attempt definitively not applied in the operation ledger. A retry
//!   re-registers the record for its new attempt first, so an earlier attempt's
//!   negative result cannot retire the retry's obligation, whenever the sweep reads it.
//! - **Abandonment** (`abandoned`) reclaims a record whose dispatcher stopped between
//!   registration and arming: unarmed, and registered more than
//!   [`OUTCOME_ARMING_GRACE_SECONDS`] ago. Age only says when to try; the fence is the
//!   compare-and-swap. A dispatcher that resumes afterwards cannot arm, records its
//!   attempt as not dispatched, and sends nothing. One that armed first keeps the
//!   record, and the abandonment fails.
//!
//! The record is written before it enters the tenant's index, and that before the
//! run's: an index entry without its record is left only by an older version (the
//! completion check and the sweep drop such entries), and a record in either index is
//! in the tenant's, where the sweep finds it.

use contextos_contract::canonical::sha256_text;
use contextos_contract::validation::{add_contract_seconds, compare_contract_times};
use contextos_store::{AppendLog, DocKey, DocKind, DocumentStore};
use serde_json::{Value, json};

use crate::admission::RunAdmission;
use crate::manifest::CapabilityManifest;
use crate::outcomes::{MAX_RUN_OUTCOMES, MAX_TENANT_OUTCOMES, digest, record_key, run_index, tenant_index};
use crate::{Gateway, GatewayError};

/// How long a registered outcome may wait for its attempt to be armed before the sweep
/// may abandon it.
pub const OUTCOME_ARMING_GRACE_SECONDS: u64 = 300;

/// The attempt a record is owed by, and whether that attempt was armed. A record
/// written before attempts were fenced is owed by the ledger's last attempt, armed.
pub(crate) fn owed_by(record: &Value, op: &Value) -> (Option<String>, bool) {
    match record["attempt_id"].as_str() {
        Some(attempt) => (Some(attempt.to_owned()), record["armed"] == true),
        None => (
            op["attempts"]
                .as_array()
                .and_then(|a| a.last())
                .and_then(|a| a["attempt_id"].as_str())
                .map(str::to_owned),
            true,
        ),
    }
}

/// Whether the ledger holds a definitive negative result for `attempt`.
pub(crate) fn attempt_not_applied(op: &Value, attempt: &str) -> bool {
    op["observations"].as_array().into_iter().flatten().any(|o| {
        o["attempt_id"] == attempt
            && o["finality"] == "definitive"
            && matches!(o["outcome"].as_str(), Some("not_applied" | "not_dispatched"))
    })
}

impl<S: DocumentStore + 'static, L: AppendLog + 'static> Gateway<S, L> {
    /// Records the capability's outcome contract for `attempt_id` of this operation
    /// before it is claimed. `Ok(Err)` refuses the call.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn register_outcome(
        &self,
        admission: &RunAdmission,
        manifest: &CapabilityManifest,
        operation_id: &str,
        action_digest: &str,
        attempt_id: &str,
        binding: &Value,
    ) -> Result<Result<(), &'static str>, GatewayError> {
        let Some(contract) = &manifest.outcome else {
            return Ok(Ok(()));
        };
        // An earlier attempt's result is applied first: retired, the record is owed again.
        self.sync_outcome(admission, operation_id).await?;
        let key = record_key(&admission.tenant_id, &admission.run_id, operation_id, action_digest);
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
            "binds": contract.binds, "on_missed": contract.on_missed, "resource_digests": resource_digests,
            "amount": binding.get("amount").cloned().unwrap_or(Value::Null),
            "state": "awaiting_effect", "attempt_id": attempt_id, "armed": false,
            "registered_at": self.now(),
        });
        let mut written = false;
        for _ in 0..8 {
            let existing = self.store.get(&key).await?;
            let result = match &existing {
                None => self.store.create(&key, &record).await,
                // Owed again, by this attempt.
                Some(doc) if matches!(doc.body["state"].as_str(), Some("not_applicable" | "abandoned")) => {
                    self.store.compare_and_swap(&key, doc.revision, &record).await
                }
                // Not yet armed: this attempt takes it over (the other cannot arm).
                Some(doc) if doc.body["state"] == "awaiting_effect" && doc.body["armed"] == false => {
                    self.store.compare_and_swap(&key, doc.revision, &record).await
                }
                // Armed by an attempt the ledger has not resolved, or applied: this
                // attempt cannot arm, and its claim is refused or withheld.
                Some(_) => break,
            };
            match result {
                Ok(_) => {
                    written = true;
                    break;
                }
                Err(e) if e.is_conflict() => {}
                Err(e) => return Err(e.into()),
            }
        }
        if !written {
            return Ok(Ok(()));
        }
        // The tenant's index first: the sweep reads it, so a record a crash left in
        // either index is found and abandoned.
        if !self
            .note_in_index(tenant_index(&admission.tenant_id), &key.id, MAX_TENANT_OUTCOMES)
            .await?
            || !self
                .note_in_index(run_index(admission), &key.id, MAX_RUN_OUTCOMES)
                .await?
        {
            // Never armed, the record is abandoned with the call.
            return Ok(Err("outcome_index_full"));
        }
        Ok(Ok(()))
    }

    /// Arms the outcome record for `attempt_id` after its claim committed. `false`:
    /// the record was abandoned or taken over meanwhile, and nothing may be sent.
    pub(crate) async fn arm_outcome(
        &self,
        admission: &RunAdmission,
        manifest: &CapabilityManifest,
        operation_id: &str,
        action_digest: &str,
        attempt_id: &str,
    ) -> Result<bool, GatewayError> {
        if manifest.outcome.is_none() {
            return Ok(true);
        }
        let key = record_key(&admission.tenant_id, &admission.run_id, operation_id, action_digest);
        for _ in 0..8 {
            let Some(doc) = self.store.get(&key).await? else {
                return Ok(false);
            };
            if doc.body["state"] != "awaiting_effect" || doc.body["attempt_id"] != attempt_id {
                return Ok(false);
            }
            if doc.body["armed"] == true {
                return Ok(true);
            }
            let mut armed = doc.body.clone();
            armed["armed"] = json!(true);
            armed["armed_at"] = json!(self.now());
            match self.store.compare_and_swap(&key, doc.revision, &armed).await {
                Ok(_) => return Ok(true),
                Err(e) if e.is_conflict() => {}
                Err(e) => return Err(e.into()),
            }
        }
        Ok(false)
    }

    /// Abandons the record at `key` if it is unarmed past its grace, releasing its
    /// index entries. Whether it did.
    pub(crate) async fn abandon_stale_outcome(&self, key: &DocKey) -> Result<bool, GatewayError> {
        let Some(doc) = self.store.get(key).await? else {
            return Ok(false);
        };
        if doc.body["state"] != "awaiting_effect" || doc.body["armed"] != false {
            return Ok(false);
        }
        let registered = doc.body["registered_at"].as_str().unwrap_or_default();
        let stale = add_contract_seconds(registered, OUTCOME_ARMING_GRACE_SECONDS)
            .and_then(|until| compare_contract_times(&until, &self.now()))
            .is_some_and(|o| o != std::cmp::Ordering::Greater);
        if !stale {
            return Ok(false);
        }
        let mut abandoned = doc.body.clone();
        abandoned["state"] = json!("abandoned");
        abandoned["abandoned_at"] = json!(self.now());
        match self.store.compare_and_swap(key, doc.revision, &abandoned).await {
            Ok(_) => {}
            // Armed (or taken over) meanwhile: it stays owed.
            Err(e) if e.is_conflict() => return Ok(false),
            Err(e) => return Err(e.into()),
        }
        let run_id = doc.body["run_id"].as_str().unwrap_or_default();
        self.drop_from(tenant_index(&key.tenant_id), &key.id).await?;
        self.drop_from(
            DocKey::new(&key.tenant_id, DocKind::Outcome, format!("run:{run_id}")),
            &key.id,
        )
        .await?;
        let payload = json!({"run_id": run_id, "operation_id": doc.body["operation_id"],
            "attempt_id": doc.body["attempt_id"], "capability_id": doc.body["capability_id"],
            "record_digest": sha256_text(&key.id)});
        self.audit
            .append(&key.tenant_id, "outcome_abandoned", payload, &self.now())
            .await?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_record_is_owed_by_its_own_attempt() {
        let op = json!({"attempts": [{"attempt_id": "a1"}, {"attempt_id": "a2"}],
            "observations": [{"attempt_id": "a1", "finality": "definitive", "outcome": "not_applied"}]});
        assert_eq!(
            owed_by(&json!({"attempt_id": "a2", "armed": false}), &op),
            (Some("a2".into()), false)
        );
        assert_eq!(owed_by(&json!({}), &op), (Some("a2".into()), true), "older records");
        assert!(attempt_not_applied(&op, "a1"));
        assert!(!attempt_not_applied(&op, "a2"), "a1's result is not a2's");
    }
}
