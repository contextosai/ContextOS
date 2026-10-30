//! Attesting that a started dispatch did not apply.
//!
//! An attempt whose dispatch opened its gate and then recorded no fact (the executor
//! died, or the provider's reply and the executor's own `unknown` were both lost) may
//! have been sent. Reconciliation refuses to record it as not applied
//! (`dispatch_active`, `shared_guarantee_dispatch_active`), so what it holds — budget,
//! task-limit charge, shared capacity — stays held. Nothing ever releases it by time.
//!
//! An attestation is the audited way out: a principal holding `attest` (and neither
//! `admit` nor `dispatch`) states that the provider's records, checked through
//! `checked_through`, show no effect, and cites them. It is accepted only when:
//!
//! - the latest attempt was claimed, its dispatch gate is `started` and it has no
//!   definitive fact (anything else is resolved by ordinary reconciliation);
//! - `checked_through` is no earlier than the attempt's start plus the capability's
//!   timeout plus [`ATTESTATION_MARGIN_SECONDS`], so a call still in flight had time to
//!   land in the records checked, and is not in the future.
//!
//! A running run's executor generation is advanced first, fencing the executor that
//! sent the call; a dispatch stalled past [`DISPATCH_STALL_SECONDS`] since its claim
//! sends nothing. `effect_absence_attested` is then signed before anything else changes. The attestation is
//! then recorded as the attempt's definitive `not_applied` fact, which seals it: a
//! later contrary report from a revived executor is refused and audited
//! (`shared_guarantee_observation_refused`) or marks the operation conflicting, for
//! escalation. The attestation is a claim by a named principal about evidence it
//! cites; the audit proves who made it and on what, not that it was true.

use contextos_contract::validation::{add_contract_seconds, compare_contract_times};
use contextos_store::{AppendLog, DocumentStore};
use serde_json::{Value, json};

use crate::reconcile::artifact_ref;
use crate::{Gateway, GatewayError, ReconcileOutcome, Resolution, RunAdmission, operation_ledger_key};

/// Added to the attempt's start and the capability's timeout: the earliest time the
/// provider's records may be checked through for an attestation.
pub const ATTESTATION_MARGIN_SECONDS: u64 = 300;

/// Longest a dispatch may take from its claim to the adapter call. One stalled longer
/// (a paused process, a stopped VM) sends nothing. Below the margin, so a send that
/// starts in time ends, bounded by the timeout, before an attestation is accepted.
pub const DISPATCH_STALL_SECONDS: u64 = 120;

impl<S: DocumentStore + 'static, L: AppendLog + 'static> Gateway<S, L> {
    /// Whether a dispatch claimed at `claimed_at` has stalled past
    /// [`DISPATCH_STALL_SECONDS`], read just before it sends. What is left is a stall
    /// between this check and the adapter's write; providers that fence on
    /// `executor_generation` (which an attestation advances) close that too.
    pub(crate) fn dispatch_stalled(&self, claimed_at: &str) -> bool {
        add_contract_seconds(claimed_at, DISPATCH_STALL_SECONDS)
            .and_then(|limit| compare_contract_times(&self.now(), &limit))
            .is_none_or(|o| o == std::cmp::Ordering::Greater)
    }

    /// Resolves a started attempt without a fact as not applied, on `principal_id`'s
    /// attestation citing `evidence_ref` (an `ArtifactRef`) for the provider's records
    /// checked through `checked_through`.
    #[tracing::instrument(name = "contextos.attest_absence", skip_all, fields(run_id = %admission.run_id, operation_id))]
    pub async fn attest_absence(
        &self,
        admission: &RunAdmission,
        operation_id: &str,
        evidence_ref: Value,
        checked_through: &str,
        principal_id: &str,
    ) -> Result<ReconcileOutcome, GatewayError> {
        let out = ReconcileOutcome::new(operation_id, "no_change");
        if !artifact_ref(&evidence_ref) || principal_id.is_empty() {
            return Ok(out.rejected("attestation_invalid"));
        }
        let Some(read) = self.store.get(&operation_ledger_key(admission, operation_id)).await? else {
            return Ok(out.rejected("operation_not_found"));
        };
        let Some(op) = read.body["operations"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|op| op["intent"]["operation_id"] == operation_id)
        else {
            return Ok(out.rejected("operation_not_found"));
        };
        let Some(attempt) = op["attempts"].as_array().and_then(|a| a.last()) else {
            return Ok(out.rejected("operation_not_found"));
        };
        let attempt_id = attempt["attempt_id"].as_str().unwrap_or_default();
        let has_fact = op["observations"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|o| o["attempt_id"] == attempt_id && o["finality"] == "definitive" && o["outcome"] != "unknown");
        let gate = self.store.get(&crate::dispatch_gate_key(admission, attempt_id)).await?;
        if attempt["dispatch_state"] != "claimed"
            || has_fact
            || op["conflict"] == true
            || gate.is_none_or(|g| g.body["state"] != "started")
        {
            // Not sent, already resolved, or resolvable by an ordinary reconciliation.
            return Ok(out.rejected("attestation_not_applicable"));
        }
        let Some(manifest) = self.manifest_for_ref(&op["intent"]["capability_ref"]) else {
            return Ok(out.rejected("capability_not_pinned"));
        };
        let started_at = attempt["started_at"].as_str().unwrap_or_default();
        let wait = manifest.timeout_ms.div_ceil(1000) + ATTESTATION_MARGIN_SECONDS;
        let Some(earliest) = add_contract_seconds(started_at, wait) else {
            return Ok(out.rejected("attestation_invalid"));
        };
        let now = self.now();
        match (
            compare_contract_times(checked_through, &earliest),
            compare_contract_times(checked_through, &now),
        ) {
            (None, _) | (_, None) => return Ok(out.rejected("attestation_invalid")),
            (_, Some(std::cmp::Ordering::Greater)) => return Ok(out.rejected("attestation_checked_in_future")),
            (Some(std::cmp::Ordering::Less), _) => {
                let mut out = out.rejected("attestation_too_early");
                out.output.insert("checked_through_not_before".into(), json!(earliest));
                return Ok(out);
            }
            _ => {}
        }
        let shared = self.has_exposure_link(admission, operation_id).await?;
        // Fence the executor that sent the call, in case it is only stalled: it must take
        // the run over before dispatching again, and providers see a stale generation.
        let generation = match self.fence_executor(admission).await? {
            crate::Ownership::Current(generation) => Some(generation),
            crate::Ownership::Refused(_) => None,
        };
        let entry = self
            .audit
            .append(
                &admission.tenant_id,
                "effect_absence_attested",
                json!({"run_id": admission.run_id, "operation_id": operation_id, "attempt_id": attempt_id,
                    "action_digest": op["intent"]["action_digest"], "attempt_started_at": started_at,
                    "checked_through": checked_through, "evidence_ref": evidence_ref,
                    "principal_id": principal_id, "shared_guarantee": shared,
                    "executor_generation": generation}),
                &now,
            )
            .await?;
        let mut outcome = self
            .reconcile(
                admission,
                operation_id,
                Resolution::AttestAbsence {
                    evidence_ref,
                    principal_id: principal_id.to_owned(),
                },
            )
            .await?;
        outcome.audit_sequences.insert(0, entry.sequence);
        Ok(outcome)
    }
}
