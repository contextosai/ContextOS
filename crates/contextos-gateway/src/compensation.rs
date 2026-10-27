//! Governed compensation of applied effects.
//!
//! A capability's manifest may declare how its effect is undone: the compensating
//! capability and where each of its arguments comes from (the original call's arguments,
//! or the provider's reference recorded with the original effect). Before such an effect
//! is dispatched, the gateway records what compensation will need, so an effect it sends
//! can always be compensated or is refused up front (`compensation_binding_incomplete`,
//! `compensation_index_full`).
//!
//! Compensation is a new governed operation, never a rollback: it passes the whole
//! pipeline (surface, authority, policy, approval, budget, claim, observation, audit)
//! under its own action digest, it can fail or partially apply, and the original effect's
//! history stays as it was. Its operation identity derives from the original operation,
//! so an effect is compensated at most once: a retry of the compensation is the same
//! operation, with the operation ledger's retry rules. The kernel checks the link
//! (`compensates_operation_id`) at the claim against the original's recorded outcome.
//!
//! The protected provider reference (`/external_ref`, the spec's reversal token) is
//! resolved by the gateway from the operation ledger and sent only to the adapter; the
//! agent names an operation, never the token.

use contextos_contract::canonical::sha256_text;
use contextos_kernel::TransitionResult;
use contextos_kernel::operation_ledger::claim_operation;
use contextos_store::{AppendLog, DocKey, DocKind, DocumentStore};
use serde_json::{Map, Value, json};

use crate::admission::RunAdmission;
use crate::manifest::CapabilityManifest;
use crate::{DispatchOutcome, Gateway, GatewayError, Pipeline, operation_ledger_key};

/// Operation ids beginning with this are reserved for compensations.
pub const COMPENSATION_OPERATION_PREFIX: &str = "compensation:";

/// Compensable effects recorded per run at most; a further compensable effect is
/// refused before dispatch (`compensation_index_full`).
pub const MAX_COMPENSABLE_EFFECTS: usize = 1024;

/// Compensations one saga request sends at most; call again to continue
/// (`stopped_at.reason: "step_limit"`).
pub const MAX_SAGA_STEPS: usize = 16;

/// The operation id of the compensation of `operation_id` (one per original effect).
pub fn compensation_operation_id(operation_id: &str) -> String {
    let digest = sha256_text(operation_id);
    format!("{COMPENSATION_OPERATION_PREFIX}{}", &digest[7..39])
}

/// One record per operation and action: a reuse of the operation id with other
/// arguments has its own record, so the effect the ledger holds always finds its own.
fn record_key(admission: &RunAdmission, operation_id: &str, action_digest: &str) -> DocKey {
    let digest = sha256_text(&format!("{}\u{0}{operation_id}\u{0}{action_digest}", admission.run_id));
    DocKey::new(
        &admission.tenant_id,
        DocKind::Compensation,
        format!("rec_{}", &digest[7..39]),
    )
}

pub(crate) fn index_key(admission: &RunAdmission) -> DocKey {
    DocKey::new(
        &admission.tenant_id,
        DocKind::Compensation,
        format!("run:{}", admission.run_id),
    )
}

/// The compensating arguments taken from the original call, and the names still to be
/// filled from the provider's reference; `None` when an argument the compensation needs
/// is missing from the call.
fn plan(manifest: &CapabilityManifest, arguments: &Value) -> Option<(Map<String, Value>, Vec<String>)> {
    let compensation = manifest.compensation.as_ref()?;
    let mut planned = Map::new();
    let mut from_reference = Vec::new();
    for (name, source) in &compensation.arguments {
        if source == "/external_ref" {
            from_reference.push(name.clone());
        } else {
            let value = arguments.pointer(source.strip_prefix("/arguments")?)?;
            planned.insert(name.clone(), value.clone());
        }
    }
    Some((planned, from_reference))
}

/// Whether the call carries every argument its capability's compensation needs.
pub(crate) fn plannable(manifest: &CapabilityManifest, arguments: &Value) -> bool {
    manifest.compensation.is_none() || plan(manifest, arguments).is_some()
}

/// The run's operation as recorded in its own ledger document.
fn recorded_operation(ledger: Option<&Value>, operation_id: &str) -> Option<Value> {
    ledger?["operations"]
        .as_array()?
        .iter()
        .find(|op| op["intent"]["operation_id"] == operation_id)
        .cloned()
}

fn in_flight(op: &Value) -> bool {
    op["attempts"]
        .as_array()
        .and_then(|a| a.last())
        .is_some_and(|a| a["dispatch_state"] == "claimed")
}

fn outcome(op: Option<&Value>) -> &str {
    op.and_then(|o| o["outcome"].as_str()).unwrap_or("none")
}

/// Where an effect stands with respect to its compensation.
fn effect_state(original: Option<&Value>, compensation: Option<&Value>) -> &'static str {
    let Some(original) = original else {
        return "not_applied";
    };
    if in_flight(original) || original["outcome"] == "unknown" {
        return "unresolved";
    }
    if !matches!(original["outcome"].as_str(), Some("confirmed" | "partial")) {
        return "not_applied";
    }
    match compensation {
        Some(c) if in_flight(c) || c["outcome"] == "unknown" => "compensating",
        Some(c) if c["outcome"] == "confirmed" => "compensated",
        Some(c) if c["outcome"] == "partial" => "partially_compensated",
        Some(c) if exhausted(c) => "compensation_exhausted",
        _ => "compensable",
    }
}

/// Whether the ledger would refuse another attempt of this operation (the kernel's
/// `retry_unsafe` for attempts and strategy).
fn exhausted(op: &Value) -> bool {
    let attempts = op["attempts"].as_array().map_or(0, Vec::len) as u64;
    op["intent"]["recovery_strategy"] == "no_retry" || attempts >= op["intent"]["max_attempts"].as_u64().unwrap_or(1)
}

/// The provider reference of the original's applied outcome, from its definitive
/// observation.
fn applied_reference(op: &Value) -> Option<String> {
    op["observations"]
        .as_array()?
        .iter()
        .rev()
        .filter(|o| o["finality"] == "definitive" && matches!(o["outcome"].as_str(), Some("confirmed" | "partial")))
        .find_map(|o| o["external_ref"].as_str().map(str::to_owned))
}

/// Claims a compensation in its own ledger document. Each operation has its own
/// document, so the kernel evaluates the claim on a projection holding the original
/// operation as well; it checks the link (an applied original, a different action) as
/// it would in one ledger. The original is not written back.
pub(crate) fn claim_with_original(
    ledger: &Value,
    claim: &Value,
    original: &Value,
    admission: &RunAdmission,
) -> TransitionResult {
    let original_id = &original["intent"]["operation_id"];
    let mut projection = ledger.clone();
    if let Some(operations) = projection["operations"].as_array_mut() {
        operations.push(original.clone());
    }
    let mut result = claim_operation(
        &projection,
        claim,
        &ledger["revision"],
        &json!(admission.executor_generation),
    );
    if let Some(operations) = result.state["operations"].as_array_mut() {
        operations.retain(|op| op["intent"]["operation_id"] != *original_id);
    }
    if result.status == "rejected" {
        result.state = ledger.clone();
    }
    result
}

impl<S: DocumentStore + 'static, L: AppendLog + 'static> Gateway<S, L> {
    /// Records what compensating a compensable effect will need, before it is
    /// dispatched. `Err` names why the effect may not be sent.
    pub(crate) async fn record_compensation(
        &self,
        admission: &RunAdmission,
        manifest: &CapabilityManifest,
        operation_id: &str,
        action_digest: &str,
        arguments: &Value,
    ) -> Result<Result<(), &'static str>, GatewayError> {
        let Some(compensation) = &manifest.compensation else {
            return Ok(Ok(()));
        };
        let Some((planned, from_reference)) = plan(manifest, arguments) else {
            return Ok(Err("compensation_binding_incomplete"));
        };
        let key = record_key(admission, operation_id, action_digest);
        // Indexed first: erasure and rollback never miss a record.
        if !self
            .note_in_index(index_key(admission), &key.id, MAX_COMPENSABLE_EFFECTS)
            .await?
        {
            return Ok(Err("compensation_index_full"));
        }
        let record = json!({
            "run_id": admission.run_id, "operation_id": operation_id, "capability_id": manifest.capability_id,
            "action_digest": action_digest, "compensator": compensation.capability_id,
            "arguments": planned, "from_external_ref": from_reference,
        });
        // A retry of the same action finds its record already written.
        match self.store.create(&key, &record).await {
            Ok(_) => Ok(Ok(())),
            Err(e) if e.is_conflict() => Ok(Ok(())),
            Err(e) => Err(e.into()),
        }
    }

    async fn operation(&self, admission: &RunAdmission, operation_id: &str) -> Result<Option<Value>, GatewayError> {
        let ledger = self.store.get(&operation_ledger_key(admission, operation_id)).await?;
        Ok(recorded_operation(ledger.as_ref().map(|l| &l.body), operation_id))
    }

    /// The original operation as recorded now, read again just before a compensation is
    /// claimed so the kernel judges the link on current facts (`Null`, refused, if gone).
    pub(crate) async fn current_original(
        &self,
        admission: &RunAdmission,
        original: &Value,
    ) -> Result<Value, GatewayError> {
        let id = original["intent"]["operation_id"].as_str().unwrap_or_default();
        Ok(self.operation(admission, id).await?.unwrap_or(Value::Null))
    }

    /// Compensates one applied effect of the run with its declared compensating
    /// capability, governed end to end as a new operation. `tool_call_id` identifies
    /// this request; the operation id derives from `operation_id`.
    #[tracing::instrument(
        name = "contextos.compensate",
        skip_all,
        fields(run_id = %admission.run_id, operation_id = %operation_id, status = tracing::field::Empty)
    )]
    pub async fn compensate(
        &self,
        admission: &RunAdmission,
        operation_id: &str,
        tool_call_id: &str,
        fence: Option<u64>,
    ) -> Result<DispatchOutcome, GatewayError> {
        let compensation_id = compensation_operation_id(operation_id);
        let (original, existing) = tokio::join!(
            self.operation(admission, operation_id),
            self.operation(admission, &compensation_id)
        );
        let (original, existing) = (original?, existing?);
        let record = match original.as_ref().and_then(|o| o["intent"]["action_digest"].as_str()) {
            Some(digest) => self
                .store
                .get(&record_key(admission, operation_id, digest))
                .await?
                .map(|r| r.body)
                .filter(|r| !crate::is_erased(r)),
            None => None,
        };
        let capability_id = record.as_ref().map_or(Value::Null, |r| r["compensator"].clone());
        let manifest = capability_id.as_str().and_then(|id| self.manifests.get(id));
        let envelope = json!({
            "envelope_version": "contextos.tool_call.v1", "tool_call_id": tool_call_id,
            "run_id": admission.run_id, "trace_id": admission.trace_id, "capability_id": capability_id,
            "args": {}, "principal_chain": [{"kind": "agent", "id": admission.actor["principal_id"]}],
            "approval_mode_requested": manifest.map(|m| m.approval_mode),
            "approval_mode_effective": manifest.map(|m| m.approval_mode),
            "approval_mode_highest": manifest.map(|m| m.approval_mode),
            "evidence_refs": [], "idempotency_key": compensation_id,
        });
        let refuse = |status: &str, reason: &str, message: &str, obligation: Option<&str>| {
            let mut p = Pipeline::new(admission, &envelope);
            p.report.operation_id = Some(compensation_id.clone());
            p.compensates = Some(operation_id.to_owned());
            p.report.obligations.extend(obligation.map(str::to_owned));
            p.stop(status, vec![reason.to_owned()], message)
        };
        let Some(record) = record else {
            return Ok(refuse(
                "rejected",
                "compensation_not_declared",
                "No compensable effect is recorded under this operation.",
                None,
            ));
        };
        match effect_state(original.as_ref(), existing.as_ref()) {
            "compensable" => {}
            "unresolved" => {
                return Ok(refuse(
                    "paused",
                    "compensation_original_unresolved",
                    "Reconcile the effect before compensating it.",
                    Some("reconcile_existing_operation"),
                ));
            }
            "not_applied" => {
                return Ok(refuse(
                    "rejected",
                    "compensation_not_applicable",
                    "The effect was not applied; there is nothing to compensate.",
                    None,
                ));
            }
            "compensating" => {
                return Ok(refuse(
                    "paused",
                    "compensation_unresolved",
                    "Reconcile the compensation before retrying it.",
                    Some("reconcile_existing_operation"),
                ));
            }
            "compensation_exhausted" => {
                return Ok(refuse(
                    "rejected",
                    "compensation_exhausted",
                    "The compensation failed and may not be attempted again; escalate.",
                    Some("escalate"),
                ));
            }
            _ => {
                return Ok(refuse(
                    "rejected",
                    "compensation_already_applied",
                    "The effect has already been compensated.",
                    None,
                ));
            }
        }
        let original = original.unwrap_or_default();
        let mut arguments = record["arguments"].as_object().cloned().unwrap_or_default();
        let from_reference: Vec<&str> = record["from_external_ref"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect();
        if !from_reference.is_empty() {
            let Some(reference) = applied_reference(&original) else {
                return Ok(refuse(
                    "rejected",
                    "compensation_reference_missing",
                    "The provider recorded no reference to compensate the effect with.",
                    Some("escalate"),
                ));
            };
            for name in from_reference {
                arguments.insert(name.to_owned(), json!(reference));
            }
        }
        let mut envelope = envelope.clone();
        envelope["args"] = Value::Object(arguments);
        let entry = self
            .audit
            .append(
                &admission.tenant_id,
                "compensation_requested",
                json!({"run_id": admission.run_id, "operation_id": compensation_id,
                    "compensates_operation_id": operation_id, "capability_id": record["compensator"],
                    "tool_call_id": tool_call_id}),
                &self.now(),
            )
            .await?;
        let mut outcome = self
            .dispatch_inner(admission, &envelope, None, fence, Some(&original))
            .await?;
        outcome.report.audit_sequences.insert(0, entry.sequence);
        tracing::Span::current().record("status", outcome.report.status.as_str());
        Ok(outcome)
    }

    /// The run's compensable effects in the order they were requested, each with its
    /// state: `compensable`, `compensated`, `partially_compensated`, `compensating`,
    /// `compensation_exhausted`, `unresolved` (the effect awaits reconciliation) or
    /// `not_applied`.
    pub async fn compensations(&self, admission: &RunAdmission) -> Result<Value, GatewayError> {
        let ids: Vec<String> = self
            .store
            .get(&index_key(admission))
            .await?
            .and_then(|i| i.body["keys"].as_array().cloned())
            .unwrap_or_default()
            .iter()
            .filter_map(|v| v.as_str().map(str::to_owned))
            .collect();
        let mut effects = Vec::new();
        for id in ids {
            let key = DocKey::new(&admission.tenant_id, DocKind::Compensation, id);
            let Some(record) = self.store.get(&key).await?.map(|r| r.body) else {
                continue;
            };
            if crate::is_erased(&record) {
                continue;
            }
            let operation_id = record["operation_id"].as_str().unwrap_or_default();
            let compensation_id = compensation_operation_id(operation_id);
            let (original, compensation) = tokio::join!(
                self.operation(admission, operation_id),
                self.operation(admission, &compensation_id)
            );
            let (original, compensation) = (original?, compensation?);
            // A record of an action the ledger does not hold under this id (an id reused
            // with other arguments) describes nothing that was sent.
            if original
                .as_ref()
                .is_some_and(|o| o["intent"]["action_digest"] != record["action_digest"])
            {
                continue;
            }
            effects.push(json!({
                "operation_id": operation_id, "capability_id": record["capability_id"],
                "compensator": record["compensator"], "outcome": outcome(original.as_ref()),
                "compensation_operation_id": compensation_id,
                "compensation_outcome": outcome(compensation.as_ref()),
                "state": effect_state(original.as_ref(), compensation.as_ref()),
            }));
        }
        Ok(json!({"run_id": admission.run_id, "effects": effects}))
    }

    /// Compensates the run's applied effects newest first, as a saga does. Stops at the
    /// first compensation that does not complete, and at any effect or compensation
    /// still unresolved: compensating an earlier effect past a later one in doubt could
    /// leave the later one stranded. Each step is a separately governed operation.
    #[tracing::instrument(name = "contextos.compensate_run", skip_all, fields(run_id = %admission.run_id))]
    pub async fn compensate_run(&self, admission: &RunAdmission, fence: Option<u64>) -> Result<Value, GatewayError> {
        // Any effect of the run in doubt stops the saga before it starts, compensable or
        // not: what to undo depends on whether it happened.
        let state = self.run_state(admission).await?.unwrap_or(Value::Null);
        let in_doubt = state["outstanding_effects"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|e| e["outcome"] == "unknown");
        let stopped = match in_doubt {
            Some(effect) => Some(json!({"operation_id": effect["operation_id"], "reason": "unresolved"})),
            None if self.effects_in_flight(admission).await? => {
                Some(json!({"operation_id": null, "reason": "effects_in_flight"}))
            }
            None => None,
        };
        if let Some(stopped) = stopped {
            return Ok(json!({"run_id": admission.run_id, "status": "stopped", "steps": [], "stopped_at": stopped}));
        }
        let listed = self.compensations(admission).await?;
        let mut steps = Vec::new();
        let mut stopped = None;
        for effect in listed["effects"].as_array().into_iter().flatten().rev() {
            let operation_id = effect["operation_id"].as_str().unwrap_or_default();
            match effect["state"].as_str().unwrap_or_default() {
                "compensated" | "not_applied" => {}
                "compensable" if steps.len() >= MAX_SAGA_STEPS => {
                    stopped = Some(json!({"operation_id": operation_id, "reason": "step_limit"}));
                    break;
                }
                "compensable" => {
                    let tool_call_id = self.new_id("compensation");
                    let outcome = self.compensate(admission, operation_id, &tool_call_id, fence).await?;
                    let done = outcome.result["status"] == "completed";
                    steps.push(
                        json!({"operation_id": operation_id, "result": outcome.result, "report": outcome.report}),
                    );
                    if !done {
                        stopped = Some(json!({"operation_id": operation_id, "reason": "compensation_incomplete"}));
                        break;
                    }
                }
                state => {
                    stopped = Some(json!({"operation_id": operation_id, "reason": state}));
                    break;
                }
            }
        }
        let status = if stopped.is_some() { "stopped" } else { "compensated" };
        Ok(json!({"run_id": admission.run_id, "status": status, "steps": steps, "stopped_at": stopped}))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn op(outcome: &str, state: &str) -> Value {
        json!({"outcome": outcome, "attempts": [{"dispatch_state": state}]})
    }

    #[test]
    fn states_follow_the_original_then_the_compensation() {
        assert_eq!(effect_state(None, None), "not_applied");
        assert_eq!(effect_state(Some(&op("not_dispatched", "claimed")), None), "unresolved");
        assert_eq!(effect_state(Some(&op("unknown", "dispatched")), None), "unresolved");
        assert_eq!(effect_state(Some(&op("not_applied", "settled")), None), "not_applied");
        let applied = op("confirmed", "settled");
        assert_eq!(effect_state(Some(&applied), None), "compensable");
        let mut failed = op("not_applied", "settled");
        failed["intent"] = json!({"recovery_strategy": "manual_reconcile", "max_attempts": 2});
        assert_eq!(effect_state(Some(&applied), Some(&failed)), "compensable");
        failed["intent"]["max_attempts"] = json!(1);
        assert_eq!(effect_state(Some(&applied), Some(&failed)), "compensation_exhausted");
        let pending = op("not_dispatched", "claimed");
        assert_eq!(effect_state(Some(&applied), Some(&pending)), "compensating");
        let done = op("confirmed", "settled");
        assert_eq!(effect_state(Some(&applied), Some(&done)), "compensated");
        let partial = op("partial", "settled");
        assert_eq!(effect_state(Some(&applied), Some(&partial)), "partially_compensated");
    }

    #[test]
    fn compensation_ids_are_reserved_and_bounded() {
        let id = compensation_operation_id(&"x".repeat(256));
        assert!(id.starts_with(COMPENSATION_OPERATION_PREFIX));
        assert_eq!(id.len(), COMPENSATION_OPERATION_PREFIX.len() + 32);
        assert_eq!(id, compensation_operation_id(&"x".repeat(256)));
    }
}
