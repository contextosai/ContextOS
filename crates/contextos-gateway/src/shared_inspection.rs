//! Read-only inspection of shared-guarantee holds: which resources have capacity held,
//! which run, operation and attempt own each hold, what is known about its outcome and
//! the next safe step. Nothing here settles, releases or retries; resolution goes
//! through reconciliation. Raw tool arguments are never returned.
use contextos_kernel::shared_exposure::{exposure_digest, exposure_summary};
use contextos_store::{AppendLog, DocKey, DocKind, DocumentStore};
use serde_json::{Value, json};

use crate::shared_guarantees::{exposure_key, identifier};
use crate::{Gateway, GatewayError, run_operation_key};

/// At most this many ledgers are read per page of resources with holds.
pub const MAX_INSPECTION_SCAN: usize = 1000;

fn invalid() -> GatewayError {
    GatewayError::Guarantee("shared_guarantee_invalid".into())
}

pub(crate) fn held_receipts(ledger: &Value) -> impl Iterator<Item = (&String, &Value)> {
    ledger["receipts"]
        .as_object()
        .into_iter()
        .flatten()
        .filter(|(_, r)| r["status"] == "held")
}

/// The state of one hold and the step that can resolve it without risking a
/// duplicate effect. Elapsed time never appears here: it proves nothing about an
/// effect, so no state is resolved by waiting.
pub(crate) fn diagnose(
    receipt: &Value,
    op: Option<&Value>,
    attempt_id: &str,
) -> (&'static str, &'static str, &'static str) {
    let Some(op) = op else {
        return (
            "unlinked",
            "investigate",
            "The hold has no readable operation record. Capacity stays held; investigate the protected store before acting.",
        );
    };
    let observations: Vec<&Value> = op["observations"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|o| o["attempt_id"] == attempt_id)
        .collect();
    let latest = observations.last();
    if op["conflict"] == true {
        return (
            "conflicting_facts",
            "incident",
            "Contradictory outcomes were recorded for this operation. Capacity stays held; treat it as an incident and resolve it with the provider.",
        );
    }
    if receipt["dispatch_aborted"] == true || op["outcome"] == "confirmed" {
        return (
            "settlement_pending",
            "reconcile_again",
            "The outcome is decided but the balance was not updated. Reconcile again to repair it; reconciliation never sends the effect again.",
        );
    }
    if receipt["dispatch_started"] != true {
        return (
            "reserved_not_sent",
            "wait_or_reconcile",
            "The call has not been sent. If its executor is still running, wait. If it is gone, reconcile: the dispatch gate closes first, so the attempt cannot be sent afterwards, and the capacity is released.",
        );
    }
    let Some(latest) = latest else {
        return (
            "dispatch_active",
            "confirm_or_attest_absence",
            "The call was sent and nothing was observed, so it may still apply. Do not retry. If the provider shows the effect applied, an operator confirms it citing that evidence. If it shows none, an attester (scope attest) may release the hold once the provider's records are checked through the attempt's start plus the timeout plus 5 minutes, citing them.",
        );
    };
    if latest["finality"] == "definitive"
        && matches!(
            latest["outcome"].as_str(),
            Some("confirmed" | "not_applied" | "not_dispatched")
        )
    {
        return (
            "settlement_pending",
            "reconcile_again",
            "A definitive outcome is recorded but the balance was not updated. Reconcile again to repair it; reconciliation never sends the effect again.",
        );
    }
    if latest["outcome"] == "partial" {
        return (
            "partial",
            "operator_reconcile",
            "Part of the effect applied, so the capacity cannot be released. An operator who has checked the provider's records can confirm the effect, citing that evidence; this commits the full amount.",
        );
    }
    if latest["external_ref"].as_str().is_some() {
        (
            "unknown_provider_reference",
            "provider_query",
            "The outcome is unknown and the provider returned a reference. Reconcile with {\"source\":\"provider\"} to ask the provider; this never re-sends the effect.",
        )
    } else {
        (
            "unknown",
            "operator_reconcile",
            "The outcome is unknown and there is no provider reference to query. Check the provider's records, then reconcile as an operator with the outcome and the evidence you checked. Do not retry first.",
        )
    }
}

/// The run and operation a hold belongs to, from its link, and that operation's record.
pub(crate) struct HoldContext {
    pub run_id: Option<String>,
    pub operation_id: Option<String>,
    pub operation: Option<Value>,
}

impl<S: DocumentStore + 'static, L: AppendLog + 'static> Gateway<S, L> {
    /// Reads the link of the hold `reservation_id` and the operation it names.
    pub(crate) async fn hold_context(&self, tenant: &str, reservation_id: &str) -> Result<HoldContext, GatewayError> {
        // The link's key is the reservation id: both hash (run, operation).
        let link = self
            .store
            .get(&DocKey::new(tenant, DocKind::ExposureLink, reservation_id))
            .await?
            .map(|d| d.body);
        let run_id = link.as_ref().and_then(|l| l["run_id"].as_str()).map(str::to_owned);
        let operation_id = link
            .as_ref()
            .and_then(|l| l["operation_id"].as_str())
            .map(str::to_owned);
        let ops = match (&run_id, &operation_id) {
            (Some(run), Some(op)) => self
                .store
                .get(&run_operation_key(tenant, run, op))
                .await?
                .map(|d| d.body),
            _ => None,
        };
        let operation = ops.and_then(|mut ops| {
            let list = ops["operations"].as_array_mut()?;
            let at = list.iter().position(|o| {
                Some(o["intent"]["operation_id"].as_str().unwrap_or_default()) == operation_id.as_deref()
            })?;
            Some(list.swap_remove(at))
        });
        Ok(HoldContext {
            run_id,
            operation_id,
            operation,
        })
    }

    fn configured(&self, guarantee_id: &str) -> bool {
        self.shared_guarantees.iter().any(|r| r.id == guarantee_id)
    }

    /// One page of the tenant's resources under `guarantee_id` with capacity held,
    /// read from at most `scan` ledgers after `after`. `next` is the cursor to
    /// continue from, or null once every ledger has been read; a page can be empty
    /// while `next` is not. `None` if the guarantee is not configured.
    pub async fn resources_with_holds(
        &self,
        tenant: &str,
        guarantee_id: &str,
        after: Option<&str>,
        scan: usize,
    ) -> Result<Option<Value>, GatewayError> {
        if !self.configured(guarantee_id) {
            return Ok(None);
        }
        let scan = scan.clamp(1, MAX_INSPECTION_SCAN);
        let ids = self.store.list(tenant, DocKind::SharedExposure, after, scan).await?;
        let mut resources = Vec::new();
        for id in &ids {
            let Some(doc) = self
                .store
                .get(&DocKey::new(tenant, DocKind::SharedExposure, id))
                .await?
            else {
                continue;
            };
            if doc.body["binding"]["guarantee_id"] != guarantee_id {
                continue;
            }
            // One unreadable ledger is listed as such, not allowed to hide the rest.
            let Some(mut view) = exposure_summary(&doc.body) else {
                tracing::warn!(resource = %id, "shared exposure ledger unreadable");
                resources.push(json!({"resource_digest": id, "unreadable": true}));
                continue;
            };
            if view["held"] == 0 {
                continue;
            }
            view["open_holds"] = json!(held_receipts(&doc.body).count());
            resources.push(view);
        }
        let next = (ids.len() == scan).then(|| ids.last().cloned()).flatten();
        Ok(Some(
            json!({"guarantee_id": guarantee_id, "resources": resources, "next": next}),
        ))
    }

    /// The resource's balance and every open hold, oldest attempt first, each mapped
    /// to its run, operation and attempt with its last observation and the next safe
    /// step. `None` if the guarantee is not configured or the resource has no ledger.
    pub async fn exposure_holds(
        &self,
        tenant: &str,
        guarantee_id: &str,
        resource_digest: &str,
    ) -> Result<Option<Value>, GatewayError> {
        if !self.configured(guarantee_id) || !identifier(guarantee_id) || !exposure_digest(resource_digest) {
            return Ok(None);
        }
        let Some(doc) = self
            .store
            .get(&exposure_key(tenant, guarantee_id, resource_digest)?)
            .await?
        else {
            return Ok(None);
        };
        let mut view = exposure_summary(&doc.body).ok_or_else(invalid)?;
        let mut holds = Vec::new();
        for (reservation_id, receipt) in held_receipts(&doc.body) {
            let attempt_id = receipt["claim"]["attempt_id"].as_str().unwrap_or_default();
            let HoldContext {
                run_id,
                operation_id,
                operation,
            } = self.hold_context(tenant, reservation_id).await?;
            let op = operation.as_ref();
            let attempt = op.and_then(|op| {
                op["attempts"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .find(|a| a["attempt_id"] == attempt_id)
            });
            let last_observation = op
                .and_then(|op| {
                    op["observations"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .rfind(|o| o["attempt_id"] == attempt_id)
                })
                .map(|o| {
                    json!({"outcome": o["outcome"], "finality": o["finality"], "observed_at": o["observed_at"],
                    "external_ref": o["external_ref"], "observer": o["observer"], "evidence_ref": o["evidence_ref"]})
                });
            let (state, action, detail) = diagnose(receipt, op, attempt_id);
            let reconcile = match (&run_id, &operation_id) {
                (Some(run), Some(op)) if action != "investigate" && action != "incident" => {
                    json!(format!("/v1/runs/{run}/operations/{op}/reconcile"))
                }
                _ => Value::Null,
            };
            let attest_absence = match (&run_id, &operation_id) {
                (Some(run), Some(op)) if action == "confirm_or_attest_absence" => {
                    json!(format!("/v1/runs/{run}/operations/{op}/attest-absence"))
                }
                _ => Value::Null,
            };
            holds.push(json!({
                "reservation_id": reservation_id, "run_id": run_id, "operation_id": operation_id,
                "attempt_id": attempt_id, "action_digest": receipt["claim"]["action_digest"],
                "amount": receipt["claim"]["amount"], "state": state,
                "dispatch_started": receipt["dispatch_started"],
                "attempt_started_at": attempt.map_or(Value::Null, |a| a["started_at"].clone()),
                "operation_outcome": op.map_or(Value::Null, |o| o["outcome"].clone()),
                "last_observation": last_observation,
                "next_safe_step": {"action": action, "detail": detail, "reconcile": reconcile,
                    "attest_absence": attest_absence},
            }));
        }
        holds.sort_by(|a, b| {
            a["attempt_started_at"]
                .as_str()
                .cmp(&b["attempt_started_at"].as_str())
                .then_with(|| a["reservation_id"].as_str().cmp(&b["reservation_id"].as_str()))
        });
        view["as_of"] = json!(self.now());
        view["holds"] = json!(holds);
        Ok(Some(view))
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::diagnose;

    fn receipt(started: bool, aborted: bool) -> Value {
        json!({"status": "held", "dispatch_started": started, "dispatch_aborted": aborted})
    }

    fn op(outcome: Value, conflict: bool, observations: Value) -> Value {
        json!({"outcome": outcome, "conflict": conflict, "observations": observations})
    }

    fn seen(outcome: &str, finality: &str, external_ref: Value) -> Value {
        json!([{"attempt_id": "att_1", "outcome": outcome, "finality": finality, "external_ref": external_ref}])
    }

    fn state(receipt: &Value, op: Option<&Value>) -> (&'static str, &'static str) {
        let (state, action, _) = diagnose(receipt, op, "att_1");
        (state, action)
    }

    #[test]
    fn every_hold_names_a_step_that_cannot_duplicate_the_effect() {
        let none = op(Value::Null, false, json!([]));
        assert_eq!(state(&receipt(false, false), None), ("unlinked", "investigate"));
        assert_eq!(
            state(&receipt(false, false), Some(&none)),
            ("reserved_not_sent", "wait_or_reconcile")
        );
        assert_eq!(
            state(&receipt(true, false), Some(&none)),
            ("dispatch_active", "confirm_or_attest_absence")
        );
        let task = op(json!("unknown"), false, seen("unknown", "provisional", json!("task_1")));
        assert_eq!(
            state(&receipt(true, false), Some(&task)),
            ("unknown_provider_reference", "provider_query")
        );
        let lost = op(json!("unknown"), false, seen("unknown", "provisional", Value::Null));
        assert_eq!(
            state(&receipt(true, false), Some(&lost)),
            ("unknown", "operator_reconcile")
        );
        let partial = op(json!("partial"), false, seen("partial", "definitive", Value::Null));
        assert_eq!(
            state(&receipt(true, false), Some(&partial)),
            ("partial", "operator_reconcile")
        );
        let absent = op(
            json!("not_applied"),
            false,
            seen("not_applied", "definitive", Value::Null),
        );
        assert_eq!(
            state(&receipt(true, false), Some(&absent)),
            ("settlement_pending", "reconcile_again")
        );
        let confirmed = op(json!("confirmed"), false, json!([]));
        assert_eq!(
            state(&receipt(true, false), Some(&confirmed)),
            ("settlement_pending", "reconcile_again")
        );
        assert_eq!(
            state(&receipt(false, true), Some(&none)),
            ("settlement_pending", "reconcile_again")
        );
        let conflict = op(json!("confirmed"), true, json!([]));
        assert_eq!(
            state(&receipt(true, false), Some(&conflict)),
            ("conflicting_facts", "incident")
        );
        // Observations of another attempt say nothing about this one.
        let other = op(
            json!("unknown"),
            false,
            json!([{"attempt_id": "att_0", "outcome": "not_applied", "finality": "definitive", "external_ref": null}]),
        );
        assert_eq!(
            state(&receipt(true, false), Some(&other)),
            ("dispatch_active", "confirm_or_attest_absence")
        );
    }
}
