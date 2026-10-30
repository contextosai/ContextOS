//! Business-resource ceilings shared by independent runs. Configuration is trusted;
//! agents supply only arguments, never a ledger name, ceiling or settlement decision.
use std::collections::HashSet;

use contextos_contract::canonical::sha256_canonical;
use contextos_contract::types::ActionEffect;
use contextos_kernel::shared_exposure::{
    ExposureBinding, ExposureClaim, MAX_EXACT_EXPOSURE, compact_exposure, empty_exposure, exposure_digest,
    exposure_summary, reserve_exposure, settle_exposure, transition_exposure_dispatch,
};
use contextos_store::{AppendLog, Commit, DocKey, DocKind, DocumentStore, StoreError, transact};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{Gateway, GatewayError, RunAdmission, operation_ledger_key};

/// How long a settled receipt stays in its resource's ledger after it is first seen
/// settled. It fences a dispatcher that stalled before sending and comes back for its
/// attempt; one that stalled past [`crate::DISPATCH_STALL_SECONDS`] sends nothing, so
/// the fence is needed for that long at most. Archived receipts leave only their
/// committed amount behind.
pub const EXPOSURE_RECEIPT_RETENTION_SECONDS: u64 = 3600;
const _: () = assert!(EXPOSURE_RECEIPT_RETENTION_SECONDS > 10 * crate::DISPATCH_STALL_SECONDS);

/// Shared attempts seal their first definitive fact. A stale concurrent resolver
/// may not append contradictory evidence after capacity has become releasable.
pub(crate) fn record_shared_observation(ledger: &Value, observation: &Value) -> contextos_kernel::TransitionResult {
    let op = ledger["operations"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|o| o["intent"]["operation_id"] == observation["operation_id"]);
    if let Some(op) = op {
        if op["attempts"]
            .as_array()
            .and_then(|a| a.last())
            .is_none_or(|a| a["attempt_id"] != observation["attempt_id"])
        {
            return contextos_kernel::TransitionResult::rejected(ledger.clone(), "shared_guarantee_stale_observation");
        }
        if op["observations"].as_array().into_iter().flatten().any(|o| {
            o["attempt_id"] == observation["attempt_id"]
                && o["observation_id"] != observation["observation_id"]
                && o["finality"] == "definitive"
                && o["outcome"] != "unknown"
        }) {
            return contextos_kernel::TransitionResult::rejected(ledger.clone(), "shared_guarantee_attempt_sealed");
        }
    }
    contextos_kernel::operation_ledger::record_effect_observation(ledger, observation, &ledger["revision"])
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SharedGuarantee {
    pub id: String,
    pub capability_ids: Vec<String>,
    pub resource_pointer: String,
    pub amount_pointer: String,
    pub limit: u64,
    pub unit: String,
}

pub(crate) fn identifier(s: &str) -> bool {
    !s.is_empty() && s.len() <= 256 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))
}

fn pointer(s: &str) -> bool {
    if !s.starts_with('/') || s.len() > 256 {
        return false;
    }
    let mut bytes = s.bytes();
    while let Some(b) = bytes.next() {
        if b == b'~' && !matches!(bytes.next(), Some(b'0' | b'1')) {
            return false;
        }
    }
    true
}

impl SharedGuarantee {
    pub fn validate(&self) -> Result<(), String> {
        if !identifier(&self.id)
            || self.id.len() > 64
            || !identifier(&self.unit)
            || self.capability_ids.is_empty()
            || self.capability_ids.len() > 64
            || self.capability_ids.iter().any(|s| !identifier(s))
            || self.capability_ids.iter().collect::<HashSet<_>>().len() != self.capability_ids.len()
            || !pointer(&self.resource_pointer)
            || !pointer(&self.amount_pointer)
            || self.resource_pointer == self.amount_pointer
            || self.limit == 0
            || self.limit > MAX_EXACT_EXPOSURE
        {
            return Err("invalid shared guarantee definition".into());
        }
        Ok(())
    }

    fn definition(&self) -> Value {
        let mut rule = self.clone();
        rule.capability_ids.sort();
        json!(rule)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Link {
    run_id: String,
    operation_id: String,
    binding: ExposureBinding,
    reservation_id: String,
    action_digest: String,
    amount: u64,
}

impl Link {
    fn claim(&self, attempt_id: &str) -> ExposureClaim {
        ExposureClaim {
            reservation_id: self.reservation_id.clone(),
            action_digest: self.action_digest.clone(),
            amount: self.amount,
            attempt_id: attempt_id.into(),
        }
    }
    fn ledger_key(&self, tenant: &str) -> Result<DocKey, GatewayError> {
        exposure_key(tenant, &self.binding.guarantee_id, &self.binding.resource_digest)
    }
}

fn hash(value: &Value) -> Result<String, GatewayError> {
    sha256_canonical(value).map_err(|_| GatewayError::Guarantee("shared_guarantee_invalid".into()))
}

pub(crate) fn exposure_key(tenant: &str, id: &str, resource: &str) -> Result<DocKey, GatewayError> {
    Ok(DocKey::new(
        tenant,
        DocKind::SharedExposure,
        hash(&json!([id, resource]))?,
    ))
}

fn link_key(admission: &RunAdmission, operation: &str) -> Result<DocKey, GatewayError> {
    Ok(DocKey::new(
        &admission.tenant_id,
        DocKind::ExposureLink,
        hash(&json!([admission.run_id, operation]))?,
    ))
}

/// Create-or-compare is idempotent and race-safe. Never replace a pinned binding.
async fn pin<S: DocumentStore>(store: &S, key: &DocKey, body: &Value) -> Result<bool, StoreError> {
    match store.create(key, body).await {
        Ok(_) => Ok(true),
        Err(e) if e.is_conflict() => Ok(store.get(key).await?.is_some_and(|d| d.body == *body)),
        Err(e) => Err(e),
    }
}

impl<S: DocumentStore + 'static, L: AppendLog + 'static> Gateway<S, L> {
    /// Must be called after capabilities are pinned. Replaces rules atomically only
    /// after validation; durable per-tenant definition pins prevent semantic resets.
    pub fn set_shared_guarantees(&mut self, rules: Vec<SharedGuarantee>) -> Result<(), GatewayError> {
        if rules.len() > 128 {
            return Err(GatewayError::Guarantee("too many shared guarantees".into()));
        }
        let (mut ids, mut covered) = (HashSet::new(), HashSet::new());
        for rule in &rules {
            rule.validate().map_err(GatewayError::Guarantee)?;
            if !ids.insert(&rule.id) {
                return Err(GatewayError::Guarantee("duplicate shared guarantee id".into()));
            }
            for cap in &rule.capability_ids {
                let Some(manifest) = self.manifests.get(cap) else {
                    return Err(GatewayError::Guarantee(
                        "shared guarantee capability is not pinned".into(),
                    ));
                };
                if manifest.action_risk.effect == ActionEffect::None || !covered.insert(cap) {
                    return Err(GatewayError::Guarantee(
                        "shared guarantee needs uniquely covered effectful capabilities".into(),
                    ));
                }
            }
        }
        self.shared_guarantees = rules;
        Ok(())
    }

    pub fn shared_guarantees(&self) -> &[SharedGuarantee] {
        &self.shared_guarantees
    }

    pub(crate) fn has_shared_guarantee(&self, capability: &str) -> bool {
        self.shared_guarantees
            .iter()
            .any(|r| r.capability_ids.iter().any(|c| c == capability))
    }

    pub async fn shared_exposure(
        &self,
        tenant: &str,
        id: &str,
        resource_digest: &str,
    ) -> Result<Option<Value>, GatewayError> {
        if !identifier(id) || !exposure_digest(resource_digest) {
            return Ok(None);
        }
        let key = exposure_key(tenant, id, resource_digest)?;
        self.store
            .get(&key)
            .await?
            .map(|d| {
                exposure_summary(&d.body).ok_or_else(|| GatewayError::Guarantee("shared_guarantee_invalid".into()))
            })
            .transpose()
    }

    pub(crate) async fn has_exposure_link(
        &self,
        admission: &RunAdmission,
        operation: &str,
    ) -> Result<bool, GatewayError> {
        Ok(self.store.get(&link_key(admission, operation)?).await?.is_some())
    }

    pub(crate) async fn reserve_shared_exposure(
        &self,
        admission: &RunAdmission,
        capability: &str,
        args: &Value,
        operation: &str,
        attempt: &str,
        digest: &str,
    ) -> Result<Result<Vec<u64>, &'static str>, GatewayError> {
        let Some(rule) = self
            .shared_guarantees
            .iter()
            .find(|r| r.capability_ids.iter().any(|c| c == capability))
        else {
            return Ok(Ok(vec![]));
        };
        // Pin BEFORE extracting the resource. A changed pointer cannot route old
        // business exposure into a new empty ledger, even across mixed replicas.
        let definition = rule.definition();
        let definition_digest = hash(&definition)?;
        let definition_key = DocKey::new(&admission.tenant_id, DocKind::GuaranteeDefinition, &rule.id);
        if !pin(self.store.as_ref(), &definition_key, &definition).await? {
            return Ok(Err("shared_guarantee_definition_mismatch"));
        }
        let Some(resource) = args
            .pointer(&rule.resource_pointer)
            .and_then(Value::as_str)
            .filter(|s| identifier(s))
        else {
            return Ok(Err("shared_guarantee_resource_invalid"));
        };
        let Some(amount) = args
            .pointer(&rule.amount_pointer)
            .and_then(Value::as_u64)
            .filter(|n| *n > 0 && *n <= MAX_EXACT_EXPOSURE)
        else {
            return Ok(Err("shared_guarantee_amount_invalid"));
        };
        let reservation_id = hash(&json!([admission.run_id, operation]))?;
        let link = Link {
            run_id: admission.run_id.clone(),
            operation_id: operation.into(),
            reservation_id,
            action_digest: digest.into(),
            amount,
            binding: ExposureBinding {
                guarantee_id: rule.id.clone(),
                definition_digest,
                resource_digest: hash(&json!(resource))?,
                limit: rule.limit,
                unit: rule.unit.clone(),
            },
        };
        let key = link.ledger_key(&admission.tenant_id)?;
        match self.store.create(&key, &empty_exposure(&link.binding)).await {
            Ok(_) => {}
            Err(e) if e.is_conflict() => {}
            Err(e) => return Err(e.into()),
        }
        // Publish a link only after the empty ledger exists. Recovery can then
        // tombstone even an attempt paused before its reservation CAS commits.
        if !pin(self.store.as_ref(), &link_key(admission, operation)?, &json!(link)).await? {
            return Ok(Err("shared_guarantee_binding_mismatch"));
        }
        let claim = link.claim(attempt);
        let now = self.now();
        // Archive settled receipts past their retention in the same commit, so a
        // resource's lifetime is not bounded by its receipt count.
        let commit = transact(self.store.as_ref(), &key, |state| {
            let compacted = compact_exposure(state, &link.binding, &now, EXPOSURE_RECEIPT_RETENTION_SECONDS);
            if !compacted.is_accepted() {
                return compacted;
            }
            reserve_exposure(&compacted.state, &link.binding, &claim)
        })
        .await?;
        if let Commit::Rejected { reason_codes } = commit {
            let reason = match reason_codes.first().map(String::as_str) {
                Some("shared_guarantee_exceeded") => "shared_guarantee_exceeded",
                Some("shared_guarantee_saturated") => "shared_guarantee_saturated",
                Some("shared_guarantee_unresolved") => "shared_guarantee_unresolved",
                _ => "shared_guarantee_invalid",
            };
            return Ok(Err(reason));
        }
        // No provider call is permitted until the reservation is durably audited.
        let entry = self
            .audit
            .append(
                &admission.tenant_id,
                "shared_guarantee_reserved",
                json!({"run_id":admission.run_id,"operation_id":operation,"attempt_id":attempt,
                "action_digest":digest,"binding":link.binding,"amount":amount}),
                &self.now(),
            )
            .await?;
        Ok(Ok(vec![entry.sequence]))
    }

    pub(crate) async fn transition_shared_dispatch(
        &self,
        admission: &RunAdmission,
        operation: &str,
        attempt: &str,
        event: &str,
    ) -> Result<Result<(), Vec<String>>, GatewayError> {
        let Some(doc) = self.store.get(&link_key(admission, operation)?).await? else {
            // A guarded dispatch reserved through its link, so a missing one means its
            // receipt cannot be marked: fail closed rather than send unmarked.
            return Ok(if event == "start" {
                Err(vec!["shared_guarantee_link_missing".into()])
            } else {
                Ok(())
            });
        };
        let link: Link =
            serde_json::from_value(doc.body).map_err(|_| GatewayError::Guarantee("shared_guarantee_invalid".into()))?;
        let claim = link.claim(attempt);
        let commit = transact(self.store.as_ref(), &link.ledger_key(&admission.tenant_id)?, |state| {
            transition_exposure_dispatch(state, &link.binding, &claim, event)
        })
        .await?;
        Ok(match commit {
            Commit::Rejected { reason_codes } => Err(reason_codes),
            _ => Ok(()),
        })
    }

    pub(crate) async fn shared_observation_refused(
        &self,
        admission: &RunAdmission,
        observation: &Value,
        reasons: &[String],
    ) -> Result<u64, GatewayError> {
        Ok(self
            .audit
            .append(
                &admission.tenant_id,
                "shared_guarantee_observation_refused",
                json!({"run_id":admission.run_id,"observation":observation,"reason_codes":reasons}),
                &self.now(),
            )
            .await?
            .sequence)
    }

    /// Repairable from protected state, including after a terminal observation was
    /// accepted but audit/settlement failed. Read receipt BEFORE operation history:
    /// a newer attempt can never be released using an older history snapshot.
    pub(crate) async fn settle_shared_exposure(
        &self,
        admission: &RunAdmission,
        operation: &str,
    ) -> Result<Vec<u64>, GatewayError> {
        let Some(link_doc) = self.store.get(&link_key(admission, operation)?).await? else {
            return Ok(vec![]);
        };
        let link: Link = serde_json::from_value(link_doc.body)
            .map_err(|_| GatewayError::Guarantee("shared_guarantee_invalid".into()))?;
        if link.run_id != admission.run_id || link.operation_id != operation {
            return Err(GatewayError::Guarantee("shared_guarantee_binding_mismatch".into()));
        }
        let key = link.ledger_key(&admission.tenant_id)?;
        let Some(read) = self.store.get(&key).await? else {
            return Ok(vec![]);
        };
        let Some(receipt) = read.body["receipts"].get(&link.reservation_id) else {
            return Ok(vec![]);
        };
        let claim: ExposureClaim = serde_json::from_value(receipt["claim"].clone())
            .map_err(|_| GatewayError::Guarantee("shared_guarantee_invalid".into()))?;
        if claim.action_digest != link.action_digest || claim.amount != link.amount {
            return Err(GatewayError::Guarantee("shared_guarantee_binding_mismatch".into()));
        }
        let Some(ops) = self.store.get(&operation_ledger_key(admission, operation)).await? else {
            return Ok(vec![]);
        };
        let Some(op) = ops.body["operations"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|o| o["intent"]["operation_id"] == operation)
        else {
            return Ok(vec![]);
        };
        if op["intent"]["action_digest"] != link.action_digest {
            return Err(GatewayError::Guarantee("shared_guarantee_binding_mismatch".into()));
        }
        let observations: Vec<&Value> = op["observations"].as_array().into_iter().flatten().collect();
        let attempts: Vec<&Value> = op["attempts"].as_array().into_iter().flatten().collect();
        // Every attempt needs a definitive absent fact before exposure can be freed.
        // A claimed attempt without an observation is uncertain, not "not sent".
        let all_absent = !attempts.is_empty()
            && attempts.iter().all(|a| {
                observations.iter().any(|o| {
                    o["attempt_id"] == a["attempt_id"]
                        && o["finality"] == "definitive"
                        && matches!(o["outcome"].as_str(), Some("not_applied" | "not_dispatched"))
                })
            });
        let outcome = if op["conflict"] == true || matches!(op["outcome"].as_str(), Some("unknown" | "partial")) {
            "held"
        } else if op["outcome"] == "confirmed" {
            "committed"
        } else if all_absent {
            "released"
        } else {
            "held"
        };
        if observations.iter().any(|o| o["attempt_id"] == claim.attempt_id) {
            let commit = transact(self.store.as_ref(), &key, |state| {
                transition_exposure_dispatch(state, &link.binding, &claim, "observe")
            })
            .await?;
            if let Commit::Rejected { reason_codes } = commit {
                return Err(GatewayError::Guarantee(reason_codes.join(",")));
            }
        }
        if outcome == "held" {
            return Ok(vec![]);
        }
        // Sign the evidence and requested transition BEFORE allowing capacity to be
        // released. A repeated reconciliation can repair any interrupted commit.
        let intent = self
            .audit
            .append(
                &admission.tenant_id,
                "shared_guarantee_settlement_requested",
                json!({"run_id":admission.run_id,"operation_id":operation,"claim":claim,"binding":link.binding,
                "outcome":outcome,"operation_state_digest":hash(op)?,
                "evidence_refs":observations.iter().map(|o| &o["evidence_ref"]).collect::<Vec<_>>()}),
                &self.now(),
            )
            .await?;
        let commit = transact(self.store.as_ref(), &key, |state| {
            settle_exposure(state, &link.binding, &claim, outcome)
        })
        .await?;
        if let Commit::Rejected { reason_codes } = commit {
            return Err(GatewayError::Guarantee(reason_codes.join(",")));
        }
        let entry = self
            .audit
            .append(
                &admission.tenant_id,
                "shared_guarantee_settled",
                json!({"run_id":admission.run_id,"operation_id":operation,"reservation_id":claim.reservation_id,
                "attempt_id":claim.attempt_id,"outcome":outcome,"binding":link.binding}),
                &self.now(),
            )
            .await?;
        Ok(vec![intent.sequence, entry.sequence])
    }
}
