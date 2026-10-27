//! Gateway operations over a team's findings (see [`crate::findings`]): the same
//! access as the work board (protected lineage, the admitting principal, the current
//! executor), one CAS document per root, audited mutation attempts.

use contextos_contract::canonical::{canonicalize, sha256_canonical};
use contextos_store::{AppendLog, DocKey, DocKind, DocumentStore, StoreError, Versioned};
use serde_json::{Value, json};

use crate::coordination::{Access, WorkError};
use crate::findings::{
    Basis, BasisInput, FindingInput, FindingKind, Ledger, MAX_FINDINGS_BYTES, NOTICES_PER_RESULT, PUBLISH_BUDGET_BYTES,
    refuse,
};
use crate::{Gateway, GatewayError, RunAdmission, is_erased, operation_ledger_key};

const CAS_ATTEMPTS: usize = 16;

pub(crate) fn findings_key(tenant: &str, root: &str) -> DocKey {
    DocKey::new(tenant, DocKind::Findings, root)
}

fn decode(read: Option<&Versioned>) -> Result<Ledger, WorkError> {
    match read {
        Some(r) if is_erased(&r.body) => refuse("findings_erased"),
        Some(r) => serde_json::from_value(r.body.clone()).map_err(|_| StoreError::Integrity.into()),
        None => Ok(Ledger::default()),
    }
}

fn root_of(admission: &RunAdmission) -> &str {
    admission.lineage.as_ref().map_or(&admission.run_id, |l| &l.root_run_id)
}

impl<S: DocumentStore + 'static, L: AppendLog + 'static> Gateway<S, L> {
    /// What the operation ledger recorded for the cited call: it must belong to a run
    /// of this team and have a definitive, confirmed outcome.
    async fn basis(&self, access: &Access, input: &BasisInput) -> Result<Basis, WorkError> {
        let run_id = input.run_id.as_deref().unwrap_or(&access.worker.run_id);
        let cited = if run_id == access.worker.run_id {
            access.worker.clone()
        } else {
            let stored = self
                .store
                .get(&DocKey::new(&access.worker.tenant_id, DocKind::RunAdmission, run_id))
                .await?
                .ok_or(WorkError::Refused("basis_not_found"))?;
            serde_json::from_value(stored.body).map_err(|_| StoreError::Integrity)?
        };
        if cited.tenant_id != access.worker.tenant_id || root_of(&cited) != access.root_id {
            return refuse("basis_outside_team");
        }
        let ledger = self
            .store
            .get(&operation_ledger_key(&cited, &input.operation_id))
            .await?
            .ok_or(WorkError::Refused("basis_not_found"))?;
        let op = ledger.body["operations"]
            .as_array()
            .and_then(|ops| {
                ops.iter()
                    .find(|op| op["intent"]["operation_id"] == input.operation_id.as_str())
            })
            .ok_or(WorkError::Refused("basis_not_found"))?;
        let in_flight = op["attempts"]
            .as_array()
            .and_then(|a| a.last())
            .is_some_and(|a| a["dispatch_state"] == "claimed");
        if op["outcome"] != "confirmed" || op["conflict"] == true || in_flight {
            return refuse("basis_unconfirmed");
        }
        let observation = op["observations"]
            .as_array()
            .into_iter()
            .flatten()
            .rev()
            .find(|o| o["finality"] == "definitive" && o["outcome"] == "confirmed")
            .ok_or(WorkError::Refused("basis_unconfirmed"))?;
        Ok(Basis {
            run_id: cited.run_id.clone(),
            operation_id: input.operation_id.clone(),
            action_digest: op["intent"]["action_digest"].clone(),
            capability_ref: op["intent"]["capability_ref"].clone(),
            outcome: "confirmed".into(),
            observation_ref: observation["evidence_ref"].clone(),
            observed_at: observation["observed_at"].clone(),
        })
    }

    /// Publishes a finding to the team. An `observed` finding's basis is taken from the
    /// operation ledger, never from the caller.
    pub async fn publish_finding(
        &self,
        admission: &RunAdmission,
        principal: &str,
        generation: u64,
        input: FindingInput,
    ) -> Result<Value, WorkError> {
        input.validate()?;
        let basis = match (&input.kind, &input.basis) {
            (FindingKind::Observed, Some(cited)) => {
                let access = self.work_access(admission, principal, generation).await?;
                Some(self.basis(&access, cited).await?)
            }
            _ => None,
        };
        let id = input.finding_id.clone();
        self.mutate_findings(admission, principal, generation, &id, "publish", |ledger, access| {
            let (finding, changed) = ledger.publish(&input, basis.clone(), &access.worker.run_id, &access.now)?;
            Ok((json!({"finding": finding}), changed))
        })
        .await
    }

    /// Falsifies a finding: the author withdraws it, or another peer cites an active
    /// `observed` finding refuting it. Dependents become suspect; the team is notified.
    pub async fn invalidate_finding(
        &self,
        admission: &RunAdmission,
        principal: &str,
        generation: u64,
        finding_id: &str,
        reason: &str,
        refuted_by: Option<&str>,
    ) -> Result<Value, WorkError> {
        self.mutate_findings(
            admission,
            principal,
            generation,
            finding_id,
            "invalidate",
            |ledger, access| {
                let finding = ledger.invalidate(finding_id, reason, refuted_by, &access.worker.run_id, &access.now)?;
                let suspect = ledger.notices.back().map(|n| n.suspect.clone()).unwrap_or_default();
                Ok((json!({"finding": finding, "suspect": suspect}), true))
            },
        )
        .await
    }

    /// Records that this run's orchestrator has seen notices through `through`.
    pub async fn acknowledge_notices(
        &self,
        admission: &RunAdmission,
        principal: &str,
        generation: u64,
        through: u64,
    ) -> Result<Value, WorkError> {
        self.mutate_findings(admission, principal, generation, "", "acknowledge", |ledger, access| {
            let changed = ledger.acknowledge(&access.worker.run_id, through)?;
            Ok((ledger.pending(&access.worker.run_id, NOTICES_PER_RESULT), changed))
        })
        .await
    }

    /// A page of the team's findings in id order (at most 100).
    pub async fn findings(
        &self,
        admission: &RunAdmission,
        principal: &str,
        generation: u64,
        after: Option<&str>,
        limit: usize,
    ) -> Result<Value, WorkError> {
        if !(1..=100).contains(&limit) {
            return refuse("findings_invalid");
        }
        let access = self.work_access(admission, principal, generation).await?;
        let read = self
            .store
            .get(&findings_key(&admission.tenant_id, &access.root_id))
            .await?;
        let ledger = decode(read.as_ref())?;
        let mut page: Vec<_> = ledger
            .findings
            .values()
            .filter(|f| after.is_none_or(|a| f.finding_id.as_str() > a))
            .take(limit + 1)
            .collect();
        let more = page.len() > limit;
        page.truncate(limit);
        let next = more.then(|| page.last().expect("nonempty page").finding_id.clone());
        Ok(json!({"root_run_id": access.root_id, "findings": page, "next_cursor": next, "data_only": true}))
    }

    /// This run's unacknowledged notices (peeked; reading does not acknowledge).
    pub async fn notices(
        &self,
        admission: &RunAdmission,
        principal: &str,
        generation: u64,
        limit: usize,
    ) -> Result<Value, WorkError> {
        if !(1..=100).contains(&limit) {
            return refuse("findings_invalid");
        }
        let access = self.work_access(admission, principal, generation).await?;
        let read = self
            .store
            .get(&findings_key(&admission.tenant_id, &access.root_id))
            .await?;
        let mut view = decode(read.as_ref())?.pending(&access.worker.run_id, limit);
        view["root_run_id"] = json!(access.root_id);
        Ok(view)
    }

    /// Notices to attach to a tool result of this run: `None` when there are none, the
    /// caller is not the run's admitting principal at its current executor generation of
    /// a running run, or they cannot be read now (a tool result never fails for its
    /// notices).
    pub async fn notices_for_result(
        &self,
        admission: &RunAdmission,
        principal: &str,
        generation: u64,
    ) -> Option<Value> {
        if admission.admitted_by.is_empty() || admission.admitted_by != principal {
            return None;
        }
        let key = findings_key(&admission.tenant_id, root_of(admission));
        let (state, read) = tokio::join!(self.run_state(admission), self.store.get(&key));
        let (state, read) = match (state, read) {
            (Ok(state), Ok(read)) => (state?, read?),
            (Err(error), _) => {
                tracing::warn!(%error, "peer notices unavailable");
                return None;
            }
            (_, Err(error)) => {
                tracing::warn!(%error, "peer notices unavailable");
                return None;
            }
        };
        if state["status"] != "running" || state["executor_generation"].as_u64() != Some(generation) {
            return None;
        }
        let view = decode(Some(&read)).ok()?.pending(&admission.run_id, NOTICES_PER_RESULT);
        (view["pending"].as_u64() > Some(0) || view["missed"] == true).then_some(view)
    }

    async fn mutate_findings<F>(
        &self,
        admission: &RunAdmission,
        principal: &str,
        generation: u64,
        finding_id: &str,
        action: &str,
        edit: F,
    ) -> Result<Value, WorkError>
    where
        F: Fn(&mut Ledger, &Access) -> Result<(Value, bool), WorkError>,
    {
        for attempt in 0..CAS_ATTEMPTS {
            if attempt > 0 {
                tokio::task::yield_now().await;
            }
            let access = self.work_access(admission, principal, generation).await?;
            let key = findings_key(&admission.tenant_id, &access.root_id);
            let read = self.store.get(&key).await?;
            let mut ledger = decode(read.as_ref())?;
            let (mut response, changed) = edit(&mut ledger, &access)?;
            response["root_run_id"] = json!(access.root_id);
            response["data_only"] = json!(true);
            if !changed {
                return Ok(response);
            }
            let body = serde_json::to_value(&ledger).map_err(|_| StoreError::Integrity)?;
            let limit = if action == "publish" {
                PUBLISH_BUDGET_BYTES
            } else {
                MAX_FINDINGS_BYTES
            };
            if canonicalize(&body).map_or(true, |s| s.len() > limit) {
                return refuse("findings_full");
            }
            let digest = sha256_canonical(&body).map_err(StoreError::from)?;
            self.audit
                .append(
                    &admission.tenant_id,
                    "findings_mutation_attempt",
                    json!({"root_run_id": access.root_id, "run_id": access.worker.run_id, "principal_id": principal,
                        "executor_generation": generation, "finding_id": finding_id, "action": action,
                        "notice_seq": ledger.next_seq, "base_store_revision": read.as_ref().map_or(0, |r| r.revision),
                        "findings_digest": digest}),
                    &access.now,
                )
                .await?;
            let written = match read {
                Some(r) => self.store.compare_and_swap(&key, r.revision, &body).await,
                None => self.store.create(&key, &body).await,
            };
            match written {
                Ok(_) => return Ok(response),
                Err(e) if e.is_conflict() => {}
                Err(e) => return Err(e.into()),
            }
        }
        refuse("findings_busy")
    }

    /// Tombstones the root's findings with the root's erasure.
    pub(crate) async fn erase_findings(
        &self,
        admission: &RunAdmission,
        operator: &str,
        reason: &str,
    ) -> Result<Option<Value>, GatewayError> {
        let key = findings_key(&admission.tenant_id, &admission.run_id);
        self.erase_team_document(admission, key, "findings", operator, reason)
            .await
    }
}
