//! Usage ceilings: model tokens or spend per agent or tenant per window, shared by every
//! run, held before a call and committed when it settles.
//!
//! Each `[[guards.usage_ceilings]]` entry caps `tokens` or `cost_cents` for one agent
//! (`per = "agent"`) or the whole tenant (`per = "tenant"`) over a window. A model-call
//! reservation first holds its amount on every ceiling that covers the run, with the
//! same conserved ledger shared guarantees use for tool effects
//! ([`contextos_kernel::shared_exposure`]): concurrent runs cannot together pass the
//! limit, because a hold counts until it is settled. If any ceiling would be passed,
//! the holds already taken are released and the reservation is refused
//! (`usage_ceiling_reached:<id>`). Settling the reservation commits its holds.
//!
//! Settling commits the holds at the reserved amount: a call that used less still
//! counts as reserved. Usage a metering gateway measured above the reservation is added
//! to every covering ceiling as well, even past its limit (the call has happened), and
//! the ceiling then refuses reservations for the rest of its window; so a caller that
//! reserves too little cannot pass a ceiling with measured calls. Self-reported usage
//! is charged at the reservation only.
//!
//! Known limits: windows are fixed (`unix time / window_seconds`), not sliding, so a
//! burst that straddles a window boundary can use up to twice the limit within one
//! window's length; and a hold never settled (an executor that crashed) stays held
//! until its window ends, since each window is a fresh ledger. Settled receipts are
//! compacted as later calls settle, so a window may hold any number of calls.

use contextos_kernel::shared_exposure::{
    ExposureBinding, ExposureClaim, ExposureImport, compact_exposure, empty_exposure, import_exposure,
    reserve_exposure, settle_exposure,
};
use contextos_store::{AppendLog, Commit, DocKey, DocKind, DocumentStore, transact};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::admission::RunAdmission;
use crate::shared_guarantees::{exposure_key, hash};
use crate::usage::UsageRefusal;
use crate::{Gateway, GatewayError};

/// Ceilings at most.
pub const MAX_CEILINGS: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CeilingResource {
    Tokens,
    CostCents,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CeilingScope {
    Agent,
    Tenant,
}

/// One `[[guards.usage_ceilings]]` entry.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UsageCeiling {
    pub id: String,
    pub resource: CeilingResource,
    pub per: CeilingScope,
    pub limit: u64,
    /// 60 seconds to 31 days.
    pub window_seconds: u64,
    /// Agents it applies to (with `per = "agent"`); every agent when empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub agents: Vec<String>,
}

/// Refuses an invalid set of ceilings.
pub fn validate(ceilings: &[UsageCeiling]) -> Result<(), String> {
    if ceilings.len() > MAX_CEILINGS {
        return Err(format!("at most {MAX_CEILINGS} usage ceilings"));
    }
    let mut ids = std::collections::BTreeSet::new();
    for c in ceilings {
        if c.id.is_empty() || c.id.len() > 128 || !ids.insert(c.id.as_str()) {
            return Err("each usage ceiling has a unique id of up to 128 bytes".into());
        }
        if c.limit == 0 || !(60..=31 * 86_400).contains(&c.window_seconds) {
            return Err(format!(
                "usage ceiling {}: limit above 0, window 60 seconds to 31 days",
                c.id
            ));
        }
    }
    Ok(())
}

fn unix_seconds(at: &str) -> u64 {
    contextos_contract::validation::elapsed_millis("1970-01-01T00:00:00Z", at).map_or(0, |ms| ms / 1000)
}

/// Where one reservation's holds are recorded, to commit them at settlement.
fn holds_key(admission: &RunAdmission, reservation_id: &str) -> Result<DocKey, GatewayError> {
    Ok(DocKey::new(
        &admission.tenant_id,
        DocKind::ExposureLink,
        hash(&json!([admission.run_id, "usage_ceilings", reservation_id]))?,
    ))
}

impl UsageCeiling {
    fn covers(&self, agent: &str) -> bool {
        self.per == CeilingScope::Tenant || self.agents.is_empty() || self.agents.iter().any(|a| a == agent)
    }

    /// The ledger this run's usage at `now` draws on: its key and binding.
    fn ledger(&self, admission: &RunAdmission, now: &str) -> Result<(DocKey, ExposureBinding), GatewayError> {
        let agent = admission.actor["principal_id"].as_str().unwrap_or_default();
        let window = unix_seconds(now) / self.window_seconds;
        let who = match self.per {
            CeilingScope::Agent => format!("agent:{agent}"),
            CeilingScope::Tenant => "tenant".to_owned(),
        };
        let resource = format!("{who}:{window}");
        let id = format!("usage:{}", self.id);
        let binding = ExposureBinding {
            guarantee_id: id.clone(),
            definition_digest: hash(&serde_json::to_value(self).unwrap_or(Value::Null))?,
            resource_digest: hash(&json!(resource))?,
            limit: self.limit,
            unit: match self.resource {
                CeilingResource::Tokens => "tokens".into(),
                CeilingResource::CostCents => "cost_cents".into(),
            },
        };
        Ok((exposure_key(&admission.tenant_id, &id, &resource)?, binding))
    }
}

impl<S: DocumentStore + 'static, L: AppendLog + 'static> Gateway<S, L> {
    /// Caps model usage per agent or tenant per window (see [`crate::usage_ceilings`]).
    pub fn set_usage_ceilings(&mut self, ceilings: Vec<UsageCeiling>) {
        self.usage_ceilings = ceilings;
    }

    /// Holds `tokens` and `cost_cents` on every ceiling covering the run, or none.
    pub(crate) async fn hold_ceilings(
        &self,
        admission: &RunAdmission,
        reservation_id: &str,
        tokens: u64,
        cost_cents: u64,
    ) -> Result<(), UsageRefusal> {
        if self.usage_ceilings.is_empty() {
            return Ok(());
        }
        let agent = admission.actor["principal_id"].as_str().unwrap_or_default().to_owned();
        let now = self.now();
        let claim_for = |amount: u64| -> Result<ExposureClaim, GatewayError> {
            Ok(ExposureClaim {
                reservation_id: reservation_id.to_owned(),
                action_digest: hash(&json!([admission.run_id, reservation_id]))?,
                attempt_id: reservation_id.to_owned(),
                amount,
            })
        };
        let mut held: Vec<(DocKey, ExposureBinding, ExposureClaim)> = Vec::new();
        for ceiling in self.usage_ceilings.iter().filter(|c| c.covers(&agent)) {
            let amount = match ceiling.resource {
                CeilingResource::Tokens => tokens,
                CeilingResource::CostCents => cost_cents,
            };
            if amount == 0 {
                continue;
            }
            let attempt = async {
                let (key, binding) = ceiling.ledger(admission, &now)?;
                let claim = claim_for(amount)?;
                self.ensure_ledger(&key, &binding).await?;
                let commit = transact(self.store.as_ref(), &key, |state| {
                    reserve_exposure(state, &binding, &claim)
                })
                .await?;
                Ok::<_, GatewayError>((commit, key, binding, claim))
            }
            .await;
            let refusal = match attempt {
                Ok((Commit::Rejected { .. }, ..)) => {
                    UsageRefusal::Budget(vec![format!("usage_ceiling_reached:{}", ceiling.id)])
                }
                Ok((_, key, binding, claim)) => {
                    held.push((key, binding, claim));
                    continue;
                }
                Err(e) => e.into(),
            };
            // Neither a refusal nor a store failure leaves earlier holds behind.
            self.release_holds(&held).await;
            return Err(refusal);
        }
        if !held.is_empty() {
            let record = json!({"holds": held.iter().map(|(key, binding, claim)| json!({"key": key.id, "binding": binding, "claim": claim})).collect::<Vec<_>>()});
            if let Err(e) = self.store.create(&holds_key(admission, reservation_id)?, &record).await {
                self.release_holds(&held).await;
                return Err(GatewayError::from(e).into());
            }
        }
        Ok(())
    }

    async fn ensure_ledger(&self, key: &DocKey, binding: &ExposureBinding) -> Result<(), GatewayError> {
        match self.store.create(key, &empty_exposure(binding)).await {
            Ok(_) => Ok(()),
            Err(e) if e.is_conflict() => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    async fn release_holds(&self, held: &[(DocKey, ExposureBinding, ExposureClaim)]) {
        for (key, binding, claim) in held {
            let _ = transact(self.store.as_ref(), key, |state| {
                settle_exposure(state, binding, claim, "released")
            })
            .await;
        }
    }

    /// Commits (or, with `released`, gives back) a reservation's holds. `measured`
    /// is usage a metering gateway verified; what it exceeds the holds by is added to
    /// each covering ceiling, even past its limit.
    pub(crate) async fn settle_ceilings(
        &self,
        admission: &RunAdmission,
        reservation_id: &str,
        outcome: &str,
        measured: Option<(u64, u64)>,
    ) -> Result<(), GatewayError> {
        if self.usage_ceilings.is_empty() {
            return Ok(());
        }
        let now = self.now();
        let record = self.store.get(&holds_key(admission, reservation_id)?).await?;
        let mut settled: Vec<(String, DocKey, ExposureBinding, u64)> = Vec::new();
        for hold in record
            .iter()
            .flat_map(|r| r.body["holds"].as_array().cloned().unwrap_or_default())
        {
            let (Ok(binding), Ok(claim)) = (
                serde_json::from_value::<ExposureBinding>(hold["binding"].clone()),
                serde_json::from_value::<ExposureClaim>(hold["claim"].clone()),
            ) else {
                continue;
            };
            let key = DocKey::new(
                &admission.tenant_id,
                DocKind::SharedExposure,
                hold["key"].as_str().unwrap_or_default(),
            );
            transact(self.store.as_ref(), &key, |state| {
                settle_exposure(state, &binding, &claim, outcome)
            })
            .await?;
            // Archive receipts settled earlier, so a window never fills with them.
            transact(self.store.as_ref(), &key, |state| {
                compact_exposure(state, &binding, &now, 0)
            })
            .await?;
            settled.push((binding.guarantee_id.clone(), key, binding, claim.amount));
        }
        let Some((tokens, cost_cents)) = measured.filter(|_| outcome == "committed") else {
            return Ok(());
        };
        let agent = admission.actor["principal_id"].as_str().unwrap_or_default().to_owned();
        for ceiling in self.usage_ceilings.iter().filter(|c| c.covers(&agent)) {
            let used = match ceiling.resource {
                CeilingResource::Tokens => tokens,
                CeilingResource::CostCents => cost_cents,
            };
            let id = format!("usage:{}", ceiling.id);
            let held = settled.iter().find(|(g, ..)| *g == id);
            let over = used.saturating_sub(held.map_or(0, |(.., amount)| *amount));
            if over == 0 {
                continue;
            }
            // The window the hold was in, or the current one when nothing was held.
            let (key, binding) = match held {
                Some((_, key, binding, _)) => (key.clone(), binding.clone()),
                None => ceiling.ledger(admission, &now)?,
            };
            self.ensure_ledger(&key, &binding).await?;
            self.add_overage(admission, reservation_id, &key, &binding, used, over)
                .await?;
        }
        Ok(())
    }

    /// Adds measured usage above the holds to a ceiling: as a committed receipt while it
    /// fits (compacted like any other), otherwise as a one-way import that may pass the
    /// limit, after which the ceiling refuses reservations until its window ends.
    async fn add_overage(
        &self,
        admission: &RunAdmission,
        reservation_id: &str,
        key: &DocKey,
        binding: &ExposureBinding,
        used: u64,
        over: u64,
    ) -> Result<(), GatewayError> {
        let id = hash(&json!([admission.run_id, reservation_id, "overage"]))?;
        let claim = ExposureClaim {
            reservation_id: id.clone(),
            action_digest: hash(&json!([admission.run_id, reservation_id, used]))?,
            attempt_id: id.clone(),
            amount: over,
        };
        let reserved = transact(self.store.as_ref(), key, |state| {
            reserve_exposure(state, binding, &claim)
        })
        .await?;
        if let Commit::Rejected { reason_codes } = &reserved
            && reason_codes.iter().any(|r| r == "shared_guarantee_already_committed")
        {
            return Ok(());
        }
        if !matches!(reserved, Commit::Rejected { .. }) {
            transact(self.store.as_ref(), key, |state| {
                settle_exposure(state, binding, &claim, "committed")
            })
            .await?;
            return Ok(());
        }
        let import = ExposureImport {
            import_id: id,
            amount: over,
            row_digest: hash(&json!({"run_id": admission.run_id, "reservation_id": reservation_id,
                "measured": used, "over": over}))?,
        };
        let imported = transact(self.store.as_ref(), key, |state| {
            import_exposure(state, binding, &import)
        })
        .await?;
        if let Commit::Rejected { reason_codes } = imported {
            tracing::warn!(guarantee = %binding.guarantee_id, reasons = ?reason_codes, "measured overage not added to a usage ceiling");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ceiling(v: Value) -> UsageCeiling {
        serde_json::from_value(v).unwrap()
    }

    #[test]
    fn ceilings_are_validated_and_scoped() {
        let c = ceiling(
            json!({"id": "tokens-per-agent", "resource": "tokens", "per": "agent", "limit": 1000,
            "window_seconds": 3600, "agents": ["agt_support"]}),
        );
        assert!(validate(std::slice::from_ref(&c)).is_ok());
        assert!(c.covers("agt_support") && !c.covers("agt_other"));
        let t = ceiling(
            json!({"id": "spend", "resource": "cost_cents", "per": "tenant", "limit": 5000, "window_seconds": 86400}),
        );
        assert!(t.covers("anyone"));
        assert!(validate(&[c.clone(), c.clone()]).is_err(), "ids are unique");
        assert!(
            validate(&[ceiling(
                json!({"id": "x", "resource": "tokens", "per": "tenant", "limit": 0, "window_seconds": 60})
            )])
            .is_err()
        );
        assert!(
            validate(&[ceiling(
                json!({"id": "x", "resource": "tokens", "per": "tenant", "limit": 5, "window_seconds": 10})
            )])
            .is_err()
        );
    }
}
