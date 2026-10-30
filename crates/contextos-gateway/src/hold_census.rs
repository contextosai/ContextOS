//! Read-only census of shared-guarantee holds, for metrics and alerting.
//!
//! A page reads a tenant's exposure ledgers and returns each held receipt with the
//! receipt flags that change as its operation progresses. Diagnosing a hold (its state
//! and when its attempt started) costs two more reads, so callers diagnose a hold once
//! and again only when its flags change or it has a recorded observation (the states
//! that need a human and can still change). Nothing here settles, releases or retries.

use contextos_kernel::shared_exposure::MAX_EXPOSURE_RECEIPTS;
use contextos_store::{AppendLog, DocKey, DocKind, DocumentStore};
use serde_json::Value;

use crate::shared_inspection::{diagnose, held_receipts};
use crate::{Gateway, GatewayError};

/// One held receipt and the flags that move its diagnosis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeldReceipt {
    pub reservation_id: String,
    pub dispatch_started: bool,
    pub dispatch_aborted: bool,
    pub observation_recorded: bool,
    attempt_id: String,
}

impl HeldReceipt {
    /// The flags that, when changed, call for a new diagnosis.
    #[must_use]
    pub fn marks(&self) -> (bool, bool, bool) {
        (self.dispatch_started, self.dispatch_aborted, self.observation_recorded)
    }
}

/// One exposure ledger of a configured guarantee.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerHolds {
    pub guarantee_id: String,
    pub resource_digest: String,
    /// Receipts live in the ledger (held, and settled ones not yet archived), of at
    /// most [`MAX_EXPOSURE_RECEIPTS`].
    pub live_receipts: usize,
    pub holds: Vec<HeldReceipt>,
}

/// A page of a tenant's exposure ledgers.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct CensusPage {
    pub ledgers: Vec<LedgerHolds>,
    /// Ledgers of a configured guarantee that could not be read; their holds are unknown.
    pub unreadable: usize,
    /// Where the next page starts, or `None` once every ledger was read.
    pub next: Option<String>,
}

/// What a hold is waiting for (the inspection API's `state`) and when its attempt
/// started, if the operation record says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HoldDiagnosis {
    pub state: &'static str,
    pub attempt_started_at: Option<String>,
}

/// Every state a hold can be diagnosed in.
pub const HOLD_STATES: [&str; 8] = [
    "unlinked",
    "reserved_not_sent",
    "dispatch_active",
    "unknown_provider_reference",
    "unknown",
    "partial",
    "settlement_pending",
    "conflicting_facts",
];

/// The share of a ledger's receipt capacity in use.
#[must_use]
#[allow(clippy::cast_precision_loss)]
pub fn receipt_fill(live_receipts: usize) -> f64 {
    live_receipts as f64 / MAX_EXPOSURE_RECEIPTS as f64
}

fn flag(receipt: &Value, name: &str) -> bool {
    receipt[name] == true
}

impl<S: DocumentStore + 'static, L: AppendLog + 'static> Gateway<S, L> {
    /// The configured shared guarantees' ids.
    #[must_use]
    pub fn shared_guarantee_ids(&self) -> Vec<String> {
        self.shared_guarantees.iter().map(|g| g.id.clone()).collect()
    }

    /// Reads at most `scan` of the tenant's exposure ledgers after `after`. Ledgers of
    /// guarantees no longer configured are skipped.
    pub async fn census_page(
        &self,
        tenant: &str,
        after: Option<&str>,
        scan: usize,
    ) -> Result<CensusPage, GatewayError> {
        let scan = scan.max(1);
        let ids = self.store.list(tenant, DocKind::SharedExposure, after, scan).await?;
        let mut page = CensusPage {
            next: (ids.len() == scan).then(|| ids.last().cloned()).flatten(),
            ..CensusPage::default()
        };
        for id in &ids {
            let Some(doc) = self
                .store
                .get(&DocKey::new(tenant, DocKind::SharedExposure, id))
                .await?
            else {
                continue;
            };
            let Some(guarantee_id) = doc.body["binding"]["guarantee_id"].as_str() else {
                page.unreadable += 1;
                continue;
            };
            if !self.shared_guarantees.iter().any(|g| g.id == guarantee_id) {
                continue;
            }
            let Some(receipts) = doc.body["receipts"].as_object() else {
                page.unreadable += 1;
                continue;
            };
            let holds = held_receipts(&doc.body)
                .map(|(reservation_id, receipt)| HeldReceipt {
                    reservation_id: reservation_id.clone(),
                    dispatch_started: flag(receipt, "dispatch_started"),
                    dispatch_aborted: flag(receipt, "dispatch_aborted"),
                    observation_recorded: flag(receipt, "observation_recorded"),
                    attempt_id: receipt["claim"]["attempt_id"].as_str().unwrap_or_default().to_owned(),
                })
                .collect();
            page.ledgers.push(LedgerHolds {
                guarantee_id: guarantee_id.to_owned(),
                resource_digest: id.clone(),
                live_receipts: receipts.len(),
                holds,
            });
        }
        Ok(page)
    }

    /// Diagnoses one hold as the inspection API would, from its link and operation.
    pub async fn diagnose_hold(&self, tenant: &str, hold: &HeldReceipt) -> Result<HoldDiagnosis, GatewayError> {
        let context = self.hold_context(tenant, &hold.reservation_id).await?;
        let receipt = serde_json::json!({
            "dispatch_started": hold.dispatch_started,
            "dispatch_aborted": hold.dispatch_aborted,
        });
        let op = context.operation.as_ref();
        let (state, _, _) = diagnose(&receipt, op, &hold.attempt_id);
        let attempt_started_at = op
            .and_then(|op| op["attempts"].as_array())
            .into_iter()
            .flatten()
            .find(|a| a["attempt_id"] == hold.attempt_id.as_str())
            .and_then(|a| a["started_at"].as_str())
            .map(str::to_owned);
        Ok(HoldDiagnosis {
            state,
            attempt_started_at,
        })
    }

    /// How many escalations the tenant has listed as open.
    pub async fn open_escalation_count(&self, tenant: &str) -> Result<usize, GatewayError> {
        Ok(self
            .store
            .get(&DocKey::new(tenant, DocKind::Escalation, "open"))
            .await?
            .and_then(|index| index.body["keys"].as_array().map(Vec::len))
            .unwrap_or(0))
    }
}
