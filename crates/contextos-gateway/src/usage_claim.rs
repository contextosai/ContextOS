//! Metering gateways claim model-call reservations before they call the model.
//!
//! A reservation covers one model call. Without a claim, a metering gateway would
//! learn that a reservation was forged, already used or belongs to a replan only when
//! it settles, after the provider has served (and billed) the call. Claiming first
//! refuses those calls before they reach the provider, and the claim is a store
//! document created once, so it holds across gateway and contextosd replicas.
//!
//! A claimed reservation settles as measured only by the gateway that claimed it; the
//! run's executor can still settle it in full (unknown usage is never free).

use contextos_store::{AppendLog, DocKey, DocKind, DocumentStore, StoreError};
use serde_json::json;

use crate::admission::RunAdmission;
use crate::usage::UsageRefusal;
use crate::{Gateway, GatewayError};

/// What a claimed reservation covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClaimedUsage {
    pub tokens: u64,
    pub cost_cents: u64,
}

fn claim_key(admission: &RunAdmission, reservation_id: &str) -> DocKey {
    DocKey::new(
        &admission.tenant_id,
        DocKind::UsageClaim,
        format!("{}/{reservation_id}", admission.run_id),
    )
}

impl<S: DocumentStore + 'static, L: AppendLog + 'static> Gateway<S, L> {
    /// Claims an open model-call reservation for one call by the metering principal
    /// `reporter`, and returns what it covers. Refused when the run is revoked, the
    /// reservation is unknown, settled or a replan's, or it was already claimed
    /// (by anyone). Audited as `usage_claimed`.
    pub async fn claim_usage(
        &self,
        admission: &RunAdmission,
        reservation_id: &str,
        reporter: &str,
        model: Option<&str>,
    ) -> Result<ClaimedUsage, UsageRefusal> {
        self.usage_revocation(admission).await?;
        let allocation = self.open_reservation(admission, reservation_id).await?;
        let get = |k: &str| allocation[k].as_u64().unwrap_or(0);
        if get("replans") > 0 || get("tool_calls") > 0 {
            return Err(UsageRefusal::UnknownReservation);
        }
        let now = self.now();
        let claim = json!({"run_id": admission.run_id, "reservation_id": reservation_id,
            "reporter": reporter, "model": model, "claimed_at": now});
        match self.store.create(&claim_key(admission, reservation_id), &claim).await {
            Ok(_) => {}
            Err(StoreError::Conflict { .. }) => return Err(UsageRefusal::Claimed),
            Err(error) => return Err(GatewayError::from(error).into()),
        }
        self.audit
            .append(
                &admission.tenant_id,
                "usage_claimed",
                json!({"run_id": admission.run_id, "reservation_id": reservation_id,
                    "reporter": reporter, "model": model}),
                &now,
            )
            .await
            .map_err(GatewayError::from)?;
        Ok(ClaimedUsage {
            tokens: get("tokens"),
            // Cost units are hundredths of a cent; report whole cents, rounded down.
            cost_cents: get("cost_units") / 100,
        })
    }

    /// Refuses measured settlement of a reservation another metering principal claimed.
    pub(crate) async fn require_claimant(
        &self,
        admission: &RunAdmission,
        reservation_id: &str,
        reporter: &str,
    ) -> Result<(), UsageRefusal> {
        let claim = self
            .store
            .get(&claim_key(admission, reservation_id))
            .await
            .map_err(GatewayError::from)?;
        match claim.map(|c| c.body) {
            Some(body) if body["reporter"] != reporter => Err(UsageRefusal::Claimed),
            _ => Ok(()),
        }
    }
}
