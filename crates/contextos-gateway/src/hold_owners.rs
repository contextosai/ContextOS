//! Telling a guarantee's business owner about a hold that has waited too long.
//!
//! On-call learns about aging holds from gauges and alerts. A held refund is often the
//! refund lead's to resolve, though, so a guarantee may name an `owner_route` (a
//! notification webhook). When the governance sweep finds a hold older than the
//! guarantee's `owner_after_seconds`, [`Gateway::report_aged_hold`] appends one
//! `shared_hold_aged` audit entry with what the owner needs to act: the resource, the
//! amount, the diagnosed state, the last observation and the next safe step with its
//! reconcile route. The notification dispatcher delivers that entry to the owner's
//! webhook only, from the audit chain, so the owner is told exactly what was audited.
//!
//! Each hold is reported once: a marker document is written after the entry, so a
//! crash between the two may report a hold twice (receivers drop duplicates by
//! `reservation_id`), never zero times. A hold that settles before it ages is never
//! reported. Age is for routing only: waiting resolves nothing.

use contextos_store::{AppendLog, DocKey, DocKind, DocumentStore};
use serde_json::{Value, json};

use crate::{Gateway, GatewayError};

/// When no `owner_after_seconds` is set.
pub const DEFAULT_OWNER_AFTER_SECONDS: u64 = 1800;

/// The audit entry kind the owner's webhook receives.
pub const HOLD_AGED: &str = "shared_hold_aged";

fn marker(tenant: &str, guarantee_id: &str, reservation_id: &str) -> DocKey {
    DocKey::new(
        tenant,
        DocKind::Escalation,
        format!("hold_aged:{guarantee_id}:{reservation_id}"),
    )
}

impl<S: DocumentStore + 'static, L: AppendLog + 'static> Gateway<S, L> {
    /// The owner route and age threshold of a guarantee, if it names an owner.
    #[must_use]
    pub fn hold_owner(&self, guarantee_id: &str) -> Option<(String, u64)> {
        self.shared_guarantees()
            .iter()
            .find(|g| g.id == guarantee_id)
            .and_then(|g| {
                g.owner_route
                    .clone()
                    .map(|route| (route, g.owner_after_seconds.unwrap_or(DEFAULT_OWNER_AFTER_SECONDS)))
            })
    }

    /// Reports one aged hold to its guarantee's owner. `Ok(true)` when an entry was
    /// appended; `Ok(false)` when the guarantee names no owner, the hold was already
    /// reported, or it is no longer held.
    pub async fn report_aged_hold(
        &self,
        tenant: &str,
        guarantee_id: &str,
        resource_digest: &str,
        reservation_id: &str,
        age_seconds: u64,
    ) -> Result<bool, GatewayError> {
        let Some((route, after)) = self.hold_owner(guarantee_id) else {
            return Ok(false);
        };
        let key = marker(tenant, guarantee_id, reservation_id);
        if self.store.get(&key).await?.is_some() {
            return Ok(false);
        }
        let Some(view) = self.exposure_holds(tenant, guarantee_id, resource_digest).await? else {
            return Ok(false);
        };
        let Some(hold) = view["holds"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|h| h["reservation_id"] == reservation_id)
        else {
            return Ok(false);
        };
        let mut payload = json!({"guarantee_id": guarantee_id, "owner_route": route, "owner_after_seconds": after,
            "resource_digest": resource_digest, "unit": view["unit"], "limit": view["limit"],
            "age_seconds": age_seconds});
        for field in [
            "reservation_id",
            "run_id",
            "operation_id",
            "attempt_id",
            "amount",
            "state",
            "attempt_started_at",
            "last_observation",
            "next_safe_step",
        ] {
            payload[field] = hold[field].clone();
        }
        self.audit.append(tenant, HOLD_AGED, payload, &self.now()).await?;
        match self.store.create(&key, &json!({"reported_at": self.now()})).await {
            Ok(_) => Ok(true),
            Err(e) if e.is_conflict() => Ok(true),
            Err(e) => Err(e.into()),
        }
    }
}

/// Whether an audit entry is an aged-hold report for `route`.
#[must_use]
pub fn routed_to(entry: &Value, route: &str) -> bool {
    entry["kind"] == HOLD_AGED && entry["payload"]["owner_route"] == route
}
