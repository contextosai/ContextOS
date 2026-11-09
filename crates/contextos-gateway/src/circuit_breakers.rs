//! Circuit breakers: automatic, rate-based stops across runs.
//!
//! The loop guard bounds one run. A runaway agent can still open many runs, or make
//! many different calls, faster than anyone watches. A breaker counts events per
//! agent, admitting principal or tenant across every run, over a sliding window
//! (two fixed windows, weighted), and refuses the next matching call while the
//! estimate is at or over its threshold (`circuit_open`):
//!
//! - `effects` counts attempts of effectful capabilities sent to providers;
//! - `refusals` counts calls governance refused (blocked or rejected), other than the
//!   breaker's own refusals, so it reopens once the agent stops being refused.
//!
//! The first refusal in a window trips the breaker. The trip is audited
//! (`circuit_breaker_tripped`). With `trip = "revoke"` it also revokes the scope's
//! target in the kill switch (`agent`, `principal` or `tenant`) as
//! `circuit_breaker:<id>`, so it stays stopped until an operator restores it.
//! Otherwise the breaker closes by itself as the window slides.
//!
//! The estimate is read with the other authorization facts and counted after the call,
//! so calls racing in parallel may overshoot the threshold by their concurrency. A
//! breaker bounds a runaway; it is not an exact quota.

use contextos_contract::types::ActionEffect;
use contextos_contract::validation::elapsed_millis;
use contextos_store::{AppendLog, DocKey, DocKind, DocumentStore, StoreError, Versioned};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::admission::RunAdmission;
use crate::manifest::CapabilityManifest;
use crate::{Gateway, GatewayError};

/// Breakers per deployment at most.
pub const MAX_BREAKERS: usize = 32;

/// Whose events a breaker counts together.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum BreakerScope {
    /// The agent a run declares (bind it to credentials with `agent_binding`).
    Agent,
    /// The authenticated principal that admitted the run.
    Principal,
    Tenant,
}

/// What a breaker counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum BreakerCount {
    /// Attempts of effectful capabilities sent to providers.
    Effects,
    /// Calls governance refused (blocked or rejected).
    Refusals,
}

/// What a trip does besides refusing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum BreakerTrip {
    /// Refuse while the estimate is over the threshold; close by itself.
    #[default]
    Refuse,
    /// Also revoke the scope's target, so it stays stopped until an operator restores it.
    Revoke,
}

fn default_window() -> u64 {
    60
}

/// One `[[guards.circuit_breakers]]` rule.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BreakerRule {
    /// Names the breaker in audit entries, reason details and revocations.
    pub id: String,
    pub scope: BreakerScope,
    pub count: BreakerCount,
    /// Capabilities the breaker counts and refuses; empty is every capability (for
    /// `effects`, every effectful one).
    #[serde(default)]
    pub capabilities: Vec<String>,
    /// Events per window at which the breaker opens.
    pub threshold: u64,
    #[serde(default = "default_window")]
    pub window_seconds: u64,
    #[serde(default)]
    pub trip: BreakerTrip,
}

impl BreakerRule {
    /// Whether the breaker governs calls of `manifest`.
    pub fn applies(&self, manifest: &CapabilityManifest) -> bool {
        if !self.capabilities.is_empty() {
            return self.capabilities.contains(&manifest.capability_id);
        }
        self.count == BreakerCount::Refusals || manifest.action_risk.effect != ActionEffect::None
    }

    fn target<'a>(&self, admission: &'a RunAdmission) -> (&'static str, &'a str) {
        match self.scope {
            BreakerScope::Agent => ("agent", admission.actor["principal_id"].as_str().unwrap_or_default()),
            BreakerScope::Principal => ("principal", admission.admitted_by.as_str()),
            BreakerScope::Tenant => ("tenant", admission.tenant_id.as_str()),
        }
    }

    fn key(&self, admission: &RunAdmission) -> DocKey {
        let (kind, target) = self.target(admission);
        DocKey::new(
            &admission.tenant_id,
            DocKind::CircuitBreaker,
            format!("{}:{kind}:{target}", self.id),
        )
    }
}

/// Checks a deployment's breakers.
pub fn validate(rules: &[BreakerRule]) -> Result<(), String> {
    if rules.len() > MAX_BREAKERS {
        return Err(format!("at most {MAX_BREAKERS} circuit_breakers"));
    }
    let mut ids = std::collections::HashSet::new();
    for rule in rules {
        let id_ok = (1..=64).contains(&rule.id.len())
            && rule
                .id
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-');
        if !id_ok || !ids.insert(&rule.id) {
            return Err(format!(
                "circuit_breakers id {:?} must be a distinct name of a-z, 0-9, _ or -",
                rule.id
            ));
        }
        if rule.threshold == 0 {
            return Err(format!("circuit_breakers {}: threshold must be at least 1", rule.id));
        }
        if !(1..=86_400).contains(&rule.window_seconds) {
            return Err(format!(
                "circuit_breakers {}: window_seconds must be 1..=86400",
                rule.id
            ));
        }
    }
    Ok(())
}

/// Milliseconds since the epoch at `now`.
fn epoch_millis(now: &str) -> u64 {
    elapsed_millis("1970-01-01T00:00:00Z", now).unwrap_or(0)
}

/// The sliding estimate of events in the window ending at `now_ms`, in thousandths
/// of an event (the previous window counts for the part of it still inside).
fn estimate(state: Option<&Value>, window_seconds: u64, now_ms: u64) -> u64 {
    let Some(state) = state else { return 0 };
    let width = window_seconds * 1000;
    let window = now_ms / width;
    let remaining = u128::from(width - now_ms % width);
    let milli = |n: &Value| u128::from(n.as_u64().unwrap_or(0)) * 1000;
    let (current, previous) = (milli(&state["current"]), milli(&state["previous"]));
    let estimate = match state["window"].as_u64() {
        Some(w) if w == window => current + previous * remaining / u128::from(width),
        Some(w) if w + 1 == window => current * remaining / u128::from(width),
        _ => 0,
    };
    u64::try_from(estimate).unwrap_or(u64::MAX)
}

/// `state` with one more event at `now_ms`.
fn counted(state: Option<&Value>, window_seconds: u64, now_ms: u64) -> Value {
    let window = now_ms / (window_seconds * 1000);
    let (mut current, mut previous, mut tripped) = (0, 0, Value::Null);
    if let Some(state) = state {
        match state["window"].as_u64() {
            Some(w) if w == window => {
                current = state["current"].as_u64().unwrap_or(0);
                previous = state["previous"].as_u64().unwrap_or(0);
                tripped = state["tripped"].clone();
            }
            Some(w) if w + 1 == window => previous = state["current"].as_u64().unwrap_or(0),
            _ => {}
        }
    }
    json!({"window": window, "current": current + 1, "previous": previous, "tripped": tripped})
}

/// An open breaker found for a call.
#[derive(Debug, Clone)]
pub(crate) struct OpenBreaker {
    pub rule: BreakerRule,
    /// Thousandths of an event.
    pub estimate: u64,
    state: Option<Versioned>,
}

impl<S: DocumentStore + 'static, L: AppendLog + 'static> Gateway<S, L> {
    /// The first breaker governing this call that is open, read concurrently.
    pub(crate) async fn open_breaker(
        &self,
        admission: &RunAdmission,
        manifest: &CapabilityManifest,
        now: &str,
    ) -> Result<Option<OpenBreaker>, StoreError> {
        let applicable: Vec<&BreakerRule> = self.breakers.iter().filter(|r| r.applies(manifest)).collect();
        if applicable.is_empty() {
            return Ok(None);
        }
        let mut states = Vec::with_capacity(applicable.len());
        for rule in &applicable {
            states.push(self.store.get(&rule.key(admission)).await);
        }
        let now_ms = epoch_millis(now);
        for (rule, state) in applicable.into_iter().zip(states) {
            let state = state?;
            let estimate = estimate(state.as_ref().map(|s| &s.body), rule.window_seconds, now_ms);
            if estimate >= rule.threshold.saturating_mul(1000) {
                return Ok(Some(OpenBreaker {
                    rule: rule.clone(),
                    estimate,
                    state,
                }));
            }
        }
        Ok(None)
    }

    /// Trips `open` once per window: audits it and, for `revoke`, revokes the
    /// scope's target. Returns the audit sequence of a new trip.
    pub(crate) async fn trip_breaker(
        &self,
        admission: &RunAdmission,
        open: &OpenBreaker,
        now: &str,
    ) -> Result<Option<u64>, GatewayError> {
        let rule = &open.rule;
        let now_ms = epoch_millis(now);
        let window = now_ms / (rule.window_seconds * 1000);
        let Some(current) = &open.state else { return Ok(None) };
        if current.body["tripped"].as_u64() == Some(window) {
            return Ok(None);
        }
        let mut marked = current.body.clone();
        marked["tripped"] = json!(window);
        match self
            .store
            .compare_and_swap(&rule.key(admission), current.revision, &marked)
            .await
        {
            Ok(_) => {}
            // Another call recorded or tripped it first; that call reports the trip.
            Err(e) if e.is_conflict() => return Ok(None),
            Err(e) => return Err(e.into()),
        }
        let (kind, target) = rule.target(admission);
        let entry = self
            .audit
            .append(
                &admission.tenant_id,
                "circuit_breaker_tripped",
                json!({"breaker_id": rule.id, "scope": kind, "target": target, "count": rule.count,
                    "estimate": open.estimate / 1000, "threshold": rule.threshold,
                    "window_seconds": rule.window_seconds, "trip": rule.trip, "run_id": admission.run_id}),
                now,
            )
            .await?;
        if rule.trip == BreakerTrip::Revoke {
            let reason = format!(
                "circuit breaker {} opened: {} {} in {}s (threshold {})",
                rule.id,
                open.estimate / 1000,
                match rule.count {
                    BreakerCount::Effects => "effects",
                    BreakerCount::Refusals => "refusals",
                },
                rule.window_seconds,
                rule.threshold
            );
            match self
                .set_revocation(
                    &admission.tenant_id,
                    kind,
                    target,
                    &reason,
                    &format!("circuit_breaker:{}", rule.id),
                    true,
                )
                .await
            {
                Ok(_) => {}
                Err(crate::RevocationError::Gateway(e)) => return Err(e),
                // A full revocation list is audited (`revocation_not_applied`); the
                // breaker still refuses.
                Err(_) => {}
            }
        }
        Ok(Some(entry.sequence))
    }

    /// Counts a finished call against the breakers that govern it.
    pub(crate) async fn count_breakers(
        &self,
        admission: &RunAdmission,
        manifest: &CapabilityManifest,
        report: &crate::DispatchReport,
    ) -> Result<(), GatewayError> {
        if self.breakers.is_empty() {
            return Ok(());
        }
        let effect = report.sent && manifest.action_risk.effect != ActionEffect::None;
        let refusal = matches!(report.status.as_str(), "blocked" | "rejected")
            && !report.reason_codes.iter().any(|c| c == "circuit_open");
        let now_ms = epoch_millis(&self.now());
        for rule in self.breakers.iter().filter(|r| r.applies(manifest)) {
            let event = match rule.count {
                BreakerCount::Effects => effect,
                BreakerCount::Refusals => refusal,
            };
            if event {
                self.count_one(rule, admission, now_ms).await?;
            }
        }
        Ok(())
    }

    async fn count_one(&self, rule: &BreakerRule, admission: &RunAdmission, now_ms: u64) -> Result<(), StoreError> {
        let key = rule.key(admission);
        for attempt in 0..32_u32 {
            if attempt > 0 {
                tokio::time::sleep(std::time::Duration::from_micros(50 << attempt.min(8))).await;
            }
            let current = self.store.get(&key).await?;
            let next = counted(current.as_ref().map(|c| &c.body), rule.window_seconds, now_ms);
            let written = match &current {
                None => self.store.create(&key, &next).await.map(|_| ()),
                Some(c) => self.store.compare_and_swap(&key, c.revision, &next).await.map(|_| ()),
            };
            match written {
                Ok(()) => return Ok(()),
                Err(e) if e.is_conflict() => {}
                Err(e) => return Err(e),
            }
        }
        Err(StoreError::Conflict {
            expected: None,
            actual: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(threshold: u64) -> BreakerRule {
        BreakerRule {
            id: "refunds".into(),
            scope: BreakerScope::Agent,
            count: BreakerCount::Effects,
            capabilities: vec![],
            threshold,
            window_seconds: 60,
            trip: BreakerTrip::Refuse,
        }
    }

    #[test]
    fn the_estimate_slides_across_two_windows() {
        let mut state = None;
        for _ in 0..10 {
            state = Some(counted(state.as_ref(), 60, 60_000));
        }
        assert_eq!(estimate(state.as_ref(), 60, 60_000), 10_000);
        // Halfway into the next window, half the previous one still counts.
        assert_eq!(estimate(state.as_ref(), 60, 150_000), 5_000);
        let next = counted(state.as_ref(), 60, 150_000);
        assert_eq!(next["previous"], 10);
        assert_eq!(next["current"], 1);
        assert_eq!(estimate(Some(&next), 60, 150_000), 6_000);
        // Two windows later nothing counts.
        assert_eq!(estimate(state.as_ref(), 60, 240_000), 0);
        assert_eq!(counted(state.as_ref(), 60, 240_000)["previous"], 0);
    }

    #[test]
    fn rules_are_validated() {
        assert!(validate(&[rule(5)]).is_ok());
        assert!(validate(&[rule(0)]).is_err());
        assert!(validate(&[rule(5), rule(6)]).is_err(), "duplicate ids");
        let mut bad = rule(5);
        bad.id = "Bad Id".into();
        assert!(validate(&[bad]).is_err());
        let mut wide = rule(5);
        wide.window_seconds = 0;
        assert!(validate(&[wide]).is_err());
    }
}
