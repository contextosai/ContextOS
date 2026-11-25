//! Risk tiers: each capability is classified `low`, `limited`, `high` or `prohibited`,
//! and `[guards.risk_tiers]` says what each tier needs at the tool boundary.
//!
//! A capability's tier is the riskier of its reviewed manifest's `risk_tier` and the
//! deployment's `capabilities` map; a capability with neither is `unclassified` and
//! treated as the configured `unclassified` tier (`high` unless set), so a new tool
//! never slips through unclassified. Per tier the guard allows the call, composes an
//! approval of the exact action (`approval`, obligation `approve_high_risk_action`), or
//! refuses it (`refuse`). `prohibited` is always refused, whatever the configuration
//! says. In `observe` mode the guard audits what it would do and lets every call
//! through, so a deployment can measure before enforcing.
//!
//! ```toml
//! [guards.risk_tiers]
//! high = "approval"
//! [guards.risk_tiers.capabilities]
//! "adp_payments.issue_refund" = "high"
//! "adp_orders.lookup" = "low"
//! ```

use std::collections::BTreeMap;

use contextos_store::{AppendLog, DocumentStore};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::admission::RunAdmission;
use crate::guard_policy::FlowGate;
use crate::manifest::CapabilityManifest;
use crate::{Gateway, GatewayError, Pipeline};

use crate::information_flow::FlowVerdict;

/// Tiers from least to most consequential.
pub const TIERS: [&str; 4] = ["low", "limited", "high", "prohibited"];
/// At most this many classified capabilities in configuration.
pub const MAX_CLASSIFIED: usize = 4_096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RiskTier {
    Low,
    Limited,
    High,
    Prohibited,
}

impl RiskTier {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        TIERS[self as usize]
    }
}

/// What a tier needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TierAction {
    Allow,
    /// An approval of the exact action, composed with the run's other policy.
    Approval,
    Refuse,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TierMode {
    #[default]
    Enforce,
    Observe,
}

fn allow() -> TierAction {
    TierAction::Allow
}
fn approval() -> TierAction {
    TierAction::Approval
}
fn high() -> RiskTier {
    RiskTier::High
}

/// `[guards.risk_tiers]`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TierPolicy {
    #[serde(default)]
    pub mode: TierMode,
    #[serde(default = "allow")]
    pub low: TierAction,
    #[serde(default = "allow")]
    pub limited: TierAction,
    #[serde(default = "approval")]
    pub high: TierAction,
    /// The tier of a capability neither its manifest nor `capabilities` classifies.
    #[serde(default = "high")]
    pub unclassified: RiskTier,
    /// Capability id to tier, beside (and never below) the manifests' own tiers.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub capabilities: BTreeMap<String, RiskTier>,
}

/// The guard's view of one call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TierCheck {
    pub tier: RiskTier,
    /// Where the tier came from: `manifest`, `configuration` or `unclassified`.
    pub source: &'static str,
    pub action: TierAction,
}

impl TierPolicy {
    /// Refuses a configuration with too many entries.
    pub fn validate(&self) -> Result<(), String> {
        if self.capabilities.len() > MAX_CLASSIFIED {
            return Err(format!(
                "[guards.risk_tiers] classifies at most {MAX_CLASSIFIED} capabilities"
            ));
        }
        Ok(())
    }

    #[must_use]
    pub fn enforced(&self) -> bool {
        self.mode == TierMode::Enforce
    }

    /// The tier and action for a call of `capability` whose manifest says `manifest`.
    #[must_use]
    pub fn check(&self, capability: &str, manifest: Option<RiskTier>) -> TierCheck {
        let configured = self.capabilities.get(capability).copied();
        let (tier, source) = match (manifest, configured) {
            (Some(m), Some(c)) if c > m => (c, "configuration"),
            (Some(m), _) => (m, "manifest"),
            (None, Some(c)) => (c, "configuration"),
            (None, None) => (self.unclassified, "unclassified"),
        };
        let action = match tier {
            RiskTier::Low => self.low,
            RiskTier::Limited => self.limited,
            RiskTier::High => self.high,
            RiskTier::Prohibited => TierAction::Refuse,
        };
        TierCheck { tier, source, action }
    }
}

impl TierCheck {
    /// The verdict the gate composes.
    #[must_use]
    pub fn verdict(&self) -> FlowVerdict {
        match self.action {
            TierAction::Allow => FlowVerdict::Allow,
            TierAction::Approval => FlowVerdict::Ask,
            TierAction::Refuse => FlowVerdict::Deny,
        }
    }

    /// The reason code for a call the tier does not simply allow.
    #[must_use]
    pub fn reason(&self) -> &'static str {
        match (self.tier, self.action) {
            (RiskTier::Prohibited, _) => "risk_tier_prohibited",
            (_, TierAction::Refuse) => "risk_tier_refused",
            _ => "risk_tier_approval_required",
        }
    }
}

impl<S: DocumentStore + 'static, L: AppendLog + 'static> Gateway<S, L> {
    /// The tier guard's part in this call's decision. A call its tier does not simply
    /// allow is audited (`risk_tier_decision`); a refused tier stops the call outright,
    /// an approval tier composes an approval of the exact action.
    pub(crate) async fn tier_guard(
        &self,
        p: &mut Pipeline<'_>,
        admission: &RunAdmission,
        manifest: &CapabilityManifest,
        operation_id: &str,
        now: &str,
    ) -> Result<FlowGate, GatewayError> {
        let Some(policy) = &self.risk_tiers else {
            return Ok(FlowGate::Pass);
        };
        let check = policy.check(&manifest.capability_id, manifest.risk_tier);
        if check.action == TierAction::Allow {
            return Ok(FlowGate::Pass);
        }
        let enforced = policy.enforced();
        let body = json!({"run_id": admission.run_id, "operation_id": operation_id,
            "capability_id": manifest.capability_id, "tier": check.tier.as_str(), "tier_source": check.source,
            "action": check.action, "enforced": enforced, "reason_codes": [check.reason()]});
        self.record(p, "risk_tier_decision", body, now).await?;
        if !enforced {
            return Ok(FlowGate::Pass);
        }
        if check.action == TierAction::Refuse {
            return Ok(FlowGate::Refuse(vec![check.reason().to_owned()]));
        }
        Ok(crate::guard_policy::gate(
            admission,
            check.verdict(),
            "risk_tiers",
            "approve_high_risk_action",
            vec![check.reason().to_owned()],
            "risk_tier_policy_unpinned",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> TierPolicy {
        serde_json::from_value(serde_json::json!({"capabilities": {
            "pay.refund": "high", "orders.lookup": "low", "crm.export": "prohibited"}}))
        .unwrap()
    }

    #[test]
    fn defaults_allow_low_ask_for_high_and_refuse_prohibited() {
        let p = policy();
        assert_eq!(p.check("orders.lookup", None).action, TierAction::Allow);
        assert_eq!(p.check("pay.refund", None).action, TierAction::Approval);
        let c = p.check("crm.export", None);
        assert_eq!((c.action, c.reason()), (TierAction::Refuse, "risk_tier_prohibited"));
    }

    #[test]
    fn an_unclassified_capability_is_high_unless_configured() {
        let c = policy().check("infra.delete_volume", None);
        assert_eq!(
            (c.tier, c.source, c.action),
            (RiskTier::High, "unclassified", TierAction::Approval)
        );
        let mut p = policy();
        p.unclassified = RiskTier::Prohibited;
        assert_eq!(p.check("infra.delete_volume", None).action, TierAction::Refuse);
    }

    #[test]
    fn the_riskier_classification_wins() {
        let p = policy();
        // The configuration cannot lower a manifest's tier ...
        let c = p.check("orders.lookup", Some(RiskTier::High));
        assert_eq!((c.tier, c.source), (RiskTier::High, "manifest"));
        // ... but can raise it.
        let c = p.check("pay.refund", Some(RiskTier::Low));
        assert_eq!((c.tier, c.source), (RiskTier::High, "configuration"));
    }

    #[test]
    fn prohibited_cannot_be_allowed_by_configuration() {
        let p: TierPolicy = serde_json::from_value(serde_json::json!({"high": "allow", "low": "refuse"})).unwrap();
        assert_eq!(p.check("x", Some(RiskTier::Prohibited)).action, TierAction::Refuse);
        assert_eq!(p.check("x", Some(RiskTier::High)).action, TierAction::Allow);
        assert_eq!(p.check("x", Some(RiskTier::Low)).reason(), "risk_tier_refused");
        assert!(serde_json::from_value::<TierPolicy>(serde_json::json!({"prohibited": "allow"})).is_err());
    }
}
