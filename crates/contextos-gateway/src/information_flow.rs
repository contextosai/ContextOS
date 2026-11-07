//! Information-flow labels: what a run has read decides what it may do next.
//!
//! Prompt injection cannot be screened away reliably, so this guard does not try to
//! judge content. It tracks, per run, two labels that only ever rise:
//!
//! - **integrity**: `trusted` until the agent receives output from a capability whose
//!   manifest does not declare it `trusted` (by default every tool output is
//!   untrusted: a web page, an email, a ticket, a document);
//! - **classification**: the most sensitive `output_classification` the agent has
//!   received (`PUBLIC` < `INTERNAL` < `CONFIDENTIAL` < `RESTRICTED`).
//!
//! Before each call the guard composes a guardrail outcome with the run's others, so
//! the kernel decides it like any policy rule and an approval binds the exact action:
//!
//! - an **effectful** call in an untrusted run gets `untrusted_effects` (`ask` by
//!   default): text the agent read may be steering it;
//! - an **egress** call (the capability `sends_data` or names recipients) in a run
//!   whose classification is above the capability's `egress_ceiling` gets
//!   `classified_egress` (`deny` by default): data cannot leave through a sink not
//!   cleared for it, whatever the arguments look like;
//! - with `rule_of_two` (on by default), a call that would combine all three of
//!   untrusted input, `CONFIDENTIAL` or higher data, and egress or an external effect
//!   needs at least an approval, even where the other two rules allow it.
//!
//! Each run pins the guard policy it was admitted under (see [`crate::guard_policy`]).
//! Labels are per run, not per value: the guard cannot tell which argument came from
//! which output, so it is coarse and errs towards asking. A delegated child starts
//! with its parent's labels; its labels flow back into the parent when it closes,
//! unless the parent rejected an isolated child's output. Labels never fall within a
//! run; start a new run for work that must not inherit what an earlier step read.

use contextos_contract::canonical::sha256_canonical;
use contextos_contract::types::ActionEffect;
use contextos_store::{AppendLog, DocKey, DocKind, DocumentStore, StoreError};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::admission::RunAdmission;
use crate::guard_policy::FlowGate;
use crate::manifest::CapabilityManifest;
use crate::{Gateway, GatewayError, Pipeline};

/// Raises recorded per run at most (labels have five levels, so real runs need few).
const MAX_SOURCES: usize = 16;

/// Whether content can be relied on not to carry instructions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Integrity {
    Trusted,
    /// The default: content an outsider could have written.
    #[default]
    Untrusted,
}

/// Data sensitivity; `Ord` is the rank.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "UPPERCASE")]
pub enum Classification {
    Public,
    Internal,
    Confidential,
    Restricted,
}

fn internal() -> Classification {
    Classification::Internal
}

/// A capability's `flow` labels. Absent, its output is untrusted `INTERNAL` and it
/// may send out at most `INTERNAL` data.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FlowLabels {
    /// Whether the tool's output can carry text an outsider wrote. Declare `trusted`
    /// only for output the deployment itself produces (an internal ledger's numbers),
    /// never for free text that came from customers, the web or email.
    #[serde(default)]
    pub output_integrity: Integrity,
    /// How sensitive the tool's output is.
    #[serde(default = "internal")]
    pub output_classification: Classification,
    /// The most sensitive data this capability may carry out of the deployment when
    /// it sends data or names recipients.
    #[serde(default = "internal")]
    pub egress_ceiling: Classification,
}

impl Default for FlowLabels {
    fn default() -> Self {
        Self {
            output_integrity: Integrity::Untrusted,
            output_classification: Classification::Internal,
            egress_ceiling: Classification::Internal,
        }
    }
}

/// `enforce` composes the guard's outcome; `observe` only audits what it would do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FlowMode {
    #[default]
    Enforce,
    Observe,
}

/// What a rule does to a call it matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FlowVerdict {
    Allow,
    /// Needs an approval of this exact action.
    Ask,
    Deny,
}

fn ask() -> FlowVerdict {
    FlowVerdict::Ask
}

fn deny() -> FlowVerdict {
    FlowVerdict::Deny
}

fn yes() -> bool {
    true
}

fn trusted() -> Integrity {
    Integrity::Trusted
}

fn public() -> Classification {
    Classification::Public
}

/// `[guards.information_flow]`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FlowPolicy {
    #[serde(default)]
    pub mode: FlowMode,
    /// An effectful call in a run that has read untrusted output.
    #[serde(default = "ask")]
    pub untrusted_effects: FlowVerdict,
    /// An egress call carrying data above its capability's `egress_ceiling`.
    #[serde(default = "deny")]
    pub classified_egress: FlowVerdict,
    /// Untrusted input, `CONFIDENTIAL`+ data and egress or an external effect
    /// together need at least an approval.
    #[serde(default = "yes")]
    pub rule_of_two: bool,
    /// Labels every run starts with; raise them for runs whose request itself carries
    /// untrusted text or sensitive data.
    #[serde(default = "trusted")]
    pub initial_integrity: Integrity,
    #[serde(default = "public")]
    pub initial_classification: Classification,
}

impl Default for FlowPolicy {
    fn default() -> Self {
        Self {
            mode: FlowMode::Enforce,
            untrusted_effects: FlowVerdict::Ask,
            classified_egress: FlowVerdict::Deny,
            rule_of_two: true,
            initial_integrity: Integrity::Trusted,
            initial_classification: Classification::Public,
        }
    }
}

/// A run's current labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunLabels {
    pub integrity: Integrity,
    pub classification: Classification,
}

impl RunLabels {
    fn join(self, integrity: Integrity, classification: Classification) -> Self {
        Self {
            integrity: self.integrity.max(integrity),
            classification: self.classification.max(classification),
        }
    }
}

/// What the guard decided for one call.
#[derive(Debug, Clone, PartialEq)]
pub struct FlowCheck {
    pub verdict: FlowVerdict,
    pub reason_codes: Vec<String>,
}

pub(crate) fn key(tenant_id: &str, run_id: &str) -> DocKey {
    DocKey::new(tenant_id, DocKind::FlowLabels, run_id)
}

fn parse<T: for<'de> Deserialize<'de>>(value: &Value) -> Option<T> {
    serde_json::from_value(value.clone()).ok()
}

impl FlowPolicy {
    /// The labels in `state` (the run's document), or the policy's initial ones.
    pub fn labels(&self, state: Option<&Value>) -> RunLabels {
        let initial = RunLabels {
            integrity: self.initial_integrity,
            classification: self.initial_classification,
        };
        state.map_or(initial, |s| {
            // A document the guard cannot read is treated as the worst case.
            initial.join(
                parse(&s["integrity"]).unwrap_or(Integrity::Untrusted),
                parse(&s["classification"]).unwrap_or(Classification::Restricted),
            )
        })
    }

    /// The guard's verdict on calling `manifest` in a run with `labels`.
    pub fn check(&self, labels: RunLabels, manifest: &CapabilityManifest) -> FlowCheck {
        let flow = manifest.flow.clone().unwrap_or_default();
        let effectful = manifest.action_risk.effect != ActionEffect::None;
        let external = matches!(
            manifest.action_risk.effect,
            ActionEffect::ExternalState | ActionEffect::PhysicalWorld
        );
        let egress = manifest.sends_data || !manifest.destination_pointers.is_empty();
        let untrusted = labels.integrity == Integrity::Untrusted;
        let mut verdict = FlowVerdict::Allow;
        let mut reason_codes = Vec::new();
        let mut apply = |rule: FlowVerdict, code: &str| {
            if rule > FlowVerdict::Allow {
                verdict = verdict.max(rule);
                reason_codes.push(code.to_owned());
            }
        };
        if untrusted && effectful {
            apply(self.untrusted_effects, "flow_untrusted_effect");
        }
        if egress && labels.classification > flow.egress_ceiling {
            apply(self.classified_egress, "flow_classified_egress");
        }
        if self.rule_of_two
            && untrusted
            && labels.classification >= Classification::Confidential
            && (egress || external)
        {
            apply(FlowVerdict::Ask, "flow_rule_of_two");
        }
        FlowCheck { verdict, reason_codes }
    }

    /// The pinned reference the guard's outcomes cite.
    pub fn bundle_ref(&self) -> Value {
        let digest = serde_json::to_value(self)
            .ok()
            .and_then(|v| sha256_canonical(&v).ok())
            .unwrap_or_default();
        json!({"artifact_type": "information_flow_policy", "artifact_id": "guards", "version": "1", "sha256": digest})
    }
}

/// Raises the run's labels by what it just received; returns whether they rose.
pub(crate) async fn raise<S: DocumentStore>(
    store: &S,
    policy: &FlowPolicy,
    admission: &RunAdmission,
    source: Value,
    integrity: Integrity,
    classification: Classification,
) -> Result<bool, StoreError> {
    raise_key(
        store,
        policy,
        &key(&admission.tenant_id, &admission.run_id),
        source,
        integrity,
        classification,
    )
    .await
}

/// As [`raise`], for the run whose labels document is `key`.
pub(crate) async fn raise_key<S: DocumentStore>(
    store: &S,
    policy: &FlowPolicy,
    key: &DocKey,
    source: Value,
    integrity: Integrity,
    classification: Classification,
) -> Result<bool, StoreError> {
    for attempt in 0..32_u32 {
        if attempt > 0 {
            tokio::time::sleep(std::time::Duration::from_micros(50 << attempt.min(8))).await;
        }
        let current = store.get(key).await?;
        let before = policy.labels(current.as_ref().map(|c| &c.body));
        let after = before.join(integrity, classification);
        if after == before && current.is_some() {
            return Ok(false);
        }
        let mut sources = current
            .as_ref()
            .and_then(|c| c.body["sources"].as_array().cloned())
            .unwrap_or_default();
        if after != before && sources.len() < MAX_SOURCES {
            sources.push(source.clone());
        }
        let body = json!({"integrity": after.integrity, "classification": after.classification, "sources": sources});
        let written = match &current {
            None => store.create(key, &body).await.map(|_| ()),
            Some(c) => store.compare_and_swap(key, c.revision, &body).await.map(|_| ()),
        };
        match written {
            Ok(()) => return Ok(after != before),
            Err(e) if e.is_conflict() => {}
            Err(e) => return Err(e),
        }
    }
    Err(StoreError::Conflict {
        expected: None,
        actual: None,
    })
}

/// The run's labels as audit facts.
pub(crate) fn facts(labels: RunLabels) -> Value {
    json!({"integrity": labels.integrity, "classification": labels.classification})
}

impl<S: DocumentStore + 'static, L: AppendLog + 'static> Gateway<S, L> {
    /// The guard's part in this call's decision. Every match is audited
    /// (`information_flow_decision`). `state` is the run's labels document as read
    /// with the other facts.
    pub(crate) async fn flow_guard(
        &self,
        p: &mut Pipeline<'_>,
        admission: &RunAdmission,
        manifest: &CapabilityManifest,
        operation_id: &str,
        state: Option<&Value>,
        now: &str,
    ) -> Result<FlowGate, GatewayError> {
        let Some(policy) = &self.information_flow else {
            return Ok(FlowGate::Pass);
        };
        let labels = policy.labels(state);
        let check = policy.check(labels, manifest);
        let enforced = policy.mode == FlowMode::Enforce;
        if check.verdict != FlowVerdict::Allow {
            let body = json!({"run_id": admission.run_id, "operation_id": operation_id,
                "capability_id": manifest.capability_id, "labels": facts(labels),
                "verdict": check.verdict, "enforced": enforced, "reason_codes": check.reason_codes,
                "policy_ref": policy.bundle_ref()});
            self.record(p, "information_flow_decision", body, now).await?;
        }
        let verdict = if enforced { check.verdict } else { FlowVerdict::Allow };
        Ok(crate::guard_policy::gate(
            admission,
            verdict,
            "information_flow",
            "review_information_flow",
            check.reason_codes,
            "flow_policy_unpinned",
        ))
    }

    /// Raises the run's labels by `manifest`'s output, which the agent is about to
    /// receive.
    pub(crate) async fn flow_received(
        &self,
        admission: &RunAdmission,
        manifest: &CapabilityManifest,
        operation_id: &str,
    ) -> Result<(), GatewayError> {
        let Some(policy) = &self.information_flow else {
            return Ok(());
        };
        let flow = manifest.flow.clone().unwrap_or_default();
        let source = json!({"capability_id": manifest.capability_id, "operation_id": operation_id,
            "integrity": flow.output_integrity, "classification": flow.output_classification});
        raise(
            self.store.as_ref(),
            policy,
            admission,
            source,
            flow.output_integrity,
            flow.output_classification,
        )
        .await?;
        Ok(())
    }

    /// Starts a delegated child with its parent's labels.
    pub(crate) async fn flow_inherit(&self, parent: &RunAdmission, child: &RunAdmission) -> Result<(), GatewayError> {
        let Some(policy) = &self.information_flow else {
            return Ok(());
        };
        let state = self.store.get(&key(&parent.tenant_id, &parent.run_id)).await?;
        let labels = policy.labels(state.as_ref().map(|s| &s.body));
        let source = json!({"parent_run_id": parent.run_id});
        raise(
            self.store.as_ref(),
            policy,
            child,
            source,
            labels.integrity,
            labels.classification,
        )
        .await?;
        Ok(())
    }

    /// Raises the parent's labels by a closing child's: what the child read reaches
    /// the parent through its output.
    pub(crate) async fn flow_return(&self, parent: &RunAdmission, child: &RunAdmission) -> Result<(), GatewayError> {
        let Some(policy) = &self.information_flow else {
            return Ok(());
        };
        let state = self.store.get(&key(&child.tenant_id, &child.run_id)).await?;
        let labels = policy.labels(state.as_ref().map(|s| &s.body));
        let source = json!({"child_run_id": child.run_id});
        raise(
            self.store.as_ref(),
            policy,
            parent,
            source,
            labels.integrity,
            labels.classification,
        )
        .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
