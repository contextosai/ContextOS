//! `[readiness]`: an opt-in, fail-closed profile for consequential workflows.
//!
//! Each mechanism a consequential workflow relies on is configured separately. A
//! refund is safe to run unattended only when all of them are present: the provider's
//! reported state settles the call, an independent witness confirms the effect, a
//! business owner hears about stuck holds, the effect is tied to a business resource,
//! evidence is about the subject it vouches for, and the agent is the one its
//! credential was issued for. Missing any one of them, the runtime still works, so
//! nothing reports it. This profile does:
//!
//! ```toml
//! [readiness]
//! mode = "required"                        # or "report": warn, do not refuse
//! capabilities = ["adp_payments.issue_refund"]   # unset: every consequential capability
//! global_evidence = ["fraud_program_active"]     # requirements not about one subject
//! ```
//!
//! With `required`, `contextosd --check-config` and startup refuse the configuration
//! and list every gap; with `report`, each gap is a warning. A capability is
//! consequential when its `action_risk.effect` is `external_state` or `physical_world`.
//! The checks read only the configuration, the packs and the pinned manifests, so a
//! ready configuration still depends on the witness and owner actually answering.
//! Packs reloaded later are not re-checked; run `--check-config` before shipping one.

use std::collections::{BTreeSet, HashMap};

use contextos_contract::types::ActionEffect;
use contextos_gateway::manifest::CapabilityManifest;
use serde::{Deserialize, Serialize};

use crate::agent_binding::AgentBinding;
use crate::evidence_admission::EvidenceMode;
use crate::{Config, LoadedPack};

/// What a gap does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ReadinessMode {
    /// Gaps refuse `--check-config` and startup.
    #[default]
    Required,
    /// Gaps are warnings.
    Report,
}

impl ReadinessMode {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Required => "required",
            Self::Report => "report",
        }
    }
}

/// `[readiness]`.
#[derive(Debug, Clone, Default, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReadinessConfig {
    /// `required` (default) refuses a configuration with gaps; `report` warns.
    #[serde(default)]
    pub mode: ReadinessMode,
    /// The capabilities held to the profile. Unset: every capability whose
    /// `action_risk.effect` is `external_state` or `physical_world`.
    #[serde(default)]
    pub capabilities: Vec<String>,
    /// Evidence requirements that are deliberately not about one subject (a program
    /// or a deployment state), so they need no `[[evidence_subjects]]` binding.
    #[serde(default)]
    pub global_evidence: Vec<String>,
}

/// The mechanism a gap is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Area {
    Finality,
    Witness,
    Owner,
    Resource,
    Evidence,
    Actor,
}

impl Area {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Finality => "finality",
            Self::Witness => "witness",
            Self::Owner => "owner",
            Self::Resource => "resource",
            Self::Evidence => "evidence",
            Self::Actor => "actor",
        }
    }
}

/// One missing mechanism: `subject` is a capability id, a pack requirement, or
/// `deployment`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Gap {
    pub subject: String,
    pub area: Area,
    pub detail: String,
}

impl std::fmt::Display for Gap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} [{}]: {}", self.subject, self.area.as_str(), self.detail)
    }
}

/// What the profile found.
#[derive(Debug, Default)]
pub struct Readiness {
    /// The capabilities checked, sorted.
    pub capabilities: Vec<String>,
    pub gaps: Vec<Gap>,
    /// Caveats that do not fail the profile.
    pub notes: Vec<String>,
}

/// Configuration check (no packs or manifests): names are well-formed and a global
/// requirement is not also bound to a subject.
pub fn check(config: &Config) -> Result<(), String> {
    let Some(readiness) = &config.readiness else {
        return Ok(());
    };
    let mut seen = BTreeSet::new();
    for id in &readiness.capabilities {
        if id.is_empty() || !seen.insert(id) {
            return Err(format!("[readiness] capabilities: {id:?} must be named once"));
        }
    }
    let mut seen = BTreeSet::new();
    for name in &readiness.global_evidence {
        if name.is_empty() || !seen.insert(name) {
            return Err(format!("[readiness] global_evidence: {name:?} must be named once"));
        }
        if config.evidence_subjects.iter().any(|s| &s.requirement == name) {
            return Err(format!(
                "[readiness] global_evidence: {name} also has an [[evidence_subjects]] binding; it is either about a subject or not"
            ));
        }
    }
    Ok(())
}

fn consequential(manifest: &CapabilityManifest) -> bool {
    matches!(
        manifest.action_risk.effect,
        ActionEffect::ExternalState | ActionEffect::PhysicalWorld
    )
}

/// Evaluates the profile; `None` when `[readiness]` is absent. An unknown or
/// non-consequential capability named in `capabilities` is an error, not a gap.
#[allow(clippy::implicit_hasher)]
pub fn evaluate(
    config: &Config,
    packs: &HashMap<String, LoadedPack>,
    manifests: &[CapabilityManifest],
) -> Option<Result<Readiness, String>> {
    let readiness = config.readiness.as_ref()?;
    Some(evaluate_with(config, readiness, packs, manifests))
}

fn evaluate_with(
    config: &Config,
    readiness: &ReadinessConfig,
    packs: &HashMap<String, LoadedPack>,
    manifests: &[CapabilityManifest],
) -> Result<Readiness, String> {
    let mut selected: Vec<&CapabilityManifest> = if readiness.capabilities.is_empty() {
        manifests.iter().filter(|m| consequential(m)).collect()
    } else {
        let mut picked = Vec::new();
        for id in &readiness.capabilities {
            let manifest = manifests
                .iter()
                .find(|m| &m.capability_id == id)
                .ok_or_else(|| format!("[readiness] capability {id} is not a configured capability"))?;
            if !consequential(manifest) {
                return Err(format!(
                    "[readiness] capability {id} changes no external state; the profile is for consequential workflows"
                ));
            }
            picked.push(manifest);
        }
        picked
    };
    selected.sort_by(|a, b| a.capability_id.cmp(&b.capability_id));
    let mut found = Readiness {
        capabilities: selected.iter().map(|m| m.capability_id.clone()).collect(),
        ..Readiness::default()
    };
    for manifest in &selected {
        capability_gaps(config, manifest, &mut found.gaps);
    }
    if !selected.is_empty() {
        deployment_gaps(config, readiness, packs, &mut found);
    }
    found.gaps.sort();
    Ok(found)
}

fn capability_gaps(config: &Config, manifest: &CapabilityManifest, gaps: &mut Vec<Gap>) {
    let id = &manifest.capability_id;
    let mut gap = |area, detail: &str| {
        gaps.push(Gap {
            subject: id.clone(),
            area,
            detail: detail.to_owned(),
        });
    };
    if manifest.recovery.completion.is_none() {
        gap(
            Area::Finality,
            "no recovery.completion: a finished call is not settled by the state the provider reports",
        );
    }
    if manifest.recovery.reference_pointer.is_none() {
        gap(
            Area::Finality,
            "no recovery.reference_pointer: the effect's provider reference is not declared, so it cannot be reconciled or witnessed by id",
        );
    }
    if manifest.outcome.is_none() {
        gap(
            Area::Witness,
            "no outcome contract: the run can complete without an independent witness confirming the effect",
        );
    }
    let covering: Vec<_> = config
        .guarantees
        .iter()
        .filter(|g| g.capability_ids.iter().any(|c| c == id))
        .collect();
    if covering.is_empty() {
        gap(
            Area::Owner,
            "no [[guarantees]] entry covers it: concurrent runs can together exceed what the business allows",
        );
    } else if covering.iter().all(|g| g.owner_route.is_none()) {
        gap(
            Area::Owner,
            "no covering guarantee names an owner_route: an aged hold reaches no business owner",
        );
    }
    if manifest.resource_pointers.is_empty() {
        gap(
            Area::Resource,
            "no resource_pointers: its effects are not tied to the business resource they change",
        );
    }
}

fn deployment_gaps(
    config: &Config,
    readiness: &ReadinessConfig,
    packs: &HashMap<String, LoadedPack>,
    found: &mut Readiness,
) {
    let deployment = |area, detail: String| Gap {
        subject: "deployment".into(),
        area,
        detail,
    };
    let evidence = crate::evidence_admission::mode(config);
    if evidence != EvidenceMode::Strict {
        found.gaps.push(deployment(
            Area::Evidence,
            format!(
                "evidence = \"{}\": callers may assert evidence themselves; set [guards] evidence = \"strict\"",
                evidence.as_str()
            ),
        ));
    }
    let agent = crate::agent_binding::mode(config);
    if agent != AgentBinding::Required {
        found.gaps.push(deployment(
            Area::Actor,
            format!(
                "agent_binding = \"{}\": a run may declare an agent its credential was not issued for",
                agent.as_str()
            ),
        ));
    }
    let mut gated: BTreeSet<&str> = BTreeSet::new();
    let mut refs: Vec<_> = packs.keys().collect();
    refs.sort();
    for pack_ref in refs {
        for name in crate::evidence_admission::gated(packs[pack_ref].compiler.pack()) {
            gated.insert(name);
            let bound = config.evidence_subjects.iter().any(|s| s.requirement == name);
            if !bound && !readiness.global_evidence.iter().any(|g| g == name) {
                found.gaps.push(Gap {
                    subject: format!("{pack_ref} requirement {name}"),
                    area: Area::Evidence,
                    detail: "no [[evidence_subjects]] binding and not listed in [readiness] global_evidence: \
                             an attestation about any subject satisfies it"
                        .into(),
                });
            }
        }
    }
    for name in &readiness.global_evidence {
        if !gated.contains(name.as_str()) {
            found.notes.push(format!(
                "[readiness] global_evidence {name} is required by no loaded pack"
            ));
        }
    }
}

/// The `--check-config` lines for the profile, or the refusal listing every gap.
#[allow(clippy::implicit_hasher)]
pub fn report(
    config: &Config,
    packs: &HashMap<String, LoadedPack>,
    manifests: &[CapabilityManifest],
) -> Result<Vec<String>, String> {
    let Some(result) = evaluate(config, packs, manifests) else {
        return Ok(Vec::new());
    };
    let found = result?;
    let mode = config.readiness.as_ref().map(|r| r.mode).unwrap_or_default();
    if mode == ReadinessMode::Required && !found.gaps.is_empty() {
        return Err(refusal(&found));
    }
    let mut lines = vec![summary(mode, &found)];
    lines.extend(found.gaps.iter().map(|g| format!("warning: readiness: {g}")));
    lines.extend(found.notes.iter().map(|n| format!("warning: {n}")));
    Ok(lines)
}

fn summary(mode: ReadinessMode, found: &Readiness) -> String {
    match (found.capabilities.len(), found.gaps.len()) {
        (0, _) => format!(
            "warning: workflow readiness ({}): no consequential capability to check",
            mode.as_str()
        ),
        (n, 0) => format!(
            "workflow readiness ({}): {n} capability(ies) ready: {}",
            mode.as_str(),
            found.capabilities.join(", ")
        ),
        (n, gaps) => format!(
            "warning: workflow readiness ({}): {gaps} gap(s) across {n} capability(ies)",
            mode.as_str()
        ),
    }
}

fn refusal(found: &Readiness) -> String {
    let lines: Vec<String> = found.gaps.iter().map(|g| format!("  {g}")).collect();
    format!(
        "workflow readiness (required): {} gap(s) across {}:\n{}",
        found.gaps.len(),
        found.capabilities.join(", "),
        lines.join("\n")
    )
}

/// Startup: refuses under `required`, returns the warnings to log under `report`.
#[allow(clippy::implicit_hasher)]
pub fn enforce(
    config: &Config,
    packs: &HashMap<String, LoadedPack>,
    manifests: &[CapabilityManifest],
) -> Result<Vec<String>, String> {
    report(config, packs, manifests).map(|lines| {
        lines
            .into_iter()
            .filter_map(|l| l.strip_prefix("warning: ").map(str::to_owned))
            .collect()
    })
}
