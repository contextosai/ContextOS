//! What an agent can do, and what that requires.
//!
//! The **authority graph** of an agent is every capability pinned in the packs it runs
//! under, with the capability's native ActionRisk (effect, authority, reversibility,
//! interaction, data scope), marked by whether runs had it surfaced and whether it was
//! used. The **required control profile** follows from that graph (what the agent *can*
//! do, not what its owner declares), using the standard profile registry the runtime
//! negotiates with: the spec's workflow applicability (external effects need the
//! enterprise profile; physical effects, irreversible external effects and restricted
//! data need high-assurance; delegation and checkpointed resume need durable-delegated)
//! and its feature-conditional controls. Risk is never collapsed into a score.

use std::collections::{BTreeMap, BTreeSet};

use contextos_kernel::STANDARD_PROFILE_REGISTRY;
use serde::Serialize;
use serde_json::{Value, json};

use crate::fleet::{AgentActivity, Fleet};

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Capability {
    pub id: String,
    pub adapter: String,
    pub effect: String,
    pub authority: String,
    pub reversibility: String,
    /// The most consequential interaction kind, for display. Kinds are not ordered by
    /// the controls they need, so those derive from `interactions`.
    pub interaction: String,
    /// Every interaction kind its packs declare: a merge keeps each variant's controls.
    pub interactions: BTreeSet<String>,
    pub data_scope: String,
    pub approval_mode: String,
    /// Packs that pin it.
    pub packs: BTreeSet<String>,
    pub surfaced: bool,
    pub used: bool,
    /// The packs pinning it declare different risk; the most consequential value of
    /// each dimension is kept.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub risk_conflict: bool,
}

/// Each risk dimension's values, least to most consequential. A value not listed ranks
/// above all of them, like the defaults for undeclared risk.
const EFFECT: [&str; 4] = ["none", "local_state", "external_state", "physical_world"];
const AUTHORITY: [&str; 4] = ["human_approved", "user_delegated", "service", "agent"];
const REVERSIBILITY: [&str; 4] = ["read_only", "reversible", "compensatable", "irreversible"];
const INTERACTION: [&str; 5] = ["api", "human_handoff", "agent_to_agent", "browser", "computer"];
const DATA_SCOPE: [&str; 4] = ["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"];
const APPROVAL_MODE: [&str; 5] = ["read_only", "local_write", "network", "delegated", "destructive"];

fn riskier(order: &[&str], current: &mut String, other: &str) {
    let rank = |v: &str| order.iter().position(|o| *o == v).unwrap_or(order.len());
    if rank(other) > rank(current) {
        other.clone_into(current);
    }
}

impl Capability {
    /// The reviewed risk of the capability: every dimension that a review approves.
    pub fn risk(&self) -> Value {
        let mut risk = json!({"effect": self.effect, "authority": self.authority, "reversibility": self.reversibility,
            "interaction": self.interaction, "data_scope": self.data_scope, "approval_mode": self.approval_mode});
        // Only a merged capability has several kinds; a single kind keeps the fingerprint
        // reviews recorded before kinds were kept.
        if self.interactions.len() > 1 {
            risk["interactions"] = json!(self.interactions);
        }
        risk
    }

    /// Whether any of its packs declares this interaction kind.
    pub fn interacts(&self, kind: &str) -> bool {
        self.interactions.contains(kind)
    }

    /// Adds another pack's declaration of the same capability, keeping the most
    /// consequential value of each dimension.
    fn merge(&mut self, other: &Capability) {
        if other.risk() != self.risk() {
            self.risk_conflict = true;
            riskier(&EFFECT, &mut self.effect, &other.effect);
            riskier(&AUTHORITY, &mut self.authority, &other.authority);
            riskier(&REVERSIBILITY, &mut self.reversibility, &other.reversibility);
            riskier(&INTERACTION, &mut self.interaction, &other.interaction);
            self.interactions.extend(other.interactions.iter().cloned());
            riskier(&DATA_SCOPE, &mut self.data_scope, &other.data_scope);
            riskier(&APPROVAL_MODE, &mut self.approval_mode, &other.approval_mode);
        }
        self.packs.extend(other.packs.iter().cloned());
    }

    pub fn external(&self) -> bool {
        matches!(self.effect.as_str(), "external_state" | "physical_world")
    }

    pub fn irreversible(&self) -> bool {
        self.reversibility == "irreversible"
    }

    pub fn human_approved(&self) -> bool {
        self.authority == "human_approved"
    }

    pub fn sensitive(&self) -> bool {
        matches!(self.data_scope.as_str(), "CONFIDENTIAL" | "RESTRICTED")
    }
}

/// A pack's capabilities with their risk, from `GET /v1/packs`.
pub fn pack_capabilities(pack_ref: &str, pack: &Value) -> Vec<Capability> {
    let mut out = Vec::new();
    for adapter in pack["tooling_layer"]["adapter_registry"]
        .as_array()
        .into_iter()
        .flatten()
    {
        let adapter_id = adapter["adapter_id"].as_str().unwrap_or("?");
        for cap in adapter["capabilities"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
        {
            let risk = &adapter["capability_risks"][cap];
            let field = |k: &str, default: &str| risk[k].as_str().unwrap_or(default).to_owned();
            out.push(Capability {
                id: format!("{adapter_id}.{cap}"),
                adapter: adapter_id.to_owned(),
                // Undeclared risk is treated as the most consequential value: fail closed.
                effect: field("effect", "physical_world"),
                authority: field("authority", "agent"),
                reversibility: field("reversibility", "irreversible"),
                interaction: field("interaction", "api"),
                interactions: BTreeSet::from([field("interaction", "api")]),
                data_scope: field("data_scope", "RESTRICTED"),
                approval_mode: adapter["approval_mode"].as_str().unwrap_or("destructive").to_owned(),
                packs: BTreeSet::from([pack_ref.to_owned()]),
                surfaced: false,
                used: false,
                risk_conflict: false,
            });
        }
    }
    out
}

/// Every pack the fleet's sources have loaded, by reference.
/// Pinned packs by `(source, pack_ref)`. Sources are independent runtimes, so the same
/// `id@version` is resolved within the source that admitted the run, never across.
pub fn packs(fleet: &Fleet) -> BTreeMap<(String, String), Value> {
    let mut out = BTreeMap::new();
    for state in fleet.sources.values() {
        for p in state.packs["packs"].as_array().into_iter().flatten() {
            if let Some(r) = p["pack_ref"].as_str() {
                out.insert((state.id.clone(), r.to_owned()), p["pack"].clone());
            }
        }
    }
    out
}

/// Pack references whose content differs between sources, with the sources that
/// publish each. One `id@version` should name one pack everywhere.
pub fn pack_conflicts(packs: &BTreeMap<(String, String), Value>) -> BTreeMap<String, Vec<String>> {
    let mut by_ref: BTreeMap<&str, Vec<(&str, &Value)>> = BTreeMap::new();
    for ((source, pack_ref), pack) in packs {
        by_ref.entry(pack_ref).or_default().push((source, pack));
    }
    by_ref
        .into_iter()
        .filter(|(_, versions)| versions.iter().any(|(_, p)| *p != versions[0].1))
        .map(|(r, versions)| (r.to_owned(), versions.iter().map(|(s, _)| (*s).to_owned()).collect()))
        .collect()
}

/// The agent's authority graph: the capabilities of the packs it runs under.
pub fn graph(agent: &AgentActivity, packs: &BTreeMap<(String, String), Value>) -> Vec<Capability> {
    let mut caps: BTreeMap<String, Capability> = BTreeMap::new();
    for key in &agent.source_packs {
        let Some(pack) = packs.get(key) else { continue };
        let pack_ref = &key.1;
        for cap in pack_capabilities(pack_ref, pack) {
            caps.entry(cap.id.clone()).and_modify(|c| c.merge(&cap)).or_insert(cap);
        }
    }
    // Capabilities seen at admission or in use but not pinned in any known pack still
    // belong to the graph: unknown risk, treated as the most consequential.
    for id in agent.surfaced.iter().chain(agent.capabilities.keys()) {
        caps.entry(id.clone()).or_insert_with(|| Capability {
            id: id.clone(),
            adapter: id.split('.').next().unwrap_or("?").to_owned(),
            effect: "physical_world".into(),
            authority: "agent".into(),
            reversibility: "irreversible".into(),
            interaction: "api".into(),
            interactions: BTreeSet::from(["api".to_owned()]),
            data_scope: "RESTRICTED".into(),
            approval_mode: "destructive".into(),
            packs: BTreeSet::new(),
            surfaced: false,
            used: false,
            risk_conflict: false,
        });
    }
    for cap in caps.values_mut() {
        cap.surfaced = agent.surfaced.contains(&cap.id);
        cap.used = agent.capabilities.get(&cap.id).is_some_and(|c| c.attempted > 0);
    }
    caps.into_values().collect()
}

/// `sha256:` of the graph's edges and their risk, for review and drift.
pub fn graph_digest(caps: &[Capability]) -> String {
    let edges: Vec<Value> = caps.iter().map(|c| json!([c.id, c.risk()])).collect();
    contextos_contract::canonical::sha256_canonical(&json!(edges)).unwrap_or_default()
}

/// The profiles and controls an agent's authority requires, with the reasons.
#[derive(Debug, Clone, Serialize)]
pub struct Requirement {
    /// The required profiles joined with `+` (an agent with external effects that also
    /// delegates needs both enterprise and durable-delegated).
    pub profile: String,
    pub profiles: BTreeSet<String>,
    pub reasons: Vec<String>,
    pub features: BTreeSet<String>,
    pub controls: BTreeSet<String>,
}

const HIGH_RISK_CONTEXTS: [&str; 6] = [
    "finance",
    "clinical",
    "legal",
    "employment",
    "critical_infrastructure",
    "eu_ai_act_high_risk",
];

pub fn requirement(agent: &AgentActivity, caps: &[Capability], declared_contexts: &[String]) -> Requirement {
    let mut reasons = Vec::new();
    let mut features = BTreeSet::new();
    let external: Vec<&Capability> = caps.iter().filter(|c| c.external()).collect();
    if !external.is_empty() {
        features.insert("external_effects".to_owned());
    }
    if caps.iter().any(|c| c.interacts("browser")) {
        features.insert("external_network".to_owned());
    }
    if caps.iter().any(|c| c.interacts("computer")) {
        features.insert("arbitrary_code".to_owned());
    }
    if caps.iter().any(Capability::sensitive) {
        features.insert("sensitive_data".to_owned());
    }
    if agent.memory_operations > 0 {
        features.insert("persistent_memory".to_owned());
    }
    if agent.child_runs > 0 {
        features.insert("delegation".to_owned());
    }
    if agent.checkpoints > 0 {
        features.insert("checkpoint_resume".to_owned());
    }

    let physical: Vec<&str> = caps
        .iter()
        .filter(|c| c.effect == "physical_world")
        .map(|c| c.id.as_str())
        .collect();
    let irreversible: Vec<&str> = external
        .iter()
        .filter(|c| c.irreversible())
        .map(|c| c.id.as_str())
        .collect();
    let restricted: Vec<&str> = caps
        .iter()
        .filter(|c| c.data_scope == "RESTRICTED")
        .map(|c| c.id.as_str())
        .collect();
    let contexts: Vec<&String> = declared_contexts
        .iter()
        .filter(|c| HIGH_RISK_CONTEXTS.contains(&c.as_str()))
        .collect();
    if !physical.is_empty() {
        reasons.push(format!("physical-world effects: {}", physical.join(", ")));
    }
    if !irreversible.is_empty() {
        reasons.push(format!("irreversible external effects: {}", irreversible.join(", ")));
    }
    if !restricted.is_empty() {
        reasons.push(format!("restricted data: {}", restricted.join(", ")));
    }
    if !contexts.is_empty() {
        reasons.push(format!(
            "declared high-risk context: {}",
            contexts.iter().map(|c| c.as_str()).collect::<Vec<_>>().join(", ")
        ));
    }
    let mut profiles = BTreeSet::new();
    if reasons.is_empty() {
        if !external.is_empty() || features.contains("sensitive_data") {
            reasons.push(if external.is_empty() {
                "handles confidential data".into()
            } else {
                format!(
                    "external effects: {}",
                    external.iter().map(|c| c.id.as_str()).collect::<Vec<_>>().join(", ")
                )
            });
            profiles.insert("contextos.enterprise".to_owned());
        }
        if features.contains("delegation") || features.contains("checkpoint_resume") {
            reasons.push("delegates work or resumes from checkpoints".into());
            profiles.insert("contextos.durable-delegated".to_owned());
        }
        if profiles.is_empty() {
            reasons.push("read-only, internal data".into());
            profiles.insert("contextos.core".to_owned());
        }
    } else {
        profiles.insert("contextos.high-assurance".to_owned());
    }
    let mut controls: BTreeSet<String> = profiles.iter().flat_map(|p| profile_controls(p)).collect();
    controls.extend(conditional_controls(&features));
    Requirement {
        profile: profiles.iter().cloned().collect::<Vec<_>>().join("+"),
        profiles,
        reasons,
        features,
        controls,
    }
}

fn registry() -> Value {
    serde_json::to_value(&*STANDARD_PROFILE_REGISTRY).unwrap_or(Value::Null)
}

/// Mandatory controls of a profile and everything it includes.
pub fn profile_controls(profile: &str) -> BTreeSet<String> {
    let registry = registry();
    let mut out = BTreeSet::new();
    let mut pending = vec![profile.to_owned()];
    let mut seen = BTreeSet::new();
    while let Some(id) = pending.pop() {
        if !seen.insert(id.clone()) {
            continue;
        }
        for p in registry["profiles"].as_array().into_iter().flatten() {
            if p["profile"]["profile_id"] != id.as_str() {
                continue;
            }
            for c in p["mandatory_controls"].as_array().into_iter().flatten() {
                if let Some(c) = c["control_id"].as_str() {
                    out.insert(c.to_owned());
                }
            }
            for i in p["includes"].as_array().into_iter().flatten() {
                if let Some(i) = i["profile_id"].as_str() {
                    pending.push(i.to_owned());
                }
            }
        }
    }
    out
}

/// Whether the admitted profiles together cover every control of the required ones.
pub fn satisfies(admitted: &BTreeSet<String>, required: &BTreeSet<String>) -> bool {
    let have: BTreeSet<String> = admitted.iter().flat_map(|p| profile_controls(p)).collect();
    required.iter().all(|r| profile_controls(r).is_subset(&have))
}

/// Controls the registry requires for enabled workflow features.
pub fn conditional_controls(features: &BTreeSet<String>) -> BTreeSet<String> {
    let registry = registry();
    let mut out = BTreeSet::new();
    for p in registry["profiles"].as_array().into_iter().flatten() {
        for c in p["conditional_controls"].as_array().into_iter().flatten() {
            if c["feature"].as_str().is_some_and(|f| features.contains(f))
                && let Some(id) = c["control"]["control_id"].as_str()
            {
                out.insert(id.to_owned());
            }
        }
    }
    out
}

/// Controls each source where the agent runs declares support for.
pub fn supported(fleet: &Fleet, agent: &AgentActivity) -> BTreeMap<String, BTreeSet<String>> {
    agent
        .sources
        .iter()
        .map(|id| {
            let declared = fleet
                .sources
                .get(id)
                .and_then(|s| s.deployment["support"]["supported_controls"].as_array().cloned())
                .unwrap_or_default()
                .iter()
                .filter_map(|c| c["control_id"].as_str().map(str::to_owned))
                .collect();
            (id.clone(), declared)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cap(id: &str, effect: &str, reversibility: &str, scope: &str) -> Capability {
        Capability {
            id: id.into(),
            adapter: "a".into(),
            effect: effect.into(),
            authority: "service".into(),
            reversibility: reversibility.into(),
            interaction: "api".into(),
            interactions: BTreeSet::from(["api".to_owned()]),
            data_scope: scope.into(),
            approval_mode: "network".into(),
            packs: BTreeSet::new(),
            surfaced: true,
            used: false,
            risk_conflict: false,
        }
    }

    #[test]
    fn the_registry_composes_profiles() {
        let core = profile_controls("contextos.core");
        assert!(core.contains("audit.correlated") && !core.contains("approval.bound"));
        let high = profile_controls("contextos.high-assurance");
        assert!(high.is_superset(&profile_controls("contextos.enterprise")));
        assert!(high.contains("assurance.fault_evidence") && high.contains("effects.reconciled"));
        let set = |ps: &[&str]| ps.iter().map(|p| (*p).to_owned()).collect::<BTreeSet<_>>();
        assert!(satisfies(
            &set(&["contextos.high-assurance"]),
            &set(&["contextos.enterprise"])
        ));
        assert!(!satisfies(&set(&["contextos.core"]), &set(&["contextos.enterprise"])));
        assert!(!satisfies(
            &set(&["contextos.enterprise"]),
            &set(&["contextos.enterprise", "contextos.durable-delegated"])
        ));
    }

    #[test]
    fn what_an_agent_can_do_decides_what_it_needs() {
        let agent = AgentActivity::default();
        let read = requirement(&agent, &[cap("orders.lookup", "none", "read_only", "INTERNAL")], &[]);
        assert_eq!(read.profile, "contextos.core");
        let refund = requirement(
            &agent,
            &[cap("pay.refund", "external_state", "compensatable", "INTERNAL")],
            &[],
        );
        assert_eq!(refund.profile, "contextos.enterprise");
        assert!(refund.controls.contains("approval.bound") && refund.controls.contains("effects.reconciled"));
        let wire = requirement(
            &agent,
            &[cap("pay.wire", "external_state", "irreversible", "INTERNAL")],
            &[],
        );
        assert_eq!(wire.profile, "contextos.high-assurance");
        assert!(wire.reasons[0].contains("pay.wire"));
        let declared = requirement(
            &agent,
            &[cap("orders.lookup", "none", "read_only", "INTERNAL")],
            &["clinical".into()],
        );
        assert_eq!(declared.profile, "contextos.high-assurance");
        let delegating = AgentActivity {
            child_runs: 2,
            ..AgentActivity::default()
        };
        let both = requirement(
            &delegating,
            &[cap("pay.refund", "external_state", "compensatable", "INTERNAL")],
            &[],
        );
        assert_eq!(both.profile, "contextos.durable-delegated+contextos.enterprise");
        assert!(both.controls.contains("governance.separation") && both.controls.contains("execution.checkpointed"));
    }

    #[test]
    fn undeclared_risk_fails_closed() {
        let pack = json!({"tooling_layer": {"adapter_registry": [{"adapter_id": "x", "capabilities": ["do"], "capability_risks": {}}]}});
        let caps = pack_capabilities("p@1", &pack);
        assert_eq!(
            (caps[0].effect.as_str(), caps[0].reversibility.as_str()),
            ("physical_world", "irreversible")
        );
    }
}
