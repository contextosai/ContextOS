//! Exact execution-contract negotiation.
//!
//! Required controls are the union of the selected profiles' mandatory controls, the
//! controls implied by the workflow's actual features, and any explicitly required
//! controls. An unsupported required control rejects admission; support alone grants
//! no authority. Callers authenticate the registry and derive features at admission.

use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};

use contextos_contract::canonical::{canonicalize, domain_digest, utf16_cmp};
use contextos_contract::execution::{
    ArtifactRef, ContractNegotiationReason, ContractNegotiationReasonCode as Code, ContractNegotiationResult,
    ControlRef, NegotiationStatus, ProfileSelection, WorkflowFeature,
};
use contextos_contract::shape::{
    bounded_array, exact_keys, is_artifact_ref, is_control_ref, is_identifier, is_identifier_list, is_profile_selection,
};
use serde_json::{Map, Value};

use crate::profiles::{CONTROL_DEFINITION_DOMAIN, PROFILE_DEFINITION_DOMAIN, PROFILE_REGISTRY_DOMAIN};

const MAX_PROFILE_DEPTH: usize = 8;
const MAX_EFFECTIVE_CONTROLS: usize = 128;

fn order_controls(a: &ControlRef, b: &ControlRef) -> Ordering {
    utf16_cmp(&a.control_id, &b.control_id).then_with(|| utf16_cmp(&a.control_version, &b.control_version))
}

fn order_profiles(a: &ProfileSelection, b: &ProfileSelection) -> Ordering {
    utf16_cmp(&a.profile_id, &b.profile_id).then_with(|| utf16_cmp(&a.profile_version, &b.profile_version))
}

/// Exact-ref union, deduplicated and sorted.
fn union_exact(groups: &[&[ControlRef]]) -> Vec<ControlRef> {
    let mut seen = HashSet::new();
    let mut out: Vec<ControlRef> = groups
        .iter()
        .flat_map(|g| g.iter())
        .filter(|r| seen.insert((*r).clone()))
        .cloned()
        .collect();
    out.sort_by(order_controls);
    out
}

fn valid_contract(v: &Value) -> bool {
    exact_keys(
        v,
        &[
            "envelope_version",
            "contract_id",
            "run_id",
            "trace_id",
            "tenant_id",
            "profiles",
            "required_controls",
            "optional_controls",
            "release_refs",
        ],
    )
    .is_some_and(|o| {
        o["envelope_version"] == "contextos.execution_contract.v1"
            && ["contract_id", "run_id", "trace_id", "tenant_id"]
                .iter()
                .all(|k| is_identifier(&o[*k]))
            && bounded_array(&o["profiles"], 1, 16, is_profile_selection)
            && bounded_array(&o["required_controls"], 0, 128, is_control_ref)
            && bounded_array(&o["optional_controls"], 0, 128, is_control_ref)
            && bounded_array(&o["release_refs"], 0, 128, is_artifact_ref)
    })
}

fn valid_support(v: &Value) -> bool {
    exact_keys(
        v,
        &[
            "implementation_id",
            "implementation_version",
            "supported_profiles",
            "supported_controls",
        ],
    )
    .is_some_and(|o| {
        is_identifier(&o["implementation_id"])
            && is_identifier(&o["implementation_version"])
            && bounded_array(&o["supported_profiles"], 0, 128, is_profile_selection)
            && bounded_array(&o["supported_controls"], 0, 128, is_control_ref)
    })
}

fn valid_control_definition(v: &Value) -> bool {
    exact_keys(
        v,
        &[
            "control",
            "definition_ref",
            "evidence_obligations",
            "positive_cases",
            "negative_cases",
        ],
    )
    .is_some_and(|o| {
        is_control_ref(&o["control"])
            && is_artifact_ref(&o["definition_ref"])
            && is_identifier_list(&o["evidence_obligations"])
            && is_identifier_list(&o["positive_cases"])
            && is_identifier_list(&o["negative_cases"])
    })
}

fn valid_condition(v: &Value) -> bool {
    exact_keys(v, &["feature", "equals", "control"]).is_some_and(|o| {
        o["feature"]
            .as_str()
            .is_some_and(|f| WorkflowFeature::ALL.iter().any(|w| w.as_str() == f))
            && o["equals"].is_boolean()
            && is_control_ref(&o["control"])
    })
}

fn valid_profile_definition(v: &Value) -> bool {
    exact_keys(
        v,
        &[
            "profile",
            "includes",
            "mandatory_controls",
            "conditional_controls",
            "definition_ref",
        ],
    )
    .is_some_and(|o| {
        is_profile_selection(&o["profile"])
            && is_artifact_ref(&o["definition_ref"])
            && bounded_array(&o["includes"], 0, 16, is_profile_selection)
            && bounded_array(&o["mandatory_controls"], 0, 128, is_control_ref)
            && bounded_array(&o["conditional_controls"], 0, 128, valid_condition)
    })
}

fn valid_registry(v: &Value) -> bool {
    exact_keys(v, &["registry_ref", "profiles", "controls"]).is_some_and(|o| {
        is_artifact_ref(&o["registry_ref"])
            && bounded_array(&o["profiles"], 1, 128, valid_profile_definition)
            && bounded_array(&o["controls"], 1, 128, valid_control_definition)
    })
}

fn valid_features(v: &Value) -> bool {
    let keys: Vec<&str> = WorkflowFeature::ALL.iter().map(|f| f.as_str()).collect();
    exact_keys(v, &keys).is_some_and(|o| o.values().all(Value::is_boolean))
}

fn parse<T: serde::de::DeserializeOwned>(v: &Value) -> T {
    serde_json::from_value(v.clone()).expect("shape validated before parsing")
}

fn without(object: &Map<String, Value>, key: &str) -> Value {
    let mut copy = object.clone();
    copy.remove(key);
    Value::Object(copy)
}

#[derive(Default)]
struct Reasons(Vec<ContractNegotiationReason>);

impl Reasons {
    fn add(&mut self, code: Code, identifier: impl Into<String>) {
        self.0.push(ContractNegotiationReason {
            code,
            identifier: identifier.into(),
        });
    }

    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn finish(self) -> Vec<ContractNegotiationReason> {
        let mut seen = HashSet::new();
        let mut out: Vec<_> = self
            .0
            .into_iter()
            .filter(|r| seen.insert((r.code, r.identifier.clone())))
            .collect();
        out.sort_by(|a, b| {
            utf16_cmp(a.code.as_str(), b.code.as_str()).then_with(|| utf16_cmp(&a.identifier, &b.identifier))
        });
        out
    }
}

struct Expanded {
    height: usize,
    controls: Vec<ControlRef>,
    profiles: Vec<ProfileSelection>,
}

struct Registry<'a> {
    controls: HashMap<ControlRef, &'a Value>,
    profiles: HashMap<ProfileSelection, &'a Value>,
    profile_ids: HashSet<String>,
    control_ids: HashSet<String>,
}

struct Expander<'a, 'r> {
    registry: &'r Registry<'a>,
    features: &'r Map<String, Value>,
    memo: HashMap<ProfileSelection, std::rc::Rc<Expanded>>,
    visiting: Vec<ProfileSelection>,
}

impl Expander<'_, '_> {
    fn resolve_control(&self, reasons: &mut Reasons, r: &ControlRef) {
        if !self.registry.controls.contains_key(r) {
            let code = if self.registry.control_ids.contains(&r.control_id) {
                Code::ControlVersionUnsupported
            } else {
                Code::ControlUnknown
            };
            reasons.add(code, r.key());
        }
    }

    fn expand(&mut self, reasons: &mut Reasons, r: &ProfileSelection) -> std::rc::Rc<Expanded> {
        if let Some(cached) = self.memo.get(r) {
            return cached.clone();
        }
        let empty = || {
            std::rc::Rc::new(Expanded {
                height: 0,
                controls: vec![],
                profiles: vec![],
            })
        };
        if self.visiting.contains(r) || self.visiting.len() >= MAX_PROFILE_DEPTH {
            reasons.add(Code::RegistryExpansionInvalid, r.key());
            return empty();
        }
        let Some(definition) = self.registry.profiles.get(r).copied() else {
            let code = if self.registry.profile_ids.contains(&r.profile_id) {
                Code::ProfileVersionUnsupported
            } else {
                Code::ProfileUnknown
            };
            reasons.add(code, r.key());
            return empty();
        };
        self.visiting.push(r.clone());
        let mandatory: Vec<ControlRef> = parse(&definition["mandatory_controls"]);
        let mut required = mandatory.clone();
        let mut height = 1;
        let mut reached: Vec<ProfileSelection> = vec![r.clone()];
        for control in &mandatory {
            self.resolve_control(reasons, control);
        }
        for condition in definition["conditional_controls"].as_array().into_iter().flatten() {
            let control: ControlRef = parse(&condition["control"]);
            self.resolve_control(reasons, &control);
            let feature = condition["feature"].as_str().unwrap_or_default();
            if self.features.get(feature) == Some(&condition["equals"]) {
                required.push(control);
            }
        }
        let includes: Vec<ProfileSelection> = parse(&definition["includes"]);
        for included in &includes {
            let child = self.expand(reasons, included);
            height = height.max(child.height + 1);
            required = union_exact(&[&required, &child.controls]);
            for p in &child.profiles {
                if !reached.contains(p) {
                    reached.push(p.clone());
                }
            }
        }
        self.visiting.retain(|v| v != r);
        if height > MAX_PROFILE_DEPTH {
            reasons.add(Code::RegistryExpansionInvalid, r.key());
        }
        let expanded = std::rc::Rc::new(Expanded {
            height,
            controls: union_exact(&[&required]),
            profiles: reached,
        });
        self.memo.insert(r.clone(), expanded.clone());
        expanded
    }
}

fn conflicts<T>(reasons: &mut Reasons, refs: &[T], id: impl Fn(&T) -> &str, version: impl Fn(&T) -> &str) {
    let mut seen: HashMap<&str, &str> = HashMap::new();
    for r in refs {
        if let Some(previous) = seen.get(id(r))
            && *previous != version(r)
        {
            reasons.add(Code::ConflictingReference, id(r));
        }
        seen.insert(id(r), version(r));
    }
}

fn result(contract_id: String, reasons: Reasons) -> ContractNegotiationResult {
    let reasons = reasons.finish();
    ContractNegotiationResult {
        contract_id,
        registry_ref: None,
        feature_set_digest: None,
        selected_profiles: vec![],
        effective_required_controls: vec![],
        supported_controls: vec![],
        unsupported_optional: vec![],
        status: if reasons.is_empty() {
            NegotiationStatus::Accepted
        } else {
            NegotiationStatus::Rejected
        },
        reasons,
    }
}

/// Pure compatibility negotiation over raw JSON inputs.
///
/// # Panics
///
/// Never in practice: internal `expect`s only parse values whose shape was validated first.
pub fn negotiate_execution_contract(
    contract: &Value,
    support: &Value,
    registry: &Value,
    features: &Value,
) -> ContractNegotiationResult {
    let mut reasons = Reasons::default();
    for (name, input) in [
        ("contract", contract),
        ("support", support),
        ("registry", registry),
        ("features", features),
    ] {
        if canonicalize(input).is_err() {
            let code = if name == "features" {
                Code::FeatureStateInvalid
            } else {
                Code::InvalidContract
            };
            reasons.add(code, name);
        }
    }
    if !reasons.is_empty() {
        return result("invalid".into(), reasons);
    }
    if !valid_contract(contract) {
        reasons.add(Code::InvalidContract, "contract");
    }
    if !valid_support(support) {
        reasons.add(Code::InvalidContract, "support");
    }
    if !valid_registry(registry) {
        reasons.add(Code::InvalidContract, "registry");
    }
    if !valid_features(features) {
        reasons.add(Code::FeatureStateInvalid, "features");
    }
    if !reasons.is_empty() {
        return result("invalid".into(), reasons);
    }

    let contract_id = contract["contract_id"].as_str().unwrap_or_default().to_owned();
    let registry_ref: ArtifactRef = parse(&registry["registry_ref"]);
    let feature_set_digest = domain_digest("contextos.workflow_features.v1", features).ok();
    let contract_profiles: Vec<ProfileSelection> = parse(&contract["profiles"]);
    let mut selected: Vec<ProfileSelection> = Vec::new();
    for p in &contract_profiles {
        if !selected.contains(p) {
            selected.push(p.clone());
        }
    }
    selected.sort_by(order_profiles);

    let supported_profiles: Vec<ProfileSelection> = parse(&support["supported_profiles"]);
    let supported_controls: Vec<ControlRef> = parse(&support["supported_controls"]);
    conflicts(
        &mut reasons,
        &contract_profiles,
        |p| &p.profile_id,
        |p| &p.profile_version,
    );
    conflicts(
        &mut reasons,
        &supported_profiles,
        |p| &p.profile_id,
        |p| &p.profile_version,
    );
    conflicts(
        &mut reasons,
        &supported_controls,
        |c| &c.control_id,
        |c| &c.control_version,
    );

    let mut releases: HashMap<(String, String), String> = HashMap::new();
    for r in contract["release_refs"].as_array().into_iter().flatten() {
        let key = (
            r["artifact_type"].as_str().unwrap_or_default().to_owned(),
            r["artifact_id"].as_str().unwrap_or_default().to_owned(),
        );
        let encoded = canonicalize(r).unwrap_or_default();
        if releases.get(&key).is_some_and(|previous| *previous != encoded) {
            reasons.add(Code::ConflictingReference, key.1.clone());
        }
        releases.insert(key, encoded);
    }

    let integrity =
        |reasons: &mut Reasons, r: &Value, kind: &str, id: &str, version: &str, domain: &str, payload: &Value| {
            let expected = domain_digest(domain, payload).ok();
            if r["artifact_type"] != kind
                || r["artifact_id"] != id
                || r["version"] != version
                || r["sha256"].as_str() != expected.as_deref()
            {
                reasons.add(Code::ArtifactBindingInvalid, id);
            }
        };

    let mut index = Registry {
        controls: HashMap::new(),
        profiles: HashMap::new(),
        profile_ids: HashSet::new(),
        control_ids: HashSet::new(),
    };
    for definition in registry["controls"].as_array().into_iter().flatten() {
        let object = definition.as_object().expect("validated");
        let r: ControlRef = parse(&object["control"]);
        let payload = without(object, "definition_ref");
        integrity(
            &mut reasons,
            &object["definition_ref"],
            "control_definition",
            &r.control_id,
            &r.control_version,
            CONTROL_DEFINITION_DOMAIN,
            &payload,
        );
        if index
            .controls
            .get(&r)
            .is_some_and(|existing| canonicalize(existing).ok() != canonicalize(definition).ok())
        {
            reasons.add(Code::ConflictingReference, r.key());
        }
        index.control_ids.insert(r.control_id.clone());
        index.controls.insert(r, definition);
    }
    for definition in registry["profiles"].as_array().into_iter().flatten() {
        let object = definition.as_object().expect("validated");
        let r: ProfileSelection = parse(&object["profile"]);
        let payload = without(object, "definition_ref");
        integrity(
            &mut reasons,
            &object["definition_ref"],
            "profile_definition",
            &r.profile_id,
            &r.profile_version,
            PROFILE_DEFINITION_DOMAIN,
            &payload,
        );
        if index
            .profiles
            .get(&r)
            .is_some_and(|existing| canonicalize(existing).ok() != canonicalize(definition).ok())
        {
            reasons.add(Code::ConflictingReference, r.key());
        }
        index.profile_ids.insert(r.profile_id.clone());
        index.profiles.insert(r, definition);
    }
    let registry_payload = without(registry.as_object().expect("validated"), "registry_ref");
    integrity(
        &mut reasons,
        &registry["registry_ref"],
        "profile_registry",
        &registry_ref.artifact_id,
        &registry_ref.version,
        PROFILE_REGISTRY_DOMAIN,
        &registry_payload,
    );

    let features_object = features.as_object().expect("validated");
    let mut expander = Expander {
        registry: &index,
        features: features_object,
        memo: HashMap::new(),
        visiting: vec![],
    };
    // Check relationships in inactive registry branches as well as selected profiles.
    for definition in registry["profiles"].as_array().into_iter().flatten() {
        let r: ProfileSelection = parse(&definition["profile"]);
        expander.expand(&mut reasons, &r);
    }
    let mut out = result(contract_id, Reasons::default());
    out.registry_ref = Some(registry_ref);
    out.feature_set_digest = feature_set_digest;
    out.selected_profiles.clone_from(&selected);
    if !reasons.is_empty() {
        let mut finished = result(out.contract_id.clone(), reasons);
        finished.registry_ref = out.registry_ref;
        finished.feature_set_digest = out.feature_set_digest;
        finished.selected_profiles = out.selected_profiles;
        return finished;
    }

    let mut expanded_controls: Vec<ControlRef> = Vec::new();
    let mut reached: Vec<ProfileSelection> = Vec::new();
    for r in &selected {
        let resolved = expander.expand(&mut reasons, r);
        expanded_controls.extend(resolved.controls.iter().cloned());
        reached.extend(resolved.profiles.iter().cloned());
        if !supported_profiles.contains(r) {
            reasons.add(Code::ProfileVersionUnsupported, r.key());
        }
    }
    conflicts(&mut reasons, &reached, |p| &p.profile_id, |p| &p.profile_version);
    let required_controls: Vec<ControlRef> = parse(&contract["required_controls"]);
    let optional_controls: Vec<ControlRef> = parse(&contract["optional_controls"]);
    let effective = union_exact(&[&expanded_controls, &required_controls]);
    if effective.len() > MAX_EFFECTIVE_CONTROLS {
        reasons.add(Code::RegistryExpansionInvalid, "effective_controls");
    }
    let combined: Vec<ControlRef> = effective.iter().chain(optional_controls.iter()).cloned().collect();
    conflicts(&mut reasons, &combined, |c| &c.control_id, |c| &c.control_version);
    for r in &effective {
        expander.resolve_control(&mut reasons, r);
        if !supported_controls.contains(r) {
            reasons.add(Code::RequiredControlUnsupported, r.key());
        }
    }
    let known_and_supported = |r: &ControlRef| index.controls.contains_key(r) && supported_controls.contains(r);
    let supported: Vec<ControlRef> = union_exact(&[&effective, &optional_controls])
        .into_iter()
        .filter(|r| known_and_supported(r))
        .collect();
    let unsupported_optional: Vec<ControlRef> = union_exact(&[&optional_controls])
        .into_iter()
        .filter(|r| !known_and_supported(r))
        .collect();

    let mut finished = result(out.contract_id, reasons);
    finished.registry_ref = out.registry_ref;
    finished.feature_set_digest = out.feature_set_digest;
    finished.selected_profiles = out.selected_profiles;
    finished.effective_required_controls = effective;
    finished.supported_controls = supported;
    finished.unsupported_optional = unsupported_optional;
    finished
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profiles::STANDARD_PROFILE_REGISTRY;
    use serde_json::json;

    fn support_all() -> Value {
        json!({
            "implementation_id": "contextos.rs",
            "implementation_version": "0.1.0",
            "supported_profiles": STANDARD_PROFILE_REGISTRY.profiles.iter().map(|p| &p.profile).collect::<Vec<_>>(),
            "supported_controls": STANDARD_PROFILE_REGISTRY.controls.iter().map(|c| &c.control).collect::<Vec<_>>(),
        })
    }

    fn contract(profile: &str) -> Value {
        json!({
            "envelope_version": "contextos.execution_contract.v1",
            "contract_id": "c1", "run_id": "r1", "trace_id": "t1", "tenant_id": "tenant_acme_prod",
            "profiles": [{"profile_id": profile, "profile_version": "1"}],
            "required_controls": [], "optional_controls": [], "release_refs": []
        })
    }

    #[test]
    fn features_add_conditional_controls() {
        let registry = serde_json::to_value(&*STANDARD_PROFILE_REGISTRY).unwrap();
        let mut features = serde_json::to_value(contextos_contract::execution::WorkflowFeatureSet::default()).unwrap();
        let base = negotiate_execution_contract(&contract("contextos.core"), &support_all(), &registry, &features);
        assert_eq!(base.status, NegotiationStatus::Accepted);
        assert_eq!(base.effective_required_controls.len(), 5);
        features["external_effects"] = json!(true);
        let effects = negotiate_execution_contract(&contract("contextos.core"), &support_all(), &registry, &features);
        let ids: Vec<_> = effects
            .effective_required_controls
            .iter()
            .map(|c| c.control_id.as_str())
            .collect();
        assert!(ids.contains(&"effects.reconciled") && ids.contains(&"approval.bound"));
    }
}
