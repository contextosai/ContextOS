//! Active execution-boundary readiness, data-flow policy across all nine stages, and
//! memory lifecycle truthfulness.
//!
//! These checks consume verified, normalized observations from trusted adapters (a
//! sandbox controller, a credential broker, a classification service, a memory
//! store). They do not provision a sandbox, inspect an environment, move data or
//! erase copies; they decide whether what was observed is current, bound to this
//! run and sufficient for the requirement.

use std::collections::{HashMap, HashSet};

use contextos_contract::canonical::{canonicalize, sha256_canonical, utf16_cmp};
use contextos_contract::shape::{
    as_safe_integer, bounded_array, exact_keys, is_artifact_ref, is_control_ref, is_digest, is_identifier,
    is_safe_non_negative_integer, is_timestamp,
};
use contextos_contract::validation::{
    age_within_limit, compare_contract_times, is_contract_timestamp, is_within_contract_interval,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::authorization::valid_principal;
use crate::pathspec::{posix_is_absolute, posix_normalize, win32_is_absolute, win32_normalize};

const MAX_LIST: usize = 128;

fn s(value: &Value) -> &str {
    value.as_str().unwrap_or_default()
}

fn identical(a: &Value, b: &Value) -> bool {
    contextos_contract::canonical::canonical_eq(a, b)
}

fn encoded(value: &Value) -> String {
    canonicalize(value).unwrap_or_default()
}

fn list(value: &Value, guard: impl Fn(&Value) -> bool) -> bool {
    bounded_array(value, 0, MAX_LIST, guard)
}

fn strings(value: &Value) -> bool {
    list(value, is_identifier)
}

fn artifact_refs(value: &Value) -> bool {
    list(value, is_artifact_ref)
}

fn sorted(codes: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut out: Vec<String> = codes.into_iter().collect::<HashSet<_>>().into_iter().collect();
    out.sort_by(|a, b| utf16_cmp(a, b));
    out
}

fn time_label(time: &Value) -> String {
    time.as_str()
        .filter(|t| is_contract_timestamp(t))
        .unwrap_or("invalid")
        .to_owned()
}

fn within(time: &Value, start: &Value, end: &Value) -> bool {
    is_within_contract_interval(s(time), s(start), s(end))
}

fn age_ok(time: &Value, observed: &Value, maximum: &Value) -> bool {
    let Some(max) = as_safe_integer(maximum).and_then(|m| u64::try_from(m).ok()) else {
        return false;
    };
    age_within_limit(s(time), s(observed), max)
}

fn verification_status(value: &Value) -> bool {
    matches!(value.as_str(), Some("verified" | "invalid" | "unavailable"))
}

fn same_artifact_refs(left: &[Value], right: &[Value]) -> bool {
    let a: HashSet<String> = left.iter().map(encoded).collect();
    let b: HashSet<String> = right.iter().map(encoded).collect();
    a.len() == left.len() && b.len() == right.len() && a == b
}

// ─── Execution boundary ────────────────────────────────────────────────────

fn isolation_mode(value: &Value) -> bool {
    matches!(
        value.as_str(),
        Some("broker_only" | "sandboxed_code" | "dedicated_environment")
    )
}

fn filesystem_grant(value: &Value) -> bool {
    let Some(o) = exact_keys(value, &["root", "path_format", "access"]) else {
        return false;
    };
    let Some(root) = o["root"].as_str() else { return false };
    let units = root.encode_utf16().count();
    if units == 0 || units > 4096 || root.contains('\0') || root.contains('*') {
        return false;
    }
    if !matches!(o["access"].as_str(), Some("read" | "read_write")) {
        return false;
    }
    match o["path_format"].as_str() {
        Some("posix") => posix_is_absolute(root) && posix_normalize(root) == root,
        Some("windows") => win32_is_absolute(root) && win32_normalize(root) == root,
        _ => false,
    }
}

/// An exact network origin: http(s)/ws(s), no credentials, path `/`, no query or
/// fragment, and already in WHATWG-serialized origin form (lowercase host, ASCII,
/// default port omitted).
pub fn network_origin_valid(origin: &str) -> bool {
    if !contextos_contract::validation::is_contract_identifier(origin) || origin.contains('*') {
        return false;
    }
    let Ok(url) = url::Url::parse(origin) else { return false };
    matches!(url.scheme(), "https" | "http" | "wss" | "ws")
        && url.username().is_empty()
        && url.password().is_none()
        && url.origin().ascii_serialization() == origin
        && url.path() == "/"
        && url.query().is_none_or(str::is_empty)
        && url.fragment().is_none_or(str::is_empty)
}

fn network_grant(value: &Value) -> bool {
    exact_keys(value, &["origin"]).is_some_and(|o| o["origin"].as_str().is_some_and(network_origin_valid))
}

fn resource_ceilings(value: &Value) -> bool {
    exact_keys(
        value,
        &[
            "cpu_ms",
            "memory_bytes",
            "pids",
            "wall_clock_ms",
            "output_bytes",
            "scratch_bytes",
        ],
    )
    .is_some_and(|o| {
        o.values().all(is_safe_non_negative_integer)
            && ["cpu_ms", "memory_bytes", "pids", "wall_clock_ms"]
                .iter()
                .all(|k| as_safe_integer(&o[*k]) > Some(0))
    })
}

fn boundary_requirement(value: &Value) -> bool {
    exact_keys(
        value,
        &[
            "contract_id",
            "run_id",
            "tenant_id",
            "boundary_id",
            "isolation_mode",
            "configuration_ref",
            "trust_domain",
            "required_controls",
            "filesystem_grants",
            "process_restrictions",
            "network_grants",
            "resource_ceilings",
            "credential_broker_ref",
            "trusted_observer",
            "maximum_observation_age_seconds",
        ],
    )
    .is_some_and(|o| {
        ["contract_id", "run_id", "tenant_id", "boundary_id", "trust_domain"]
            .iter()
            .all(|k| is_identifier(&o[*k]))
            && isolation_mode(&o["isolation_mode"])
            && is_artifact_ref(&o["configuration_ref"])
            && is_artifact_ref(&o["credential_broker_ref"])
            && list(&o["required_controls"], is_control_ref)
            && o["required_controls"].as_array().is_some_and(|c| {
                c.iter()
                    .any(|c| c["control_id"] == "isolation.required" && c["control_version"] == "1")
            })
            && list(&o["filesystem_grants"], filesystem_grant)
            && list(&o["network_grants"], network_grant)
            && resource_ceilings(&o["resource_ceilings"])
            && valid_principal(&o["trusted_observer"])
            && is_safe_non_negative_integer(&o["maximum_observation_age_seconds"])
            && exact_keys(
                &o["process_restrictions"],
                &["run_as", "allow_privileged", "allow_child_processes"],
            )
            .is_some_and(|p| {
                is_identifier(&p["run_as"])
                    && p["allow_privileged"].is_boolean()
                    && p["allow_child_processes"].is_boolean()
            })
    })
}

fn boundary_observation(value: &Value) -> bool {
    exact_keys(
        value,
        &[
            "contract_id",
            "run_id",
            "tenant_id",
            "boundary_id",
            "isolation_mode",
            "actual_configuration_sha256",
            "trust_domain",
            "active_controls",
            "failed_controls",
            "observer",
            "verification_status",
            "evidence_ref",
            "observed_at",
            "valid_until",
            "lifecycle_state",
            "enforcement",
        ],
    )
    .is_some_and(|o| {
        ["contract_id", "run_id", "tenant_id", "boundary_id", "trust_domain"]
            .iter()
            .all(|k| is_identifier(&o[*k]))
            && isolation_mode(&o["isolation_mode"])
            && is_digest(&o["actual_configuration_sha256"])
            && list(&o["active_controls"], is_control_ref)
            && list(&o["failed_controls"], is_control_ref)
            && valid_principal(&o["observer"])
            && verification_status(&o["verification_status"])
            && is_artifact_ref(&o["evidence_ref"])
            && is_timestamp(&o["observed_at"])
            && is_timestamp(&o["valid_until"])
            && matches!(
                o["lifecycle_state"].as_str(),
                Some("ready" | "unavailable" | "terminated")
            )
            && exact_keys(
                &o["enforcement"],
                &["filesystem", "process", "network", "resources", "credentials"],
            )
            .is_some_and(|e| e.values().all(Value::is_boolean))
    })
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BoundaryReadinessResult {
    pub allowed: bool,
    pub reason_codes: Vec<String>,
    pub boundary_id: String,
    pub evaluation_time: String,
    pub configuration_ref: Option<Value>,
    pub evidence_ref: Option<Value>,
    pub unsatisfied_obligations: Vec<String>,
}

/// Decides whether a verified, current, correctly bound boundary observation proves
/// the required isolation, enforcement dimensions and controls are active now.
pub fn evaluate_boundary_readiness(
    required: &Value,
    observed: &Value,
    evaluation_time: &Value,
) -> BoundaryReadinessResult {
    let mut reasons: HashSet<String> = HashSet::new();
    let mut obligations: HashSet<String> = HashSet::new();
    let mut result = BoundaryReadinessResult {
        allowed: false,
        reason_codes: vec![],
        boundary_id: "invalid".into(),
        evaluation_time: time_label(evaluation_time),
        configuration_ref: None,
        evidence_ref: None,
        unsatisfied_obligations: vec![],
    };
    let finish = |mut result: BoundaryReadinessResult, reasons: HashSet<String>, obligations: HashSet<String>| {
        result.allowed = reasons.is_empty();
        result.reason_codes = sorted(reasons);
        result.unsatisfied_obligations = sorted(obligations);
        result
    };
    if contextos_contract::canonical::check_canonical(required).is_err()
        || contextos_contract::canonical::check_canonical(observed).is_err()
    {
        reasons.insert("configuration_invalid".into());
        return finish(result, reasons, obligations);
    }
    if !boundary_requirement(required) {
        reasons.insert("configuration_invalid".into());
        let resource_policy_valid = required.is_object()
            && resource_ceilings(&required["resource_ceilings"])
            && is_safe_non_negative_integer(&required["maximum_observation_age_seconds"]);
        if !resource_policy_valid {
            reasons.insert("resource_limit_invalid".into());
        }
        return finish(result, reasons, obligations);
    }
    s(&required["boundary_id"]).clone_into(&mut result.boundary_id);
    result.configuration_ref = Some(required["configuration_ref"].clone());
    let falsy = match observed {
        Value::Null => true,
        Value::Bool(b) => !b,
        Value::Number(n) => n.as_f64() == Some(0.0),
        Value::String(text) => text.is_empty(),
        _ => false,
    };
    if falsy {
        reasons.insert("boundary_unavailable".into());
        return finish(result, reasons, obligations);
    }
    if !boundary_observation(observed) {
        reasons.insert("observation_unverified".into());
        return finish(result, reasons, obligations);
    }
    result.evidence_ref = Some(observed["evidence_ref"].clone());
    if ["contract_id", "run_id", "tenant_id", "boundary_id", "isolation_mode"]
        .iter()
        .any(|k| required[*k] != observed[*k])
    {
        reasons.insert("boundary_binding_mismatch".into());
    }
    if observed["actual_configuration_sha256"] != required["configuration_ref"]["sha256"] {
        reasons.insert("configuration_mismatch".into());
    }
    if observed["trust_domain"] != required["trust_domain"] {
        reasons.insert("trust_domain_mismatch".into());
    }
    if observed["verification_status"] != "verified"
        || observed["observer"]["tenant_id"] != required["tenant_id"]
        || !identical(&observed["observer"], &required["trusted_observer"])
    {
        reasons.insert("observation_unverified".into());
    }
    match s(&observed["lifecycle_state"]) {
        "terminated" => {
            reasons.insert("boundary_terminated".into());
        }
        "unavailable" => {
            reasons.insert("boundary_unavailable".into());
        }
        _ => {}
    }
    if !within(evaluation_time, &observed["observed_at"], &observed["valid_until"])
        || !age_ok(
            evaluation_time,
            &observed["observed_at"],
            &required["maximum_observation_age_seconds"],
        )
    {
        reasons.insert("observation_stale".into());
    }
    let mut revisions: HashMap<String, Value> = HashMap::new();
    let active = observed["active_controls"].as_array().expect("validated");
    for control in required["required_controls"].as_array().expect("validated") {
        let id = s(&control["control_id"]).to_owned();
        if revisions.get(&id).is_some_and(|v| *v != control["control_version"]) {
            reasons.insert("configuration_invalid".into());
        }
        revisions.insert(id, control["control_version"].clone());
        if !active
            .iter()
            .any(|a| a["control_id"] == control["control_id"] && a["control_version"] == control["control_version"])
        {
            reasons.insert("required_control_inactive".into());
            obligations.insert(format!(
                "{}@{}",
                s(&control["control_id"]),
                s(&control["control_version"])
            ));
        }
    }
    for failed in observed["failed_controls"].as_array().expect("validated") {
        reasons.insert("required_control_inactive".into());
        obligations.insert(format!(
            "{}@{}",
            s(&failed["control_id"]),
            s(&failed["control_version"])
        ));
    }
    let code_mode = required["isolation_mode"] != "broker_only";
    let process = &required["process_restrictions"];
    let applicable = [
        (
            "filesystem",
            code_mode || required["filesystem_grants"].as_array().is_some_and(|g| !g.is_empty()),
        ),
        (
            "process",
            code_mode || process["allow_child_processes"] == true || process["allow_privileged"] == true,
        ),
        ("network", true),
        ("resources", true),
        ("credentials", true),
    ];
    for (dimension, required_here) in applicable {
        if required_here && observed["enforcement"][dimension] != true {
            reasons.insert("required_control_inactive".into());
            obligations.insert(format!("{dimension}_enforcement"));
        }
    }
    finish(result, reasons, obligations)
}

// ─── Data flow ─────────────────────────────────────────────────────────────

/// The nine data-flow stages policy must cover.
pub const DATA_FLOW_STAGES: [&str; 9] = [
    "collection",
    "inference",
    "tool_input",
    "tool_output",
    "telemetry",
    "cache",
    "memory",
    "export",
    "delegation",
];

fn stage(value: &Value) -> bool {
    value.as_str().is_some_and(|v| DATA_FLOW_STAGES.contains(&v))
}

const OBSERVATION_KEYS: [&str; 5] = [
    "verification_status",
    "observer",
    "evidence_ref",
    "observed_at",
    "valid_until",
];

fn keys_with(extra: &[&'static str]) -> Vec<&'static str> {
    OBSERVATION_KEYS.iter().copied().chain(extra.iter().copied()).collect()
}

fn observation_fields(o: &Map<String, Value>) -> bool {
    verification_status(&o["verification_status"])
        && valid_principal(&o["observer"])
        && is_artifact_ref(&o["evidence_ref"])
        && is_timestamp(&o["observed_at"])
        && is_timestamp(&o["valid_until"])
}

fn source_observation(value: &Value) -> bool {
    exact_keys(
        value,
        &keys_with(&["artifact_ref", "classification", "tenant_id", "trust_domain"]),
    )
    .is_some_and(|o| {
        observation_fields(o)
            && is_artifact_ref(&o["artifact_ref"])
            && ["classification", "tenant_id", "trust_domain"]
                .iter()
                .all(|k| is_identifier(&o[*k]))
    })
}

const PROCESSOR_IDS: [&str; 8] = [
    "contract_id",
    "run_id",
    "tenant_id",
    "processor_id",
    "destination_id",
    "destination_tenant_id",
    "destination_trust_domain",
    "residency_region",
];

fn processor_observation(value: &Value) -> bool {
    exact_keys(value, &keys_with(&PROCESSOR_IDS))
        .is_some_and(|o| observation_fields(o) && PROCESSOR_IDS.iter().all(|k| is_identifier(&o[*k])))
}

fn transformation_observation(value: &Value) -> bool {
    exact_keys(
        value,
        &keys_with(&[
            "transformation_id",
            "source_refs",
            "result_ref",
            "result_classification",
            "policy_ref",
            "purpose_id",
            "destination_id",
            "release_status",
            "approval_ref",
            "destination_tenant_id",
            "destination_trust_domain",
            "operation_id",
            "action_digest",
            "processor_id",
            "stage",
        ]),
    )
    .is_some_and(|o| {
        observation_fields(o)
            && [
                "transformation_id",
                "result_classification",
                "purpose_id",
                "destination_id",
                "destination_tenant_id",
                "destination_trust_domain",
                "operation_id",
                "processor_id",
            ]
            .iter()
            .all(|k| is_identifier(&o[*k]))
            && is_digest(&o["action_digest"])
            && stage(&o["stage"])
            && artifact_refs(&o["source_refs"])
            && o["source_refs"].as_array().is_some_and(|a| !a.is_empty())
            && is_artifact_ref(&o["result_ref"])
            && is_artifact_ref(&o["policy_ref"])
            && is_artifact_ref(&o["approval_ref"])
            && matches!(o["release_status"].as_str(), Some("approved" | "denied" | "unknown"))
    })
}

fn flow_request(value: &Value) -> bool {
    exact_keys(
        value,
        &[
            "contract_id",
            "run_id",
            "tenant_id",
            "operation_id",
            "action_digest",
            "policy_ref",
            "source_artifacts",
            "source_trust_domain",
            "destination_tenant_id",
            "destination_trust_domain",
            "destination_id",
            "purpose_id",
            "stage",
            "requested_classification",
            "processor_id",
            "processor_observation",
            "transformation",
        ],
    )
    .is_some_and(|o| {
        [
            "contract_id",
            "run_id",
            "tenant_id",
            "operation_id",
            "source_trust_domain",
            "destination_tenant_id",
            "destination_trust_domain",
            "destination_id",
            "purpose_id",
            "requested_classification",
            "processor_id",
        ]
        .iter()
        .all(|k| is_identifier(&o[*k]))
            && is_digest(&o["action_digest"])
            && is_artifact_ref(&o["policy_ref"])
            && list(&o["source_artifacts"], |item| {
                exact_keys(item, &["artifact_ref", "classification"])
                    .is_some_and(|i| is_artifact_ref(&i["artifact_ref"]) && is_identifier(&i["classification"]))
            })
            && o["source_artifacts"].as_array().is_some_and(|a| !a.is_empty())
            && stage(&o["stage"])
            && processor_observation(&o["processor_observation"])
            && (o["transformation"].is_null() || transformation_observation(&o["transformation"]))
    })
}

fn flow_rule(value: &Value) -> bool {
    exact_keys(
        value,
        &[
            "source_trust_domain",
            "destination_trust_domain",
            "destination_tenant_id",
            "destination_id",
            "purpose_id",
            "stages",
            "source_classifications",
            "destination_classifications",
            "processor_ids",
            "residency_regions",
            "transformation_ids",
        ],
    )
    .is_some_and(|o| {
        [
            "source_trust_domain",
            "destination_trust_domain",
            "destination_tenant_id",
            "destination_id",
            "purpose_id",
        ]
        .iter()
        .all(|k| is_identifier(&o[*k]))
            && list(&o["stages"], stage)
            && [
                "source_classifications",
                "destination_classifications",
                "processor_ids",
                "residency_regions",
                "transformation_ids",
            ]
            .iter()
            .all(|k| strings(&o[*k]))
    })
}

fn flow_policy(value: &Value) -> bool {
    exact_keys(
        value,
        &[
            "policy_ref",
            "contract_id",
            "run_id",
            "tenant_id",
            "not_before",
            "expires_at",
            "known_classifications",
            "label_combinations",
            "maximum_observation_age_seconds",
            "trusted_observers",
            "source_observations",
            "allowed_flows",
        ],
    )
    .is_some_and(|o| {
        is_artifact_ref(&o["policy_ref"])
            && ["contract_id", "run_id", "tenant_id"]
                .iter()
                .all(|k| is_identifier(&o[*k]))
            && is_timestamp(&o["not_before"])
            && is_timestamp(&o["expires_at"])
            && strings(&o["known_classifications"])
            && o["known_classifications"]
                .as_array()
                .is_some_and(|k| !k.is_empty() && k.iter().map(encoded).collect::<HashSet<_>>().len() == k.len())
            && is_safe_non_negative_integer(&o["maximum_observation_age_seconds"])
            && list(&o["trusted_observers"], valid_principal)
            && list(&o["source_observations"], source_observation)
            && list(&o["allowed_flows"], flow_rule)
            && list(&o["label_combinations"], |entry| {
                exact_keys(entry, &["inputs", "output"]).is_some_and(|e| {
                    strings(&e["inputs"])
                        && e["inputs"].as_array().is_some_and(|i| !i.is_empty())
                        && is_identifier(&e["output"])
                })
            })
    })
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DataFlowDecision {
    pub allowed: bool,
    pub reason_codes: Vec<String>,
    pub evaluation_time: String,
    pub policy_ref: Option<Value>,
    pub artifact_refs: Vec<Value>,
    pub classification: Option<String>,
    pub unsatisfied_obligations: Vec<String>,
    pub contract_id: Option<String>,
    pub run_id: Option<String>,
    pub operation_id: Option<String>,
    pub action_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub propagation_status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completion_verified: Option<bool>,
}

fn unique_sorted_labels(inputs: &Value) -> Vec<String> {
    sorted(inputs.as_array().into_iter().flatten().map(|v| s(v).to_owned()))
}

/// Applies a pinned, finite data policy: actual recipient and trust domain, purpose,
/// stage, classification (including label combination and verified transformation),
/// processor and residency. Unknown or unverifiable facts deny.
pub fn evaluate_data_flow(request: &Value, policy: &Value, evaluation_time: &Value) -> DataFlowDecision {
    let mut reasons: HashSet<String> = HashSet::new();
    let mut decision = DataFlowDecision {
        allowed: false,
        reason_codes: vec![],
        evaluation_time: time_label(evaluation_time),
        policy_ref: None,
        artifact_refs: vec![],
        classification: None,
        unsatisfied_obligations: vec![],
        contract_id: None,
        run_id: None,
        operation_id: None,
        action_digest: None,
        propagation_status: None,
        completion_verified: None,
    };
    let finish = |mut decision: DataFlowDecision, reasons: HashSet<String>| {
        decision.allowed = reasons.is_empty();
        decision.reason_codes = sorted(reasons);
        decision.unsatisfied_obligations.clone_from(&decision.reason_codes);
        decision
    };
    if contextos_contract::canonical::check_canonical(policy).is_err()
        || contextos_contract::canonical::check_canonical(request).is_err()
        || !flow_policy(policy)
    {
        reasons.insert("policy_unavailable".into());
        return finish(decision, reasons);
    }
    decision.policy_ref = Some(policy["policy_ref"].clone());
    if !flow_request(request) {
        reasons.insert("data_flow_invalid".into());
        return finish(decision, reasons);
    }
    decision.contract_id = Some(s(&request["contract_id"]).to_owned());
    decision.run_id = Some(s(&request["run_id"]).to_owned());
    decision.operation_id = Some(s(&request["operation_id"]).to_owned());
    decision.action_digest = Some(s(&request["action_digest"]).to_owned());
    let mut add = |code: &str| {
        reasons.insert(code.to_owned());
    };
    if !identical(&request["policy_ref"], &policy["policy_ref"])
        || !within(evaluation_time, &policy["not_before"], &policy["expires_at"])
    {
        add("policy_unavailable");
    }
    if request["contract_id"] != policy["contract_id"]
        || request["run_id"] != policy["run_id"]
        || request["tenant_id"] != policy["tenant_id"]
    {
        add("tenant_mismatch");
    }
    let known: HashSet<&str> = policy["known_classifications"]
        .as_array()
        .expect("validated")
        .iter()
        .map(s)
        .collect();
    let valid_labels = |labels: Vec<&Value>| labels.iter().all(|l| known.contains(s(l)));
    let combinations = policy["label_combinations"].as_array().expect("validated");
    let mut combination_keys: HashSet<Vec<String>> = HashSet::new();
    for combination in combinations {
        let key = unique_sorted_labels(&combination["inputs"]);
        let labels_ok = valid_labels(
            combination["inputs"]
                .as_array()
                .expect("validated")
                .iter()
                .chain(std::iter::once(&combination["output"]))
                .collect(),
        );
        if combination_keys.contains(&key) || !labels_ok {
            add("policy_unavailable");
        }
        combination_keys.insert(key);
    }
    let rules = policy["allowed_flows"].as_array().expect("validated");
    if rules.iter().any(|r| {
        !valid_labels(
            r["source_classifications"]
                .as_array()
                .expect("validated")
                .iter()
                .chain(r["destination_classifications"].as_array().expect("validated").iter())
                .collect(),
        )
    }) {
        add("policy_unavailable");
    }
    let trusted = policy["trusted_observers"].as_array().expect("validated");
    let current = |o: &Value| {
        o["verification_status"] == "verified"
            && o["observer"]["tenant_id"] == policy["tenant_id"]
            && trusted.iter().any(|t| identical(t, &o["observer"]))
            && within(evaluation_time, &o["observed_at"], &o["valid_until"])
            && age_ok(
                evaluation_time,
                &o["observed_at"],
                &policy["maximum_observation_age_seconds"],
            )
    };
    let sources = request["source_artifacts"].as_array().expect("validated");
    let source_refs: Vec<Value> = sources.iter().map(|src| src["artifact_ref"].clone()).collect();
    if source_refs.iter().map(encoded).collect::<HashSet<_>>().len() != source_refs.len() {
        add("classification_denied");
    }
    let observations = policy["source_observations"].as_array().expect("validated");
    let mut labels: Vec<String> = Vec::new();
    for source in sources {
        if !known.contains(s(&source["classification"])) {
            add("classification_unknown");
        }
        let matches: Vec<&Value> = observations
            .iter()
            .filter(|o| identical(&o["artifact_ref"], &source["artifact_ref"]))
            .collect();
        let observed = matches.first().copied();
        if matches.len() != 1
            || observed.is_none_or(|o| {
                !current(o)
                    || o["tenant_id"] != request["tenant_id"]
                    || o["trust_domain"] != request["source_trust_domain"]
                    || o["classification"] != source["classification"]
            })
        {
            add("classification_denied");
        }
        if let Some(o) = observed {
            let label = s(&o["classification"]).to_owned();
            if !labels.contains(&label) {
                labels.push(label.clone());
            }
            if !known.contains(label.as_str()) {
                add("classification_unknown");
            }
        }
    }
    let input_labels = sorted(labels);
    let mut classification: Option<String> = None;
    if input_labels.len() == 1 {
        classification = Some(input_labels[0].clone());
    } else if let Some(combination) = combinations
        .iter()
        .find(|c| unique_sorted_labels(&c["inputs"]) == input_labels)
    {
        classification = Some(s(&combination["output"]).to_owned());
    } else {
        add("classification_denied");
    }
    if !known.contains(s(&request["requested_classification"])) {
        add("classification_unknown");
    }
    let mut candidates: Vec<&Value> = rules
        .iter()
        .filter(|r| {
            r["source_trust_domain"] == request["source_trust_domain"]
                && r["destination_tenant_id"] == request["destination_tenant_id"]
                && r["destination_trust_domain"] == request["destination_trust_domain"]
                && r["destination_id"] == request["destination_id"]
        })
        .collect();
    if candidates.is_empty() {
        add("destination_denied");
    }
    candidates.retain(|r| r["purpose_id"] == request["purpose_id"]);
    if candidates.is_empty() {
        add("purpose_denied");
    }
    let contains = |list: &Value, item: &Value| list.as_array().is_some_and(|l| l.contains(item));
    candidates.retain(|r| contains(&r["stages"], &request["stage"]));
    if candidates.is_empty() {
        add("processing_stage_denied");
    }
    candidates.retain(|r| {
        classification
            .as_ref()
            .is_some_and(|c| contains(&r["source_classifications"], &Value::String(c.clone())))
            && contains(&r["destination_classifications"], &request["requested_classification"])
    });
    if candidates.is_empty() {
        add("classification_denied");
    }
    let processor = &request["processor_observation"];
    if !current(processor)
        || processor["contract_id"] != request["contract_id"]
        || processor["run_id"] != request["run_id"]
        || processor["tenant_id"] != request["tenant_id"]
        || processor["processor_id"] != request["processor_id"]
        || processor["destination_id"] != request["destination_id"]
        || processor["destination_tenant_id"] != request["destination_tenant_id"]
        || processor["destination_trust_domain"] != request["destination_trust_domain"]
    {
        add("residency_unverified");
    }
    candidates.retain(|r| {
        contains(&r["processor_ids"], &processor["processor_id"])
            && contains(&r["residency_regions"], &processor["residency_region"])
    });
    if candidates.is_empty() {
        add("residency_unverified");
    }
    let transformation = &request["transformation"];
    let mut artifacts: Vec<Value> = Vec::new();
    if transformation.is_null() {
        if classification.as_deref() != Some(s(&request["requested_classification"])) {
            add("transformation_unverified");
        }
        if reasons.is_empty() {
            artifacts.clone_from(&source_refs);
        }
    } else {
        let t = transformation;
        let t_sources = t["source_refs"].as_array().expect("validated");
        if !current(t)
            || t["release_status"] != "approved"
            || !identical(&t["policy_ref"], &policy["policy_ref"])
            || t["result_classification"] != request["requested_classification"]
            || t["purpose_id"] != request["purpose_id"]
            || t["destination_id"] != request["destination_id"]
            || !same_artifact_refs(t_sources, &source_refs)
            || t["destination_tenant_id"] != request["destination_tenant_id"]
            || t["destination_trust_domain"] != request["destination_trust_domain"]
            || t["operation_id"] != request["operation_id"]
            || t["action_digest"] != request["action_digest"]
            || t["processor_id"] != request["processor_id"]
            || t["stage"] != request["stage"]
            || source_refs.iter().any(|r| identical(r, &t["result_ref"]))
            || !candidates
                .iter()
                .any(|r| contains(&r["transformation_ids"], &t["transformation_id"]))
        {
            add("transformation_unverified");
        }
        if reasons.is_empty() {
            classification = Some(s(&t["result_classification"]).to_owned());
            artifacts = vec![t["result_ref"].clone()];
        }
    }
    decision.classification = classification;
    decision.artifact_refs = artifacts;
    finish(decision, reasons)
}

// ─── Memory lifecycle ──────────────────────────────────────────────────────

fn memory_operation(value: &Value) -> bool {
    matches!(value.as_str(), Some("propose" | "promote" | "correct" | "delete"))
}

fn propagation_state(value: &Value) -> bool {
    matches!(
        value.as_str(),
        Some("pending" | "confirmed" | "failed" | "external_unknown")
    )
}

fn memory_review(value: &Value) -> bool {
    exact_keys(value, &keys_with(&["record_digest", "decision"])).is_some_and(|o| {
        observation_fields(o)
            && is_digest(&o["record_digest"])
            && matches!(o["decision"].as_str(), Some("approved" | "denied"))
    })
}

fn propagation_observation(value: &Value) -> bool {
    exact_keys(
        value,
        &keys_with(&["artifact_ref", "status", "record_id", "operation_id", "record_digest"]),
    )
    .is_some_and(|o| {
        observation_fields(o)
            && is_artifact_ref(&o["artifact_ref"])
            && propagation_state(&o["status"])
            && is_identifier(&o["record_id"])
            && is_identifier(&o["operation_id"])
            && is_digest(&o["record_digest"])
    })
}

fn memory_access(value: &Value) -> bool {
    exact_keys(value, &keys_with(&["tenant_id", "owner_id", "namespace", "purpose_id"])).is_some_and(|o| {
        observation_fields(o)
            && ["tenant_id", "owner_id", "namespace", "purpose_id"]
                .iter()
                .all(|k| is_identifier(&o[*k]))
    })
}

/// Maximum propagation receipts: the source memory plus 128 derived copies.
pub const MAX_PROPAGATION_ENTRIES: usize = 129;

fn memory_record(value: &Value) -> bool {
    exact_keys(
        value,
        &[
            "record_id",
            "memory_ref",
            "contract_id",
            "run_id",
            "operation_id",
            "action_digest",
            "tenant_id",
            "owner_id",
            "namespace",
            "purpose_id",
            "source_refs",
            "readers",
            "operation",
            "policy_ref",
            "retention_expires_at",
            "review",
            "derived_copy_refs",
            "propagation_entries",
            "propagation_status",
        ],
    )
    .is_some_and(|o| {
        [
            "record_id",
            "contract_id",
            "run_id",
            "operation_id",
            "tenant_id",
            "owner_id",
            "namespace",
            "purpose_id",
        ]
        .iter()
        .all(|k| is_identifier(&o[*k]))
            && is_artifact_ref(&o["memory_ref"])
            && is_digest(&o["action_digest"])
            && artifact_refs(&o["source_refs"])
            && o["source_refs"].as_array().is_some_and(|a| !a.is_empty())
            && strings(&o["readers"])
            && memory_operation(&o["operation"])
            && is_artifact_ref(&o["policy_ref"])
            && is_timestamp(&o["retention_expires_at"])
            && (o["review"].is_null() || memory_review(&o["review"]))
            && artifact_refs(&o["derived_copy_refs"])
            && bounded_array(
                &o["propagation_entries"],
                0,
                MAX_PROPAGATION_ENTRIES,
                propagation_observation,
            )
            && propagation_state(&o["propagation_status"])
    })
}

fn memory_context(value: &Value) -> bool {
    exact_keys(
        value,
        &[
            "tenant_id",
            "owner_id",
            "namespace",
            "purpose_id",
            "allowed_readers",
            "allowed_operations",
            "requires_review",
            "maximum_retention_expires_at",
            "retention_exception",
            "trusted_observers",
            "access_observation",
            "data_flow_request",
            "data_policy",
            "known_derived_copy_refs",
            "derived_inventory_status",
        ],
    )
    .is_some_and(|o| {
        ["tenant_id", "owner_id", "namespace", "purpose_id"]
            .iter()
            .all(|k| is_identifier(&o[*k]))
            && strings(&o["allowed_readers"])
            && list(&o["allowed_operations"], memory_operation)
            && list(&o["requires_review"], memory_operation)
            && is_timestamp(&o["maximum_retention_expires_at"])
            && matches!(o["retention_exception"].as_str(), Some("none" | "requires_escalation"))
            && list(&o["trusted_observers"], valid_principal)
            && memory_access(&o["access_observation"])
            && flow_request(&o["data_flow_request"])
            && flow_policy(&o["data_policy"])
            && artifact_refs(&o["known_derived_copy_refs"])
            && matches!(
                o["derived_inventory_status"].as_str(),
                Some("verified_complete" | "incomplete" | "external_unknown")
            )
    })
}

/// Digest of the lifecycle intent: the record without its review and propagation state.
pub fn memory_intent_digest(record: &Value) -> Option<String> {
    let mut intent = record.as_object()?.clone();
    for key in ["review", "propagation_entries", "propagation_status"] {
        intent.remove(key);
    }
    sha256_canonical(&json!({"domain": "contextos.memory_lifecycle_intent.v1", "intent": intent})).ok()
}

/// Record-level authority and truthfulness for propose/promote/correct/delete:
/// owned scope, permitted data flow into memory, finite retention, review bound to the
/// exact intent, tracked derived copies and honest propagation status. Completion is
/// verified only when every known copy confirms against a complete inventory.
pub fn validate_memory_lifecycle(record: &Value, context: &Value, evaluation_time: &Value) -> DataFlowDecision {
    if contextos_contract::canonical::check_canonical(record).is_err()
        || contextos_contract::canonical::check_canonical(context).is_err()
        || !memory_record(record)
        || !memory_context(context)
    {
        let code = vec!["memory_record_invalid".to_owned()];
        return DataFlowDecision {
            allowed: false,
            reason_codes: code.clone(),
            evaluation_time: time_label(evaluation_time),
            policy_ref: None,
            artifact_refs: vec![],
            classification: None,
            unsatisfied_obligations: code,
            contract_id: None,
            run_id: None,
            operation_id: None,
            action_digest: None,
            propagation_status: Some("pending".into()),
            completion_verified: Some(false),
        };
    }
    let request = &context["data_flow_request"];
    let flow = evaluate_data_flow(request, &context["data_policy"], evaluation_time);
    let mut reasons: HashSet<String> = flow.reason_codes.iter().cloned().collect();
    let mut add = |code: &str| {
        reasons.insert(code.to_owned());
    };
    if ["tenant_id", "owner_id", "namespace", "purpose_id"]
        .iter()
        .any(|k| record[*k] != context[*k])
    {
        add("memory_scope_mismatch");
    }
    let request_sources: Vec<Value> = request["source_artifacts"]
        .as_array()
        .expect("validated")
        .iter()
        .map(|x| x["artifact_ref"].clone())
        .collect();
    if record["contract_id"] != request["contract_id"]
        || record["run_id"] != request["run_id"]
        || record["operation_id"] != request["operation_id"]
        || record["action_digest"] != request["action_digest"]
        || request["stage"] != "memory"
        || s(&request["destination_id"]) != format!("memory:{}", s(&record["namespace"]))
        || request["purpose_id"] != record["purpose_id"]
        || request["destination_tenant_id"] != record["tenant_id"]
        || request["tenant_id"] != record["tenant_id"]
        || !identical(&record["policy_ref"], &context["data_policy"]["policy_ref"])
        || !same_artifact_refs(record["source_refs"].as_array().expect("validated"), &request_sources)
    {
        add("memory_scope_mismatch");
    }
    let allowed_readers = context["allowed_readers"].as_array().expect("validated");
    if !context["allowed_operations"]
        .as_array()
        .expect("validated")
        .contains(&record["operation"])
        || record["readers"]
            .as_array()
            .expect("validated")
            .iter()
            .any(|r| !allowed_readers.contains(r))
    {
        add("memory_scope_mismatch");
    }
    let trusted = context["trusted_observers"].as_array().expect("validated");
    let max_age = &context["data_policy"]["maximum_observation_age_seconds"];
    let current = |o: &Value| {
        o["verification_status"] == "verified"
            && o["observer"]["tenant_id"] == context["tenant_id"]
            && trusted.iter().any(|t| identical(t, &o["observer"]))
            && within(evaluation_time, &o["observed_at"], &o["valid_until"])
            && age_ok(evaluation_time, &o["observed_at"], max_age)
    };
    let access = &context["access_observation"];
    if !current(access)
        || ["tenant_id", "owner_id", "namespace", "purpose_id"]
            .iter()
            .any(|k| access[*k] != record[*k])
    {
        add("memory_access_unverified");
    }
    if context["retention_exception"] == "requires_escalation" {
        add("retention_escalation_required");
    }
    if record["operation"] != "delete"
        && (compare_contract_times(s(evaluation_time), s(&record["retention_expires_at"]))
            != Some(std::cmp::Ordering::Less)
            || compare_contract_times(
                s(&record["retention_expires_at"]),
                s(&context["maximum_retention_expires_at"]),
            ) == Some(std::cmp::Ordering::Greater))
    {
        add("memory_retention_invalid");
    }
    let intent_digest = memory_intent_digest(record).unwrap_or_default();
    let review = &record["review"];
    let review_required = context["requires_review"]
        .as_array()
        .expect("validated")
        .contains(&record["operation"]);
    if (review_required && review.is_null())
        || (!review.is_null()
            && (!current(review)
                || review["decision"] != "approved"
                || review["record_digest"] != intent_digest.as_str()))
    {
        add("memory_review_unverified");
    }
    let derived = record["derived_copy_refs"].as_array().expect("validated");
    if !same_artifact_refs(
        derived,
        context["known_derived_copy_refs"].as_array().expect("validated"),
    ) {
        add("memory_copy_tracking_invalid");
    }
    let targets: Vec<Value> = std::iter::once(record["memory_ref"].clone())
        .chain(derived.iter().cloned())
        .collect();
    let target_keys: HashSet<String> = targets.iter().map(encoded).collect();
    if target_keys.len() != targets.len() {
        add("memory_copy_tracking_invalid");
    }
    let current_entry = |e: &Value| {
        current(e)
            && e["record_id"] == record["record_id"]
            && e["operation_id"] == record["operation_id"]
            && e["record_digest"] == intent_digest.as_str()
    };
    let entries_list = record["propagation_entries"].as_array().expect("validated");
    let mut entries: HashMap<String, &Value> = HashMap::new();
    for entry in entries_list {
        let key = encoded(&entry["artifact_ref"]);
        if entries.contains_key(&key) || !target_keys.contains(&key) {
            add("memory_copy_tracking_invalid");
        }
        if !current_entry(entry) {
            add("memory_propagation_unverified");
        }
        entries.insert(key, entry);
    }
    let inventory = s(&context["derived_inventory_status"]);
    let state = if entries_list.iter().any(|e| e["status"] == "failed" && current_entry(e)) {
        "failed"
    } else if inventory == "external_unknown"
        || entries_list
            .iter()
            .any(|e| e["status"] == "external_unknown" && current_entry(e))
    {
        "external_unknown"
    } else if inventory == "verified_complete"
        && targets.iter().all(|t| {
            entries
                .get(&encoded(t))
                .is_some_and(|e| e["status"] == "confirmed" && current_entry(e))
        })
    {
        "confirmed"
    } else {
        "pending"
    };
    if record["propagation_status"] != state {
        add("memory_propagation_incomplete");
    }
    let reason_codes = sorted(reasons);
    let allowed = reason_codes.is_empty();
    DataFlowDecision {
        allowed,
        unsatisfied_obligations: reason_codes.clone(),
        reason_codes,
        policy_ref: Some(record["policy_ref"].clone()),
        artifact_refs: targets,
        propagation_status: Some(state.into()),
        completion_verified: Some(allowed && state == "confirmed"),
        ..flow
    }
}
