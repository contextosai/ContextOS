//! Authority, policy composition, approval binding and the conjunctive authorization
//! decision for one proposed effect.
//!
//! Every function consumes facts that trusted adapters have already verified
//! (signatures, live revocation, entitlement lookups) and checks that they are
//! current, correctly scoped and exactly bound to the proposed action. None of them
//! performs that verification itself, and none of them dispatches anything.
//!
//! The action binding digest is `sha256` over RFC 8785 JSON of
//! `{"domain": "contextos.action_binding.v1", "payload"/"binding": …}`; any change to
//! the proposal — arguments, resources, amount, evidence or policy refs — changes the
//! digest and voids approvals bound to the old one.

use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};

use contextos_contract::canonical::{CanonicalError, canonicalize, sha256_canonical, utf16_cmp};
use contextos_contract::shape::{
    as_safe_integer, bounded_array, exact_keys, exact_keys_with_optional, is_artifact_ref, is_control_ref, is_digest,
    is_identifier, is_safe_non_negative_integer, is_timestamp,
};
use contextos_contract::validation::{compare_contract_times, is_within_contract_interval};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

const CLASSIFICATIONS: [&str; 4] = ["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"];
const MAX_LIST: usize = 128;
const MAX_CHAIN: usize = 16;
const MAX_SAFE_INTEGER: i64 = (1 << 53) - 1;

fn s(value: &Value) -> &str {
    value.as_str().unwrap_or_default()
}

fn same_json(a: &Value, b: &Value) -> bool {
    contextos_contract::canonical::canonical_eq(a, b)
}

fn encoded(value: &Value) -> String {
    canonicalize(value).unwrap_or_default()
}

fn sorted_codes(codes: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut out: Vec<String> = codes.into_iter().collect::<HashSet<_>>().into_iter().collect();
    out.sort_by(|a, b| utf16_cmp(a, b));
    out
}

fn within(time: &Value, start: &Value, end: &Value) -> bool {
    is_within_contract_interval(s(time), s(start), s(end))
}

fn cmp_times(a: &Value, b: &Value) -> Option<Ordering> {
    compare_contract_times(s(a), s(b))
}

fn list(value: &Value, max: usize, guard: impl Fn(&Value) -> bool) -> bool {
    bounded_array(value, 0, max, guard)
}

fn refs(value: &Value, min: usize) -> bool {
    bounded_array(value, min, MAX_LIST, is_artifact_ref)
}

fn ids(value: &Value) -> bool {
    bounded_array(value, 0, MAX_LIST, is_identifier)
}

fn verification_status(value: &Value) -> bool {
    matches!(s(value), "verified" | "invalid" | "unavailable") && value.is_string()
}

pub fn valid_principal(value: &Value) -> bool {
    exact_keys(value, &["principal_id", "principal_type", "trust_domain", "tenant_id"]).is_some_and(|o| {
        is_identifier(&o["principal_id"])
            && is_identifier(&o["trust_domain"])
            && is_identifier(&o["tenant_id"])
            && matches!(o["principal_type"].as_str(), Some("person" | "workload" | "agent"))
    })
}

fn valid_amount(value: &Value) -> bool {
    exact_keys(value, &["minor_units", "currency"]).is_some_and(|o| {
        is_safe_non_negative_integer(&o["minor_units"])
            && o["currency"]
                .as_str()
                .is_some_and(|c| c.len() == 3 && c.bytes().all(|b| b.is_ascii_uppercase()))
    })
}

fn valid_risk(value: &Value) -> bool {
    exact_keys_with_optional(
        value,
        &["effect", "authority", "reversibility", "interaction", "data_scope"],
        &["decision_ttl_seconds"],
    )
    .is_some_and(|o| {
        matches!(
            o["effect"].as_str(),
            Some("none" | "local_state" | "external_state" | "physical_world")
        ) && matches!(
            o["authority"].as_str(),
            Some("agent" | "service" | "user_delegated" | "human_approved")
        ) && matches!(
            o["reversibility"].as_str(),
            Some("read_only" | "reversible" | "compensatable" | "irreversible")
        ) && matches!(
            o["interaction"].as_str(),
            Some("api" | "browser" | "computer" | "agent_to_agent" | "human_handoff")
        ) && o["data_scope"].as_str().is_some_and(|d| CLASSIFICATIONS.contains(&d))
            && o.get("decision_ttl_seconds").is_none_or(is_safe_non_negative_integer)
    })
}

const BINDING_KEYS: [&str; 19] = [
    "binding_version",
    "contract_id",
    "run_id",
    "tenant_id",
    "operation_id",
    "proposal_id",
    "actor",
    "authority_refs",
    "purpose_id",
    "capability_id",
    "capability_version",
    "arguments",
    "resource_ids",
    "destination_ids",
    "evidence_refs",
    "policy_refs",
    "profile_refs",
    "release_refs",
    "action_risk",
];

/// Exact shape of an `ActionBinding` (`contextos.action_binding.v1`).
pub fn valid_binding(value: &Value) -> bool {
    exact_keys_with_optional(value, &BINDING_KEYS, &["amount"]).is_some_and(|o| {
        o["binding_version"] == "contextos.action_binding.v1"
            && [
                "contract_id",
                "run_id",
                "tenant_id",
                "operation_id",
                "proposal_id",
                "purpose_id",
                "capability_id",
                "capability_version",
            ]
            .iter()
            .all(|k| is_identifier(&o[*k]))
            && valid_principal(&o["actor"])
            && refs(&o["authority_refs"], 1)
            && ids(&o["resource_ids"])
            && ids(&o["destination_ids"])
            && refs(&o["evidence_refs"], 0)
            && refs(&o["policy_refs"], 1)
            && refs(&o["profile_refs"], 1)
            && refs(&o["release_refs"], 1)
            && o["arguments"].is_object()
            && valid_risk(&o["action_risk"])
            && o.get("amount").is_none_or(valid_amount)
    })
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BindingError {
    #[error(transparent)]
    Canonical(#[from] CanonicalError),
    #[error("Invalid action binding")]
    Invalid,
}

/// Digest of the complete proposal. It binds data; it does not establish permission
/// or authenticity.
pub fn digest_action_binding(binding: &Value) -> Result<String, BindingError> {
    canonicalize(binding)?;
    if !valid_binding(binding) {
        return Err(BindingError::Invalid);
    }
    Ok(sha256_canonical(
        &json!({"domain": "contextos.action_binding.v1", "binding": binding}),
    )?)
}

// ─── Authority ─────────────────────────────────────────────────────────────

fn valid_pointer(value: &Value) -> bool {
    let Some(p) = value.as_str() else { return false };
    if p.encode_utf16().count() > 256 || !(p.is_empty() || p.starts_with('/')) {
        return false;
    }
    let bytes = p.as_bytes();
    bytes
        .iter()
        .enumerate()
        .all(|(i, b)| *b != b'~' || matches!(bytes.get(i + 1), Some(b'0' | b'1')))
}

fn valid_constraint(value: &Value) -> bool {
    let Some(kind) = value.as_object().and_then(|o| o.get("kind")) else {
        return false;
    };
    let kind = kind.as_str().unwrap_or_default();
    match kind {
        "equals" => exact_keys(value, &["pointer", "kind", "value"]).is_some_and(|o| valid_pointer(&o["pointer"])),
        "one_of" => exact_keys(value, &["pointer", "kind", "values"]).is_some_and(|o| {
            valid_pointer(&o["pointer"])
                && o["values"]
                    .as_array()
                    .is_some_and(|v| !v.is_empty() && v.len() <= MAX_LIST)
        }),
        "max_integer" => exact_keys(value, &["pointer", "kind", "maximum"])
            .is_some_and(|o| valid_pointer(&o["pointer"]) && is_safe_non_negative_integer(&o["maximum"])),
        _ => false,
    }
}

fn valid_scope(value: &Value) -> bool {
    exact_keys_with_optional(
        value,
        &[
            "root_run_id",
            "purpose_ids",
            "capability_ids",
            "resource_ids",
            "destination_ids",
            "classification_labels",
            "argument_constraints",
        ],
        &["amount_ceiling"],
    )
    .is_some_and(|o| {
        is_identifier(&o["root_run_id"])
            && ["purpose_ids", "capability_ids", "resource_ids", "destination_ids"]
                .iter()
                .all(|k| ids(&o[*k]))
            && list(&o["classification_labels"], MAX_LIST, |l| {
                l.as_str().is_some_and(|l| CLASSIFICATIONS.contains(&l))
            })
            && list(&o["argument_constraints"], MAX_LIST, valid_constraint)
            && {
                let pointers: Vec<&str> = o["argument_constraints"]
                    .as_array()
                    .map(|a| a.iter().map(|c| s(&c["pointer"])).collect())
                    .unwrap_or_default();
                pointers.iter().collect::<HashSet<_>>().len() == pointers.len()
            }
            && o.get("amount_ceiling").is_none_or(valid_amount)
    })
}

fn valid_grant_ref(value: &Value) -> bool {
    exact_keys(value, &["grant_id", "grant_revision"])
        .is_some_and(|o| is_identifier(&o["grant_id"]) && is_identifier(&o["grant_revision"]))
}

fn valid_grant(value: &Value) -> bool {
    exact_keys_with_optional(
        value,
        &[
            "grant_id",
            "grant_revision",
            "issuer",
            "subject",
            "audience",
            "scope",
            "not_before",
            "expires_at",
            "delegation_depth_remaining",
            "verification_ref",
        ],
        &["parent_grant_ref"],
    )
    .is_some_and(|o| {
        is_identifier(&o["grant_id"])
            && is_identifier(&o["grant_revision"])
            && valid_principal(&o["issuer"])
            && valid_principal(&o["subject"])
            && is_identifier(&o["audience"])
            && valid_scope(&o["scope"])
            && is_timestamp(&o["not_before"])
            && is_timestamp(&o["expires_at"])
            && as_safe_integer(&o["delegation_depth_remaining"]).is_some_and(|d| (0..=16).contains(&d))
            && is_artifact_ref(&o["verification_ref"])
            && o.get("parent_grant_ref").is_none_or(valid_grant_ref)
    })
}

fn valid_observation(value: &Value) -> bool {
    exact_keys(
        value,
        &[
            "grant_id",
            "grant_revision",
            "grant_digest",
            "verification_ref",
            "verification_status",
            "observed_at",
            "valid_until",
            "revocation_status",
            "observer",
        ],
    )
    .is_some_and(|o| {
        is_identifier(&o["grant_id"])
            && is_identifier(&o["grant_revision"])
            && is_digest(&o["grant_digest"])
            && is_artifact_ref(&o["verification_ref"])
            && verification_status(&o["verification_status"])
            && is_timestamp(&o["observed_at"])
            && is_timestamp(&o["valid_until"])
            && matches!(o["revocation_status"].as_str(), Some("active" | "revoked" | "unknown"))
            && valid_principal(&o["observer"])
    })
}

fn valid_authenticated(value: &Value) -> bool {
    exact_keys_with_optional(
        value,
        &[
            "principal",
            "audience",
            "root_run_id",
            "run_id",
            "mandate_kind",
            "trusted_issuers",
            "trusted_observers",
            "verification_status",
            "verification_ref",
            "observed_at",
            "valid_until",
        ],
        &["mandating_person"],
    )
    .is_some_and(|o| {
        valid_principal(&o["principal"])
            && ["audience", "root_run_id", "run_id"]
                .iter()
                .all(|k| is_identifier(&o[*k]))
            && list(&o["trusted_issuers"], MAX_LIST, valid_principal)
            && list(&o["trusted_observers"], MAX_LIST, valid_principal)
            && verification_status(&o["verification_status"])
            && is_artifact_ref(&o["verification_ref"])
            && is_timestamp(&o["observed_at"])
            && is_timestamp(&o["valid_until"])
            && match (o["mandate_kind"].as_str(), o.get("mandating_person")) {
                (Some("workload"), None) => true,
                (Some("person_directed"), Some(person)) => {
                    valid_principal(person) && person["principal_type"] == "person"
                }
                _ => false,
            }
    })
}

fn valid_run_link(value: &Value) -> bool {
    exact_keys(
        value,
        &[
            "parent_run_id",
            "child_run_id",
            "root_run_id",
            "tenant_id",
            "subject",
            "observer",
            "verification_status",
            "verification_ref",
            "observed_at",
            "valid_until",
        ],
    )
    .is_some_and(|o| {
        ["parent_run_id", "child_run_id", "root_run_id", "tenant_id"]
            .iter()
            .all(|k| is_identifier(&o[*k]))
            && valid_principal(&o["subject"])
            && valid_principal(&o["observer"])
            && verification_status(&o["verification_status"])
            && is_artifact_ref(&o["verification_ref"])
            && is_timestamp(&o["observed_at"])
            && is_timestamp(&o["valid_until"])
    })
}

/// RFC 6901 lookup over own JSON members (array `length` included, as in JavaScript).
fn pointer_value<'a>(root: &'a Value, pointer: &str) -> Option<std::borrow::Cow<'a, Value>> {
    if pointer.is_empty() {
        return Some(std::borrow::Cow::Borrowed(root));
    }
    let mut current = std::borrow::Cow::Borrowed(root);
    for segment in pointer[1..].split('/') {
        let key = segment.replace("~1", "/").replace("~0", "~");
        current = match current {
            std::borrow::Cow::Borrowed(Value::Object(map)) => std::borrow::Cow::Borrowed(map.get(&key)?),
            std::borrow::Cow::Borrowed(Value::Array(items)) => {
                if key == "length" {
                    std::borrow::Cow::Owned(Value::from(items.len()))
                } else {
                    let index = canonical_index(&key)?;
                    std::borrow::Cow::Borrowed(items.get(index)?)
                }
            }
            _ => return None,
        };
    }
    Some(current)
}

fn canonical_index(key: &str) -> Option<usize> {
    if key == "0" {
        return Some(0);
    }
    if key.is_empty() || key.starts_with('0') || !key.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    key.parse().ok()
}

fn satisfies(value: &Value, constraint: &Value) -> bool {
    match s(&constraint["kind"]) {
        "equals" => same_json(value, &constraint["value"]),
        "one_of" => constraint["values"]
            .as_array()
            .is_some_and(|v| v.iter().any(|c| same_json(value, c))),
        _ => as_safe_integer(value)
            .zip(as_safe_integer(&constraint["maximum"]))
            .is_some_and(|(v, max)| v >= 0 && v <= max),
    }
}

fn constraint_narrows(child: &Value, parent: &Value) -> bool {
    match s(&child["kind"]) {
        "equals" => satisfies(&child["value"], parent),
        "one_of" => child["values"]
            .as_array()
            .is_some_and(|v| v.iter().all(|c| satisfies(c, parent))),
        _ => {
            parent["kind"] == "max_integer" && as_safe_integer(&child["maximum"]) <= as_safe_integer(&parent["maximum"])
        }
    }
}

fn subset(child: &Value, parent: &Value) -> bool {
    let parent: Vec<&Value> = parent.as_array().map(|a| a.iter().collect()).unwrap_or_default();
    child.as_array().is_none_or(|c| c.iter().all(|v| parent.contains(&v)))
}

fn scope_narrows(child: &Value, parent: &Value) -> bool {
    child["root_run_id"] == parent["root_run_id"]
        && [
            "purpose_ids",
            "capability_ids",
            "resource_ids",
            "destination_ids",
            "classification_labels",
        ]
        .iter()
        .all(|k| subset(&child[*k], &parent[*k]))
        && parent["argument_constraints"]
            .as_array()
            .into_iter()
            .flatten()
            .all(|required| {
                child["argument_constraints"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .any(|candidate| {
                        candidate["pointer"] == required["pointer"] && constraint_narrows(candidate, required)
                    })
            })
        && match (parent.get("amount_ceiling"), child.get("amount_ceiling")) {
            (None, _) => true,
            (Some(_), None) => false,
            (Some(p), Some(c)) => {
                c["currency"] == p["currency"]
                    && as_safe_integer(&c["minor_units"]) <= as_safe_integer(&p["minor_units"])
            }
        }
}

fn contains(list: &Value, item: &Value) -> bool {
    list.as_array().is_some_and(|a| a.contains(item))
}

fn in_scope(binding: &Value, scope: &Value) -> bool {
    scope_mismatch(binding, scope).is_none()
}

/// Whether `value` is a well-formed `AuthorityGrant` scope.
pub fn valid_authority_scope(value: &Value) -> bool {
    valid_scope(value)
}

/// The first dimension in which an action binding falls outside a grant scope
/// (`purpose`, `capability`, `resource`, `destination`, `classification`, `argument`
/// or `amount`), or `None` when the scope covers it.
pub fn scope_mismatch(binding: &Value, scope: &Value) -> Option<&'static str> {
    if !contains(&scope["purpose_ids"], &binding["purpose_id"]) {
        return Some("purpose");
    }
    if !contains(&scope["capability_ids"], &binding["capability_id"]) {
        return Some("capability");
    }
    if !subset(&binding["resource_ids"], &scope["resource_ids"]) {
        return Some("resource");
    }
    if !subset(&binding["destination_ids"], &scope["destination_ids"]) {
        return Some("destination");
    }
    if !contains(&scope["classification_labels"], &binding["action_risk"]["data_scope"]) {
        return Some("classification");
    }
    let arguments_hold = scope["argument_constraints"]
        .as_array()
        .into_iter()
        .flatten()
        .all(|constraint| {
            pointer_value(&binding["arguments"], s(&constraint["pointer"])).is_some_and(|v| satisfies(&v, constraint))
        });
    if !arguments_hold {
        return Some("argument");
    }
    let amount_holds = match binding.get("amount") {
        None => true,
        Some(amount) => scope.get("amount_ceiling").is_some_and(|ceiling| {
            amount["currency"] == ceiling["currency"]
                && as_safe_integer(&amount["minor_units"]) <= as_safe_integer(&ceiling["minor_units"])
        }),
    };
    if !amount_holds {
        return Some("amount");
    }
    None
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuthorityValidationResult {
    pub allowed: bool,
    pub action_digest: Option<String>,
    pub grant_refs: Vec<Value>,
    pub reason_codes: Vec<String>,
}

fn grant_key(value: &Value) -> (String, String) {
    (s(&value["grant_id"]).to_owned(), s(&value["grant_revision"]).to_owned())
}

/// Validates the authenticated actor, the complete delegated grant chain, current
/// grant observations and the verified run lineage for one action binding.
pub fn validate_authority(input: &Value) -> AuthorityValidationResult {
    let mut reasons: HashSet<String> = HashSet::new();
    let mut action_digest = None;
    let mut grant_refs: Vec<Value> = Vec::new();
    macro_rules! finish {
        () => {
            return AuthorityValidationResult {
                allowed: reasons.is_empty(),
                action_digest,
                grant_refs,
                reason_codes: sorted_codes(reasons),
            }
        };
    }
    let add = |reasons: &mut HashSet<String>, code: &str| {
        reasons.insert(code.to_owned());
    };
    if contextos_contract::canonical::check_canonical(input).is_err() {
        add(&mut reasons, "grant_invalid");
        finish!();
    }
    let shape_ok = exact_keys(
        input,
        &[
            "binding",
            "authenticated",
            "leaf_grant_ref",
            "grants",
            "observations",
            "run_links",
            "evaluation_time",
        ],
    )
    .is_some_and(|o| {
        valid_binding(&o["binding"])
            && valid_authenticated(&o["authenticated"])
            && valid_grant_ref(&o["leaf_grant_ref"])
            && list(&o["grants"], MAX_CHAIN, valid_grant)
            && list(&o["observations"], MAX_CHAIN, valid_observation)
            && list(&o["run_links"], MAX_CHAIN, valid_run_link)
            && is_timestamp(&o["evaluation_time"])
    });
    if !shape_ok {
        add(&mut reasons, "grant_invalid");
        finish!();
    }
    let binding = &input["binding"];
    let auth = &input["authenticated"];
    let time = &input["evaluation_time"];
    let grants_list = input["grants"].as_array().expect("validated");
    let observations = input["observations"].as_array().expect("validated");
    let run_links = input["run_links"].as_array().expect("validated");
    action_digest = digest_action_binding(binding).ok();

    if auth["verification_status"] != "verified"
        || auth["principal"]["principal_type"] == "person"
        || !same_json(&auth["principal"], &binding["actor"])
        || auth["run_id"] != binding["run_id"]
    {
        add(&mut reasons, "identity_unverified");
    }
    if binding["actor"]["tenant_id"] != binding["tenant_id"] || auth["principal"]["tenant_id"] != binding["tenant_id"] {
        add(&mut reasons, "tenant_mismatch");
    }
    if !within(time, &auth["observed_at"], &auth["valid_until"]) {
        add(&mut reasons, "precondition_stale");
    }
    let mut grants: HashMap<(String, String), &Value> = HashMap::new();
    for grant in grants_list {
        grants.insert(grant_key(grant), grant);
    }
    if grants.len() != grants_list.len() {
        add(&mut reasons, "grant_invalid");
    }
    let mut chain: Vec<&Value> = Vec::new();
    let mut visited: HashSet<(String, String)> = HashSet::new();
    let mut next = Some(&input["leaf_grant_ref"]);
    while let Some(r) = next {
        let key = grant_key(r);
        let Some(grant) = grants
            .get(&key)
            .copied()
            .filter(|_| !visited.contains(&key) && chain.len() < MAX_CHAIN)
        else {
            add(&mut reasons, "grant_invalid");
            break;
        };
        chain.push(grant);
        visited.insert(key);
        next = grant.get("parent_grant_ref");
    }
    if chain.is_empty() || chain.len() != grants_list.len() {
        add(&mut reasons, "grant_invalid");
    }
    let (Some(leaf), Some(root)) = (chain.first().copied(), chain.last().copied()) else {
        finish!();
    };
    if !same_json(&leaf["subject"], &binding["actor"]) {
        add(&mut reasons, "identity_unverified");
    }
    let issuers = auth["trusted_issuers"].as_array().expect("validated");
    let trusted_observers = auth["trusted_observers"].as_array().expect("validated");
    if !issuers.iter().any(|i| same_json(i, &root["issuer"])) {
        add(&mut reasons, "identity_unverified");
    }
    let mandate = s(&auth["mandate_kind"]);
    if mandate == "person_directed" && !same_json(&root["issuer"], &auth["mandating_person"]) {
        add(&mut reasons, "identity_unverified");
    }
    if mandate == "workload" && root["issuer"]["principal_type"] == "person" {
        add(&mut reasons, "identity_unverified");
    }
    if binding["action_risk"]["authority"] == "user_delegated" && mandate != "person_directed" {
        add(&mut reasons, "identity_unverified");
    }
    grant_refs = chain.iter().map(|g| g["verification_ref"].clone()).collect();
    let expected: HashSet<String> = grant_refs.iter().map(encoded).collect();
    let bound: Vec<String> = binding["authority_refs"]
        .as_array()
        .into_iter()
        .flatten()
        .map(encoded)
        .collect();
    if expected.len() != chain.len()
        || bound.len() != expected.len()
        || bound.iter().collect::<HashSet<_>>().len() != expected.len()
        || bound.iter().any(|r| !expected.contains(r))
    {
        add(&mut reasons, "grant_invalid");
    }
    if observations.len() != chain.len() {
        add(&mut reasons, "grant_invalid");
    }
    let tenant = &binding["tenant_id"];
    for grant in &chain {
        if grant["subject"]["tenant_id"] != *tenant || grant["issuer"]["tenant_id"] != *tenant {
            add(&mut reasons, "tenant_mismatch");
        }
        if grant["audience"] != auth["audience"] || grant["scope"]["root_run_id"] != auth["root_run_id"] {
            add(&mut reasons, "scope_mismatch");
        }
        if !within(time, &grant["not_before"], &grant["expires_at"]) {
            add(&mut reasons, "grant_expired");
        }
        if !in_scope(binding, &grant["scope"]) {
            add(&mut reasons, "scope_mismatch");
        }
        let matches: Vec<&Value> = observations
            .iter()
            .filter(|o| grant_key(o) == grant_key(grant))
            .collect();
        let [observation] = matches.as_slice() else {
            add(&mut reasons, "verification_unavailable");
            continue;
        };
        let grant_digest = sha256_canonical(&json!({"domain": "contextos.authority_grant.v1", "grant": grant})).ok();
        if observation["verification_status"] != "verified"
            || !same_json(&observation["verification_ref"], &grant["verification_ref"])
            || observation["grant_digest"].as_str() != grant_digest.as_deref()
            || observation["observer"]["tenant_id"] != *tenant
            || !trusted_observers.iter().any(|t| same_json(t, &observation["observer"]))
        {
            add(&mut reasons, "verification_unavailable");
        }
        if !within(time, &observation["observed_at"], &observation["valid_until"]) {
            add(&mut reasons, "precondition_stale");
        }
        match s(&observation["revocation_status"]) {
            "revoked" => add(&mut reasons, "grant_revoked"),
            "unknown" => add(&mut reasons, "revocation_unknown"),
            _ => {}
        }
    }
    for pair in chain.windows(2) {
        let (child, parent) = (pair[0], pair[1]);
        let depth = |g: &Value| as_safe_integer(&g["delegation_depth_remaining"]).unwrap_or(0);
        if !same_json(&child["issuer"], &parent["subject"])
            || child["audience"] != parent["audience"]
            || !scope_narrows(&child["scope"], &parent["scope"])
            || depth(parent) == 0
            || depth(child) >= depth(parent)
            || cmp_times(&child["not_before"], &parent["not_before"]) == Some(Ordering::Less)
            || cmp_times(&child["expires_at"], &parent["expires_at"]) == Some(Ordering::Greater)
        {
            add(&mut reasons, "delegation_scope_expanded");
        }
    }
    if binding["run_id"] != auth["root_run_id"] {
        let mut run = s(&binding["run_id"]).to_owned();
        let mut depth = 0;
        let mut seen: HashSet<String> = HashSet::new();
        while run != s(&auth["root_run_id"]) {
            let matches: Vec<&Value> = run_links.iter().filter(|l| l["child_run_id"] == run.as_str()).collect();
            if seen.contains(&run) || depth >= MAX_CHAIN || matches.len() != 1 || depth + 1 >= chain.len() {
                add(&mut reasons, "grant_invalid");
                break;
            }
            let link = matches[0];
            seen.insert(run.clone());
            if link["verification_status"] != "verified"
                || !trusted_observers.iter().any(|t| same_json(t, &link["observer"]))
                || link["observer"]["tenant_id"] != *tenant
                || !same_json(&link["subject"], &chain[depth]["subject"])
            {
                add(&mut reasons, "verification_unavailable");
            }
            if link["tenant_id"] != *tenant || link["root_run_id"] != auth["root_run_id"] {
                add(&mut reasons, "tenant_mismatch");
            }
            if !within(time, &link["observed_at"], &link["valid_until"]) {
                add(&mut reasons, "precondition_stale");
            }
            run = s(&link["parent_run_id"]).to_owned();
            depth += 1;
        }
    }
    finish!();
}

// ─── Policy composition ────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ComposedPolicyOutcome {
    pub verdict: String,
    pub reason_codes: Vec<String>,
    pub obligations: Vec<String>,
    pub policy_refs: Vec<Value>,
    pub rule_ids: Vec<String>,
}

fn valid_policy_outcome(value: &Value) -> bool {
    exact_keys(
        value,
        &[
            "category",
            "priority",
            "verdict",
            "rule_id",
            "bundle_ref",
            "obligations",
        ],
    )
    .is_some_and(|o| {
        matches!(o["category"].as_str(), Some("guardrail" | "business"))
            && as_safe_integer(&o["priority"]).is_some()
            && matches!(
                o["verdict"].as_str(),
                Some("allow" | "deny" | "require_approval" | "escalate" | "error")
            )
            && is_identifier(&o["rule_id"])
            && is_artifact_ref(&o["bundle_ref"])
            && ids(&o["obligations"])
    })
}

/// Composes normalized applicable outcomes: any evaluation error fails visibly;
/// guardrail deny wins; then the highest business priority decides, deny winning at
/// equal priority; escalation and approval requirements from guardrails or winning
/// business rules apply. No applicable business rule means deny.
pub fn compose_policy_outcomes(outcomes: &Value) -> ComposedPolicyOutcome {
    let error = |code: &str| ComposedPolicyOutcome {
        verdict: "error".into(),
        reason_codes: vec![code.into()],
        obligations: vec![],
        policy_refs: vec![],
        rule_ids: vec![],
    };
    if contextos_contract::canonical::check_canonical(outcomes).is_err()
        || !list(outcomes, MAX_LIST, valid_policy_outcome)
    {
        return error("policy_invalid");
    }
    let mut normalized: Vec<((String, String, String), &Value)> = Vec::new();
    let mut bundles: HashMap<(String, String), String> = HashMap::new();
    for outcome in outcomes.as_array().expect("validated") {
        let r = &outcome["bundle_ref"];
        let bundle_key = (s(&r["artifact_type"]).to_owned(), s(&r["artifact_id"]).to_owned());
        let key = (
            bundle_key.0.clone(),
            bundle_key.1.clone(),
            s(&outcome["rule_id"]).to_owned(),
        );
        let ref_encoded = encoded(r);
        if bundles.get(&bundle_key).is_some_and(|e| *e != ref_encoded) {
            return error("policy_outcome_conflict");
        }
        if let Some(pos) = normalized.iter().position(|(k, _)| *k == key) {
            if !same_json(normalized[pos].1, outcome) {
                return error("policy_outcome_conflict");
            }
            normalized[pos].1 = outcome;
        } else {
            normalized.push((key, outcome));
        }
        bundles.insert(bundle_key, ref_encoded);
    }
    let all: Vec<&Value> = normalized.iter().map(|(_, o)| *o).collect();
    let guardrails: Vec<&Value> = all.iter().copied().filter(|o| o["category"] == "guardrail").collect();
    let business: Vec<&Value> = all.iter().copied().filter(|o| o["category"] == "business").collect();
    let priority = business.iter().filter_map(|o| as_safe_integer(&o["priority"])).max();
    let winning: Vec<&Value> = business
        .iter()
        .copied()
        .filter(|o| as_safe_integer(&o["priority"]) == priority)
        .collect();
    let obligations = sorted_codes(
        all.iter()
            .flat_map(|o| o["obligations"].as_array().into_iter().flatten())
            .map(|v| s(v).to_owned()),
    );
    if obligations.len() > MAX_LIST {
        return error("policy_invalid");
    }
    let has = |set: &[&Value], verdict: &str| set.iter().any(|o| o["verdict"] == verdict);
    let decisive: Vec<&Value> = guardrails.iter().chain(winning.iter()).copied().collect();
    let (verdict, reason) = if has(&all, "error") {
        ("error", Some("policy_eval_error"))
    } else if has(&guardrails, "deny") {
        ("deny", Some("guardrail_denied"))
    } else if business.is_empty() || has(&winning, "deny") {
        ("deny", Some("business_policy_denied"))
    } else if has(&decisive, "escalate") {
        ("escalate", Some("escalation_required"))
    } else if has(&decisive, "require_approval") {
        ("require_approval", Some("approval_required"))
    } else {
        ("allow", None)
    };
    let mut policy_refs: Vec<(String, Value)> = Vec::new();
    for o in &all {
        let key = encoded(&o["bundle_ref"]);
        if !policy_refs.iter().any(|(k, _)| *k == key) {
            policy_refs.push((key, o["bundle_ref"].clone()));
        }
    }
    policy_refs.sort_by(|(a, _), (b, _)| utf16_cmp(a, b));
    ComposedPolicyOutcome {
        verdict: verdict.into(),
        reason_codes: reason.map(|r| vec![r.to_owned()]).unwrap_or_default(),
        obligations,
        policy_refs: policy_refs.into_iter().map(|(_, r)| r).collect(),
        rule_ids: sorted_codes(all.iter().map(|o| s(&o["rule_id"]).to_owned())),
    }
}

// ─── Approvals ─────────────────────────────────────────────────────────────

const PROPOSAL_KEYS: [&str; 10] = [
    "request_id",
    "proposal_id",
    "run_id",
    "tenant_id",
    "operation_id",
    "action_digest",
    "policy_refs",
    "authority_refs",
    "not_before",
    "expires_at",
];

fn proposal_fields(o: &serde_json::Map<String, Value>) -> bool {
    ["request_id", "proposal_id", "run_id", "tenant_id", "operation_id"]
        .iter()
        .all(|k| is_identifier(&o[*k]))
        && is_digest(&o["action_digest"])
        && refs(&o["policy_refs"], 1)
        && refs(&o["authority_refs"], 1)
        && is_timestamp(&o["not_before"])
        && is_timestamp(&o["expires_at"])
}

fn with_proposal_keys(extra: &[&'static str]) -> Vec<&'static str> {
    PROPOSAL_KEYS.iter().copied().chain(extra.iter().copied()).collect()
}

fn valid_proposal(value: &Value) -> bool {
    exact_keys(value, &PROPOSAL_KEYS).is_some_and(proposal_fields)
}

fn valid_approval_request(value: &Value) -> bool {
    let keys = with_proposal_keys(&[
        "approval_request_id",
        "requester",
        "eligible_approvers",
        "eligible_approver_roles",
        "required_approvals",
        "prohibit_self_approval",
        "verification_ref",
    ]);
    exact_keys(value, &keys).is_some_and(|o| {
        proposal_fields(o)
            && is_identifier(&o["approval_request_id"])
            && valid_principal(&o["requester"])
            && list(&o["eligible_approvers"], MAX_LIST, valid_principal)
            && ids(&o["eligible_approver_roles"])
            && o["eligible_approver_roles"].as_array().is_some_and(|r| !r.is_empty())
            && as_safe_integer(&o["required_approvals"]).is_some_and(|n| (1..=128).contains(&n))
            && o["prohibit_self_approval"].is_boolean()
            && is_artifact_ref(&o["verification_ref"])
    })
}

fn valid_approval(value: &Value) -> bool {
    let keys = with_proposal_keys(&[
        "approval_id",
        "approval_request_id",
        "approver",
        "decision",
        "decided_at",
        "verification_ref",
    ]);
    exact_keys(value, &keys).is_some_and(|o| {
        proposal_fields(o)
            && is_identifier(&o["approval_id"])
            && is_identifier(&o["approval_request_id"])
            && valid_principal(&o["approver"])
            && matches!(o["decision"].as_str(), Some("approved" | "denied"))
            && is_timestamp(&o["decided_at"])
            && is_artifact_ref(&o["verification_ref"])
    })
}

fn valid_approval_observation(value: &Value) -> bool {
    exact_keys(
        value,
        &[
            "approval_id",
            "decision_digest",
            "verification_ref",
            "verification_status",
            "observer",
            "observed_at",
            "valid_until",
        ],
    )
    .is_some_and(|o| {
        is_identifier(&o["approval_id"])
            && is_digest(&o["decision_digest"])
            && is_artifact_ref(&o["verification_ref"])
            && verification_status(&o["verification_status"])
            && valid_principal(&o["observer"])
            && is_timestamp(&o["observed_at"])
            && is_timestamp(&o["valid_until"])
    })
}

fn valid_entitlement(value: &Value) -> bool {
    exact_keys(
        value,
        &[
            "approver",
            "role_id",
            "approval_request_id",
            "action_digest",
            "observer",
            "verification_status",
            "verification_ref",
            "observed_at",
            "valid_until",
        ],
    )
    .is_some_and(|o| {
        valid_principal(&o["approver"])
            && is_identifier(&o["role_id"])
            && is_identifier(&o["approval_request_id"])
            && is_digest(&o["action_digest"])
            && valid_principal(&o["observer"])
            && verification_status(&o["verification_status"])
            && is_artifact_ref(&o["verification_ref"])
            && is_timestamp(&o["observed_at"])
            && is_timestamp(&o["valid_until"])
    })
}

fn valid_redemption(value: &Value) -> bool {
    exact_keys(
        value,
        &["approval_request_id", "revision", "operation_id", "action_digest"],
    )
    .is_some_and(|o| {
        is_identifier(&o["approval_request_id"])
            && is_safe_non_negative_integer(&o["revision"])
            && ((o["operation_id"].is_null() && o["action_digest"].is_null())
                || (is_identifier(&o["operation_id"]) && is_digest(&o["action_digest"])))
    })
}

fn same_reference_set(left: &Value, right: &Value) -> bool {
    let (Some(l), Some(r)) = (left.as_array(), right.as_array()) else {
        return false;
    };
    let ls: HashSet<String> = l.iter().map(encoded).collect();
    let rs: HashSet<String> = r.iter().map(encoded).collect();
    ls.len() == l.len() && rs.len() == r.len() && ls == rs
}

fn proposal_matches(record: &Value, proposal: &Value, binding: &Value, digest: &str) -> bool {
    record["request_id"] == proposal["request_id"]
        && record["proposal_id"] == binding["proposal_id"]
        && record["run_id"] == binding["run_id"]
        && record["tenant_id"] == binding["tenant_id"]
        && record["operation_id"] == binding["operation_id"]
        && record["action_digest"] == digest
        && same_reference_set(&record["policy_refs"], &binding["policy_refs"])
        && same_reference_set(&record["authority_refs"], &binding["authority_refs"])
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ApprovalValidationResult {
    pub allowed: bool,
    pub action_digest: Option<String>,
    pub approval_refs: Vec<Value>,
    pub reason_codes: Vec<String>,
}

/// Validates stored proposal/request/decision records and post-verification
/// observations: exact action binding, validity windows, eligible and entitled
/// distinct approvers, self-approval prohibition, quorum and single redemption.
pub fn validate_approval_binding(input: &Value) -> ApprovalValidationResult {
    validate_approval_binding_with(input, None)
}

/// As [`validate_approval_binding`], reusing a digest already computed for an
/// identical binding.
fn validate_approval_binding_with(input: &Value, known: Option<(&Value, &str)>) -> ApprovalValidationResult {
    let mut reasons: HashSet<String> = HashSet::new();
    let mut approval_refs: Vec<Value> = Vec::new();
    let add = |reasons: &mut HashSet<String>, code: &str| {
        reasons.insert(code.to_owned());
    };
    let shape_ok = contextos_contract::canonical::check_canonical(input).is_ok()
        && exact_keys(
            input,
            &[
                "binding",
                "proposal",
                "request",
                "decisions",
                "verification_observations",
                "entitlements",
                "trusted_observers",
                "redemption_state",
                "evaluation_time",
            ],
        )
        .is_some_and(|o| {
            valid_binding(&o["binding"])
                && valid_proposal(&o["proposal"])
                && valid_approval_request(&o["request"])
                && list(&o["decisions"], MAX_LIST, valid_approval)
                && list(&o["verification_observations"], MAX_LIST, valid_approval_observation)
                && list(&o["entitlements"], MAX_LIST, valid_entitlement)
                && list(&o["trusted_observers"], MAX_LIST, valid_principal)
                && valid_redemption(&o["redemption_state"])
                && is_timestamp(&o["evaluation_time"])
        });
    if !shape_ok {
        return ApprovalValidationResult {
            allowed: false,
            action_digest: None,
            approval_refs,
            reason_codes: vec!["approval_binding_mismatch".into()],
        };
    }
    let (binding, proposal, request) = (&input["binding"], &input["proposal"], &input["request"]);
    let (state, time) = (&input["redemption_state"], &input["evaluation_time"]);
    let decisions = input["decisions"].as_array().expect("validated");
    let observations = input["verification_observations"].as_array().expect("validated");
    let entitlements = input["entitlements"].as_array().expect("validated");
    let trusted_observers = input["trusted_observers"].as_array().expect("validated");
    let digest = match known {
        Some((known_binding, digest)) if same_json(known_binding, binding) => digest.to_owned(),
        _ => digest_action_binding(binding).expect("validated binding"),
    };

    for record in std::iter::once(proposal)
        .chain(std::iter::once(request))
        .chain(decisions.iter())
    {
        if !proposal_matches(record, proposal, binding, &digest) {
            add(&mut reasons, "approval_binding_mismatch");
        }
        if !within(time, &record["not_before"], &record["expires_at"]) {
            add(&mut reasons, "approval_expired");
        }
    }
    if cmp_times(&request["not_before"], &proposal["not_before"]) == Some(Ordering::Less)
        || cmp_times(&request["expires_at"], &proposal["expires_at"]) == Some(Ordering::Greater)
    {
        add(&mut reasons, "approval_binding_mismatch");
    }
    if state["approval_request_id"] != request["approval_request_id"] {
        add(&mut reasons, "approval_binding_mismatch");
    }
    if !state["operation_id"].is_null()
        && (state["operation_id"] != binding["operation_id"] || state["action_digest"] != digest.as_str())
    {
        add(&mut reasons, "approval_consumed");
    }
    let tenant = &binding["tenant_id"];
    let eligible = request["eligible_approvers"].as_array().expect("validated");
    if request["requester"]["tenant_id"] != *tenant || eligible.iter().any(|p| p["tenant_id"] != *tenant) {
        add(&mut reasons, "tenant_mismatch");
    }
    let trusted =
        |observer: &Value| observer["tenant_id"] == *tenant && trusted_observers.iter().any(|t| same_json(t, observer));
    let mut distinct: HashSet<String> = HashSet::new();
    let mut approval_ids: HashSet<String> = HashSet::new();
    if observations.len() != decisions.len() {
        add(&mut reasons, "verification_unavailable");
    }
    let roles = request["eligible_approver_roles"].as_array().expect("validated");
    for decision in decisions {
        approval_refs.push(decision["verification_ref"].clone());
        let key = encoded(&decision["approver"]);
        let id = s(&decision["approval_id"]).to_owned();
        if distinct.contains(&key) || approval_ids.contains(&id) {
            add(&mut reasons, "approval_approver_duplicate");
        }
        distinct.insert(key);
        approval_ids.insert(id);
        if decision["approval_request_id"] != request["approval_request_id"]
            || decision["approver"]["tenant_id"] != *tenant
            || !eligible.iter().any(|c| same_json(c, &decision["approver"]))
        {
            add(&mut reasons, "approval_binding_mismatch");
        }
        if request["prohibit_self_approval"] == true
            && (same_json(&decision["approver"], &binding["actor"])
                || same_json(&decision["approver"], &request["requester"]))
        {
            add(&mut reasons, "approval_self_denied");
        }
        if decision["decision"] != "approved" {
            add(&mut reasons, "approval_denied");
        }
        if !within(&decision["decided_at"], &request["not_before"], &request["expires_at"])
            || cmp_times(&decision["decided_at"], time) == Some(Ordering::Greater)
            || cmp_times(&decision["not_before"], &request["not_before"]) == Some(Ordering::Less)
            || cmp_times(&decision["expires_at"], &request["expires_at"]) == Some(Ordering::Greater)
        {
            add(&mut reasons, "approval_binding_mismatch");
        }
        let matching: Vec<&Value> = observations
            .iter()
            .filter(|o| o["approval_id"] == decision["approval_id"])
            .collect();
        let decision_digest =
            sha256_canonical(&json!({"domain": "contextos.approval_decision.v1", "decision": decision})).ok();
        let observed = matching.first().copied();
        if matching.len() != 1
            || observed.is_none_or(|o| {
                o["verification_status"] != "verified"
                    || !trusted(&o["observer"])
                    || !same_json(&o["verification_ref"], &decision["verification_ref"])
                    || o["decision_digest"].as_str() != decision_digest.as_deref()
            })
        {
            add(&mut reasons, "verification_unavailable");
        }
        if let Some(o) = observed
            && (!within(time, &o["observed_at"], &o["valid_until"])
                || cmp_times(&o["observed_at"], &decision["decided_at"]) == Some(Ordering::Less))
        {
            add(&mut reasons, "precondition_stale");
        }
        let entitled = entitlements.iter().any(|e| {
            same_json(&e["approver"], &decision["approver"])
                && e["approval_request_id"] == request["approval_request_id"]
                && e["action_digest"] == digest.as_str()
                && roles.contains(&e["role_id"])
                && e["verification_status"] == "verified"
                && trusted(&e["observer"])
                && within(time, &e["observed_at"], &e["valid_until"])
        });
        if !entitled {
            add(&mut reasons, "approval_entitlement_missing");
        }
    }
    if as_safe_integer(&request["required_approvals"])
        .is_some_and(|n| i64::try_from(distinct.len()).unwrap_or(i64::MAX) < n)
    {
        add(&mut reasons, "approval_required");
    }
    ApprovalValidationResult {
        allowed: reasons.is_empty(),
        action_digest: Some(digest),
        approval_refs,
        reason_codes: sorted_codes(reasons),
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ApprovalRedemptionResult {
    pub status: String,
    pub state: Option<Value>,
    pub expected_revision: Option<i64>,
    /// Always false: neither an existing redemption nor this transition permits a
    /// new external effect on its own.
    pub permits_new_effect: bool,
    pub reason_codes: Vec<String>,
}

/// Intended compare-and-swap for single approval redemption. The store must apply it
/// atomically against `expected_revision`.
pub fn transition_approval_redemption(input: &Value) -> ApprovalRedemptionResult {
    let rejected = |state: Option<Value>, expected: Option<i64>, codes: Vec<String>| ApprovalRedemptionResult {
        status: "rejected".into(),
        state,
        expected_revision: expected,
        permits_new_effect: false,
        reason_codes: codes,
    };
    let expected = exact_keys(input, &["approval", "expected_revision"])
        .and_then(|o| as_safe_integer(&o["expected_revision"]).filter(|n| *n >= 0));
    let Some(expected) = expected.filter(|_| contextos_contract::canonical::check_canonical(input).is_ok()) else {
        return rejected(None, None, vec!["approval_binding_mismatch".into()]);
    };
    let approval = &input["approval"];
    let validation = validate_approval_binding(approval);
    let state = approval
        .get("redemption_state")
        .filter(|s| valid_redemption(s))
        .cloned();
    let Some(state) = state.filter(|_| validation.allowed) else {
        let state = approval
            .get("redemption_state")
            .filter(|s| valid_redemption(s))
            .cloned();
        return rejected(state, Some(expected), validation.reason_codes);
    };
    let revision = as_safe_integer(&state["revision"]).unwrap_or(-1);
    if revision != expected {
        return rejected(Some(state), Some(expected), vec!["approval_revision_conflict".into()]);
    }
    if state["operation_id"].as_str().is_some_and(|op| !op.is_empty()) {
        return ApprovalRedemptionResult {
            status: "existing".into(),
            state: Some(state),
            expected_revision: Some(expected),
            permits_new_effect: false,
            reason_codes: vec![],
        };
    }
    if revision + 1 > MAX_SAFE_INTEGER {
        return rejected(Some(state), Some(expected), vec!["approval_revision_conflict".into()]);
    }
    let mut next = state;
    next["revision"] = Value::from(revision + 1);
    next["operation_id"] = approval["binding"]["operation_id"].clone();
    next["action_digest"] = validation.action_digest.map_or(Value::Null, Value::String);
    ApprovalRedemptionResult {
        status: "redeem".into(),
        state: Some(next),
        expected_revision: Some(expected),
        permits_new_effect: false,
        reason_codes: vec![],
    }
}

// ─── Authorization ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuthorizationDecision {
    pub decision_id: String,
    pub contract_id: String,
    pub run_id: String,
    pub operation_id: String,
    pub action_digest: Option<String>,
    pub evaluation_time: String,
    pub policy_refs: Vec<Value>,
    pub grant_refs: Vec<Value>,
    pub approval_refs: Vec<Value>,
    pub reason_codes: Vec<String>,
    pub obligations: Vec<String>,
    pub verdict: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuthorizationOutcome {
    pub verdict: String,
    pub decision: AuthorizationDecision,
}

impl AuthorizationOutcome {
    pub fn is_allow(&self) -> bool {
        self.verdict == "allow"
    }
}

fn valid_constraint_observation(value: &Value) -> bool {
    exact_keys(
        value,
        &[
            "control",
            "action_digest",
            "policy_refs",
            "verdict",
            "verification_status",
            "verification_ref",
            "observer",
            "observed_at",
            "valid_until",
        ],
    )
    .is_some_and(|o| {
        is_control_ref(&o["control"])
            && is_digest(&o["action_digest"])
            && refs(&o["policy_refs"], 1)
            && matches!(o["verdict"].as_str(), Some("allow" | "deny" | "unknown"))
            && verification_status(&o["verification_status"])
            && is_artifact_ref(&o["verification_ref"])
            && valid_principal(&o["observer"])
            && is_timestamp(&o["observed_at"])
            && is_timestamp(&o["valid_until"])
    })
}

/// Conjunctive authorization of one effect: current authority ∧ composed policy ∧
/// every required independent constraint ∧ (when required) an exactly bound,
/// entitled approval. Any independent failure stays blocking, including after an
/// approval resolves the business gate.
pub fn evaluate_authorization(input: &Value) -> AuthorizationOutcome {
    let invalid = || AuthorizationOutcome {
        verdict: "error".into(),
        decision: AuthorizationDecision {
            decision_id: "invalid".into(),
            contract_id: "invalid".into(),
            run_id: "invalid".into(),
            operation_id: "invalid".into(),
            action_digest: None,
            evaluation_time: "invalid".into(),
            policy_refs: vec![],
            grant_refs: vec![],
            approval_refs: vec![],
            reason_codes: vec!["authorization_invalid".into()],
            obligations: vec![],
            verdict: "error".into(),
        },
    };
    let shape_ok = contextos_contract::canonical::check_canonical(input).is_ok()
        && exact_keys(
            input,
            &[
                "decision_id",
                "authority",
                "policy_outcomes",
                "approval",
                "required_constraints",
                "constraint_observations",
            ],
        )
        .is_some_and(|o| {
            is_identifier(&o["decision_id"])
                && list(&o["required_constraints"], MAX_LIST, is_control_ref)
                && list(&o["constraint_observations"], MAX_LIST, valid_constraint_observation)
        });
    if !shape_ok {
        return invalid();
    }
    let authority = validate_authority(&input["authority"]);
    let policy = compose_policy_outcomes(&input["policy_outcomes"]);
    let Some(action_digest) = authority.action_digest.clone() else {
        return invalid();
    };
    let binding = &input["authority"]["binding"];
    let authenticated = &input["authority"]["authenticated"];
    let time = &input["authority"]["evaluation_time"];
    let trusted_observers = authenticated["trusted_observers"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let mut reasons: HashSet<String> = authority
        .reason_codes
        .iter()
        .chain(policy.reason_codes.iter())
        .cloned()
        .collect();
    let mut verdict = policy.verdict.clone();
    let mut approval_refs: Vec<Value> = Vec::new();
    if !authority.allowed {
        verdict = "deny".into();
    }
    let policy_refs_value = Value::Array(policy.policy_refs.clone());
    if !same_reference_set(&policy_refs_value, &binding["policy_refs"]) {
        verdict = "error".into();
        reasons.insert("policy_binding_mismatch".into());
    }
    let mut required: HashMap<String, Value> = HashMap::new();
    let observations = input["constraint_observations"].as_array().expect("validated");
    for control in input["required_constraints"].as_array().expect("validated") {
        let id = s(&control["control_id"]).to_owned();
        if required.get(&id).is_some_and(|v| *v != control["control_version"]) {
            reasons.insert("constraint_conflict".into());
            verdict = "deny".into();
        }
        required.insert(id, control["control_version"].clone());
        let matches: Vec<&Value> = observations
            .iter()
            .filter(|o| same_json(&o["control"], control))
            .collect();
        let ok = matches.len() == 1 && {
            let o = matches[0];
            o["verdict"] == "allow"
                && o["verification_status"] == "verified"
                && o["action_digest"] == action_digest.as_str()
                && same_reference_set(&o["policy_refs"], &binding["policy_refs"])
                && o["observer"]["tenant_id"] == binding["tenant_id"]
                && trusted_observers.iter().any(|t| same_json(t, &o["observer"]))
                && within(time, &o["observed_at"], &o["valid_until"])
        };
        if !ok {
            verdict = "deny".into();
            reasons.insert("required_constraint_failed".into());
        }
    }
    let needs_approval =
        policy.verdict == "require_approval" || binding["action_risk"]["authority"] == "human_approved";
    let approval_input = &input["approval"];
    if approval_input.is_null() {
        if needs_approval && verdict == "allow" {
            verdict = "require_approval".into();
            reasons.insert("approval_required".into());
        }
    } else {
        let approval = validate_approval_binding_with(approval_input, Some((binding, action_digest.as_str())));
        let mandating = authenticated.get("mandating_person");
        let self_approval = approval.allowed
            && approval_input["request"]["prohibit_self_approval"] == true
            && mandating.is_some_and(|person| {
                approval_input["decisions"]
                    .as_array()
                    .is_some_and(|d| d.iter().any(|decision| same_json(&decision["approver"], person)))
            });
        let mismatch = !approval.allowed
            || approval.action_digest.as_deref() != Some(action_digest.as_str())
            || cmp_times(&approval_input["evaluation_time"], time) != Some(Ordering::Equal)
            || !same_reference_set(
                &approval_input["trusted_observers"],
                &authenticated["trusted_observers"],
            )
            || self_approval;
        if mismatch {
            verdict = "deny".into();
            reasons.extend(approval.reason_codes.iter().cloned());
            reasons.insert("approval_binding_mismatch".into());
            if self_approval {
                reasons.insert("approval_self_denied".into());
            }
        } else {
            approval_refs = approval.approval_refs;
            if verdict == "require_approval" && authority.allowed {
                verdict = "allow".into();
                reasons.remove("approval_required");
            }
        }
    }
    if !authority.allowed || reasons.contains("required_constraint_failed") || reasons.contains("constraint_conflict") {
        verdict = "deny".into();
    }
    AuthorizationOutcome {
        verdict: verdict.clone(),
        decision: AuthorizationDecision {
            decision_id: s(&input["decision_id"]).to_owned(),
            contract_id: s(&binding["contract_id"]).to_owned(),
            run_id: s(&binding["run_id"]).to_owned(),
            operation_id: s(&binding["operation_id"]).to_owned(),
            action_digest: Some(action_digest),
            evaluation_time: s(time).to_owned(),
            policy_refs: policy.policy_refs,
            grant_refs: authority.grant_refs,
            approval_refs,
            reason_codes: sorted_codes(reasons),
            obligations: policy.obligations,
            verdict,
        },
    }
}
