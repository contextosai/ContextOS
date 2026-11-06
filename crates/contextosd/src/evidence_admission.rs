//! Evidence admission: what may satisfy a decision's evidence gate.
//!
//! The compiler counts a required-evidence item as satisfied by any non-null,
//! non-`false` value under its name in `request.input.context`, with no integrity,
//! conflict or freshness check. The compiler is pure and locked to parity, so the
//! deployment decides here, before compiling, whether a run may do that:
//!
//! - `strict` refuses a run whose request context has a key that names a
//!   `required_evidence` item of any DecisionSpec in its pack
//!   (`422 evidence_in_request_context`). Gated facts must arrive as evidence entries.
//!   Required with the `contextos.enterprise` profile, and its default there.
//! - `caller` admits it, as the compiler always has. The default otherwise.
//!
//! Under `strict` the caller's `integrity` and `freshness` labels on evidence entries
//! are also replaced: [`crate::evidence_issuers`] sets them from each entry's
//! issuer-signed attestation and the server clock.

use std::collections::BTreeSet;

use axum::http::StatusCode;
use contextos_contract::types::ContextPack;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::Config;
use crate::http::ApiError;

const ENTERPRISE: &str = "contextos.enterprise";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceMode {
    Strict,
    Caller,
}

impl EvidenceMode {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Strict => "strict",
            Self::Caller => "caller",
        }
    }
}

fn enterprise(config: &Config) -> bool {
    config.support.profiles.iter().any(|p| p == ENTERPRISE)
}

/// `[guards] evidence`, or the default for the declared profiles.
#[must_use]
pub fn mode(config: &Config) -> EvidenceMode {
    config.guards.evidence.unwrap_or_else(|| {
        if enterprise(config) {
            EvidenceMode::Strict
        } else {
            EvidenceMode::Caller
        }
    })
}

/// Startup check: the enterprise profile cannot opt out of strict evidence.
pub fn check(config: &Config) -> Result<(), String> {
    if enterprise(config) && mode(config) != EvidenceMode::Strict {
        return Err(format!(
            "[guards] evidence = \"{}\" is not allowed with the {ENTERPRISE} profile: it requires \"strict\"",
            mode(config).as_str()
        ));
    }
    Ok(())
}

/// Every evidence name a DecisionSpec of the pack gates on.
#[must_use]
pub fn gated(pack: &ContextPack) -> BTreeSet<&str> {
    pack.decision_layer
        .decision_specs
        .iter()
        .flat_map(|spec| &spec.required_evidence)
        .map(String::as_str)
        .collect()
}

/// The gated names a request's `input.context` carries, whatever their values.
#[must_use]
pub fn in_request_context<'a>(pack: &'a ContextPack, request: &Value) -> Vec<&'a str> {
    let Some(context) = request["input"]["context"].as_object() else {
        return Vec::new();
    };
    gated(pack)
        .into_iter()
        .filter(|name| context.contains_key(*name))
        .collect()
}

/// Rules that read a gated name from the request context (`request.context.<name>`),
/// as `rule_id: name`. Strict evidence refuses such a context, so these rules never
/// match; `--check-config` names them.
#[must_use]
pub fn rules_reading_gated_context(pack: &ContextPack) -> Vec<String> {
    fn vars<'v>(value: &'v Value, out: &mut Vec<&'v str>) {
        match value {
            Value::Object(map) => {
                if let Some(Value::String(path)) = map.get("var") {
                    out.push(path);
                }
                map.values().for_each(|v| vars(v, out));
            }
            Value::Array(items) => items.iter().for_each(|v| vars(v, out)),
            _ => {}
        }
    }
    let gated = gated(pack);
    let mut found = Vec::new();
    for rule in pack
        .policy_layer
        .policy_bundles
        .iter()
        .flat_map(|b| &b.policy_dsl.rules)
    {
        let value = serde_json::to_value(rule).unwrap_or(Value::Null);
        let mut paths = Vec::new();
        vars(&value, &mut paths);
        for path in paths {
            let Some(rest) = path.strip_prefix("request.context.") else {
                continue;
            };
            for name in &gated {
                let entry = format!("{}: {name}", rule.rule_id);
                if (rest == *name || rest.strip_prefix(*name).is_some_and(|r| r.starts_with('.')))
                    && !found.contains(&entry)
                {
                    found.push(entry);
                }
            }
        }
    }
    found
}

/// Admission: under `strict`, refuse a request whose context names a gated item.
pub fn admit(mode: EvidenceMode, pack: &ContextPack, request: &Value) -> Result<(), ApiError> {
    if mode != EvidenceMode::Strict {
        return Ok(());
    }
    let named = in_request_context(pack, request);
    if named.is_empty() {
        return Ok(());
    }
    Err(ApiError::new(
        StatusCode::UNPROCESSABLE_ENTITY,
        "evidence_in_request_context",
        "The request context names evidence a decision requires; supply it as an evidence entry.",
    )
    .with_detail(json!({"requirements": named})))
}

/// The run's `deps` as the compiler and the replay case see them: under `strict`,
/// with every evidence entry's labels set by its issuer's attestation, and its
/// `satisfies` narrowed to the requirements whose subject is the run's (`run` is the
/// request and run context; see [`crate::evidence_subjects`]).
#[must_use]
pub fn relabel<'a>(
    mode: EvidenceMode,
    issuers: &crate::evidence_issuers::Issuers,
    subjects: &[crate::evidence_subjects::EvidenceSubject],
    tenant: &str,
    now: &str,
    (request, run_context): (&Value, &Value),
    deps: &'a Value,
) -> std::borrow::Cow<'a, Value> {
    if mode != EvidenceMode::Strict || !deps["evidence"].is_array() {
        return std::borrow::Cow::Borrowed(deps);
    }
    let mut deps = deps.clone();
    if let Some(evidence) = deps["evidence"].as_array_mut() {
        issuers.relabel(tenant, now, evidence);
        crate::evidence_subjects::bind(subjects, request, run_context, evidence);
    }
    std::borrow::Cow::Owned(deps)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pack() -> ContextPack {
        serde_json::from_str(include_str!("../../../examples/support-refund/pack.json")).unwrap()
    }

    #[test]
    fn strict_refuses_any_gated_name_in_context_whatever_its_value() {
        let pack = pack();
        assert!(gated(&pack).contains("identity_verified"));
        for value in [json!(true), json!(false), Value::Null, json!("yes")] {
            let request = json!({"input": {"context": {"identity_verified": value, "refund_amount": 4200}}});
            let error = admit(EvidenceMode::Strict, &pack, &request).unwrap_err();
            assert!(format!("{error:?}").contains("evidence_in_request_context"));
            assert!(admit(EvidenceMode::Caller, &pack, &request).is_ok());
        }
        // Ungated context and no context at all are admitted.
        let plain = json!({"input": {"context": {"refund_amount": 4200}}});
        assert!(admit(EvidenceMode::Strict, &pack, &plain).is_ok());
        assert!(admit(EvidenceMode::Strict, &pack, &json!({"input": {}})).is_ok());
    }

    #[test]
    fn rules_conditioned_on_a_gated_context_value_are_named() {
        assert_eq!(
            rules_reading_gated_context(&pack()),
            ["R_REFUND_REQUIRES_IDV: identity_verified"]
        );
    }

    #[test]
    fn names_are_reported_once_and_sorted() {
        let pack = pack();
        let request = json!({"input": {"context": {"policy.eval": 1, "order_lookup": {}, "identity_verified": 1}}});
        assert_eq!(
            in_request_context(&pack, &request),
            ["identity_verified", "order_lookup", "policy.eval"]
        );
    }
}
