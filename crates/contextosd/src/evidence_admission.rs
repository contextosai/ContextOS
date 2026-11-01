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
//! The caller's `integrity` and `freshness` labels on evidence entries are still
//! taken as given; verifying them against configured issuers comes next
//! (docs/design/business-correctness.md, B2 and B3).

use std::collections::BTreeSet;

use axum::http::StatusCode;
use contextos_contract::types::ContextPack;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::Config;
use crate::http::ApiError;

const ENTERPRISE: &str = "contextos.enterprise";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
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
    fn names_are_reported_once_and_sorted() {
        let pack = pack();
        let request = json!({"input": {"context": {"policy.eval": 1, "order_lookup": {}, "identity_verified": 1}}});
        assert_eq!(
            in_request_context(&pack, &request),
            ["identity_verified", "order_lookup", "policy.eval"]
        );
    }
}
