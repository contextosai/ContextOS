//! `POST /v1/runs/{run_id}/operations/{operation_id}/outcome` (`outcome:report`): a
//! witness's observation that an applied effect reached its postcondition (see
//! [`contextos_gateway::outcomes`]).
//!
//! The body is `{"attestation": "<compact JWS>"}` from the capability's witness, an
//! `[[evidence_issuers]]` issuer, with the payload `{iss, sub, satisfies, observed_at,
//! valid_until, amount?}`: `sub` is the resource observed, `satisfies` names the
//! postcondition, and `amount` (`{minor_units, currency}`) is what posted when the
//! action has one. Anyone holding the scope may relay it (the witness itself, or the
//! run's executor): the signature is what is trusted, not the caller.
//!
//! Here the attestation is checked as evidence is: the issuer's signature, that it is
//! the contract's witness, serves the run's tenant and may satisfy the postcondition,
//! that it signed it, and that `observed_at <= now < valid_until` within its maximum
//! validity. The gateway then binds it to the effect (resource, amount, observed after
//! the effect) and closes the outcome.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use contextos_contract::canonical::sha256_text;
use contextos_gateway::manifest::OutcomeContract;
use contextos_gateway::outcomes::WitnessObservation;
use contextos_store::{AppendLog, DocumentStore};
use serde_json::{Value, json};

use crate::app::{ApiError, ApiResult, AppState, dispatch_gateway, load_admission};
use crate::evidence_issuers::{EvidenceIssuerConfig, Issuers, freshness};
use crate::http::{authorize, parse_body};

/// Refuses a capability whose witness is not a configured issuer able to satisfy its
/// postcondition.
pub fn check(contracts: &[(String, OutcomeContract)], issuers: &[EvidenceIssuerConfig]) -> Result<(), String> {
    for (capability, contract) in contracts {
        let issuer = issuers.iter().find(|i| i.issuer == contract.witness).ok_or_else(|| {
            format!(
                "capability {capability}: outcome witness {} is not an [[evidence_issuers]] issuer",
                contract.witness
            )
        })?;
        if !issuer.satisfies.contains(&contract.postcondition) {
            return Err(format!(
                "capability {capability}: evidence issuer {} may not satisfy postcondition {}",
                contract.witness, contract.postcondition
            ));
        }
    }
    Ok(())
}

/// Verifies a witness attestation for `record` (the gateway's outcome record) at `now`.
pub fn verify(
    issuers: &Issuers,
    tenant: &str,
    now: &str,
    token: &str,
    record: &Value,
) -> Result<WitnessObservation, &'static str> {
    let (config, claims) = issuers.decode(token)?;
    if record["witness"] != config.issuer.as_str() {
        return Err("outcome_witness_mismatch");
    }
    if !config.tenants.iter().any(|t| t == tenant) {
        return Err("issuer_not_for_tenant");
    }
    let postcondition = record["postcondition"].as_str().unwrap_or_default();
    let signed = claims["satisfies"]
        .as_array()
        .is_some_and(|a| a.iter().any(|s| s == postcondition));
    if !signed || !config.satisfies.iter().any(|s| s == postcondition) {
        return Err("requirement_not_attested");
    }
    let subject = claims["sub"]
        .as_str()
        .filter(|s| !s.is_empty())
        .ok_or("outcome_subject_missing")?;
    let (Some(observed_at), Some(valid_until)) = (claims["observed_at"].as_str(), claims["valid_until"].as_str())
    else {
        return Err("validity_missing");
    };
    let mut reasons = Vec::new();
    if freshness(now, observed_at, valid_until, config.max_validity_seconds, &mut reasons) != "current" {
        return Err(reasons.first().copied().unwrap_or("validity_invalid"));
    }
    Ok(WitnessObservation {
        issuer: config.issuer.clone(),
        subject: subject.to_owned(),
        observed_at: observed_at.to_owned(),
        valid_until: valid_until.to_owned(),
        amount: claims.get("amount").filter(|a| !a.is_null()).cloned(),
        attestation_digest: sha256_text(token),
    })
}

fn refused(status: StatusCode, reason: &'static str) -> ApiError {
    ApiError::new(
        status,
        reason,
        "The witness observation was not accepted for this effect.",
    )
}

pub async fn report_outcome<S, L>(
    State(state): State<Arc<AppState<S, L>>>,
    Path((run_id, operation_id)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult
where
    S: DocumentStore + 'static,
    L: AppendLog + 'static,
{
    let caller = authorize(&state, &headers, Some("outcome:report"))?;
    let gateway = dispatch_gateway(&state)?;
    let input = parse_body(&state, &body)?;
    let token = input["attestation"]
        .as_str()
        .filter(|t| input.as_object().is_some_and(|o| o.len() == 1) && t.len() <= 16_384)
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "request_invalid",
                "Send {\"attestation\": \"<compact JWS>\"} from the capability's outcome witness.",
            )
        })?;
    let admission = load_admission(&state, &caller, &run_id).await?;
    let unavailable = |error: contextos_gateway::GatewayError| {
        tracing::warn!(%error, "outcome report unavailable");
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "store_unavailable",
            "The store is unavailable.",
        )
    };
    let record = gateway
        .outcome(&admission, &operation_id)
        .await
        .map_err(unavailable)?
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::NOT_FOUND,
                "outcome_not_required",
                "This operation has no outcome contract.",
            )
        })?;
    let observation = verify(
        &state.evidence_issuers,
        &caller.tenant_id,
        &gateway.now(),
        token,
        &record,
    )
    .map_err(|reason| refused(StatusCode::UNPROCESSABLE_ENTITY, reason))?;
    let closed = gateway
        .witness_outcome(&admission, &operation_id, &observation)
        .await
        .map_err(unavailable)?
        .map_err(|reason| {
            let status = if reason == "outcome_effect_not_applied" {
                StatusCode::CONFLICT
            } else {
                StatusCode::UNPROCESSABLE_ENTITY
            };
            refused(status, reason)
        })?;
    Ok(axum::Json(
        json!({"run_id": run_id, "operation_id": operation_id, "state": closed["state"],
        "postcondition": closed["postcondition"], "late": closed["late"], "observation": closed["observation"]}),
    )
    .into_response())
}
