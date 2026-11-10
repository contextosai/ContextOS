//! Signing in to Tower with the organization's identity provider (see [`crate::sso`]).
//!
//! The UI runs the authorization-code flow with PKCE: it reads where to send the
//! browser from `GET /api/sso`, and hands the code it gets back to
//! `POST /api/sso/token`. Tower, not the browser, calls the issuer's token endpoint
//! (the UI may connect only to Tower), adds the client secret for a confidential
//! client, and returns the ID token only if Tower itself accepts it, with the nonce the
//! browser chose.
//!
//! | Route | Role | Purpose |
//! |---|---|---|
//! | `GET /api/sso` | none | issuer, client id, scopes, redirect URI and authorization endpoint; 404 without `[sso]` |
//! | `POST /api/sso/token` | none | `{code, code_verifier, nonce}` → `{id_token, principal_id, roles, teams}` |

use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, post};
use contextos_store::{AppendLog, DocumentStore};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::api::{ApiError, ApiResult, Shared, body, ok};

pub fn routes<S, L>() -> Router<Shared<S, L>>
where
    S: DocumentStore + 'static,
    L: AppendLog + 'static,
{
    Router::new()
        .route("/api/sso", get(settings::<S, L>))
        .route("/api/sso/token", post(exchange::<S, L>))
}

async fn settings<S, L>(State(t): State<Shared<S, L>>) -> ApiResult {
    match &t.sso {
        Some(sso) => ok(sso.public_settings()),
        None => Err(ApiError::not_found("single sign-on")),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Exchange {
    code: String,
    code_verifier: String,
    nonce: String,
}

/// RFC 7636: 43 to 128 unreserved characters.
fn verifier_ok(v: &str) -> bool {
    (43..=128).contains(&v.len())
        && v.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'))
}

async fn exchange<S, L>(State(t): State<Shared<S, L>>, bytes: Bytes) -> ApiResult {
    let Some(sso) = t.sso.clone() else {
        return Err(ApiError::not_found("single sign-on"));
    };
    let request: Exchange = body(&bytes)?;
    if request.code.is_empty() || request.code.len() > 4096 || !verifier_ok(&request.code_verifier) {
        return Err(ApiError::bad(
            "code and a PKCE code_verifier (43 to 128 characters) are required",
        ));
    }
    if request.nonce.len() < 16 || request.nonce.len() > 256 {
        return Err(ApiError::bad("nonce must be 16 to 256 characters"));
    }
    let _permit = sso.exchanges.try_acquire().map_err(|_| {
        ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "busy",
            "Too many sign-ins at once; try again.",
        )
    })?;
    let endpoint = sso.token_endpoint().ok_or_else(|| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "sso_unavailable",
            "The identity provider's metadata is not loaded yet.",
        )
    })?;
    let config = sso.config();
    let secret = config.client_secret_env.as_ref().and_then(|v| std::env::var(v).ok());
    let mut form = vec![
        ("grant_type", "authorization_code".to_owned()),
        ("code", request.code),
        ("redirect_uri", config.redirect_uri.clone()),
        ("client_id", config.client_id.clone()),
        ("code_verifier", request.code_verifier),
    ];
    if let Some(secret) = secret {
        form.push(("client_secret", secret));
    }
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "internal", e.to_string()))?;
    let refused = || {
        ApiError::new(
            StatusCode::UNAUTHORIZED,
            "sign_in_refused",
            "The identity provider did not sign you in.",
        )
    };
    let response = client.post(&endpoint).form(&form).send().await.map_err(|e| {
        tracing::warn!(error = %e, "sso: token endpoint unreachable");
        ApiError::new(
            StatusCode::BAD_GATEWAY,
            "sso_unavailable",
            "The identity provider could not be reached.",
        )
    })?;
    if !response.status().is_success() {
        tracing::info!(status = %response.status(), "sso: code exchange refused");
        return Err(refused());
    }
    if response
        .content_length()
        .is_some_and(|n| n > crate::sso::MAX_DOCUMENT_BYTES as u64)
    {
        return Err(refused());
    }
    let bytes = response.bytes().await.map_err(|_| refused())?;
    if bytes.len() > crate::sso::MAX_DOCUMENT_BYTES {
        return Err(refused());
    }
    let tokens: Value = serde_json::from_slice(&bytes).map_err(|_| refused())?;
    let id_token = tokens["id_token"].as_str().ok_or_else(refused)?;
    let caller = sso.verify(id_token, Some(&request.nonce)).ok_or_else(|| {
        ApiError::forbidden("Signed in, but the token is not accepted or your groups grant no Tower role.")
    })?;
    ok(json!({"id_token": id_token, "principal_id": caller.principal_id,
        "roles": caller.roles, "teams": caller.teams}))
}
