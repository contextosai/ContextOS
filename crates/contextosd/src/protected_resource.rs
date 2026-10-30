//! OAuth 2.0 Protected Resource Metadata (RFC 9728), as the MCP authorization spec
//! requires of an MCP server.
//!
//! With `[server] public_url` set, the server publishes which authorization servers
//! (the configured OIDC issuers) issue tokens for it, at
//! `/.well-known/oauth-protected-resource` for the API and at
//! `/.well-known/oauth-protected-resource/v1/runs/{run_id}/mcp` for each run's MCP
//! endpoint. A `401` names that document in `WWW-Authenticate` (`resource_metadata`),
//! so an MCP host can discover where to get a token; a `403` for a missing scope says
//! which scope (`error="insufficient_scope"`). Tokens are validated exactly as before:
//! set an issuer's `audience` to the public URL so tokens are bound to this server
//! (RFC 8707). Caller tokens are never passed to providers; adapters get credentials
//! from their broker.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;

use crate::app::AppState;

pub const METADATA_PATH: &str = "/.well-known/oauth-protected-resource";

/// Checks `[server] public_url`: an absolute `https` URL (`http` only in development)
/// without query, fragment or trailing slash.
pub fn check_public_url(url: &str, development: bool) -> Result<(), String> {
    let parsed = url::Url::parse(url).map_err(|_| "[server] public_url must be an absolute URL".to_owned())?;
    if parsed.scheme() != "https" && !(development && parsed.scheme() == "http") {
        return Err("[server] public_url must use https".into());
    }
    if parsed.query().is_some() || parsed.fragment().is_some() || url.ends_with('/') || parsed.host().is_none() {
        return Err("[server] public_url must have a host and no query, fragment or trailing slash".into());
    }
    Ok(())
}

/// The `WWW-Authenticate` challenge for a request to `resource_path` (empty for the API
/// as a whole).
#[must_use]
pub fn challenge(public_url: Option<&str>, resource_path: &str, scope: Option<&str>) -> String {
    let mut parts = Vec::new();
    if let Some(scope) = scope {
        parts.push(format!("error=\"insufficient_scope\", scope=\"{scope}\""));
    }
    if let Some(base) = public_url {
        parts.push(format!("resource_metadata=\"{base}{METADATA_PATH}{resource_path}\""));
    }
    if parts.is_empty() {
        "Bearer".into()
    } else {
        format!("Bearer {}", parts.join(", "))
    }
}

fn document<S, L>(state: &AppState<S, L>, resource_path: &str, scopes: &[&str]) -> Response {
    let Some(base) = state.public_url.as_deref() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let issuers: Vec<&str> = state.auth.issuers().iter().map(|i| i.issuer()).collect();
    axum::Json(json!({
        "resource": format!("{base}{resource_path}"),
        "authorization_servers": issuers,
        "scopes_supported": scopes,
        "bearer_methods_supported": ["header"],
        "resource_name": "ContextOS",
    }))
    .into_response()
}

pub(crate) async fn api_metadata<S, L>(State(state): State<Arc<AppState<S, L>>>) -> Response {
    document(&state, "", &crate::oidc::KNOWN_SCOPES)
}

pub(crate) async fn mcp_metadata<S, L>(
    State(state): State<Arc<AppState<S, L>>>,
    Path(run_id): Path<String>,
) -> Response {
    if !contextos_contract::validation::is_contract_identifier(&run_id) {
        return StatusCode::NOT_FOUND.into_response();
    }
    document(&state, &format!("/v1/runs/{run_id}/mcp"), &["dispatch"])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenges_name_the_metadata_and_the_missing_scope() {
        assert_eq!(challenge(None, "", None), "Bearer");
        assert_eq!(
            challenge(Some("https://ctx.example"), "/v1/runs/run_1/mcp", None),
            "Bearer resource_metadata=\"https://ctx.example/.well-known/oauth-protected-resource/v1/runs/run_1/mcp\""
        );
        assert_eq!(
            challenge(Some("https://ctx.example"), "", Some("dispatch")),
            "Bearer error=\"insufficient_scope\", scope=\"dispatch\", resource_metadata=\"https://ctx.example/.well-known/oauth-protected-resource\""
        );
    }

    #[test]
    fn public_urls_are_absolute_https_without_extras() {
        assert!(check_public_url("https://ctx.example", false).is_ok());
        assert!(check_public_url("https://ctx.example/base", false).is_ok());
        assert!(check_public_url("http://localhost:8080", true).is_ok());
        for bad in [
            "http://ctx.example",
            "https://ctx.example/",
            "https://ctx.example?x=1",
            "ctx.example",
        ] {
            assert!(check_public_url(bad, false).is_err(), "{bad}");
        }
    }
}
