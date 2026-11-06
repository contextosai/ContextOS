//! Streamable HTTP transport checks for the MCP endpoint, applied before any JSON-RPC
//! message is read.
//!
//! - **Origin.** A browser page can reach a server on a private network (DNS
//!   rebinding), so a request carrying an `Origin` header is refused unless that origin
//!   is `[server] public_url`'s or one listed in `[server] allowed_origins`. Requests
//!   without `Origin` (agent hosts, SDKs, curl) are not browser requests and pass.
//! - **Protocol version.** A host names the negotiated version in
//!   `MCP-Protocol-Version` on every request after initialization. An unsupported value
//!   is refused with 400, and the response echoes the version the request used.

use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::Response;

use crate::http::ApiError;

use crate::mcp::{PROTOCOL_VERSION, SUPPORTED_VERSIONS};

pub const VERSION_HEADER: &str = "mcp-protocol-version";

/// The origins allowed to call the MCP endpoint from a browser, each as
/// `scheme://host[:port]` in lowercase.
#[derive(Debug, Clone, Default)]
pub struct AllowedOrigins(Vec<String>);

/// `scheme://host[:port]` of an absolute http(s) URL, without a default port.
fn origin_of(url: &str) -> Option<String> {
    let parsed = url::Url::parse(url).ok()?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return None;
    }
    let origin = parsed.origin();
    origin.is_tuple().then(|| origin.ascii_serialization())
}

impl AllowedOrigins {
    /// From `[server] public_url` and `[server] allowed_origins`, which
    /// [`check_allowed_origins`] has validated.
    pub fn new(public_url: Option<&str>, allowed: &[String]) -> Self {
        let mut origins: Vec<String> = public_url
            .into_iter()
            .chain(allowed.iter().map(String::as_str))
            .filter_map(origin_of)
            .collect();
        origins.sort();
        origins.dedup();
        Self(origins)
    }

    fn allows(&self, origin: &str) -> bool {
        origin_of(origin).is_some_and(|o| self.0.contains(&o))
    }
}

/// Checks `[server] allowed_origins`: each an http(s) origin with no path, query or
/// fragment (`https://console.example`, `http://localhost:3000`).
pub fn check_allowed_origins(allowed: &[String]) -> Result<(), String> {
    for entry in allowed {
        let bare = url::Url::parse(entry)
            .is_ok_and(|u| u.path() == "/" && u.query().is_none() && u.fragment().is_none() && !entry.ends_with('/'));
        if !bare || origin_of(entry).is_none() {
            return Err(format!(
                "[server] allowed_origins: {entry:?} must be an http(s) origin such as https://console.example"
            ));
        }
    }
    Ok(())
}

fn refusal(status: StatusCode, code: &'static str, message: &'static str) -> ApiError {
    ApiError::new(status, code, message)
}

/// The transport checks: `Ok` with the version the request names (if any), or why the
/// request is refused.
pub fn check(headers: &HeaderMap, origins: &AllowedOrigins) -> Result<Option<&'static str>, ApiError> {
    if let Some(origin) = headers.get(axum::http::header::ORIGIN) {
        let allowed = origin.to_str().is_ok_and(|o| origins.allows(o));
        if !allowed {
            return Err(refusal(
                StatusCode::FORBIDDEN,
                "origin_not_allowed",
                "this origin may not call the MCP endpoint; list it in [server] allowed_origins",
            ));
        }
    }
    let Some(asked) = headers.get(VERSION_HEADER) else {
        return Ok(None);
    };
    let asked = asked.to_str().unwrap_or_default();
    SUPPORTED_VERSIONS
        .iter()
        .find(|v| **v == asked)
        .map(|v| Some(*v))
        .ok_or_else(|| {
            refusal(
                StatusCode::BAD_REQUEST,
                "protocol_version_unsupported",
                "unsupported MCP-Protocol-Version",
            )
        })
}

/// Sets the response's protocol version: one the handler chose (`initialize` sets the
/// negotiated version), else the request's, else the current one.
pub fn set_version(response: &mut Response, requested: Option<&'static str>) {
    if !response.headers().contains_key(VERSION_HEADER) {
        let version = requested.unwrap_or(PROTOCOL_VERSION);
        response
            .headers_mut()
            .insert(VERSION_HEADER, HeaderValue::from_static(version));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::response::IntoResponse;

    fn headers(pairs: &[(&'static str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (k, v) in pairs {
            map.insert(*k, HeaderValue::from_str(v).unwrap());
        }
        map
    }

    #[test]
    fn browser_origins_need_listing_and_other_callers_pass() {
        let origins = AllowedOrigins::new(Some("https://ctx.example/base"), &["http://localhost:3000".into()]);
        assert!(check(&headers(&[]), &origins).is_ok());
        assert!(check(&headers(&[("origin", "https://ctx.example")]), &origins).is_ok());
        assert!(check(&headers(&[("origin", "https://CTX.example:443")]), &origins).is_ok());
        assert!(check(&headers(&[("origin", "http://localhost:3000")]), &origins).is_ok());
        for bad in [
            "https://evil.example",
            "null",
            "http://ctx.example",
            "http://localhost:3001",
        ] {
            let refused = check(&headers(&[("origin", bad)]), &origins).unwrap_err();
            assert_eq!(refused.into_response().status(), StatusCode::FORBIDDEN, "{bad}");
        }
        let none = AllowedOrigins::default();
        assert!(check(&headers(&[("origin", "http://localhost:8080")]), &none).is_err());
    }

    #[test]
    fn protocol_versions_are_checked_and_echoed() {
        let origins = AllowedOrigins::default();
        assert_eq!(check(&headers(&[]), &origins).unwrap(), None);
        assert_eq!(
            check(&headers(&[(VERSION_HEADER, "2025-06-18")]), &origins).unwrap(),
            Some("2025-06-18")
        );
        let refused = check(&headers(&[(VERSION_HEADER, "1999-01-01")]), &origins).unwrap_err();
        assert_eq!(refused.into_response().status(), StatusCode::BAD_REQUEST);

        let mut response = StatusCode::OK.into_response();
        set_version(&mut response, Some("2025-06-18"));
        assert_eq!(response.headers()[VERSION_HEADER], "2025-06-18");
        let mut response = StatusCode::OK.into_response();
        set_version(&mut response, None);
        assert_eq!(response.headers()[VERSION_HEADER], PROTOCOL_VERSION);
    }

    #[test]
    fn allowed_origins_are_bare_http_origins() {
        assert!(check_allowed_origins(&["https://console.example".into(), "http://localhost:3000".into()]).is_ok());
        for bad in [
            "https://console.example/",
            "https://console.example/app",
            "console.example",
            "ftp://x.example",
        ] {
            assert!(check_allowed_origins(&[bad.into()]).is_err(), "{bad}");
        }
    }
}
