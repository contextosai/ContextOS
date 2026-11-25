//! X.509 SVIDs as agent identity: with mutual TLS and `[server.tls] spiffe_agents`, the
//! agents a caller may admit runs as are narrowed to the one its client certificate's
//! SPIFFE ID maps to.
//!
//! After the handshake, the TLS server reads the client certificate's `spiffe://` URI
//! SAN (the certificate chain was already verified against `client_ca_path`) and
//! attaches it to every request on that connection as an extension. The router's
//! outermost middleware removes any client-sent copy of the internal header and
//! re-creates it from the extension only, so a client cannot claim an identity its
//! certificate does not carry.
//!
//! Narrowing combines with the credential: a token or key that names agents keeps only
//! the certificate's agent if it is among them (none otherwise); one that names none
//! gets the certificate's. A connection without a mapped certificate names no agent, so
//! `[guards] agent_binding = "required"` refuses its admissions (`agent_not_bound`).

use std::collections::BTreeMap;

use axum::extract::Request;
use axum::http::HeaderValue;
use axum::middleware::Next;
use axum::response::Response;

use crate::auth::Caller;

/// The internal header carrying a verified peer's SPIFFE ID.
pub const PEER_HEADER: &str = "x-contextos-peer-spiffe-id";
/// Mapped SPIFFE IDs at most.
pub const MAX_MAPPED: usize = 1024;

/// The verified SPIFFE ID of the connection's client certificate, if any.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerSpiffeId(pub Option<String>);

/// The first `spiffe://` URI SAN of a DER certificate.
#[must_use]
pub fn spiffe_id(der: &rustls::pki_types::CertificateDer<'_>) -> Option<String> {
    let cert = webpki::EndEntityCert::try_from(der).ok()?;
    cert.valid_uri_names()
        .find(|u| u.starts_with("spiffe://") && u.len() <= 2048)
        .map(str::to_owned)
}

/// Strips any client-sent peer header and sets it from the connection's verified
/// identity (see the module documentation).
pub async fn propagate(mut request: Request, next: Next) -> Response {
    request.headers_mut().remove(PEER_HEADER);
    let id = request
        .extensions()
        .get::<PeerSpiffeId>()
        .and_then(|p| p.0.clone())
        .and_then(|id| HeaderValue::from_str(&id).ok());
    if let Some(value) = id {
        request.headers_mut().insert(PEER_HEADER, value);
    }
    next.run(request).await
}

/// Validates `spiffe_agents`.
pub fn validate(mapping: &BTreeMap<String, String>) -> Result<(), String> {
    if mapping.len() > MAX_MAPPED {
        return Err(format!("[server.tls] spiffe_agents maps at most {MAX_MAPPED} ids"));
    }
    if let Some((id, _)) = mapping
        .iter()
        .find(|(id, agent)| !id.starts_with("spiffe://") || agent.is_empty() || agent.len() > 256)
    {
        return Err(format!(
            "[server.tls] spiffe_agents: {id} must be a spiffe:// id mapped to an agent id"
        ));
    }
    Ok(())
}

/// The caller with its agents narrowed by the connection's SVID (see the module
/// documentation); unchanged when no mapping is configured.
#[must_use]
pub fn narrow(mapping: Option<&BTreeMap<String, String>>, peer: Option<&str>, mut caller: Caller) -> Caller {
    let Some(mapping) = mapping.filter(|m| !m.is_empty()) else {
        return caller;
    };
    let certified = peer.and_then(|id| mapping.get(id));
    caller.agents = Some(match (caller.agents.take(), certified) {
        (_, None) => Vec::new(),
        (None, Some(agent)) => vec![agent.clone()],
        (Some(named), Some(agent)) => named.into_iter().filter(|a| a == agent).collect(),
    });
    caller.agent_source = Some(match caller.agent_source.take() {
        Some(source) => format!("{source}+x509_svid"),
        None => "x509_svid".into(),
    });
    caller
}

#[cfg(test)]
mod tests {
    use super::*;

    fn caller(agents: Option<Vec<&str>>) -> Caller {
        Caller {
            tenant_id: "t".into(),
            principal_id: "p".into(),
            scopes: vec!["admit".into()],
            agents: agents.map(|a| a.into_iter().map(str::to_owned).collect()),
            agent_source: None,
            user: None,
        }
    }

    #[test]
    fn the_certificate_narrows_what_the_credential_names() {
        let map = BTreeMap::from([("spiffe://acme/sa/support".to_owned(), "agt_support".to_owned())]);
        let id = Some("spiffe://acme/sa/support");
        assert_eq!(
            narrow(Some(&map), id, caller(None)).agents,
            Some(vec!["agt_support".to_owned()])
        );
        assert_eq!(
            narrow(Some(&map), id, caller(Some(vec!["agt_support", "agt_other"]))).agents,
            Some(vec!["agt_support".to_owned()])
        );
        assert_eq!(
            narrow(Some(&map), id, caller(Some(vec!["agt_other"]))).agents,
            Some(vec![])
        );
        assert_eq!(
            narrow(Some(&map), None, caller(None)).agents,
            Some(vec![]),
            "no certificate, no agent"
        );
        assert_eq!(
            narrow(Some(&map), Some("spiffe://acme/sa/unknown"), caller(None)).agents,
            Some(vec![])
        );
        assert_eq!(narrow(None, id, caller(None)).agents, None, "off without a mapping");
        assert_eq!(
            narrow(Some(&map), id, caller(None)).agent_source.as_deref(),
            Some("x509_svid")
        );
    }

    #[test]
    fn mappings_name_spiffe_ids() {
        assert!(validate(&BTreeMap::from([("spiffe://a/b".to_owned(), "agt".to_owned())])).is_ok());
        assert!(validate(&BTreeMap::from([("https://a/b".to_owned(), "agt".to_owned())])).is_err());
        assert!(validate(&BTreeMap::from([("spiffe://a/b".to_owned(), String::new())])).is_err());
    }
}
