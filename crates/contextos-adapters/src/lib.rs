//! Protocol adapters for the ContextOS Tool Gateway.
//!
//! Adapters translate a governed [`contextos_gateway::AdapterCall`] into a provider
//! request and report what is *known* about the effect. They never decide whether an
//! effect is allowed; the gateway has already done so before an adapter runs.

pub mod http;
pub mod mcp;
pub mod oauth;
pub mod remote;
pub mod tls;
pub mod transport;

pub use http::HttpAdapter;
pub use mcp::{McpAdapter, ResultProjection};
pub use oauth::OAuthClientCredentials;
pub use remote::{RemoteApprovals, RemoteAuthority, RemoteConstraints, RemoteFacts, RemoteIdempotency};
pub use transport::{Credential, CredentialBroker, EndpointError, NoCredentials, TransportPolicy};
