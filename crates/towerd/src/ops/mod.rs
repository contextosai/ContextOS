//! Operational console APIs, one module per job, each adding its own routes to
//! [`crate::api::router`] through [`routes`].

use axum::Router;
use contextos_store::{AppendLog, DocumentStore};

use crate::api::Shared;

pub mod approvals;
pub mod inbox;
pub mod revocations;
mod sources;
pub mod spend;

/// The routes of every operational console module.
pub fn routes<S, L>() -> Router<Shared<S, L>>
where
    S: DocumentStore + 'static,
    L: AppendLog + 'static,
{
    Router::new()
        .merge(approvals::routes())
        .merge(inbox::routes())
        .merge(revocations::routes())
        .merge(sources::routes())
        .merge(spend::routes())
}
