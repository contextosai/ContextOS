//! Operational console APIs, one module per job, each adding its own routes to
//! [`crate::api::router`] through [`routes`].

pub mod spend;

use axum::Router;
use contextos_store::{AppendLog, DocumentStore};

use crate::api::Shared;

/// The routes of every operational console module.
pub fn routes<S, L>() -> Router<Shared<S, L>>
where
    S: DocumentStore + 'static,
    L: AppendLog + 'static,
{
    Router::new().merge(spend::routes())
}
