//! Operational console APIs, one module per job, each adding its own routes to
//! [`crate::api::router`] through [`routes`].

use axum::Router;
use contextos_store::{AppendLog, DocumentStore};

use crate::api::Shared;

pub mod access_review;
pub mod approvals;
pub mod break_glass;
pub mod cases;
pub mod dashboard;
pub mod inbox;
pub mod inventory;
pub mod lifecycle;
pub mod revocations;
mod sources;
pub mod spend;
pub mod sso;

/// The routes of every operational console module.
pub fn routes<S, L>() -> Router<Shared<S, L>>
where
    S: DocumentStore + 'static,
    L: AppendLog + 'static,
{
    Router::new()
        .merge(access_review::routes())
        .merge(approvals::routes())
        .merge(break_glass::routes())
        .merge(cases::routes())
        .merge(dashboard::routes())
        .merge(inbox::routes())
        .merge(inventory::routes())
        .merge(lifecycle::routes())
        .merge(revocations::routes())
        .merge(sources::routes())
        .merge(spend::routes())
        .merge(sso::routes())
}
