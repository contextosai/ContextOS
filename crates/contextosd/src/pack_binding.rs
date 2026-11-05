//! Each pack reference bound to one content, in the store.
//!
//! Runs, decision records and replay cases cite a pack by reference, not by digest, so
//! a reference must never come to mean other content. The first time any server loads
//! a reference it records `pack_loaded` (reference, sha256, source) in the tenant's
//! audit chain, then binds the reference to that sha256 in a `context_pack` document.
//! Every later load, whether a reload, another replica or a restart, must match the
//! binding: at startup a mismatch stops the server, and on reload the file is refused
//! (`pack_ref_immutable`). A pack serves traffic only once it is recorded and bound.
//!
//! The binding lives in the configured store, so it outlasts a restart only with a
//! durable store (`postgres`); the in-memory store starts with no bindings.

use contextos_audit::AuditWriter;
use contextos_store::{AppendLog, DocKey, DocKind, DocumentStore, StoreError};
use serde_json::json;

/// Why a pack could not be bound.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindError {
    /// The reference is bound to other content.
    Changed { bound: String },
    /// The audit entry or the binding could not be written.
    Unrecorded(String),
}

impl std::fmt::Display for BindError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BindError::Changed { bound } => {
                write!(f, "the reference is bound to {bound}; publish changes as a new version")
            }
            BindError::Unrecorded(error) => write!(f, "the pack load could not be recorded: {error}"),
        }
    }
}

/// One pack to bind.
#[derive(Debug, Clone, Copy)]
pub struct PackIdentity<'a> {
    pub pack_ref: &'a str,
    pub tenant_id: &'a str,
    pub sha256: &'a str,
    pub source: &'a str,
}

fn key(pack: &PackIdentity<'_>) -> DocKey {
    DocKey::new(pack.tenant_id, DocKind::ContextPack, pack.pack_ref)
}

fn check(body: &serde_json::Value, pack: &PackIdentity<'_>) -> Result<bool, BindError> {
    let bound = body["sha256"].as_str().unwrap_or_default();
    if bound == pack.sha256 {
        Ok(false)
    } else {
        Err(BindError::Changed {
            bound: bound.to_owned(),
        })
    }
}

/// Binds `pack`, recording it first if it is new. `Ok(true)` when this call bound it,
/// `Ok(false)` when it was already bound to the same content.
pub async fn bind<S, L>(store: &S, audit: &AuditWriter<L>, pack: PackIdentity<'_>, now: &str) -> Result<bool, BindError>
where
    S: DocumentStore,
    L: AppendLog,
{
    let unrecorded = |e: &dyn std::fmt::Display| BindError::Unrecorded(e.to_string());
    let key = key(&pack);
    if let Some(doc) = store.get(&key).await.map_err(|e| unrecorded(&e))? {
        return check(&doc.body, &pack);
    }
    // Recorded before it is bound: a binding always has its audit entry. A crash in
    // between records the load again on the next attempt.
    audit
        .append(
            pack.tenant_id,
            "pack_loaded",
            json!({"pack_ref": pack.pack_ref, "sha256": pack.sha256, "source": pack.source}),
            now,
        )
        .await
        .map_err(|e| unrecorded(&e))?;
    let body = json!({"pack_ref": pack.pack_ref, "sha256": pack.sha256, "bound_at": now});
    match store.create(&key, &body).await {
        Ok(_) => Ok(true),
        // Another replica bound it first.
        Err(StoreError::Conflict { .. }) => match store.get(&key).await.map_err(|e| unrecorded(&e))? {
            Some(doc) => check(&doc.body, &pack),
            None => Err(BindError::Unrecorded("the binding vanished".into())),
        },
        Err(error) => Err(unrecorded(&error)),
    }
}
