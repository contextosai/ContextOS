//! Each pack reference bound to one content, in the store.
//!
//! Runs, decision records and replay cases cite a pack by reference, not by digest, so
//! a reference must never come to mean other content. The first time any server loads
//! a reference it binds the reference to its content's sha256 in a `context_pack`
//! document, records `pack_loaded` (reference, sha256, source) in the tenant's audit
//! chain, and marks the binding recorded. Every later load, whether a reload, another replica or a restart, must match the
//! binding: at startup a mismatch stops the server, and on reload the file is refused
//! (`pack_ref_immutable`). A pack serves traffic only once it is recorded and bound.
//!
//! The binding lives in the configured store, so it outlasts a restart only with a
//! durable store (`postgres`); the in-memory store, which loses the audit chain on a
//! restart as well, starts with no bindings.

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

/// Binds `pack`, recording it if it is new. `Ok(true)` when this call recorded it,
/// `Ok(false)` when it was already bound to the same content and recorded.
///
/// The binding is claimed before the audit entry is written and marked recorded after
/// it, so a server that loses the claim to other content writes nothing, and a binding
/// left unrecorded by a crash is recorded by the next load of the same content.
pub async fn bind<S, L>(store: &S, audit: &AuditWriter<L>, pack: PackIdentity<'_>, now: &str) -> Result<bool, BindError>
where
    S: DocumentStore,
    L: AppendLog,
{
    let unrecorded = |e: &dyn std::fmt::Display| BindError::Unrecorded(e.to_string());
    let key = key(&pack);
    let body = |recorded: bool| json!({"pack_ref": pack.pack_ref, "sha256": pack.sha256, "bound_at": now, "recorded": recorded});
    // Each pass either finishes or loses a race to another writer; three are plenty.
    for _ in 0..3 {
        let revision = match store.get(&key).await.map_err(|e| unrecorded(&e))? {
            Some(doc) => {
                check(&doc.body, &pack)?;
                if doc.body["recorded"] != false {
                    return Ok(false);
                }
                doc.revision
            }
            None => match store.create(&key, &body(false)).await {
                Ok(created) => created.revision,
                Err(StoreError::Conflict { .. }) => continue,
                Err(error) => return Err(unrecorded(&error)),
            },
        };
        audit
            .append(
                pack.tenant_id,
                "pack_loaded",
                json!({"pack_ref": pack.pack_ref, "sha256": pack.sha256, "source": pack.source}),
                now,
            )
            .await
            .map_err(|e| unrecorded(&e))?;
        match store.compare_and_swap(&key, revision, &body(true)).await {
            Ok(_) => return Ok(true),
            // Another server recorded it meanwhile (the entry is then written twice).
            Err(StoreError::Conflict { .. }) => {}
            Err(error) => return Err(unrecorded(&error)),
        }
    }
    Err(BindError::Unrecorded("the binding kept changing".into()))
}

#[cfg(test)]
mod tests {
    use contextos_audit::AuditSigner;
    use contextos_store::{MemoryLog, MemoryStore};

    use super::*;

    const NOW: &str = "2026-11-05T10:00:00Z";

    fn pack(sha256: &str) -> PackIdentity<'_> {
        PackIdentity {
            pack_ref: "ctxpack.support@5.2.0",
            tenant_id: "tenant_a",
            sha256,
            source: "startup",
        }
    }

    async fn recorded(audit: &AuditWriter<MemoryLog>) -> usize {
        let rows = audit.log().range("tenant_a", 1, 100).await.unwrap();
        rows.iter().filter(|r| r.body["kind"] == "pack_loaded").count()
    }

    fn audit() -> AuditWriter<MemoryLog> {
        AuditWriter::new(MemoryLog::new(), AuditSigner::from_seed("k", [3; 32]))
    }

    #[tokio::test]
    async fn binds_and_records_once() {
        let (store, audit) = (MemoryStore::new(), audit());
        assert_eq!(bind(&store, &audit, pack("sha256:a"), NOW).await, Ok(true));
        assert_eq!(bind(&store, &audit, pack("sha256:a"), NOW).await, Ok(false));
        assert_eq!(recorded(&audit).await, 1);
        assert_eq!(
            bind(&store, &audit, pack("sha256:b"), NOW).await,
            Err(BindError::Changed {
                bound: "sha256:a".into()
            })
        );
        assert_eq!(recorded(&audit).await, 1);
    }

    #[tokio::test]
    async fn a_server_that_loses_the_claim_writes_nothing() {
        let (store, audit) = (MemoryStore::new(), audit());
        // Another replica has claimed the reference for other content and is still
        // recording it.
        let claim = json!({"pack_ref": "ctxpack.support@5.2.0", "sha256": "sha256:other", "recorded": false});
        store.create(&key(&pack("sha256:a")), &claim).await.unwrap();
        assert!(matches!(
            bind(&store, &audit, pack("sha256:a"), NOW).await,
            Err(BindError::Changed { .. })
        ));
        assert_eq!(recorded(&audit).await, 0);
    }

    #[tokio::test]
    async fn a_binding_left_unrecorded_is_recorded_by_the_next_load() {
        let (store, audit) = (MemoryStore::new(), audit());
        let claim = json!({"pack_ref": "ctxpack.support@5.2.0", "sha256": "sha256:a", "recorded": false});
        store.create(&key(&pack("sha256:a")), &claim).await.unwrap();
        assert_eq!(bind(&store, &audit, pack("sha256:a"), NOW).await, Ok(true));
        assert_eq!(recorded(&audit).await, 1);
        let doc = store.get(&key(&pack("sha256:a"))).await.unwrap().unwrap();
        assert_eq!(doc.body["recorded"], true);
    }
}
