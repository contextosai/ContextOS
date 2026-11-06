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
//! Exactly one server writes the `pack_loaded` entry. The binding is claimed with a
//! lease and the log sequence the entry will follow; a server that finds a live claim
//! waits for it, and one that finds an expired claim looks for the entry from that
//! sequence before taking the claim over, so a server that crashed after writing it is
//! not recorded twice. Only a claim holder stalled past its lease between its last
//! check and the append can still be recorded twice.
//!
//! A lease's end (`until_ms`) is the holder's wall clock, compared against the
//! waiter's, so leases assume replicas with synchronized clocks (NTP or equivalent).
//! A holder whose clock runs behind looks expired while it is still healthy, which
//! widens that window across replicas; a duplicate entry leaves the chain verifiable.
//!
//! The binding lives in the configured store, so it outlasts a restart only with a
//! durable store (`postgres`); the in-memory store, which loses the audit chain on a
//! restart as well, starts with no bindings.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use contextos_audit::AuditWriter;
use contextos_store::{AppendLog, DocKey, DocKind, DocumentStore, StoreError, Versioned};
use serde_json::{Value, json};

/// How long a claim lets its holder write the entry before others may take it over.
const LEASE_MS: u64 = 30_000;
/// How often a server waiting on another's live claim re-reads the binding.
const POLL: Duration = Duration::from_millis(50);
/// Log rows read per page when looking for an entry an expired claim left.
const PAGE: usize = 500;

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

fn check(body: &Value, pack: &PackIdentity<'_>) -> Result<(), BindError> {
    let bound = body["sha256"].as_str().unwrap_or_default();
    if bound == pack.sha256 {
        Ok(())
    } else {
        Err(BindError::Changed {
            bound: bound.to_owned(),
        })
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// Binds `pack`, recording it if it is new. `Ok(true)` when this call recorded it,
/// `Ok(false)` when it was already bound to the same content and recorded.
///
/// The binding is claimed before the audit entry is written and marked recorded after
/// it, so a server that loses the claim to other content writes nothing, a server that
/// finds the claim held waits for its holder, and a binding left unrecorded by a crash
/// is recorded by the next load of the same content, once.
pub async fn bind<S, L>(store: &S, audit: &AuditWriter<L>, pack: PackIdentity<'_>, now: &str) -> Result<bool, BindError>
where
    S: DocumentStore,
    L: AppendLog,
{
    let unrecorded = |e: &dyn std::fmt::Display| BindError::Unrecorded(e.to_string());
    let key = key(&pack);
    // Long enough to outwait one lease of another server and take its claim over.
    let deadline = now_ms() + 2 * LEASE_MS + 1_000;
    loop {
        if now_ms() > deadline {
            return Err(BindError::Unrecorded("the binding kept changing".into()));
        }
        let current = store.get(&key).await.map_err(|e| unrecorded(&e))?;
        let claimed = match &current {
            None => claim(store, audit.log(), &key, &pack, now, None).await,
            Some(doc) => {
                check(&doc.body, &pack)?;
                if doc.body["recorded"] != false {
                    return Ok(false);
                }
                let lease = &doc.body["claim"];
                if lease["until_ms"].as_u64().is_some_and(|until| until > now_ms()) {
                    tokio::time::sleep(POLL).await;
                    continue;
                }
                // The claim expired, or an earlier release left the binding without one.
                if let Some(from) = lease["from"].as_u64()
                    && was_recorded(audit.log(), &pack, from)
                        .await
                        .map_err(|e| unrecorded(&e))?
                {
                    match store
                        .compare_and_swap(&key, doc.revision, &recorded_body(&pack, now))
                        .await
                    {
                        Ok(_) => return Ok(false),
                        Err(error) if error.is_conflict() => continue,
                        Err(error) => return Err(unrecorded(&error)),
                    }
                }
                claim(store, audit.log(), &key, &pack, now, Some(doc)).await
            }
        };
        let revision = match claimed {
            Ok(revision) => revision,
            Err(error) if error.is_conflict() => continue,
            Err(error) => return Err(unrecorded(&error)),
        };
        let entry = json!({"pack_ref": pack.pack_ref, "sha256": pack.sha256, "source": pack.source});
        if let Err(error) = audit.append(pack.tenant_id, "pack_loaded", entry, now).await {
            // Whether the entry landed is unknown; expire the claim so the next load
            // looks for it at once instead of waiting out the lease.
            if let Ok(Some(doc)) = store.get(&key).await
                && doc.revision == revision
            {
                let mut body = doc.body;
                body["claim"]["until_ms"] = json!(0);
                let _ = store.compare_and_swap(&key, revision, &body).await;
            }
            return Err(unrecorded(&error));
        }
        return match store.compare_and_swap(&key, revision, &recorded_body(&pack, now)).await {
            Ok(_) => Ok(true),
            // Another server took the claim over after our lease ran out; whichever
            // finishes marks it recorded.
            Err(error) if error.is_conflict() => Ok(true),
            Err(error) => Err(unrecorded(&error)),
        };
    }
}

fn recorded_body(pack: &PackIdentity<'_>, now: &str) -> Value {
    json!({"pack_ref": pack.pack_ref, "sha256": pack.sha256, "bound_at": now, "recorded": true})
}

/// Claims the binding for this server, creating it or taking over `expired`. Returns
/// the revision the entry is then marked recorded against.
async fn claim<S, L>(
    store: &S,
    log: &L,
    key: &DocKey,
    pack: &PackIdentity<'_>,
    now: &str,
    expired: Option<&Versioned>,
) -> Result<u64, StoreError>
where
    S: DocumentStore,
    L: AppendLog,
{
    // The entry will follow the current head, so a later search starts after it.
    let from = log.head(pack.tenant_id).await?.map_or(1, |row| row.sequence + 1);
    let body = json!({
        "pack_ref": pack.pack_ref,
        "sha256": pack.sha256,
        "bound_at": now,
        "recorded": false,
        "claim": {"from": from, "until_ms": now_ms() + LEASE_MS},
    });
    Ok(match expired {
        None => store.create(key, &body).await?.revision,
        Some(doc) => store.compare_and_swap(key, doc.revision, &body).await?.revision,
    })
}

/// Whether the tenant's chain holds a `pack_loaded` entry for this content at or
/// after `from`. A reference is bound to one content, so any such entry records it.
async fn was_recorded<L: AppendLog>(log: &L, pack: &PackIdentity<'_>, from: u64) -> Result<bool, StoreError> {
    let mut next = from;
    loop {
        let rows = log.range(pack.tenant_id, next, PAGE).await?;
        let Some(last) = rows.last() else {
            return Ok(false);
        };
        next = last.sequence + 1;
        if rows.iter().any(|row| {
            row.body["kind"] == "pack_loaded"
                && row.body["payload"]["pack_ref"] == pack.pack_ref
                && row.body["payload"]["sha256"] == pack.sha256
        }) {
            return Ok(true);
        }
    }
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

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_loads_record_once() {
        let store = std::sync::Arc::new(MemoryStore::new());
        let audit = std::sync::Arc::new(audit());
        let tasks: Vec<_> = (0..8)
            .map(|_| {
                let (store, audit) = (store.clone(), audit.clone());
                tokio::spawn(async move { bind(store.as_ref(), audit.as_ref(), pack("sha256:a"), NOW).await })
            })
            .collect();
        let mut recorders = 0;
        for task in tasks {
            recorders += usize::from(task.await.unwrap().unwrap());
        }
        assert_eq!(recorders, 1);
        assert_eq!(recorded(&audit).await, 1);
    }

    #[tokio::test]
    async fn a_server_waits_for_a_live_claim() {
        let (store, audit) = (std::sync::Arc::new(MemoryStore::new()), audit());
        let key = key(&pack("sha256:a"));
        let claim = json!({"pack_ref": "ctxpack.support@5.2.0", "sha256": "sha256:a", "recorded": false,
            "claim": {"from": 1, "until_ms": now_ms() + 60_000}});
        let created = store.create(&key, &claim).await.unwrap();
        let holder = {
            let store = store.clone();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(200)).await;
                store
                    .compare_and_swap(&key, created.revision, &recorded_body(&pack("sha256:a"), NOW))
                    .await
                    .unwrap();
            })
        };
        assert_eq!(bind(store.as_ref(), &audit, pack("sha256:a"), NOW).await, Ok(false));
        holder.await.unwrap();
        assert_eq!(recorded(&audit).await, 0, "the holder writes the entry, not the waiter");
    }

    #[tokio::test]
    async fn an_expired_claim_whose_entry_was_written_is_not_recorded_again() {
        let (store, audit) = (MemoryStore::new(), audit());
        let payload = json!({"pack_ref": "ctxpack.support@5.2.0", "sha256": "sha256:a", "source": "startup"});
        audit.append("tenant_a", "pack_loaded", payload, NOW).await.unwrap();
        // The holder wrote entry 1 and crashed before marking the binding recorded.
        let claim = json!({"pack_ref": "ctxpack.support@5.2.0", "sha256": "sha256:a", "recorded": false,
            "claim": {"from": 1, "until_ms": 0}});
        store.create(&key(&pack("sha256:a")), &claim).await.unwrap();
        assert_eq!(bind(&store, &audit, pack("sha256:a"), NOW).await, Ok(false));
        assert_eq!(recorded(&audit).await, 1);
        let doc = store.get(&key(&pack("sha256:a"))).await.unwrap().unwrap();
        assert_eq!(doc.body["recorded"], true);
    }

    #[tokio::test]
    async fn an_expired_claim_without_its_entry_is_taken_over() {
        let (store, audit) = (MemoryStore::new(), audit());
        // An entry before the claim's sequence does not count.
        let payload = json!({"pack_ref": "ctxpack.support@5.2.0", "sha256": "sha256:a", "source": "startup"});
        audit.append("tenant_a", "pack_loaded", payload, NOW).await.unwrap();
        let claim = json!({"pack_ref": "ctxpack.support@5.2.0", "sha256": "sha256:a", "recorded": false,
            "claim": {"from": 2, "until_ms": 0}});
        store.create(&key(&pack("sha256:a")), &claim).await.unwrap();
        assert_eq!(bind(&store, &audit, pack("sha256:a"), NOW).await, Ok(true));
        assert_eq!(recorded(&audit).await, 2);
    }
}
