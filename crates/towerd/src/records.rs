//! The governance plane's own records, and its signed journal.
//!
//! Records are low-cardinality collections (one per kind) in the document store, so
//! they survive restarts on PostgreSQL and change only by compare-and-swap. Every
//! change to them is journaled in Tower's journal: an Ed25519-signed hash chain (the
//! same format as a runtime's audit chain), so governance decisions are evidence too,
//! verifiable with `ctx audit-verify` against `GET /api/journal/keys`.
//!
//! The journal is an outbox of the records. A change commits together with its
//! journal entry, marked pending, in one compare-and-swap; the entry is signed only
//! after that commit, so the journal never holds an event for a change that did not
//! happen.
//!
//! A collection holds at most one pending entry. A change commits only when none is
//! pending, a condition the compare-and-swap enforces: it first journals entries whose
//! writer is gone (lease expired), and waits for an entry another writer is still
//! publishing. So a collection's entries are journaled in commit order, and each change
//! is journaled before the collection changes again. The order is per collection:
//! entries of different collections interleave in the journal without a defined order.
//! Each entry's payload also carries the collection and its commit number
//! (`collection_seq`), so a verifier reads commit order without relying on journal
//! position. Numbering starts at 1 with a collection's first change made by a version
//! that numbers them and has no gaps from there; entries written before carry none. A sweep once per
//! lease period journals an entry whose writer crashed even if nothing else changes.
//!
//! One writer at a time publishes a pending entry: the committer holds a lease on it,
//! written by the same compare-and-swap, and recovery takes over only entries whose
//! lease has expired, claiming them by compare-and-swap first. Each entry's payload
//! carries a `change_id`, and a publisher looks for it in the journal before
//! appending, so an entry already journaled is not signed again. An entry is journaled
//! twice only if its publisher stalls for longer than the lease between that check and
//! its append; both copies then name the same `change_id`.

use std::sync::Arc;

use contextos_audit::AuditWriter;
use contextos_store::{AppendLog, DocKey, DocKind, DocumentStore, StoreError};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

pub const NAMESPACE: &str = "tower";

/// How long a writer owns publishing a pending entry before recovery may take it over.
pub const PUBLISH_LEASE_MICROS: u64 = 30_000_000;

fn micros_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_micros()).unwrap_or(u64::MAX))
}

/// The record collections, recovered at startup.
pub const COLLECTIONS: [&str; 4] = ["declarations", "reviews", "guardrails", "waivers"];

/// What an agent's owner states about it. Inputs to review, never evidence.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Declaration {
    pub owner: String,
    pub team: String,
    #[serde(default)]
    pub business_unit: Option<String>,
    pub purpose: String,
    /// `internal`, `customers` or `public`.
    pub users_served: String,
    /// `proposed`, `pilot`, `production`, `deprecated` or `retired`.
    pub lifecycle: String,
    #[serde(default)]
    pub data_categories: Vec<String>,
    /// e.g. `finance`, `clinical`, `employment`, `eu_ai_act_high_risk`.
    #[serde(default)]
    pub regulatory_contexts: Vec<String>,
}

pub const LIFECYCLE: [&str; 5] = ["proposed", "pilot", "production", "deprecated", "retired"];
pub const USERS: [&str; 3] = ["internal", "customers", "public"];

impl Declaration {
    pub fn check(&self) -> Result<(), String> {
        let sized = |s: &str, max: usize| !s.trim().is_empty() && s.len() <= max;
        if !sized(&self.owner, 256) || !sized(&self.team, 256) || !sized(&self.purpose, 2048) {
            return Err("owner, team and purpose are required (purpose up to 2048 bytes)".into());
        }
        if !LIFECYCLE.contains(&self.lifecycle.as_str()) {
            return Err(format!("lifecycle must be one of {LIFECYCLE:?}"));
        }
        if !USERS.contains(&self.users_served.as_str()) {
            return Err(format!("users_served must be one of {USERS:?}"));
        }
        if self.data_categories.len() > 32 || self.regulatory_contexts.len() > 32 {
            return Err("at most 32 data categories and regulatory contexts".into());
        }
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RecordError {
    #[error("{0}")]
    Invalid(String),
    #[error("not found")]
    NotFound,
    #[error("{0}")]
    Forbidden(&'static str),
    #[error("conflict: {0}")]
    Conflict(&'static str),
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("journal unavailable")]
    Journal,
    /// The change is committed; its journal entry is pending and is written before the
    /// collection changes again.
    #[error("journal entry pending")]
    JournalPending,
}

pub struct Records<S, L> {
    store: Arc<S>,
    journal: Arc<AuditWriter<L>>,
}

impl<S, L> std::fmt::Debug for Records<S, L> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Records").finish_non_exhaustive()
    }
}

fn key(collection: &str) -> DocKey {
    DocKey::new(NAMESPACE, DocKind::Governance, collection)
}

impl<S: DocumentStore, L: AppendLog> Records<S, L> {
    pub fn new(store: Arc<S>, journal: Arc<AuditWriter<L>>) -> Self {
        Self { store, journal }
    }

    pub fn journal(&self) -> &AuditWriter<L> {
        &self.journal
    }

    /// A collection's items (`{}` or `[]` when empty).
    pub async fn load(&self, collection: &str) -> Result<Value, RecordError> {
        Ok(self
            .store
            .get(&key(collection))
            .await?
            .map_or(Value::Null, |v| v.body["items"].clone()))
    }

    /// Changes the collection by compare-and-swap, then journals `kind` with `payload`
    /// (see the module documentation). The change function sees the current items and
    /// may refuse; a refused change is never journaled.
    pub async fn change<R>(
        &self,
        collection: &str,
        kind: &str,
        mut payload: Value,
        at: &str,
        mut change: impl FnMut(&mut Value) -> Result<R, RecordError>,
    ) -> Result<R, RecordError> {
        let change_id = new_id();
        if let Some(fields) = payload.as_object_mut() {
            fields.insert("change_id".into(), json!(change_id));
            fields.insert("collection".into(), json!(collection));
        }
        let started = std::time::Instant::now();
        let mut pause = std::time::Duration::from_millis(5);
        let mut conflicts = 0;
        let (result, entry) = loop {
            // Earlier changes' evidence first: nothing changes while it cannot be written.
            self.recover(collection).await?;
            let current = self.store.get(&key(collection)).await?;
            let body = current.as_ref().map_or(Value::Null, |c| c.body.clone());
            if body["pending"].as_array().is_some_and(|p| !p.is_empty()) {
                // Another writer is publishing its entry: commit after it, so the journal
                // keeps commit order. A writer that never finishes loses its lease, and
                // recovery above then journals its entry.
                if started.elapsed() > std::time::Duration::from_micros(2 * PUBLISH_LEASE_MICROS) {
                    return Err(RecordError::Conflict("an earlier change is not journaled yet"));
                }
                tokio::time::sleep(pause).await;
                pause = (pause * 2).min(std::time::Duration::from_millis(200));
                continue;
            }
            let seq = body["seq"].as_u64().unwrap_or(0) + 1;
            let after = self
                .journal
                .log()
                .head(NAMESPACE)
                .await
                .map_err(|_| RecordError::Journal)?
                .map_or(0, |row| row.sequence);
            let mut payload = payload.clone();
            if let Some(fields) = payload.as_object_mut() {
                fields.insert("collection_seq".into(), json!(seq));
            }
            let entry = json!({"change_id": change_id, "kind": kind, "payload": payload, "at": at, "after": after,
                "claimed_until": micros_now() + PUBLISH_LEASE_MICROS});
            let mut items = body["items"].clone();
            let result = change(&mut items)?;
            let next = json!({"items": items, "pending": [entry], "seq": seq});
            let written = match &current {
                None => self.store.create(&key(collection), &next).await.map(|_| ()),
                Some(c) => self
                    .store
                    .compare_and_swap(&key(collection), c.revision, &next)
                    .await
                    .map(|_| ()),
            };
            match written {
                Ok(()) => break (result, entry),
                Err(e) if e.is_conflict() => {
                    conflicts += 1;
                    if conflicts >= 64 {
                        return Err(RecordError::Conflict("too much contention"));
                    }
                }
                Err(e) => return Err(e.into()),
            }
        };
        if self.publish(&entry).await.is_err() {
            // Give the entry up, so the collection's next change journals it first.
            let _ = self.claim(collection, Some(&change_id), 0).await;
            return Err(RecordError::JournalPending);
        }
        if self.settle(collection, std::slice::from_ref(&change_id)).await.is_err() {
            // Still marked pending: release it, so the next writer finds it journaled
            // and clears it at once rather than waiting out the lease.
            let _ = self.claim(collection, Some(&change_id), 0).await;
        }
        Ok(result)
    }

    /// Journals the collection's pending entries that no writer is publishing (their
    /// lease has expired), and clears them. Entries another writer holds are left to it.
    pub async fn recover(&self, collection: &str) -> Result<(), RecordError> {
        let claimed = self
            .claim(collection, None, micros_now() + PUBLISH_LEASE_MICROS)
            .await?;
        if claimed.is_empty() {
            return Ok(());
        }
        let mut ids = Vec::with_capacity(claimed.len());
        for entry in &claimed {
            self.publish(entry).await.map_err(|_| RecordError::Journal)?;
            ids.extend(entry["change_id"].as_str().map(str::to_owned));
        }
        self.settle(collection, &ids).await
    }

    /// Sets the lease of pending entries to `until` by compare-and-swap and returns
    /// them: the entry `change_id` names, or, with none, every entry whose lease has
    /// expired.
    async fn claim(&self, collection: &str, change_id: Option<&str>, until: u64) -> Result<Vec<Value>, RecordError> {
        for _ in 0..16 {
            let Some(current) = self.store.get(&key(collection)).await? else {
                return Ok(Vec::new());
            };
            let now = micros_now();
            let mut pending = current.body["pending"].as_array().cloned().unwrap_or_default();
            let mut claimed = Vec::new();
            for entry in &mut pending {
                let chosen = match change_id {
                    Some(id) => entry["change_id"] == id,
                    None => entry["claimed_until"].as_u64().unwrap_or(0) <= now,
                };
                if chosen {
                    entry["claimed_until"] = json!(until);
                    claimed.push(entry.clone());
                }
            }
            if claimed.is_empty() {
                return Ok(claimed);
            }
            let mut body = current.body.clone();
            body["pending"] = json!(pending);
            match self
                .store
                .compare_and_swap(&key(collection), current.revision, &body)
                .await
            {
                Ok(_) => return Ok(claimed),
                Err(e) if e.is_conflict() => {}
                Err(e) => return Err(e.into()),
            }
        }
        Err(RecordError::Conflict("too much contention"))
    }

    /// Appends a pending entry unless the journal already holds its `change_id`.
    async fn publish(&self, entry: &Value) -> Result<(), RecordError> {
        let id = &entry["change_id"];
        let log = self.journal.log();
        let mut from = entry["after"].as_u64().unwrap_or(0) + 1;
        loop {
            let rows = log.range(NAMESPACE, from, 500).await?;
            if rows.iter().any(|r| r.body["payload"]["change_id"] == *id) {
                return Ok(());
            }
            match rows.last() {
                Some(last) if rows.len() == 500 => from = last.sequence + 1,
                _ => break,
            }
        }
        let kind = entry["kind"].as_str().unwrap_or_default();
        let at = entry["at"].as_str().unwrap_or_default();
        self.journal
            .append(NAMESPACE, kind, entry["payload"].clone(), at)
            .await
            .map(|_| ())
            .map_err(|_| RecordError::Journal)
    }

    /// Removes journaled entries from the collection's pending list.
    async fn settle(&self, collection: &str, ids: &[String]) -> Result<(), RecordError> {
        for _ in 0..16 {
            let Some(current) = self.store.get(&key(collection)).await? else {
                return Ok(());
            };
            let pending = current.body["pending"].as_array().cloned().unwrap_or_default();
            let left: Vec<Value> = pending
                .iter()
                .filter(|e| !ids.iter().any(|id| e["change_id"] == id.as_str()))
                .cloned()
                .collect();
            if left.len() == pending.len() {
                return Ok(());
            }
            let mut body = current.body.clone();
            body["pending"] = json!(left);
            match self
                .store
                .compare_and_swap(&key(collection), current.revision, &body)
                .await
            {
                Ok(_) => return Ok(()),
                Err(e) if e.is_conflict() => {}
                Err(e) => return Err(e.into()),
            }
        }
        Err(RecordError::Conflict("too much contention"))
    }

    /// Journals an event that changes no record (e.g. use of intelligence).
    pub async fn note(&self, kind: &str, payload: Value, at: &str) -> Result<(), RecordError> {
        self.journal
            .append(NAMESPACE, kind, payload, at)
            .await
            .map(|_| ())
            .map_err(|_| RecordError::Journal)
    }
}

/// Items of an object collection as a map (empty when unset).
pub fn object(items: &mut Value) -> &mut serde_json::Map<String, Value> {
    if !items.is_object() {
        *items = json!({});
    }
    items.as_object_mut().expect("just set")
}

/// Items of an array collection (empty when unset).
pub fn array(items: &mut Value) -> &mut Vec<Value> {
    if !items.is_array() {
        *items = json!([]);
    }
    items.as_array_mut().expect("just set")
}

/// A new record id: a full UUIDv7. Its first 48 bits are the creation millisecond, so
/// a prefix of it would collide for records created together; the random bits keep
/// ids distinct.
pub fn new_id() -> String {
    uuid::Uuid::now_v7().simple().to_string()
}

/// Appends a record to an array collection, refusing an `id` a stored record has.
pub fn push_new(items: &mut Value, record: &Value) -> Result<(), RecordError> {
    let items = array(items);
    if items.iter().any(|i| i["id"] == record["id"]) {
        return Err(RecordError::Conflict("a record with this id exists"));
    }
    items.push(record.clone());
    Ok(())
}
