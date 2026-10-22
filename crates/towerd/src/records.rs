//! The governance plane's own records, and its signed journal.
//!
//! Records are low-cardinality collections (one per kind) in the document store, so
//! they survive restarts on PostgreSQL and change only by compare-and-swap. Every
//! change to them is first written to Tower's journal: an Ed25519-signed hash chain
//! (the same format as a runtime's audit chain), so governance decisions are evidence
//! too, verifiable with `ctx audit-verify` against `GET /api/journal/keys`.

use std::sync::Arc;

use contextos_audit::AuditWriter;
use contextos_store::{AppendLog, DocKey, DocKind, DocumentStore, StoreError};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

pub const NAMESPACE: &str = "tower";

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

    /// Journals `kind` with `payload`, then changes the collection by compare-and-swap.
    /// The change function sees the current items and may refuse.
    pub async fn change<R>(
        &self,
        collection: &str,
        kind: &str,
        payload: Value,
        at: &str,
        mut change: impl FnMut(&mut Value) -> Result<R, RecordError>,
    ) -> Result<R, RecordError> {
        // Validate against the current state before journalling, so a refused change
        // leaves no journal entry.
        let current = self.store.get(&key(collection)).await?;
        let mut probe = current.as_ref().map_or(Value::Null, |c| c.body["items"].clone());
        change(&mut probe)?;
        self.journal
            .append(NAMESPACE, kind, payload, at)
            .await
            .map_err(|_| RecordError::Journal)?;
        let mut current = current;
        for _ in 0..16 {
            let mut items = current.as_ref().map_or(Value::Null, |c| c.body["items"].clone());
            let result = change(&mut items)?;
            let body = json!({"items": items});
            let written = match &current {
                None => self.store.create(&key(collection), &body).await.map(|_| ()),
                Some(c) => self
                    .store
                    .compare_and_swap(&key(collection), c.revision, &body)
                    .await
                    .map(|_| ()),
            };
            match written {
                Ok(()) => return Ok(result),
                Err(e) if e.is_conflict() => current = self.store.get(&key(collection)).await?,
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
