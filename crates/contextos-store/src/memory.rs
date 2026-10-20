//! In-process store for embedded use and tests. Linearizable per key.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use serde_json::Value;

use crate::{DocKey, DocumentStore, Encoded, StoreError, Versioned};

/// A stored document: revision, parsed body and the digest of its canonical form.
/// The in-process store keeps the parsed body, so reads need no re-parsing; bodies
/// are only ever written through canonical encoding. The lock covers a pointer copy
/// only: the deep clone a reader needs happens after it is released.
type StoredDoc = (u64, Arc<Value>, String);

#[derive(Debug, Default)]
pub struct MemoryStore {
    docs: RwLock<HashMap<DocKey, StoredDoc>>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn poisoned() -> StoreError {
        StoreError::Backend("memory store lock poisoned".into())
    }
}

impl DocumentStore for MemoryStore {
    fn reads_are_cheap(&self) -> bool {
        true
    }

    async fn get(&self, key: &DocKey) -> Result<Option<Versioned>, StoreError> {
        let found = {
            let docs = self.docs.read().map_err(|_| Self::poisoned())?;
            docs.get(key).cloned()
        };
        Ok(found.map(|(revision, body, digest)| Versioned {
            revision,
            body: Value::clone(&body),
            digest,
        }))
    }

    async fn create(&self, key: &DocKey, body: &Value) -> Result<Versioned, StoreError> {
        let Encoded { text, digest } = Encoded::of(body)?;
        // Store the decoded canonical form so reads match what Postgres would return.
        let canonical: Value = serde_json::from_str(&text).map_err(|_| StoreError::Integrity)?;
        let mut docs = self.docs.write().map_err(|_| Self::poisoned())?;
        if let Some((revision, _, _)) = docs.get(key) {
            return Err(StoreError::Conflict {
                expected: None,
                actual: Some(*revision),
            });
        }
        docs.insert(key.clone(), (1, Arc::new(canonical.clone()), digest.clone()));
        Ok(Versioned {
            revision: 1,
            body: canonical,
            digest,
        })
    }

    async fn compare_and_swap(
        &self,
        key: &DocKey,
        expected_revision: u64,
        body: &Value,
    ) -> Result<Versioned, StoreError> {
        let encoded = Encoded::of(body)?;
        let digest = encoded.digest.clone();
        let revision = self
            .compare_and_swap_encoded(key, expected_revision, body.clone(), encoded)
            .await?;
        Ok(Versioned {
            revision,
            body: body.clone(),
            digest,
        })
    }

    async fn compare_and_swap_encoded(
        &self,
        key: &DocKey,
        expected_revision: u64,
        body: Value,
        encoded: Encoded,
    ) -> Result<u64, StoreError> {
        let body = Arc::new(body);
        let mut docs = self.docs.write().map_err(|_| Self::poisoned())?;
        let Some(entry) = docs.get_mut(key) else {
            return Err(StoreError::NotFound);
        };
        if entry.0 != expected_revision {
            return Err(StoreError::Conflict {
                expected: Some(expected_revision),
                actual: Some(entry.0),
            });
        }
        let revision = entry.0 + 1;
        let replaced = std::mem::replace(entry, (revision, body, encoded.digest));
        drop(docs);
        // The replaced body is freed outside the lock.
        drop(replaced);
        Ok(revision)
    }
}

/// `(sequence, record_hash, canonical body)`.
type StoredRow = (u64, String, String);

/// In-process append-only log.
#[derive(Debug, Default)]
pub struct MemoryLog {
    rows: RwLock<HashMap<String, Vec<StoredRow>>>,
}

impl MemoryLog {
    pub fn new() -> Self {
        Self::default()
    }
}

impl crate::AppendLog for MemoryLog {
    async fn head(&self, tenant_id: &str) -> Result<Option<crate::LogRow>, StoreError> {
        let rows = self.rows.read().map_err(|_| MemoryStore::poisoned())?;
        rows.get(tenant_id)
            .and_then(|r| r.last())
            .map(|(sequence, hash, text)| row(*sequence, hash, text))
            .transpose()
    }

    async fn append_batch(&self, tenant_id: &str, batch: &[crate::AppendRow]) -> Result<(), StoreError> {
        let Some(first) = batch.first() else {
            return Ok(());
        };
        if batch.windows(2).any(|w| w[1].sequence != w[0].sequence + 1) {
            return Err(StoreError::Integrity);
        }
        let stored: Vec<StoredRow> = batch
            .iter()
            .map(|r| (r.sequence, r.record_hash.clone(), r.text.clone()))
            .collect();
        let mut rows = self.rows.write().map_err(|_| MemoryStore::poisoned())?;
        let chain = rows.entry(tenant_id.to_owned()).or_default();
        let head = chain.last().map(|(sequence, _, _)| *sequence);
        if first.sequence != head.map_or(1, |h| h + 1) {
            return Err(StoreError::Conflict {
                expected: Some(first.sequence.saturating_sub(1)),
                actual: head,
            });
        }
        chain.extend(stored);
        Ok(())
    }

    async fn range(&self, tenant_id: &str, from: u64, limit: usize) -> Result<Vec<crate::LogRow>, StoreError> {
        let rows = self.rows.read().map_err(|_| MemoryStore::poisoned())?;
        rows.get(tenant_id)
            .into_iter()
            .flatten()
            .filter(|(sequence, _, _)| *sequence >= from)
            .take(limit)
            .map(|(sequence, hash, text)| row(*sequence, hash, text))
            .collect()
    }
}

fn row(sequence: u64, record_hash: &str, text: &str) -> Result<crate::LogRow, StoreError> {
    let body = serde_json::from_str(text).map_err(|_| StoreError::Integrity)?;
    Ok(crate::LogRow {
        sequence,
        record_hash: record_hash.to_owned(),
        body,
    })
}
