//! In-process store for embedded use and tests. Linearizable per key.

use std::collections::HashMap;
use std::future::{Future, poll_fn};
use std::sync::{Arc, RwLock};
use std::task::Poll;

use serde_json::Value;

use crate::{DocKey, DocumentStore, Encoded, StoreError, Versioned};

// Synchronous memory operations still execute only when their future is polled.
// In particular, dropping an unpolled write must not mutate the store.
fn deferred<T>(work: impl FnOnce() -> T) -> impl Future<Output = T> {
    let mut work = Some(work);
    poll_fn(move |_| Poll::Ready(work.take().expect("future polled after completion")()))
}

/// A stored document: revision, parsed body and the digest of its canonical form.
/// The in-process store keeps the parsed body, so reads need no re-parsing; bodies
/// are only ever written through canonical encoding. The lock covers a pointer copy
/// only: the deep clone a reader needs happens after it is released.
/// `(revision, body, digest, created µs since the epoch)`.
type StoredDoc = (u64, Arc<Value>, String, u64);

#[derive(Debug, Default)]
pub struct MemoryStore {
    docs: RwLock<HashMap<DocKey, StoredDoc>>,
}

fn now_us() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_micros()).unwrap_or(u64::MAX))
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

    fn get(&self, key: &DocKey) -> impl Future<Output = Result<Option<Versioned>, StoreError>> + Send {
        deferred(move || {
            let found = {
                let docs = self.docs.read().map_err(|_| Self::poisoned())?;
                docs.get(key).cloned()
            };
            Ok(found.map(|(revision, body, digest, _)| Versioned {
                revision,
                body: Value::clone(&body),
                digest,
            }))
        })
    }

    fn create(&self, key: &DocKey, body: &Value) -> impl Future<Output = Result<Versioned, StoreError>> + Send {
        deferred(move || {
            let Encoded { text, digest } = Encoded::of(body)?;
            // Store the decoded canonical form so reads match what Postgres would return.
            let canonical: Value = serde_json::from_str(&text).map_err(|_| StoreError::Integrity)?;
            let mut docs = self.docs.write().map_err(|_| Self::poisoned())?;
            if let Some((revision, _, _, _)) = docs.get(key) {
                return Err(StoreError::Conflict {
                    expected: None,
                    actual: Some(*revision),
                });
            }
            docs.insert(key.clone(), (1, Arc::new(canonical.clone()), digest.clone(), now_us()));
            Ok(Versioned {
                revision: 1,
                body: canonical,
                digest,
            })
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

    fn compare_and_swap_encoded(
        &self,
        key: &DocKey,
        expected_revision: u64,
        body: Value,
        encoded: Encoded,
    ) -> impl Future<Output = Result<u64, StoreError>> + Send {
        deferred(move || {
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
            let replaced = std::mem::replace(entry, (revision, body, encoded.digest, entry.3));
            drop(docs);
            // The replaced body is freed outside the lock.
            drop(replaced);
            Ok(revision)
        })
    }

    fn expiring(
        &self,
        kind: crate::DocKind,
        before_us: u64,
        after: Option<&crate::ScanCursor>,
        limit: usize,
    ) -> impl Future<Output = Result<Vec<crate::ScanCursor>, StoreError>> + Send {
        deferred(move || {
            let docs = self.docs.read().map_err(|_| Self::poisoned())?;
            let mut found: Vec<crate::ScanCursor> = docs
                .iter()
                .filter(|(key, (_, body, _, created))| {
                    key.kind == kind && *created < before_us && !crate::is_tombstone(body)
                })
                .map(|(key, (_, _, _, created))| (*created, key.clone()))
                .filter(|cursor| after.is_none_or(|after| cursor > after))
                .collect();
            drop(docs);
            found.sort();
            found.truncate(limit);
            Ok(found)
        })
    }

    fn list(
        &self,
        tenant_id: &str,
        kind: crate::DocKind,
        after: Option<&str>,
        limit: usize,
    ) -> impl Future<Output = Result<Vec<String>, StoreError>> + Send {
        deferred(move || {
            let docs = self.docs.read().map_err(|_| Self::poisoned())?;
            let mut found: Vec<String> = docs
                .iter()
                .filter(|(key, (_, body, _, _))| {
                    key.tenant_id == tenant_id
                        && key.kind == kind
                        && after.is_none_or(|after| key.id.as_str() > after)
                        && !crate::is_tombstone(body)
                })
                .map(|(key, _)| key.id.clone())
                .collect();
            drop(docs);
            found.sort();
            found.truncate(limit);
            Ok(found)
        })
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
    fn head(&self, tenant_id: &str) -> impl Future<Output = Result<Option<crate::LogRow>, StoreError>> + Send {
        deferred(move || {
            let rows = self.rows.read().map_err(|_| MemoryStore::poisoned())?;
            rows.get(tenant_id)
                .and_then(|r| r.last())
                .map(|(sequence, hash, text)| row(*sequence, hash, text))
                .transpose()
        })
    }

    fn append_batch(
        &self,
        tenant_id: &str,
        batch: &[crate::AppendRow],
    ) -> impl Future<Output = Result<(), StoreError>> + Send {
        deferred(move || {
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
        })
    }

    fn range(
        &self,
        tenant_id: &str,
        from: u64,
        limit: usize,
    ) -> impl Future<Output = Result<Vec<crate::LogRow>, StoreError>> + Send {
        deferred(move || {
            let rows = self.rows.read().map_err(|_| MemoryStore::poisoned())?;
            rows.get(tenant_id)
                .into_iter()
                .flatten()
                .filter(|(sequence, _, _)| *sequence >= from)
                .take(limit)
                .map(|(sequence, hash, text)| row(*sequence, hash, text))
                .collect()
        })
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AppendLog, AppendRow, DocKind, LogRow};
    use serde_json::json;

    #[tokio::test]
    async fn memory_operations_remain_lazy_until_polled() {
        let store = MemoryStore::new();
        let key = DocKey::new("tenant", DocKind::RunState, "lazy");
        let body = json!({"version": 1});
        let create = store.create(&key, &body);
        assert_eq!(store.get(&key).await.unwrap(), None);
        create.await.unwrap();

        let read = store.get(&key);
        let next = json!({"version": 2});
        let swap = store.compare_and_swap_encoded(&key, 1, next.clone(), Encoded::of(&next).unwrap());
        assert_eq!(store.get(&key).await.unwrap().unwrap().revision, 1);
        swap.await.unwrap();
        assert_eq!(read.await.unwrap().unwrap().body, next);

        let cancelled = json!({"version": 3});
        drop(store.compare_and_swap_encoded(&key, 2, cancelled.clone(), Encoded::of(&cancelled).unwrap()));
        assert_eq!(store.get(&key).await.unwrap().unwrap().revision, 2);
        let other = DocKey::new("tenant", DocKind::RunState, "cancelled");
        drop(store.create(&other, &body));
        assert_eq!(store.get(&other).await.unwrap(), None);

        let scan = store.expiring(DocKind::RunState, u64::MAX, None, 10);
        store.create(&other, &body).await.unwrap();
        assert_eq!(scan.await.unwrap().len(), 2);

        let log = MemoryLog::new();
        let head = log.head("tenant");
        let range = log.range("tenant", 1, 10);
        let row = AppendRow::encode(&LogRow {
            sequence: 1,
            record_hash: "digest".into(),
            body,
        })
        .unwrap();
        let batch = [row];
        let append = log.append_batch("tenant", &batch);
        assert_eq!(log.head("tenant").await.unwrap(), None);
        append.await.unwrap();
        assert_eq!(head.await.unwrap().unwrap().sequence, 1);
        assert_eq!(range.await.unwrap().len(), 1);
    }
}
