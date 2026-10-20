//! In-process store for embedded use and tests. Linearizable per key.

use std::collections::HashMap;
use std::sync::RwLock;

use serde_json::Value;

use crate::{DocKey, DocumentStore, StoreError, Versioned, decode, encode};

#[derive(Debug, Default)]
pub struct MemoryStore {
    docs: RwLock<HashMap<DocKey, (u64, String, String)>>,
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
    async fn get(&self, key: &DocKey) -> Result<Option<Versioned>, StoreError> {
        let docs = self.docs.read().map_err(|_| Self::poisoned())?;
        docs.get(key)
            .map(|(revision, text, digest)| decode(*revision, text, digest))
            .transpose()
    }

    async fn create(&self, key: &DocKey, body: &Value) -> Result<Versioned, StoreError> {
        let (text, digest) = encode(body)?;
        let mut docs = self.docs.write().map_err(|_| Self::poisoned())?;
        if let Some((revision, _, _)) = docs.get(key) {
            return Err(StoreError::Conflict {
                expected: None,
                actual: Some(*revision),
            });
        }
        docs.insert(key.clone(), (1, text, digest.clone()));
        Ok(Versioned {
            revision: 1,
            body: body.clone(),
            digest,
        })
    }

    async fn compare_and_swap(
        &self,
        key: &DocKey,
        expected_revision: u64,
        body: &Value,
    ) -> Result<Versioned, StoreError> {
        let (text, digest) = encode(body)?;
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
        *entry = (revision, text, digest.clone());
        Ok(Versioned {
            revision,
            body: body.clone(),
            digest,
        })
    }
}
