//! Pinned anchors: the last entry Tower verified from each source, kept in Tower's
//! store so a restart cannot be used to rewrite a runtime's history.
//!
//! Tower's fleet model lives in memory and is rebuilt after a restart by reading every
//! chain again from genesis. Without a pin, a runtime whose audit history was rewritten
//! or truncated while Tower was down would simply be read afresh. With one, the
//! collector checks that the chain it reads again passes through the pinned entry: the
//! same sequence with the same record hash. A different hash marks the source broken
//! (`history_rewritten`); a chain that ends before the pin marks it broken
//! (`history_truncated`). Either way nothing after it is shown as fact. Once past the
//! pin, the pin advances with every page Tower verifies.
//!
//! A source removed and added again under the same id keeps its pin. A runtime whose
//! history was legitimately reset (a new store) is added under a new source id.

use std::sync::Arc;

use async_trait::async_trait;
use contextos_store::{DocKey, DocKind, DocumentStore};
use serde_json::json;

use crate::records::NAMESPACE;

/// The pinned entry of one source: its sequence and record hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pin {
    pub sequence: u64,
    pub record_hash: String,
}

/// Where pins are kept.
#[async_trait]
pub trait Pins: Send + Sync {
    async fn get(&self, source: &str) -> Result<Option<Pin>, String>;
    /// Moves the pin forward to `pin`; never back.
    async fn advance(&self, source: &str, pin: &Pin) -> Result<(), String>;
}

fn key(source: &str) -> DocKey {
    DocKey::new(NAMESPACE, DocKind::Governance, format!("collector_anchor:{source}"))
}

/// Pins in a document store.
#[derive(Debug)]
pub struct StorePins<S> {
    store: Arc<S>,
}

impl<S> StorePins<S> {
    pub fn new(store: Arc<S>) -> Self {
        Self { store }
    }
}

#[async_trait]
impl<S: DocumentStore + 'static> Pins for StorePins<S> {
    async fn get(&self, source: &str) -> Result<Option<Pin>, String> {
        let doc = self.store.get(&key(source)).await.map_err(|e| e.to_string())?;
        Ok(doc.and_then(|d| {
            Some(Pin {
                sequence: d.body["sequence"].as_u64()?,
                record_hash: d.body["record_hash"].as_str()?.to_owned(),
            })
        }))
    }

    async fn advance(&self, source: &str, pin: &Pin) -> Result<(), String> {
        let body = json!({"sequence": pin.sequence, "record_hash": pin.record_hash});
        for _ in 0..4 {
            let current = self.store.get(&key(source)).await.map_err(|e| e.to_string())?;
            let written = match &current {
                Some(c) if c.body["sequence"].as_u64().is_some_and(|s| s >= pin.sequence) => return Ok(()),
                Some(c) => self
                    .store
                    .compare_and_swap(&key(source), c.revision, &body)
                    .await
                    .map(|_| ()),
                None => self.store.create(&key(source), &body).await.map(|_| ()),
            };
            match written {
                Ok(()) => return Ok(()),
                Err(e) if e.is_conflict() => {}
                Err(e) => return Err(e.to_string()),
            }
        }
        Ok(())
    }
}
