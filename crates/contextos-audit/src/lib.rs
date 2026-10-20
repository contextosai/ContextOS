//! Tamper-evident audit for ContextOS runtimes: a per-tenant, ed25519-signed hash
//! chain of governed events, typed DecisionRecords and replay packets.

pub mod chain;
pub mod decision;

pub use chain::{
    AuditEntry, AuditSigner, ChainError, ChainHead, KeyRing, Link, assemble_entry, link, link_entry, next_entry,
    verify_chain, verify_entry,
};
pub use decision::{DecisionDraft, DecisionError, assemble_decision, decision_record_hash, replay_packet};

use std::collections::HashMap;
use std::sync::Arc;

use contextos_contract::canonical::{canonicalize, canonicalize_serialize, sha256_text};
use contextos_contract::types::{DecisionAudit, DecisionRecord};
use contextos_contract::validation::compare_contract_times;
use contextos_store::{AppendLog, AppendRow, StoreError};
use serde_json::Value;

#[derive(Debug, Clone, thiserror::Error)]
pub enum AuditError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Chain(#[from] ChainError),
    #[error("stored audit entry is malformed")]
    Malformed,
    #[error("the audit append was interrupted before its outcome was known")]
    Interrupted,
}

/// Appends signed entries to a tenant's chain in an [`AppendLog`].
#[derive(Debug)]
pub struct AuditWriter<L> {
    log: L,
    signer: AuditSigner,
    tenants: std::sync::Mutex<HashMap<String, Arc<TenantChain>>>,
}

/// One tenant's chain in this process.
///
/// A hash chain is serial by construction, so appends use group commit: each
/// appender queues its encoded entry, and whichever appender holds the chain links
/// everything queued and writes it to the log in one atomic batch. Throughput no
/// longer depends on a lock handoff (and, with PostgreSQL, a round trip) per entry.
/// The chain head is cached and re-read only after another process has appended;
/// the log's sequence check arbitrates between processes. Tenants never wait on
/// each other.
#[derive(Default)]
struct TenantChain {
    queue: std::sync::Mutex<Vec<Pending>>,
    head: tokio::sync::Mutex<Head>,
}

impl std::fmt::Debug for TenantChain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TenantChain").finish_non_exhaustive()
    }
}

/// This process's view of a tenant's chain head.
#[derive(Debug, Clone, Default)]
enum Head {
    /// Not known: read it from the log before linking.
    #[default]
    Unknown,
    /// Known; `None` for an empty chain.
    Known(Option<ChainHead>),
}

struct Pending {
    kind: String,
    emitted_at: String,
    payload_digest: String,
    payload_text: String,
    /// The linkage and the effective `emitted_at` of the committed entry.
    reply: tokio::sync::oneshot::Sender<Result<(Link, String), AuditError>>,
}

/// Entries one group commit writes at most.
pub const MAX_BATCH: usize = 256;

/// Cross-process append attempts before reporting contention.
pub const MAX_APPEND_ATTEMPTS: u32 = 64;

impl<L: AppendLog> AuditWriter<L> {
    pub fn new(log: L, signer: AuditSigner) -> Self {
        Self {
            log,
            signer,
            tenants: std::sync::Mutex::default(),
        }
    }

    fn slot(&self, tenant_id: &str) -> Arc<TenantChain> {
        let mut tenants = self.tenants.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        tenants.entry(tenant_id.to_owned()).or_default().clone()
    }

    pub fn log(&self) -> &L {
        &self.log
    }

    /// Appends `payload` as the next entry. Concurrent writers never fork the chain:
    /// entries are linked in commit order, and a batch that loses a race with another
    /// process is re-linked on the new head.
    pub async fn append(
        &self,
        tenant_id: &str,
        kind: &str,
        payload: Value,
        emitted_at: &str,
    ) -> Result<AuditEntry, AuditError> {
        let mut entries = self
            .append_all(tenant_id, vec![(kind.to_owned(), payload, emitted_at.to_owned())])
            .await?;
        entries.pop().ok_or(AuditError::Interrupted)
    }

    /// Appends several entries as consecutive chain entries, normally in one batch
    /// (one round trip on a remote log). Returns them in order. If any fails, the
    /// error is returned; entries before it may have been committed.
    pub async fn append_all(
        &self,
        tenant_id: &str,
        items: Vec<(String, Value, String)>,
    ) -> Result<Vec<AuditEntry>, AuditError> {
        let mut prepared = Vec::with_capacity(items.len());
        let mut pending = Vec::with_capacity(items.len());
        for (kind, payload, emitted_at) in items {
            if !contextos_contract::validation::is_contract_timestamp(&emitted_at) {
                return Err(ChainError::Invalid {
                    index: 0,
                    reason: "emitted_at is not a contract timestamp",
                }
                .into());
            }
            // Encode and hash each payload before joining the tenant's queue.
            let payload_text = canonicalize(&payload).map_err(ChainError::from)?;
            let payload_digest = sha256_text(&payload_text);
            let (reply, committed) = tokio::sync::oneshot::channel();
            pending.push(Pending {
                kind: kind.clone(),
                emitted_at,
                payload_digest: payload_digest.clone(),
                payload_text,
                reply,
            });
            prepared.push((kind, payload, payload_digest, committed));
        }
        let Some(mut last) = prepared.pop() else {
            return Ok(Vec::new());
        };
        let chain = self.slot(tenant_id);
        chain
            .queue
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .extend(pending);
        // Batches commit in queue order, so once the last entry is committed every
        // earlier one has been answered too.
        let last_outcome = loop {
            tokio::select! {
                biased;
                outcome = &mut last.3 => break outcome,
                mut head = chain.head.lock() => {
                    let batch: Vec<Pending> = {
                        let mut queue = chain.queue.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                        let take = queue.len().min(MAX_BATCH);
                        queue.drain(..take).collect()
                    };
                    if batch.is_empty() {
                        // Another holder already took these entries; the reply is coming.
                        drop(head);
                        break (&mut last.3).await;
                    }
                    self.commit(tenant_id, &mut head, batch).await;
                }
            }
        };
        let mut entries = Vec::with_capacity(prepared.len() + 1);
        for (kind, payload, payload_digest, mut committed) in prepared {
            let (link, emitted_at) = committed.try_recv().map_err(|_| AuditError::Interrupted)??;
            entries.push(assemble_entry(
                link,
                tenant_id,
                &kind,
                &emitted_at,
                payload,
                payload_digest,
            ));
        }
        let (kind, payload, payload_digest, _) = last;
        let (link, emitted_at) = last_outcome.map_err(|_| AuditError::Interrupted)??;
        entries.push(assemble_entry(
            link,
            tenant_id,
            &kind,
            &emitted_at,
            payload,
            payload_digest,
        ));
        Ok(entries)
    }

    /// Links and writes one batch, then answers every appender in it.
    async fn commit(&self, tenant_id: &str, head: &mut Head, batch: Vec<Pending>) {
        let mut failure = AuditError::Store(StoreError::Conflict {
            expected: None,
            actual: None,
        });
        for attempt in 0..MAX_APPEND_ATTEMPTS {
            if attempt > 0 {
                // Another process appended. The first retry just re-reads the head (the
                // cache was stale); repeated losses back off, bounded.
                if attempt > 1 {
                    let millis = 1_u64 << attempt.min(6);
                    tokio::time::sleep(std::time::Duration::from_millis(millis)).await;
                }
                *head = Head::Unknown;
            }
            if matches!(head, Head::Unknown) {
                match self.read_head(tenant_id).await {
                    Ok(stored) => *head = Head::Known(stored),
                    Err(error) => {
                        failure = error;
                        break;
                    }
                }
            }
            let mut current = match head {
                Head::Known(known) => known.clone(),
                Head::Unknown => None,
            };
            let mut linked = Vec::with_capacity(batch.len());
            let mut rows = Vec::with_capacity(batch.len());
            for pending in &batch {
                // Appenders read the clock before queueing; an entry never records a
                // time before the entry it follows.
                let emitted_at = match &current {
                    Some(h)
                        if compare_contract_times(&pending.emitted_at, &h.emitted_at)
                            == Some(std::cmp::Ordering::Less) =>
                    {
                        h.emitted_at.clone()
                    }
                    _ => pending.emitted_at.clone(),
                };
                let built = link(
                    current.as_ref(),
                    tenant_id,
                    &pending.kind,
                    &pending.payload_digest,
                    &emitted_at,
                    &self.signer,
                )
                .map_err(AuditError::from)
                .and_then(|link| {
                    let text = entry_text(
                        &link,
                        tenant_id,
                        &pending.kind,
                        &emitted_at,
                        &pending.payload_digest,
                        &pending.payload_text,
                    )?;
                    Ok((link, text))
                });
                match built {
                    Ok((link, text)) => {
                        current = Some(ChainHead {
                            sequence: link.sequence,
                            record_hash: link.record_hash.clone(),
                            emitted_at: emitted_at.clone(),
                        });
                        rows.push(AppendRow {
                            sequence: link.sequence,
                            record_hash: link.record_hash.clone(),
                            text,
                        });
                        linked.push(Ok((link, emitted_at)));
                    }
                    Err(error) => linked.push(Err(error)),
                }
            }
            // Unknown until the write is confirmed, so an interrupted commit re-reads.
            *head = Head::Unknown;
            match self.log.append_batch(tenant_id, &rows).await {
                Ok(()) => {
                    *head = Head::Known(current);
                    for (pending, outcome) in batch.into_iter().zip(linked) {
                        let _ = pending.reply.send(outcome);
                    }
                    return;
                }
                Err(error) if error.is_conflict() => failure = error.into(),
                Err(error) => {
                    // The batch may or may not have landed; nothing is reported as written.
                    failure = error.into();
                    break;
                }
            }
        }
        for pending in batch {
            let _ = pending.reply.send(Err(failure.clone()));
        }
    }

    async fn read_head(&self, tenant_id: &str) -> Result<Option<ChainHead>, AuditError> {
        match self.log.head(tenant_id).await? {
            Some(row) => {
                let entry: AuditEntry = serde_json::from_value(row.body).map_err(|_| AuditError::Malformed)?;
                if entry.tenant_id != tenant_id {
                    return Err(AuditError::Malformed);
                }
                Ok(Some(ChainHead::from(&entry)))
            }
            None => Ok(None),
        }
    }

    /// Records a DecisionRecord and returns it with its `audit` block filled from
    /// the chain entry. The chained payload is the record without `audit`.
    pub async fn record_decision(
        &self,
        tenant_id: &str,
        mut record: DecisionRecord,
        emitted_at: &str,
    ) -> Result<DecisionRecord, AuditError> {
        record.audit = None;
        let payload = serde_json::to_value(&record).map_err(|_| AuditError::Malformed)?;
        let entry = self.append(tenant_id, "decision_record", payload, emitted_at).await?;
        record.audit = Some(DecisionAudit {
            prev_hash: entry.prev_hash,
            record_hash: Some(entry.record_hash),
            signed_by: Some(entry.signature.kid),
            emitted_at: Some(entry.emitted_at),
        });
        Ok(record)
    }
}

/// The RFC 8785 text of an entry, splicing in the payload's pre-computed canonical
/// text. Keys sort `kind` < `payload` < `payload_digest`, and every string value is
/// JSON-escaped, so `"payload":null` occurs exactly once in the placeholder encoding.
fn entry_text(
    link: &Link,
    tenant_id: &str,
    kind: &str,
    emitted_at: &str,
    payload_digest: &str,
    payload_text: &str,
) -> Result<String, AuditError> {
    let spine = assemble_entry(
        link.clone(),
        tenant_id,
        kind,
        emitted_at,
        Value::Null,
        payload_digest.to_owned(),
    );
    let placeholder = canonicalize_serialize(&spine).map_err(ChainError::from)?;
    let at = placeholder.find("\"payload\":null").ok_or(AuditError::Malformed)?;
    let mut text = String::with_capacity(placeholder.len() + payload_text.len());
    text.push_str(&placeholder[..at + "\"payload\":".len()]);
    text.push_str(payload_text);
    text.push_str(&placeholder[at + "\"payload\":null".len()..]);
    Ok(text)
}

/// Reads and verifies a tenant's whole chain from genesis.
pub async fn verify_tenant_chain<L: AppendLog>(log: &L, tenant_id: &str, keys: &KeyRing) -> Result<u64, AuditError> {
    const PAGE: usize = 1_000;
    let mut anchor: Option<AuditEntry> = None;
    let mut from = 1;
    loop {
        let rows = log.range(tenant_id, from, PAGE).await?;
        if rows.is_empty() {
            return Ok(anchor.map_or(0, |a| a.sequence));
        }
        let entries: Vec<AuditEntry> = rows
            .into_iter()
            .map(|row| {
                let entry: AuditEntry = serde_json::from_value(row.body).map_err(|_| AuditError::Malformed)?;
                if entry.sequence != row.sequence || entry.record_hash != row.record_hash {
                    return Err(AuditError::Malformed);
                }
                Ok(entry)
            })
            .collect::<Result<_, _>>()?;
        verify_chain(&entries, anchor.as_ref(), keys)?;
        from = entries.last().map_or(from, |e| e.sequence + 1);
        anchor = entries.into_iter().last();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn spliced_entry_text_is_the_canonical_encoding() {
        let signer = AuditSigner::from_seed("k", [9; 32]);
        let payload = json!({"z": [1, 2.5, "\u{e9}"], "payload": null, "a": {"payload": "x"}});
        let payload_text = canonicalize(&payload).unwrap();
        let digest = sha256_text(&payload_text);
        let kind = "kind \"payload\":null";
        let link = link(None, "tenant", kind, &digest, "2026-10-20T10:00:00Z", &signer).unwrap();
        let text = entry_text(&link, "tenant", kind, "2026-10-20T10:00:00Z", &digest, &payload_text).unwrap();
        let entry = assemble_entry(link, "tenant", kind, "2026-10-20T10:00:00Z", payload, digest);
        assert_eq!(text, canonicalize_serialize(&entry).unwrap());
    }
}
