//! Tamper-evident audit for ContextOS runtimes: a per-tenant, ed25519-signed hash
//! chain of governed events, typed DecisionRecords and replay packets.

pub mod chain;
pub mod decision;

pub use chain::{AuditEntry, AuditSigner, ChainError, KeyRing, next_entry, verify_chain, verify_entry};
pub use decision::{DecisionDraft, DecisionError, assemble_decision, decision_record_hash, replay_packet};

use contextos_contract::types::{DecisionAudit, DecisionRecord};
use contextos_store::{AppendLog, LogRow, StoreError};
use serde_json::Value;

#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Chain(#[from] ChainError),
    #[error("stored audit entry is malformed")]
    Malformed,
}

/// Appends signed entries to a tenant's chain in an [`AppendLog`].
#[derive(Debug)]
pub struct AuditWriter<L> {
    log: L,
    signer: AuditSigner,
    // A hash chain is serial by construction. Appends from this process queue here so
    // they never compete with each other; compare-and-swap only arbitrates between
    // processes sharing the same log.
    local: tokio::sync::Mutex<()>,
}

/// Cross-process append attempts before reporting contention.
pub const MAX_APPEND_ATTEMPTS: u32 = 64;

impl<L: AppendLog> AuditWriter<L> {
    pub fn new(log: L, signer: AuditSigner) -> Self {
        Self {
            log,
            signer,
            local: tokio::sync::Mutex::new(()),
        }
    }

    pub fn log(&self) -> &L {
        &self.log
    }

    /// Appends `payload` as the next entry. Concurrent writers never fork the chain:
    /// a writer that loses the race rebuilds its entry on the new head.
    pub async fn append(
        &self,
        tenant_id: &str,
        kind: &str,
        payload: Value,
        emitted_at: &str,
    ) -> Result<AuditEntry, AuditError> {
        let _serial = self.local.lock().await;
        for attempt in 0..MAX_APPEND_ATTEMPTS {
            if attempt > 0 {
                // Bounded exponential backoff while another process holds the head.
                let millis = 1_u64 << attempt.min(6);
                tokio::time::sleep(std::time::Duration::from_millis(millis)).await;
            }
            let head = match self.log.head(tenant_id).await? {
                Some(row) => Some(serde_json::from_value::<AuditEntry>(row.body).map_err(|_| AuditError::Malformed)?),
                None => None,
            };
            let entry = next_entry(
                head.as_ref(),
                tenant_id,
                kind,
                payload.clone(),
                emitted_at,
                &self.signer,
            )?;
            let row = LogRow {
                sequence: entry.sequence,
                record_hash: entry.record_hash.clone(),
                body: serde_json::to_value(&entry).map_err(|_| AuditError::Malformed)?,
            };
            match self.log.append(tenant_id, &row).await {
                Ok(()) => return Ok(entry),
                Err(error) if error.is_conflict() => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err(StoreError::Conflict {
            expected: None,
            actual: None,
        }
        .into())
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
