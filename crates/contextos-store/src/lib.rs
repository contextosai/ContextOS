//! Protected state for ContextOS runtimes.
//!
//! The kernel decides *what* the next state is; stores make that decision safe under
//! concurrency. Every protected document (run state, operation ledger, budget ledger,
//! approval redemption, checkpoint) is written only by compare-and-swap against the
//! revision that was read. Two workers that race on the same run cannot both commit:
//! the loser re-reads and the kernel re-decides on fresh state, so a stale executor
//! can never dispatch on top of a newer generation.
//!
//! Bodies are stored as RFC 8785 canonical JSON text with their digest, so what is
//! read back is byte-identical to what the kernel produced.

use std::future::Future;

use contextos_contract::canonical::{CanonicalError, canonicalize, sha256_text};
use contextos_kernel::TransitionResult;
use serde_json::Value;

pub mod memory;
#[cfg(feature = "postgres")]
pub mod postgres;

pub use memory::{MemoryLog, MemoryStore};

/// Kinds of protected documents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum DocKind {
    RunState,
    OperationLedger,
    BudgetLedger,
    ApprovalRedemption,
    Checkpoint,
    ContextPack,
    ProfileRegistry,
    RunAdmission,
    /// Input requested by a tool (`input_required`) for an operation's latest attempt.
    PendingInput,
}

impl DocKind {
    pub fn as_str(self) -> &'static str {
        match self {
            DocKind::RunState => "run_state",
            DocKind::OperationLedger => "operation_ledger",
            DocKind::BudgetLedger => "budget_ledger",
            DocKind::ApprovalRedemption => "approval_redemption",
            DocKind::Checkpoint => "checkpoint",
            DocKind::ContextPack => "context_pack",
            DocKind::ProfileRegistry => "profile_registry",
            DocKind::RunAdmission => "run_admission",
            DocKind::PendingInput => "pending_input",
        }
    }
}

/// Address of one document. Tenant isolation is part of every key.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DocKey {
    pub tenant_id: String,
    pub kind: DocKind,
    pub id: String,
}

impl DocKey {
    pub fn new(tenant_id: impl Into<String>, kind: DocKind, id: impl Into<String>) -> Self {
        Self {
            tenant_id: tenant_id.into(),
            kind,
            id: id.into(),
        }
    }
}

/// A stored document with its store revision (incremented on every write) and the
/// digest of its canonical body.
#[derive(Debug, Clone, PartialEq)]
pub struct Versioned {
    pub revision: u64,
    pub body: Value,
    pub digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StoreError {
    #[error("revision conflict: expected {expected:?}, found {actual:?}")]
    Conflict { expected: Option<u64>, actual: Option<u64> },
    #[error("document not found")]
    NotFound,
    #[error("document body is not canonical JSON: {0}")]
    Encoding(#[from] CanonicalError),
    #[error("stored document failed integrity check")]
    Integrity,
    #[error("store backend error: {0}")]
    Backend(String),
}

impl StoreError {
    pub fn is_conflict(&self) -> bool {
        matches!(self, StoreError::Conflict { .. })
    }
}

/// Canonical text and digest for a body.
pub fn encode(body: &Value) -> Result<(String, String), StoreError> {
    let text = canonicalize(body)?;
    let digest = sha256_text(&text);
    Ok((text, digest))
}

/// Decodes stored text, verifying it against the stored digest.
pub fn decode(revision: u64, text: &str, digest: &str) -> Result<Versioned, StoreError> {
    if sha256_text(text) != digest {
        return Err(StoreError::Integrity);
    }
    let body: Value = serde_json::from_str(text).map_err(|_| StoreError::Integrity)?;
    Ok(Versioned {
        revision,
        body,
        digest: digest.to_owned(),
    })
}

/// Compare-and-swap document storage.
pub trait DocumentStore: Send + Sync {
    fn get(&self, key: &DocKey) -> impl Future<Output = Result<Option<Versioned>, StoreError>> + Send;

    /// Creates a document at revision 1; `Conflict` if it already exists.
    fn create(&self, key: &DocKey, body: &Value) -> impl Future<Output = Result<Versioned, StoreError>> + Send;

    /// Replaces the body only if the stored revision equals `expected_revision`.
    fn compare_and_swap(
        &self,
        key: &DocKey,
        expected_revision: u64,
        body: &Value,
    ) -> impl Future<Output = Result<Versioned, StoreError>> + Send;

    /// As [`DocumentStore::compare_and_swap`] for a body already encoded with
    /// [`encode`]; returns the new revision. Lets callers encode once.
    fn compare_and_swap_encoded(
        &self,
        key: &DocKey,
        expected_revision: u64,
        body: Value,
        encoded: Encoded,
    ) -> impl Future<Output = Result<u64, StoreError>> + Send;
}

/// Canonical text and digest of a body, computed once per write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Encoded {
    pub text: String,
    pub digest: String,
}

impl Encoded {
    pub fn of(body: &Value) -> Result<Self, StoreError> {
        let (text, digest) = encode(body)?;
        Ok(Self { text, digest })
    }
}

/// What happened when a kernel transition was committed.
#[derive(Debug, Clone, PartialEq)]
pub enum Commit {
    /// The kernel rejected the transition; nothing was written.
    Rejected { reason_codes: Vec<String> },
    /// The transition was accepted without changing state (for example a replayed
    /// mutation returning its original receipt); nothing was written.
    Unchanged { obligations: Vec<String> },
    /// The new state was written.
    Written { revision: u64, obligations: Vec<String> },
}

/// Commits a kernel transition computed from `read`, by compare-and-swap.
pub async fn commit_transition<S: DocumentStore>(
    store: &S,
    key: &DocKey,
    read: &Versioned,
    result: TransitionResult,
) -> Result<Commit, StoreError> {
    if !result.is_accepted() {
        return Ok(Commit::Rejected {
            reason_codes: result.reason_codes.unwrap_or_default(),
        });
    }
    let obligations = result.obligations.unwrap_or_default();
    let encoded = Encoded::of(&result.state)?;
    if encoded.digest == read.digest {
        return Ok(Commit::Unchanged { obligations });
    }
    let revision = store
        .compare_and_swap_encoded(key, read.revision, result.state, encoded)
        .await?;
    Ok(Commit::Written { revision, obligations })
}

/// Maximum optimistic retries before reporting contention.
pub const MAX_CAS_ATTEMPTS: u32 = 64;

/// Read → decide → compare-and-swap, re-reading and re-deciding on conflict.
///
/// `decide` is the pure kernel transition over the current body. Re-deciding on
/// fresh state is always safe because the kernel re-validates every precondition;
/// a decision is never replayed against state it was not computed from.
pub async fn transact<S, F>(store: &S, key: &DocKey, mut decide: F) -> Result<Commit, StoreError>
where
    S: DocumentStore,
    F: FnMut(&Value) -> TransitionResult + Send,
{
    for attempt in 0..MAX_CAS_ATTEMPTS {
        if attempt > 0 {
            // Bounded exponential backoff on a hot document (≤ 8 ms per wait).
            let micros = 50_u64 << attempt.min(7);
            tokio::time::sleep(std::time::Duration::from_micros(micros)).await;
        }
        let read = store.get(key).await?.ok_or(StoreError::NotFound)?;
        let result = decide(&read.body);
        match commit_transition(store, key, &read, result).await {
            Err(error) if error.is_conflict() => {}
            other => return other,
        }
    }
    Err(StoreError::Conflict {
        expected: None,
        actual: None,
    })
}

/// A shared log (several writers in one process, as separate replicas would share a
/// database).
impl<T: AppendLog> AppendLog for std::sync::Arc<T> {
    fn head(&self, tenant_id: &str) -> impl Future<Output = Result<Option<LogRow>, StoreError>> + Send {
        T::head(self, tenant_id)
    }

    fn append_batch(&self, tenant_id: &str, rows: &[AppendRow]) -> impl Future<Output = Result<(), StoreError>> + Send {
        T::append_batch(self, tenant_id, rows)
    }

    fn range(
        &self,
        tenant_id: &str,
        from: u64,
        limit: usize,
    ) -> impl Future<Output = Result<Vec<LogRow>, StoreError>> + Send {
        T::range(self, tenant_id, from, limit)
    }
}

/// One row of a per-tenant append-only log.
#[derive(Debug, Clone, PartialEq)]
pub struct LogRow {
    pub sequence: u64,
    pub record_hash: String,
    pub body: Value,
}

/// A row to append, already in canonical JSON. Writers encode once (outside any
/// serial section they hold); logs store the text as given.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppendRow {
    pub sequence: u64,
    pub record_hash: String,
    /// RFC 8785 text of the row body.
    pub text: String,
}

impl AppendRow {
    /// Encodes a [`LogRow`].
    pub fn encode(row: &LogRow) -> Result<Self, StoreError> {
        Ok(Self {
            sequence: row.sequence,
            record_hash: row.record_hash.clone(),
            text: encode(&row.body)?.0,
        })
    }
}

/// Append-only, per-tenant hash-chained log storage. `append` succeeds only for the
/// next sequence after the current head, so concurrent writers cannot fork the chain;
/// the loser gets `Conflict` and must rebuild its entry on the new head.
pub trait AppendLog: Send + Sync {
    fn head(&self, tenant_id: &str) -> impl Future<Output = Result<Option<LogRow>, StoreError>> + Send;

    fn append(&self, tenant_id: &str, row: &AppendRow) -> impl Future<Output = Result<(), StoreError>> + Send {
        self.append_batch(tenant_id, std::slice::from_ref(row))
    }

    /// Appends consecutive rows atomically: all land, or none do. The first row must
    /// follow the current head; otherwise `Conflict`.
    fn append_batch(&self, tenant_id: &str, rows: &[AppendRow]) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// Rows with `sequence >= from`, ascending, at most `limit`.
    fn range(
        &self,
        tenant_id: &str,
        from: u64,
        limit: usize,
    ) -> impl Future<Output = Result<Vec<LogRow>, StoreError>> + Send;
}
