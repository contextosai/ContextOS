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
    /// Settled reservations and receipts moved out of a budget ledger by compaction.
    BudgetArchive,
    /// A run's compiled context, kept for decision assembly.
    CompiledContext,
    /// A run's DecisionRecords and replay packets.
    DecisionLog,
    /// A memory's current governed lifecycle state.
    MemoryRecord,
    /// The inputs a run was admitted with, for release-gate replay.
    ReplayCase,
    /// The evaluator scores of one decision.
    RunScore,
    /// The tenant's revoked targets (kill switch).
    Revocations,
    /// Live server replicas (shared tenant limits).
    Replicas,
    /// The tenant's staged rollouts of Context Pack versions.
    Rollouts,
    /// A run's counts of identical tool calls (loop guard).
    LoopGuard,
    /// Operator feedback records and the tenant's open index (improvement loop).
    Feedback,
    /// Policy escalations awaiting a human, and the tenant's open index.
    Escalation,
    /// Which memory record currently holds a memory key (by owner and namespace).
    MemoryKey,
    /// A run's applied effects, for the completion score gate.
    AppliedEffects,
    /// The governance plane's records (declarations, reviews, guardrails, waivers).
    Governance,
    /// A tenant's pinned semantic definition of a shared business guarantee.
    GuaranteeDefinition,
    /// Conserved exposure shared across independent runs for one business resource.
    SharedExposure,
    /// Immutable action-to-resource binding used for crash recovery.
    ExposureLink,
    /// What a task authorization's limits have used, across the issuing run and its
    /// delegated runs.
    TaskExposure,
    /// Whether an attempt was sent or aborted, decided once (the gateway's dispatch
    /// gate).
    DispatchGate,
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
            DocKind::BudgetArchive => "budget_archive",
            DocKind::CompiledContext => "compiled_context",
            DocKind::DecisionLog => "decision_log",
            DocKind::MemoryRecord => "memory_record",
            DocKind::ReplayCase => "replay_case",
            DocKind::RunScore => "run_score",
            DocKind::Revocations => "revocations",
            DocKind::Replicas => "replicas",
            DocKind::Rollouts => "rollouts",
            DocKind::LoopGuard => "loop_guard",
            DocKind::Feedback => "feedback",
            DocKind::Escalation => "escalation",
            DocKind::MemoryKey => "memory_key",
            DocKind::AppliedEffects => "applied_effects",
            DocKind::Governance => "governance",
            DocKind::GuaranteeDefinition => "guarantee_definition",
            DocKind::SharedExposure => "shared_exposure",
            DocKind::ExposureLink => "exposure_link",
            DocKind::TaskExposure => "task_exposure",
            DocKind::DispatchGate => "dispatch_gate",
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

/// Position in an expiry scan: creation time (microseconds since the Unix epoch) and key.
pub type ScanCursor = (u64, DocKey);

/// The canonical text every erasure tombstone starts with (RFC 8785 sorts keys, so a
/// tombstone's `content_digest` and `erased` come first; no other document starts so).
fn is_tombstone_text(text: &str) -> bool {
    let Some(rest) = text.strip_prefix(r#"{"content_digest":"sha256:"#) else {
        return false;
    };
    rest.len() > 64
        && rest.as_bytes()[..64].iter().all(u8::is_ascii_hexdigit)
        && rest[64..].starts_with(r#"","erased":true,"#)
}

/// Whether a body is an erasure tombstone (`{"content_digest", "erased": true, ...}`).
pub fn is_tombstone(body: &Value) -> bool {
    encode(body).is_ok_and(|(text, _)| is_tombstone_text(&text))
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

    /// Whether a read costs less than copying a document the caller already holds.
    /// Callers use it to decide whether to seed transactions from state they have
    /// (saving a round trip on a remote store) or simply re-read.
    fn reads_are_cheap(&self) -> bool {
        false
    }

    /// As [`DocumentStore::compare_and_swap`] for a body already encoded with
    /// [`encode`]; returns the new revision. Lets callers encode once.
    fn compare_and_swap_encoded(
        &self,
        key: &DocKey,
        expected_revision: u64,
        body: Value,
        encoded: Encoded,
    ) -> impl Future<Output = Result<u64, StoreError>> + Send;

    /// Documents of `kind` created before `before_us` that are not erasure tombstones,
    /// ordered by creation time then key, strictly after `after`; at most `limit`.
    fn expiring(
        &self,
        kind: DocKind,
        before_us: u64,
        after: Option<&ScanCursor>,
        limit: usize,
    ) -> impl Future<Output = Result<Vec<ScanCursor>, StoreError>> + Send;
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
/// As [`transact`], also returning the document's revision and state after the
/// transition when `keep` wants it, so callers that need it do not read it back (and
/// callers that rarely need it do not pay for a copy). `None` when the transition was
/// rejected or `keep` declined.
pub async fn transact_state<S, F, K>(
    store: &S,
    key: &DocKey,
    mut decide: F,
    keep: K,
) -> Result<(Commit, Option<(u64, Value)>), StoreError>
where
    S: DocumentStore,
    F: FnMut(&Value) -> TransitionResult + Send,
    K: Fn(&Value) -> bool + Send,
{
    for attempt in 0..MAX_CAS_ATTEMPTS {
        if attempt > 0 {
            let micros = 50_u64 << attempt.min(7);
            tokio::time::sleep(std::time::Duration::from_micros(micros)).await;
        }
        let read = store.get(key).await?.ok_or(StoreError::NotFound)?;
        let result = decide(&read.body);
        if !result.is_accepted() {
            let reason_codes = result.reason_codes.unwrap_or_default();
            return Ok((Commit::Rejected { reason_codes }, None));
        }
        let obligations = result.obligations.unwrap_or_default();
        let encoded = Encoded::of(&result.state)?;
        if encoded.digest == read.digest {
            let kept = keep(&read.body).then_some((read.revision, read.body));
            return Ok((Commit::Unchanged { obligations }, kept));
        }
        let state = keep(&result.state).then(|| result.state.clone());
        match store
            .compare_and_swap_encoded(key, read.revision, result.state, encoded)
            .await
        {
            Ok(revision) => return Ok((Commit::Written { revision, obligations }, state.map(|s| (revision, s)))),
            Err(error) if error.is_conflict() => {}
            Err(error) => return Err(error),
        }
    }
    Err(StoreError::Conflict {
        expected: None,
        actual: None,
    })
}

/// As [`transact_state`], but the first attempt starts from `seed` (a revision and
/// state the caller already holds, for example from its previous transition) instead
/// of reading. A stale seed costs nothing: its compare-and-swap conflicts and the next
/// attempt reads. A rejection computed from the seed is never trusted; it is retried
/// on a fresh read.
pub async fn transact_from<S, F, K>(
    store: &S,
    key: &DocKey,
    seed: Option<(u64, Value)>,
    mut decide: F,
    keep: K,
) -> Result<(Commit, Option<(u64, Value)>), StoreError>
where
    S: DocumentStore,
    F: FnMut(&Value) -> TransitionResult + Send,
    K: Fn(&Value) -> bool + Send,
{
    if let Some((revision, seeded)) = seed {
        let result = decide(&seeded);
        if result.is_accepted() && result.state != seeded {
            let obligations = result.obligations.unwrap_or_default();
            let encoded = Encoded::of(&result.state)?;
            let state = keep(&result.state).then(|| result.state.clone());
            match store
                .compare_and_swap_encoded(key, revision, result.state, encoded)
                .await
            {
                Ok(written) => {
                    return Ok((
                        Commit::Written {
                            revision: written,
                            obligations,
                        },
                        state.map(|s| (written, s)),
                    ));
                }
                Err(error) if error.is_conflict() => {}
                Err(error) => return Err(error),
            }
        }
    }
    transact_state(store, key, decide, keep).await
}

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
