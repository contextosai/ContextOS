//! Operator feedback for the improvement loop (the spec's FeedbackStore: every operator
//! override or correction enters it with provenance; source pressure is closed as
//! `fixed`, `still_failing`, `invalid` or `superseded` with evidence).
//!
//! A feedback record is filed by an independent reviewer against a run (and optionally
//! one of its decisions), names the surface the correction points at, and carries the
//! run's replay case as its replay obligation: open feedback is exactly the corpus a
//! candidate change must be gated on (`ctx gate`). It is closed only with an evidence
//! reference (for example the digest of a passing gate report), never by assertion.
//! Records are their own documents; a per-tenant index of open records is bounded.

use contextos_store::{DocKey, DocKind, DocumentStore, StoreError};
use serde::Deserialize;
use serde_json::{Value, json};

/// Open feedback records per tenant at most.
pub const MAX_OPEN: usize = 10_000;

pub const KINDS: [&str; 3] = ["correction", "override", "approval_verdict"];
pub const SURFACES: [&str; 8] = [
    "run_context",
    "pack",
    "policy",
    "tool",
    "memory",
    "skill",
    "evaluator",
    "unknown",
];
pub const CLOSED: [&str; 4] = ["fixed", "still_failing", "invalid", "superseded"];

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeedbackBody {
    pub kind: String,
    pub target_surface: String,
    /// What was wrong and what should have happened. Keep personal data out: cite
    /// evidence by reference.
    pub summary: String,
    #[serde(default)]
    pub decision_record_id: Option<String>,
    #[serde(default)]
    pub expected_outcome: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloseBody {
    pub status: String,
    /// Evidence for the status, e.g. `{"artifact_type": "gate_report", "artifact_id":
    /// "...", "sha256": "sha256:..."}`.
    pub evidence_ref: EvidenceRef,
}

/// A reference to the evidence for a closure: exactly these three fields, bounded, so
/// nothing else reaches the (unerasable) audit chain.
#[derive(Debug, Clone, Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceRef {
    pub artifact_type: String,
    pub artifact_id: String,
    pub sha256: String,
}

impl CloseBody {
    pub fn check(&self) -> Result<(), FeedbackError> {
        let e = &self.evidence_ref;
        let bounded = |s: &str| !s.trim().is_empty() && s.len() <= 256;
        if !CLOSED.contains(&self.status.as_str())
            || !bounded(&e.artifact_type)
            || !bounded(&e.artifact_id)
            || !contextos_contract::canonical::is_sha256_digest(&e.sha256)
        {
            return Err(FeedbackError::Invalid(
                "status must be fixed, still_failing, invalid or superseded, with an evidence_ref {artifact_type, artifact_id (1..256 bytes), sha256}",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum FeedbackError {
    #[error("invalid feedback: {0}")]
    Invalid(&'static str),
    #[error("too many open feedback records")]
    Full,
    #[error("no such feedback record")]
    NotFound,
    #[error("the feedback record is already closed")]
    Closed,
    #[error(transparent)]
    Store(#[from] StoreError),
}

fn index_key(tenant_id: &str) -> DocKey {
    DocKey::new(tenant_id, DocKind::Feedback, "open")
}

pub fn record_key(tenant_id: &str, id: &str) -> DocKey {
    DocKey::new(tenant_id, DocKind::Feedback, format!("record:{id}"))
}

impl FeedbackBody {
    pub fn check(&self) -> Result<(), FeedbackError> {
        if !KINDS.contains(&self.kind.as_str()) {
            return Err(FeedbackError::Invalid(
                "kind must be correction, override or approval_verdict",
            ));
        }
        if !SURFACES.contains(&self.target_surface.as_str()) {
            return Err(FeedbackError::Invalid("unknown target_surface"));
        }
        let sized = |s: &str, max: usize| !s.trim().is_empty() && s.len() <= max;
        if !sized(&self.summary, 2048) || self.expected_outcome.as_deref().is_some_and(|o| !sized(o, 1024)) {
            return Err(FeedbackError::Invalid(
                "summary (and expected_outcome) must be 1..2048 (1024) bytes",
            ));
        }
        Ok(())
    }
}

/// Adds `id` to the tenant's open index (once), refusing past [`MAX_OPEN`].
pub async fn index_open<S: DocumentStore>(store: &S, tenant_id: &str, id: &str) -> Result<(), FeedbackError> {
    change_index(store, tenant_id, |ids| {
        if ids.iter().any(|v| v == id) {
            return Ok(());
        }
        if ids.len() >= MAX_OPEN {
            return Err(FeedbackError::Full);
        }
        ids.push(json!(id));
        Ok(())
    })
    .await
}

/// Removes `id` from the tenant's open index.
pub async fn index_close<S: DocumentStore>(store: &S, tenant_id: &str, id: &str) -> Result<(), FeedbackError> {
    change_index(store, tenant_id, |ids| {
        ids.retain(|v| v != id);
        Ok(())
    })
    .await
}

async fn change_index<S: DocumentStore>(
    store: &S,
    tenant_id: &str,
    change: impl Fn(&mut Vec<Value>) -> Result<(), FeedbackError>,
) -> Result<(), FeedbackError> {
    let key = index_key(tenant_id);
    for _ in 0..16 {
        let current = store.get(&key).await?;
        let mut ids = current
            .as_ref()
            .and_then(|c| c.body["ids"].as_array().cloned())
            .unwrap_or_default();
        change(&mut ids)?;
        let state = json!({"ids": ids});
        let written = match &current {
            None => store.create(&key, &state).await.map(|_| ()),
            Some(c) => store.compare_and_swap(&key, c.revision, &state).await.map(|_| ()),
        };
        match written {
            Ok(()) => return Ok(()),
            Err(e) if e.is_conflict() => {}
            Err(e) => return Err(e.into()),
        }
    }
    Err(StoreError::Conflict {
        expected: None,
        actual: None,
    }
    .into())
}

/// The tenant's open feedback ids, oldest first.
pub async fn open_ids<S: DocumentStore>(store: &S, tenant_id: &str) -> Result<Vec<String>, FeedbackError> {
    Ok(store
        .get(&index_key(tenant_id))
        .await?
        .and_then(|c| c.body["ids"].as_array().cloned())
        .unwrap_or_default()
        .iter()
        .filter_map(|v| v.as_str().map(str::to_owned))
        .collect())
}
