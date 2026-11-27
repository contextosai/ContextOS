//! Persisted collector checkpoints: stores a checksummed snapshot of Tower's verified
//! fleet model and each source's verified audit anchor so restarts resume from the last
//! verified entry instead of re-reading and re-verifying every chain from genesis.
//!
//! Safety invariants:
//! - Every saved checkpoint carries an RFC 8785 canonical SHA-256 digest over its body;
//!   any corrupt, truncated, or schema-mismatched checkpoint is discarded and rebuilt
//!   from genesis against the pinned anchors in [`crate::pins`].
//! - Before restoring, each source's checkpointed anchor is checked against its pin in
//!   [`crate::pins`]. If any anchor disagrees with its pin, the checkpoint is refused
//!   so genesis verification detects the rewrite.
//! - On resumption, [`crate::collector::sync_pinned`] verifies every new page directly
//!   against the restored anchor (`prev_hash`, `sequence`, Ed25519 signature) and marks
//!   the source `history_truncated` if the runtime's head is behind the anchor.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::Arc;

use contextos_audit::AuditEntry;
use contextos_contract::canonical::sha256_canonical;
use contextos_store::{DocKey, DocKind, DocumentStore};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::approvals::Approvals;
use crate::fleet::{AgentActivity, AgentKey, Change, Counts, Fleet, Hour, Open, Revoked, RunSummary, SourceState};
use crate::inventory::SeenMap;
use crate::pins::Pins;
use crate::records::NAMESPACE;
use crate::spend::AgentSpend;

/// Snapshot schema version. Incompatible versions are ignored and rebuilt from genesis.
pub const SCHEMA_VERSION: u32 = 1;
/// Hard ceiling on a persisted checkpoint document (4 MiB). Larger fleets skip saving
/// and fall back gracefully to pin-verified rebuild on restart.
pub const MAX_CHECKPOINT_BYTES: usize = 4 * 1024 * 1024;

fn checkpoint_key() -> DocKey {
    DocKey::new(NAMESPACE, DocKind::Governance, "collector_fleet_checkpoint")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedSource {
    id: String,
    tenant_id: Option<String>,
    verified_to: u64,
    head: u64,
    broken: Option<Value>,
    last_error: Option<String>,
    last_sync: Option<String>,
    unattributed: u64,
    revoked: BTreeMap<String, String>,
    revocations: BTreeMap<String, Revoked>,
    conformance: Vec<Value>,
    break_glass: Vec<Value>,
    event_counts: BTreeMap<String, u64>,
    anchor: Option<AuditEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedAgent {
    key: AgentKey,
    agent_id: String,
    agent_urn: Option<String>,
    sources: BTreeSet<String>,
    tenants: BTreeSet<String>,
    packs: BTreeSet<String>,
    source_packs: BTreeSet<(String, String)>,
    intents: BTreeSet<String>,
    models: BTreeSet<String>,
    evaluators: BTreeSet<String>,
    admitted_profiles: BTreeSet<String>,
    admitted_controls: BTreeSet<String>,
    admitted_by: BTreeSet<String>,
    surfaced: BTreeSet<String>,
    first_seen: String,
    last_seen: String,
    runs: u64,
    runs_by_status: BTreeMap<String, u64>,
    child_runs: u64,
    delegates_to: BTreeSet<AgentKey>,
    capabilities: BTreeMap<String, Counts>,
    refusals: BTreeMap<String, u64>,
    approvals_required: u64,
    approvals_redeemed: u64,
    escalations: u64,
    decisions: u64,
    scores: u64,
    low_scores: u64,
    loops: u64,
    repeated_effects: u64,
    output_schema_violations: u64,
    memory_operations: u64,
    checkpoints: u64,
    unresolved: BTreeSet<String>,
    unresolved_untracked: u64,
    hours: BTreeMap<i64, Hour>,
    seen: SeenMap,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct FleetSnapshot {
    schema_version: u32,
    revision: u64,
    sources: Vec<PersistedSource>,
    agents: Vec<PersistedAgent>,
    spend: BTreeMap<AgentKey, AgentSpend>,
    approvals: Approvals,
    runs: Vec<((String, String), RunSummary)>,
    order: VecDeque<(String, String)>,
    traces: Vec<((String, String), String)>,
    attempts: Vec<((String, String), Open)>,
    attempt_order: VecDeque<(String, String)>,
    changes: VecDeque<Change>,
    agents_per_tenant: Vec<((String, String), usize)>,
}

impl From<&SourceState> for PersistedSource {
    fn from(s: &SourceState) -> Self {
        Self {
            id: s.id.clone(),
            tenant_id: s.tenant_id.clone(),
            verified_to: s.verified_to,
            head: s.head,
            broken: s.broken.clone(),
            last_error: s.last_error.clone(),
            last_sync: s.last_sync.clone(),
            unattributed: s.unattributed,
            revoked: s.revoked.clone(),
            revocations: s.revocations.clone(),
            conformance: s.conformance.clone(),
            break_glass: s.break_glass.clone(),
            event_counts: s.event_counts.clone(),
            anchor: s.anchor.clone(),
        }
    }
}

impl From<PersistedSource> for SourceState {
    fn from(s: PersistedSource) -> Self {
        Self {
            id: s.id,
            tenant_id: s.tenant_id,
            verified_to: s.verified_to,
            head: s.head,
            broken: s.broken,
            last_error: s.last_error,
            last_sync: s.last_sync,
            unattributed: s.unattributed,
            revoked: s.revoked,
            revocations: s.revocations,
            conformance: s.conformance,
            break_glass: s.break_glass,
            event_counts: s.event_counts,
            deployment: Value::Null,
            packs: Value::Null,
            anchor: s.anchor,
        }
    }
}

impl From<&AgentActivity> for PersistedAgent {
    fn from(a: &AgentActivity) -> Self {
        Self {
            key: a.key.clone(),
            agent_id: a.agent_id.clone(),
            agent_urn: a.agent_urn.clone(),
            sources: a.sources.clone(),
            tenants: a.tenants.clone(),
            packs: a.packs.clone(),
            source_packs: a.source_packs.clone(),
            intents: a.intents.clone(),
            models: a.models.clone(),
            evaluators: a.evaluators.clone(),
            admitted_profiles: a.admitted_profiles.clone(),
            admitted_controls: a.admitted_controls.clone(),
            admitted_by: a.admitted_by.clone(),
            surfaced: a.surfaced.clone(),
            first_seen: a.first_seen.clone(),
            last_seen: a.last_seen.clone(),
            runs: a.runs,
            runs_by_status: a.runs_by_status.clone(),
            child_runs: a.child_runs,
            delegates_to: a.delegates_to.clone(),
            capabilities: a.capabilities.clone(),
            refusals: a.refusals.clone(),
            approvals_required: a.approvals_required,
            approvals_redeemed: a.approvals_redeemed,
            escalations: a.escalations,
            decisions: a.decisions,
            scores: a.scores,
            low_scores: a.low_scores,
            loops: a.loops,
            repeated_effects: a.repeated_effects,
            output_schema_violations: a.output_schema_violations,
            memory_operations: a.memory_operations,
            checkpoints: a.checkpoints,
            unresolved: a.unresolved.clone(),
            unresolved_untracked: a.unresolved_untracked,
            hours: a.hours.clone(),
            seen: a.seen.clone(),
        }
    }
}

impl From<PersistedAgent> for AgentActivity {
    fn from(a: PersistedAgent) -> Self {
        Self {
            key: a.key,
            agent_id: a.agent_id,
            agent_urn: a.agent_urn,
            sources: a.sources,
            tenants: a.tenants,
            packs: a.packs,
            source_packs: a.source_packs,
            intents: a.intents,
            models: a.models,
            evaluators: a.evaluators,
            admitted_profiles: a.admitted_profiles,
            admitted_controls: a.admitted_controls,
            admitted_by: a.admitted_by,
            surfaced: a.surfaced,
            first_seen: a.first_seen,
            last_seen: a.last_seen,
            runs: a.runs,
            runs_by_status: a.runs_by_status,
            child_runs: a.child_runs,
            delegates_to: a.delegates_to,
            capabilities: a.capabilities,
            refusals: a.refusals,
            approvals_required: a.approvals_required,
            approvals_redeemed: a.approvals_redeemed,
            escalations: a.escalations,
            decisions: a.decisions,
            scores: a.scores,
            low_scores: a.low_scores,
            loops: a.loops,
            repeated_effects: a.repeated_effects,
            output_schema_violations: a.output_schema_violations,
            memory_operations: a.memory_operations,
            checkpoints: a.checkpoints,
            unresolved: a.unresolved,
            unresolved_untracked: a.unresolved_untracked,
            hours: a.hours,
            seen: a.seen,
        }
    }
}

fn capture(fleet: &Fleet) -> FleetSnapshot {
    FleetSnapshot {
        schema_version: SCHEMA_VERSION,
        revision: fleet.revision,
        sources: fleet.sources.values().map(PersistedSource::from).collect(),
        agents: fleet.agents.values().map(PersistedAgent::from).collect(),
        spend: fleet.spend.clone(),
        approvals: fleet.approvals.clone(),
        runs: fleet.runs.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
        order: fleet.order.clone(),
        traces: fleet.traces.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
        attempts: fleet.attempts.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
        attempt_order: fleet.attempt_order.clone(),
        changes: fleet.changes.clone(),
        agents_per_tenant: fleet.agents_per_tenant.iter().map(|(k, v)| (k.clone(), *v)).collect(),
    }
}

fn apply_snapshot(fleet: &mut Fleet, snap: FleetSnapshot) {
    fleet.revision = snap.revision;
    fleet.sources = snap
        .sources
        .into_iter()
        .map(|s| (s.id.clone(), SourceState::from(s)))
        .collect();
    fleet.agents = snap
        .agents
        .into_iter()
        .map(|a| (a.key.clone(), AgentActivity::from(a)))
        .collect();
    fleet.spend = snap.spend;
    fleet.approvals = snap.approvals;
    fleet.runs = snap.runs.into_iter().collect();
    fleet.order = snap.order;
    fleet.traces = snap.traces.into_iter().collect();
    fleet.attempts = snap.attempts.into_iter().collect();
    fleet.attempt_order = snap.attempt_order;
    fleet.changes = snap.changes;
    fleet.agents_per_tenant = snap.agents_per_tenant.into_iter().collect();
}

/// Persists and restores checksummed fleet checkpoints in a [`DocumentStore`].
#[derive(Debug)]
pub struct StoreCheckpoints<S> {
    store: Arc<S>,
}

impl<S: DocumentStore + 'static> StoreCheckpoints<S> {
    pub fn new(store: Arc<S>) -> Self {
        Self { store }
    }

    /// Saves `fleet` as a checksummed checkpoint document. Skips (with a warning) if
    /// the serialized document exceeds [`MAX_CHECKPOINT_BYTES`].
    pub async fn save(&self, fleet: &Fleet) -> Result<bool, String> {
        let snapshot = capture(fleet);
        let payload = serde_json::to_value(&snapshot).map_err(|e| e.to_string())?;
        let digest = sha256_canonical(&payload).map_err(|e| e.to_string())?;
        let doc = json!({
            "schema_version": SCHEMA_VERSION,
            "digest": digest,
            "snapshot": payload,
        });
        let size = serde_json::to_vec(&doc).map_err(|e| e.to_string())?.len();
        if size > MAX_CHECKPOINT_BYTES {
            tracing::warn!(bytes = size, "fleet checkpoint exceeds size cap; skipping save");
            return Ok(false);
        }
        let key = checkpoint_key();
        for _ in 0..4 {
            let current = self.store.get(&key).await.map_err(|e| e.to_string())?;
            let written = match &current {
                Some(c)
                    if c.body["snapshot"]["revision"]
                        .as_u64()
                        .is_some_and(|r| r >= fleet.revision) =>
                {
                    return Ok(true);
                }
                Some(c) => self.store.compare_and_swap(&key, c.revision, &doc).await.map(|_| ()),
                None => self.store.create(&key, &doc).await.map(|_| ()),
            };
            match written {
                Ok(()) => return Ok(true),
                Err(e) if e.is_conflict() => {}
                Err(e) => return Err(e.to_string()),
            }
        }
        Ok(false)
    }

    /// Restores the last valid checkpoint into `fleet`, verifying its canonical digest
    /// and checking every checkpointed anchor against `pins`. Returns how many sources
    /// had verified anchors restored, or `0` if no valid checkpoint could be restored.
    pub async fn restore(&self, fleet: &mut Fleet, pins: &dyn Pins) -> Result<usize, String> {
        let Some(doc) = self.store.get(&checkpoint_key()).await.map_err(|e| e.to_string())? else {
            return Ok(0);
        };
        if doc.body["schema_version"].as_u64() != Some(u64::from(SCHEMA_VERSION)) {
            return Ok(0);
        }
        let Some(expected_digest) = doc.body["digest"].as_str() else {
            return Ok(0);
        };
        let payload = &doc.body["snapshot"];
        let Ok(actual_digest) = sha256_canonical(payload) else {
            return Ok(0);
        };
        if actual_digest != expected_digest {
            tracing::warn!("discarding fleet checkpoint with mismatched digest");
            return Ok(0);
        }
        let Ok(snap) = serde_json::from_value::<FleetSnapshot>(payload.clone()) else {
            tracing::warn!("discarding unreadable fleet checkpoint");
            return Ok(0);
        };
        for src in &snap.sources {
            if let Some(anchor) = &src.anchor
                && let Some(pin) = pins.get(&src.id).await?
                && anchor.sequence == pin.sequence
                && anchor.record_hash != pin.record_hash
            {
                tracing::warn!(source = %src.id, "checkpoint anchor disagrees with pin; rebuilding from genesis");
                return Ok(0);
            }
        }
        let restored_sources = snap.sources.iter().filter(|s| s.anchor.is_some()).count();
        apply_snapshot(fleet, snap);
        Ok(restored_sources)
    }
}

#[cfg(test)]
mod tests {
    use contextos_audit::{AuditSigner, AuditWriter};
    use contextos_store::{MemoryLog, MemoryStore};

    use super::*;
    use crate::pins::{Pin, StorePins};

    #[tokio::test]
    async fn checkpoint_round_trips_fleet_and_rejects_tampered_digest() {
        let store = Arc::new(MemoryStore::new());
        let pins = StorePins::new(store.clone());
        let cp = StoreCheckpoints::new(store.clone());

        let writer = AuditWriter::new(MemoryLog::new(), AuditSigner::from_seed("k1", [3u8; 32]));
        let e1 = writer
            .append(
                "tenant_a",
                "run_admitted",
                json!({"run_id": "r1", "trace_id": "t1", "pack_ref": "p@1", "agent": {"principal_id": "agt_1"}}),
                "2026-11-27T10:00:00Z",
            )
            .await
            .unwrap();
        let mut fleet = Fleet::new(100, 48);
        fleet.apply("eu", &e1);
        fleet.source("eu").anchor = Some(e1.clone());
        pins.advance(
            "eu",
            &Pin {
                sequence: e1.sequence,
                record_hash: e1.record_hash.clone(),
            },
        )
        .await
        .unwrap();

        assert!(cp.save(&fleet).await.unwrap());

        let mut restored = Fleet::new(100, 48);
        assert_eq!(cp.restore(&mut restored, &pins).await.unwrap(), 1);
        assert_eq!(restored.source("eu").verified_to, 1);
        assert_eq!(restored.source("eu").event_counts.get("run_admitted"), Some(&1));
        assert_eq!(restored.agents.len(), 1);

        // Corrupt the stored checkpoint body -> restore safely refuses it.
        let key = checkpoint_key();
        let cur = store.get(&key).await.unwrap().unwrap();
        let mut bad = cur.body.clone();
        bad["snapshot"]["revision"] = json!(999);
        store.compare_and_swap(&key, cur.revision, &bad).await.unwrap();
        let mut fresh = Fleet::new(100, 48);
        assert_eq!(cp.restore(&mut fresh, &pins).await.unwrap(), 0);
        assert!(fresh.agents.is_empty());
    }
}
