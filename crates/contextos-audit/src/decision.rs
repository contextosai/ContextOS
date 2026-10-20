//! DecisionRecord assembly and replay packets.
//!
//! A governed decision becomes a typed `DecisionRecord` (schema
//! `decision-record.v1`) that carries the compiled-context hash, the controls that
//! were active, the evidence it cites, policy decisions, approvals, tool lineage and
//! budget usage. Assembly refuses to mark a decision `DECIDED` or `CLOSED` while its
//! evidence gate is insufficient: an open gate cannot be closed by the model.

use contextos_contract::canonical::{CanonicalError, sha256_canonical};
use contextos_contract::schema::{SchemaDoc, SchemaError, SchemaTarget, validate};
use contextos_contract::types::{
    BudgetUsage, CompiledContext, DecisionActor, DecisionApproval, DecisionLineage, DecisionPolicyDecision,
    DecisionRationale, DecisionRecord, DecisionReplay, DecisionReplayStatus, DecisionScorecard, DecisionStatus,
    JsonObject, ReplayExpected, ReplayPacket, ReplaySourceKind, SideEffectPolicy, ToolLineageEntry,
};
use serde_json::Value;

#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum DecisionError {
    #[error("decision {0} cannot be committed while its evidence gate is insufficient")]
    EvidenceGateOpen(String),
    #[error("outcome {0:?} is not an allowed outcome of the decision spec")]
    OutcomeNotAllowed(String),
    #[error(transparent)]
    Schema(#[from] SchemaError),
    #[error(transparent)]
    Encoding(#[from] CanonicalError),
}

/// Inputs to one DecisionRecord. Identifiers and the timestamp come from the runtime.
#[derive(Debug, Clone)]
pub struct DecisionDraft<'a> {
    pub record_id: String,
    pub decision_key: String,
    pub decision_version: String,
    pub timestamp: String,
    pub status: DecisionStatus,
    pub actor: DecisionActor,
    pub trace_id: String,
    pub compiled: &'a CompiledContext,
    pub allowed_outcomes: Option<&'a [String]>,
    pub outcome: Option<String>,
    pub outputs: Option<JsonObject>,
    pub intent_ref: Option<String>,
    pub subject_ids: Option<Vec<String>>,
    pub policy_decisions: Vec<DecisionPolicyDecision>,
    pub approvals: Vec<DecisionApproval>,
    pub tool_lineage: Vec<ToolLineageEntry>,
    pub budget_usage: BudgetUsage,
    pub lineage: DecisionLineage,
    pub scorecard: Option<DecisionScorecard>,
    pub confidence: Option<f64>,
    pub rationale: Option<DecisionRationale>,
}

/// Assembles and schema-validates a DecisionRecord.
pub fn assemble_decision(draft: DecisionDraft<'_>) -> Result<DecisionRecord, DecisionError> {
    let committing = matches!(draft.status, DecisionStatus::Decided | DecisionStatus::Closed);
    if committing {
        let gate_open = draft
            .compiled
            .runtime_controls
            .evidence_gates
            .iter()
            .any(|gate| gate.decision_key == draft.decision_key && !gate.commit_allowed);
        if gate_open {
            return Err(DecisionError::EvidenceGateOpen(draft.decision_key));
        }
    }
    if let (Some(allowed), Some(outcome)) = (draft.allowed_outcomes, draft.outcome.as_ref())
        && !allowed.contains(outcome)
    {
        return Err(DecisionError::OutcomeNotAllowed(outcome.clone()));
    }
    let mut outputs = draft.outputs.unwrap_or_default();
    if let Some(outcome) = draft.outcome {
        outputs.insert("outcome".into(), Value::String(outcome));
    }
    let hash = draft.compiled.context_ledger.compiled_context_hash.clone();
    let record = DecisionRecord {
        record_id: draft.record_id,
        decision_key: draft.decision_key,
        decision_version: draft.decision_version,
        timestamp: draft.timestamp,
        status: draft.status,
        actor: draft.actor,
        intent_ref: draft.intent_ref,
        context_snapshot_hash: Some(hash.clone()),
        subject_ids: draft.subject_ids,
        inputs_refs: None,
        outputs: (!outputs.is_empty()).then_some(outputs),
        evidence_refs: draft
            .compiled
            .manifests
            .evidence_manifest
            .iter()
            .map(|e| e.evidence_ref.clone())
            .collect(),
        policy_decisions: draft.policy_decisions,
        approvals: draft.approvals,
        controls_active: draft.compiled.runtime_controls.clone(),
        tool_lineage: (!draft.tool_lineage.is_empty()).then_some(draft.tool_lineage),
        scorecard: draft.scorecard,
        confidence: draft.confidence,
        rationale: draft.rationale,
        budget_usage: draft.budget_usage,
        lineage: draft.lineage,
        replay: Some(DecisionReplay {
            compiled_context_hash: Some(hash),
            last_status: Some(DecisionReplayStatus::NotRun),
            ..DecisionReplay::default()
        }),
        audit: None,
        trace_id: draft.trace_id,
    };
    let value = serde_json::to_value(&record).map_err(|_| CanonicalError::InvalidJson)?;
    validate(&SchemaTarget::document(SchemaDoc::DecisionRecord), &value)?;
    Ok(record)
}

/// Digest of a record excluding its `audit` block (which is filled in from the
/// chain entry that recorded it).
pub fn decision_record_hash(record: &DecisionRecord) -> Result<String, CanonicalError> {
    let mut value = serde_json::to_value(record).map_err(|_| CanonicalError::InvalidJson)?;
    if let Value::Object(map) = &mut value {
        map.remove("audit");
    }
    sha256_canonical(&value)
}

/// Replay packet for audit or regression replay of a recorded decision. Replays use
/// recorded tool transcripts; live side effects are never re-executed.
pub fn replay_packet(
    record: &DecisionRecord,
    replay_packet_id: String,
    context_pack_ref: String,
    tool_transcript_chain_hash: Option<String>,
) -> Result<ReplayPacket, DecisionError> {
    let packet = ReplayPacket {
        replay_packet_id,
        trace_id: record.trace_id.clone(),
        session_id: None,
        source_kind: ReplaySourceKind::DecisionRecord,
        source_ref: record.record_id.clone(),
        context_pack_ref,
        run_context_ref: None,
        knowledge_snapshot_ref: record.lineage.kg_snapshot.clone(),
        compiled_context_hash: record.context_snapshot_hash.clone().unwrap_or_default(),
        tool_transcript_chain_hash,
        side_effect_policy: SideEffectPolicy::TranscriptOnly,
        expected: ReplayExpected {
            status: serde_json::to_value(record.status)
                .ok()
                .and_then(|v| v.as_str().map(str::to_owned))
                .unwrap_or_default(),
            decision_record_hash: Some(decision_record_hash(record)?),
            scorecard: None,
            properties: None,
        },
        latest_result: None,
        metadata: None,
    };
    let value = serde_json::to_value(&packet).map_err(|_| CanonicalError::InvalidJson)?;
    validate(&SchemaTarget::document(SchemaDoc::ReplayPacket), &value)?;
    Ok(packet)
}
