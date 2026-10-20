//! DecisionRecords, replay packets and run evidence.
//!
//! The orchestrator reports a decision (its key, status, outcome and rationale) and the
//! tool calls it relied on. The gateway does not take its word for the rest:
//!
//! - every lineage entry must name an operation of this run, found in the run's own
//!   operation ledger, whose effect was confirmed or partially applied; the entry's
//!   capability and idempotency key come from that ledger;
//! - policy decisions are the outcomes pinned at admission;
//! - budget usage is read from the run's budget ledger;
//! - the record is assembled against the run's compiled context, so `decided` and
//!   `closed` are refused while that decision's evidence gate is open;
//! - the record is signed into the audit chain, and a replay packet binds it to the
//!   compiled context and a hash of the verified tool transcript.

use contextos_audit::{DecisionDraft, DecisionError, assemble_decision, replay_packet};
use contextos_contract::canonical::sha256_canonical;
use contextos_contract::types::{
    BudgetUsage, CompiledContext, DecisionActor, DecisionActorType, DecisionLineage, DecisionPolicyDecision,
    DecisionRationale, DecisionRecord, DecisionStatus, JsonObject, PolicyVerdict, ReplayPacket, ToolLineageEntry,
};
use contextos_kernel::TransitionResult;
use contextos_store::{AppendLog, Commit, DocKey, DocKind, DocumentStore, transact};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::admission::RunAdmission;
use crate::{Gateway, GatewayError, operation_ledger_key};

/// Decisions recorded per run at most.
pub const MAX_DECISIONS_PER_RUN: usize = 1024;
/// Tool calls one decision may cite.
pub const MAX_DECISION_TOOL_CALLS: usize = 256;
/// Canonical size of a decision's free-form parts (outputs, rationale, subjects).
pub const MAX_DECISION_DETAIL_BYTES: usize = 64 * 1024;

/// What the orchestrator reports.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionReport {
    pub decision_key: String,
    pub decision_version: String,
    pub status: DecisionStatus,
    #[serde(default)]
    pub outcome: Option<String>,
    #[serde(default)]
    pub allowed_outcomes: Option<Vec<String>>,
    #[serde(default)]
    pub outputs: Option<JsonObject>,
    #[serde(default)]
    pub intent_ref: Option<String>,
    #[serde(default)]
    pub subject_ids: Option<Vec<String>>,
    #[serde(default)]
    pub confidence: Option<f64>,
    #[serde(default)]
    pub rationale: Option<DecisionRationale>,
    /// The tool calls the decision relied on, by `tool_call_id` and operation id
    /// (the call's idempotency key, or its tool call id when it had none).
    #[serde(default)]
    pub tool_calls: Vec<ReportedToolCall>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReportedToolCall {
    pub tool_call_id: String,
    pub operation_id: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RecordedDecision {
    pub record: DecisionRecord,
    pub replay_packet: ReplayPacket,
}

#[derive(Debug, thiserror::Error)]
pub enum DecisionRefusal {
    #[error("the run's compiled context is not available")]
    CompiledContextMissing,
    #[error("tool call {0} is not a governed effect of this run")]
    UnknownToolCall(String),
    #[error(transparent)]
    Decision(#[from] DecisionError),
    #[error("the run has too many recorded decisions")]
    TooManyDecisions,
    #[error("the decision report is too large")]
    TooLarge,
    #[error(transparent)]
    Gateway(#[from] GatewayError),
}

fn compiled_key(admission: &RunAdmission) -> DocKey {
    DocKey::new(&admission.tenant_id, DocKind::CompiledContext, &admission.run_id)
}

pub(crate) fn decisions_key(admission: &RunAdmission) -> DocKey {
    DocKey::new(&admission.tenant_id, DocKind::DecisionLog, &admission.run_id)
}

impl<S: DocumentStore + 'static, L: AppendLog + 'static> Gateway<S, L> {
    /// Keeps the run's compiled context, which decisions are assembled against.
    pub async fn remember_compiled(
        &self,
        admission: &RunAdmission,
        compiled: &CompiledContext,
    ) -> Result<(), GatewayError> {
        let body = serde_json::to_value(compiled).unwrap_or(Value::Null);
        match self.store.create(&compiled_key(admission), &body).await {
            Ok(_) => Ok(()),
            Err(e) if e.is_conflict() => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    /// Keeps the inputs the run was admitted with as a release-gate replay case.
    pub async fn remember_replay_case(
        &self,
        admission: &RunAdmission,
        request: &Value,
        run_context: &Value,
        deps: &Value,
    ) -> Result<(), GatewayError> {
        let key = DocKey::new(&admission.tenant_id, DocKind::ReplayCase, &admission.run_id);
        let case = json!({"name": admission.run_id, "request": request, "run_context": run_context,
            "deps": if deps.is_null() { json!({}) } else { deps.clone() }});
        match self.store.create(&key, &case).await {
            Ok(_) => Ok(()),
            Err(e) if e.is_conflict() => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    /// The run's replay case, for `ctx gate`.
    pub async fn replay_case(&self, admission: &RunAdmission) -> Result<Option<Value>, GatewayError> {
        let key = DocKey::new(&admission.tenant_id, DocKind::ReplayCase, &admission.run_id);
        Ok(self.store.get(&key).await?.map(|r| r.body))
    }

    /// Verifies, assembles, signs and stores a decision of the run.
    /// `recorded_by` is the authenticated principal reporting it; it may not score it.
    pub async fn record_decision(
        &self,
        admission: &RunAdmission,
        report: DecisionReport,
        recorded_by: &str,
    ) -> Result<RecordedDecision, DecisionRefusal> {
        // Bound the work and storage one report can cause before touching anything.
        let detail = json!([
            report.outputs,
            report.rationale,
            report.subject_ids,
            report.allowed_outcomes
        ]);
        if report.tool_calls.len() > MAX_DECISION_TOOL_CALLS
            || contextos_contract::canonical::canonicalize(&detail)
                .map_or(true, |t| t.len() > MAX_DECISION_DETAIL_BYTES)
        {
            return Err(DecisionRefusal::TooLarge);
        }
        let compiled: CompiledContext = self
            .store
            .get(&compiled_key(admission))
            .await
            .map_err(GatewayError::from)?
            .and_then(|r| serde_json::from_value(r.body).ok())
            .ok_or(DecisionRefusal::CompiledContextMissing)?;

        // Tool lineage, verified against the run's operation ledgers.
        let mut lineage = Vec::new();
        let mut transcript = Vec::new();
        for call in &report.tool_calls {
            let op = self
                .store
                .get(&operation_ledger_key(admission, &call.operation_id))
                .await
                .map_err(GatewayError::from)?
                .and_then(|r| r.body["operations"].as_array().and_then(|ops| ops.first().cloned()));
            let Some(op) = op.filter(|op| {
                op["intent"]["operation_id"] == call.operation_id.as_str()
                    && op["intent"]["run_id"] == admission.run_id.as_str()
                    && matches!(op["outcome"].as_str(), Some("confirmed" | "partial"))
            }) else {
                return Err(DecisionRefusal::UnknownToolCall(call.tool_call_id.clone()));
            };
            let capability_id = self
                .manifests
                .values()
                .find(|m| {
                    serde_json::to_value(&m.capability_ref).ok().as_ref() == Some(&op["intent"]["capability_ref"])
                })
                .map(|m| m.capability_id.clone());
            transcript.push(
                json!({"tool_call_id": call.tool_call_id, "operation_id": call.operation_id,
                "action_digest": op["intent"]["action_digest"], "outcome": op["outcome"]}),
            );
            lineage.push(ToolLineageEntry {
                tool_call_id: call.tool_call_id.clone(),
                tool_result_id: None,
                capability_id,
                approval_mode_effective: None,
                policy_decision_id: None,
                idempotency_key: Some(op["intent"]["idempotency_key"].as_str().map(str::to_owned)),
                artifact_refs: None,
                mutation_refs: (op["outcome"] == "confirmed" || op["outcome"] == "partial")
                    .then(|| vec![call.operation_id.clone()]),
                reversal_token: None,
            });
        }
        let transcript_hash = sha256_canonical(&json!(transcript)).ok();

        let policy_decisions = admission
            .policy_outcomes
            .iter()
            .map(|o| DecisionPolicyDecision {
                policy_decision_id: o["rule_id"].as_str().unwrap_or_default().to_owned(),
                bundle_id: o["bundle_ref"]["artifact_id"].as_str().map(str::to_owned),
                rule_ids: vec![o["rule_id"].as_str().unwrap_or_default().to_owned()],
                verdict: serde_json::from_value::<PolicyVerdict>(o["verdict"].clone()).ok(),
            })
            .collect();
        let budget = self
            .store
            .get(&DocKey::new(
                &admission.tenant_id,
                DocKind::BudgetLedger,
                &admission.budget_ledger_id,
            ))
            .await
            .map_err(GatewayError::from)?
            .map_or(Value::Null, |r| r.body["used"].clone());
        #[allow(clippy::cast_precision_loss)]
        let mut budget_usage = BudgetUsage {
            tokens: budget["tokens"].as_u64().unwrap_or(0),
            tool_calls: budget["tool_calls"].as_u64().unwrap_or(0),
            cost_usd_cents: budget["cost_units"].as_u64().unwrap_or(0) as f64 / 100.0,
            wall_clock_ms: 0,
        };
        let now = self.now();
        budget_usage.wall_clock_ms =
            contextos_contract::validation::elapsed_millis(&admission.admitted_at, &now).unwrap_or(0);
        let record_id = self.ports.ids.new_id("decision");
        let record = assemble_decision(DecisionDraft {
            record_id: record_id.clone(),
            decision_key: report.decision_key,
            decision_version: report.decision_version,
            timestamp: now.clone(),
            status: report.status,
            actor: DecisionActor {
                actor_type: DecisionActorType::Agent,
                id: admission.actor["principal_id"].as_str().unwrap_or_default().to_owned(),
            },
            trace_id: admission.trace_id.clone(),
            compiled: &compiled,
            allowed_outcomes: report.allowed_outcomes.as_deref(),
            outcome: report.outcome,
            outputs: report.outputs,
            intent_ref: report.intent_ref,
            subject_ids: report.subject_ids,
            policy_decisions,
            approvals: Vec::new(),
            tool_lineage: lineage,
            budget_usage,
            lineage: DecisionLineage {
                pack_version: compiled.context_ledger.pack_ref.clone(),
                snapshot_version: None,
                policy_versions: Some(compiled.context_ledger.policy_bundles.clone()),
                decision_spec: None,
                kg_snapshot: None,
                model_profile: pinned_release(admission, "model_profile"),
                evaluator_suite: pinned_release(admission, "evaluator_suite"),
                routing_decision_id: None,
            },
            scorecard: None,
            confidence: report.confidence,
            rationale: report.rationale,
        })?;
        // Reserve the record's place in the run's index before signing, so a refused
        // decision never leaves a signed entry behind.
        let index_key = decisions_key(admission);
        if self.store.get(&index_key).await.map_err(GatewayError::from)?.is_none() {
            match self
                .store
                .create(&index_key, &json!({"run_id": admission.run_id, "record_ids": []}))
                .await
            {
                Ok(_) => {}
                Err(e) if e.is_conflict() => {}
                Err(e) => return Err(GatewayError::from(e).into()),
            }
        }
        let reserved = transact(self.store.as_ref(), &index_key, |index| {
            let mut next = index.clone();
            let Some(ids) = next["record_ids"].as_array_mut() else {
                return TransitionResult::rejected(index.clone(), "decision_index_invalid");
            };
            if ids.len() >= MAX_DECISIONS_PER_RUN {
                return TransitionResult::rejected(index.clone(), "too_many_decisions");
            }
            ids.push(json!(record_id));
            TransitionResult::accepted(next, vec![])
        })
        .await
        .map_err(GatewayError::from)?;
        if matches!(reserved, Commit::Rejected { .. }) {
            return Err(DecisionRefusal::TooManyDecisions);
        }
        let record = self
            .audit
            .record_decision(&admission.tenant_id, record, &now)
            .await
            .map_err(GatewayError::from)?;
        let packet = replay_packet(
            &record,
            format!("replay_{record_id}"),
            compiled.context_ledger.pack_ref.clone(),
            transcript_hash,
        )?;
        let entry = json!({"record": record, "replay_packet": packet, "recorded_by": recorded_by});

        // One document per decision: storage per write stays bounded.
        let entry_key = DocKey::new(
            &admission.tenant_id,
            DocKind::DecisionLog,
            format!("{}/{record_id}", admission.run_id),
        );
        self.store
            .create(&entry_key, &entry)
            .await
            .map_err(GatewayError::from)?;
        Ok(RecordedDecision {
            record,
            replay_packet: packet,
        })
    }

    /// Everything an auditor needs about one run.
    pub async fn run_evidence(&self, admission: &RunAdmission) -> Result<Value, GatewayError> {
        let get = |key: DocKey| async move { Ok::<_, GatewayError>(self.store.get(&key).await?.map(|r| r.body)) };
        let budget = get(DocKey::new(
            &admission.tenant_id,
            DocKind::BudgetLedger,
            &admission.budget_ledger_id,
        ))
        .await?;
        // Walk the compaction archives from the live ledger back to admission.
        let mut archives = Vec::new();
        let mut next = budget
            .as_ref()
            .and_then(|b| b["opening_usage_ref"]["artifact_id"].as_str().map(str::to_owned));
        while let Some(id) = next.filter(|id| *id != admission.budget_ledger_id) {
            let Some(archive) = get(DocKey::new(&admission.tenant_id, DocKind::BudgetArchive, &id)).await? else {
                break;
            };
            next = archive["previous_opening_usage_ref"]["artifact_id"]
                .as_str()
                .map(str::to_owned);
            archives.push(archive);
        }
        let mut decisions = Vec::new();
        let ids = get(decisions_key(admission))
            .await?
            .map(|d| d["record_ids"].clone())
            .unwrap_or(json!([]));
        for id in ids.as_array().into_iter().flatten().filter_map(Value::as_str) {
            let key = DocKey::new(
                &admission.tenant_id,
                DocKind::DecisionLog,
                format!("{}/{id}", admission.run_id),
            );
            // A reserved slot whose signing failed has no document.
            if let Some(mut entry) = get(key).await? {
                entry["scores"] = Value::Array(self.decision_scores(admission, id).await?);
                decisions.push(entry);
            }
        }
        Ok(json!({
            "evidence_version": "contextos-rs.run_evidence.v1",
            "run_id": admission.run_id,
            "admission": admission,
            "run_state": self.run_state(admission).await?,
            "budget_ledger": budget,
            "budget_archives": archives,
            "decisions": decisions,
        }))
    }
}

/// The run's pinned release reference of one artifact type, as `id@version` (the
/// executing model profile and the evaluator suite are pinned at admission through
/// the execution contract's `release_refs`).
fn pinned_release(admission: &RunAdmission, artifact_type: &str) -> Option<String> {
    admission
        .release_refs
        .iter()
        .find(|r| r["artifact_type"] == artifact_type)
        .and_then(|r| Some(format!("{}@{}", r["artifact_id"].as_str()?, r["version"].as_str()?)))
}
