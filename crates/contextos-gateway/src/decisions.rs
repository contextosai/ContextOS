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
use contextos_store::{AppendLog, DocKey, DocKind, DocumentStore, transact};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::admission::RunAdmission;
use crate::{Gateway, GatewayError, operation_ledger_key};

/// Decisions recorded per run at most.
pub const MAX_DECISIONS_PER_RUN: usize = 1024;

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
    #[error(transparent)]
    Gateway(#[from] GatewayError),
}

fn compiled_key(admission: &RunAdmission) -> DocKey {
    DocKey::new(&admission.tenant_id, DocKind::CompiledContext, &admission.run_id)
}

fn decisions_key(admission: &RunAdmission) -> DocKey {
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

    /// Verifies, assembles, signs and stores a decision of the run.
    pub async fn record_decision(
        &self,
        admission: &RunAdmission,
        report: DecisionReport,
    ) -> Result<RecordedDecision, DecisionRefusal> {
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
        let budget_usage = BudgetUsage {
            tokens: budget["tokens"].as_u64().unwrap_or(0),
            tool_calls: budget["tool_calls"].as_u64().unwrap_or(0),
            cost_usd_cents: budget["cost_units"].as_u64().unwrap_or(0) as f64 / 100.0,
            wall_clock_ms: 0,
        };
        let now = self.now();
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
                model_profile: None,
                evaluator_suite: None,
                routing_decision_id: None,
            },
            scorecard: None,
            confidence: report.confidence,
            rationale: report.rationale,
        })?;
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
        let entry = json!({"record": record, "replay_packet": packet});

        let key = decisions_key(admission);
        if self.store.get(&key).await.map_err(GatewayError::from)?.is_none() {
            match self
                .store
                .create(&key, &json!({"run_id": admission.run_id, "decisions": []}))
                .await
            {
                Ok(_) => {}
                Err(e) if e.is_conflict() => {}
                Err(e) => return Err(GatewayError::from(e).into()),
            }
        }
        let mut full = false;
        transact(self.store.as_ref(), &key, |log| {
            let mut next = log.clone();
            let Some(decisions) = next["decisions"].as_array_mut() else {
                return TransitionResult::rejected(log.clone(), "decision_log_invalid");
            };
            if decisions.len() >= MAX_DECISIONS_PER_RUN {
                full = true;
                return TransitionResult::rejected(log.clone(), "too_many_decisions");
            }
            full = false;
            decisions.push(entry.clone());
            TransitionResult::accepted(next, vec![])
        })
        .await
        .map_err(GatewayError::from)?;
        if full {
            return Err(DecisionRefusal::TooManyDecisions);
        }
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
        let decisions = get(decisions_key(admission))
            .await?
            .map(|d| d["decisions"].clone())
            .unwrap_or(json!([]));
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
