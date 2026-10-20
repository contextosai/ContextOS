//! Delegated child runs (subagent lanes).
//!
//! A parent run delegates work with an `AgentDelegationEnvelope`. The envelope
//! *states* the delegation; it proves nothing about authority. The gateway enforces it:
//!
//! - **Narrowing.** The child's capabilities must be a subset of the parent's
//!   surfaced capabilities, its deadline (`expires_at`) no later than the parent's,
//!   its issuer the parent's actor and its subject the child's actor, and its
//!   `parent_claim_hash` the parent's compiled-context hash. The child's tool surface
//!   is the intersection of what its own compilation surfaced, the envelope's
//!   capabilities, the classification ceiling, and — for `read_only` children —
//!   capabilities with no effect.
//! - **Budget.** The child's sub-budget is reserved from the parent's ledger before
//!   the child exists, as a child-scoped reservation. The child gets its own ledger
//!   whose ceiling is exactly that allocation; it can never create a fresh pool.
//! - **Authority.** Every child action is still authorized by the kernel against
//!   grants from the authority broker, which must supply a grant chain narrowing at
//!   each level. The gateway, as the observer that created the lineage, attests the
//!   run links from the child up to the root.
//! - **Close.** Closing a child first reserves all of its remaining capacity inside
//!   its own ledger, atomically, so no further effect can spend after its usage is
//!   reported. The parent then settles the child reservation at the child's final
//!   usage, releasing the rest. A child with unresolved effects cannot close until
//!   they are reconciled. The parent's decision (`accept` or `reject` the child's
//!   output) is audited; for `isolate_until_accepted` children it is what admits the
//!   output into the parent's lineage.

use contextos_contract::schema::{SchemaDoc, SchemaTarget, validate};
use contextos_contract::types::DataClassification;
use contextos_contract::validation::{add_contract_seconds, compare_contract_times};
use contextos_kernel::TransitionResult;
use contextos_kernel::budget_ledger::{
    CostUnitConversion, convert_legacy_cost_to_units, reserve_budget, reserve_child_budget,
};
use contextos_store::{AppendLog, Commit, DocKey, DocKind, DocumentStore, transact};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::admission::{AdmissionError, AdmissionRequest, BudgetLimits, RunAdmission, admit_run};
use crate::{Gateway, GatewayError, OBSERVATION_VALIDITY_SECONDS};

/// How a child run descends from its root.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Lineage {
    pub delegation_id: String,
    pub root_run_id: String,
    pub parent_run_id: String,
    /// `read_only` or `isolate_until_accepted`.
    pub effect_policy: String,
    /// Run links from this run up to the root's direct child: each names a run, its
    /// parent and the actor acting in it.
    pub links: Vec<RunLink>,
    /// The schema the child's results must meet (`scope.output_schema_ref`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_schema_ref: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RunLink {
    pub child_run_id: String,
    pub parent_run_id: String,
    pub subject: Value,
}

/// The parent's decision on a closed child's output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CloseDecision {
    Accept,
    Reject,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CloseOutcome {
    /// `closed`, or `rejected` with reasons.
    pub status: String,
    pub reason_codes: Vec<String>,
    /// The child's final usage, settled into the parent.
    pub usage: Option<Value>,
    pub audit_sequences: Vec<u64>,
}

fn rank(label: &str) -> Option<DataClassification> {
    serde_json::from_value(json!(label)).ok()
}

/// The parent ledger reservation that funds a child.
pub fn delegation_reservation_id(child_run_id: &str) -> String {
    format!("delegation:{child_run_id}")
}

impl<S: DocumentStore + 'static, L: AppendLog + 'static> Gateway<S, L> {
    /// Admits a child run delegated by `parent`. `request` is the child's own
    /// admission (its compiled context, contract and actor); its limits and deadline
    /// are replaced by the envelope's sub-budget and expiry. The caller persists the
    /// returned admission like any other.
    #[tracing::instrument(name = "contextos.delegate", skip_all, fields(tenant_id = %parent.tenant_id, parent_run_id = %parent.run_id))]
    pub async fn delegate(
        &self,
        parent: &RunAdmission,
        envelope: &Value,
        mut request: AdmissionRequest<'_>,
    ) -> Result<RunAdmission, AdmissionError> {
        let reject = |reason: &str| AdmissionError::Delegation(vec![reason.to_owned()]);
        let now = self.now();
        let parent_state = self
            .run_state(parent)
            .await
            .map_err(|e| AdmissionError::Unavailable(e.to_string()))?;
        if parent_state.as_ref().is_some_and(|s| s["status"] != "running") {
            return Err(reject("parent_not_running"));
        }
        if validate(&SchemaTarget::document(SchemaDoc::AgentDelegation), envelope).is_err() {
            return Err(reject("delegation_invalid"));
        }
        let text = |key: &str| envelope[key].as_str().unwrap_or_default();
        let child_run_id = request.contract["run_id"].as_str().unwrap_or_default().to_owned();
        if text("tenant_id") != parent.tenant_id
            || text("parent_run_id") != parent.run_id
            || text("trace_id") != parent.trace_id
            || text("child_run_id") != child_run_id
            || request.run_context.run_id != child_run_id
            || child_run_id == parent.run_id
        {
            return Err(reject("delegation_unbound"));
        }
        if text("issuer") != parent.actor["principal_id"].as_str().unwrap_or_default()
            || text("subject") != request.actor["principal_id"].as_str().unwrap_or_default()
        {
            return Err(reject("delegation_principal_mismatch"));
        }
        if parent.compiled_context_hash.is_empty() || text("parent_claim_hash") != parent.compiled_context_hash {
            return Err(reject("delegation_claim_mismatch"));
        }
        let expires_at = text("expires_at");
        let current = |a: &str, b: &str, ordering| compare_contract_times(a, b) == Some(ordering);
        if current(text("issued_at"), &now, std::cmp::Ordering::Greater)
            || !current(&now, expires_at, std::cmp::Ordering::Less)
            || current(expires_at, &parent.deadline, std::cmp::Ordering::Greater)
        {
            return Err(reject("delegation_expired_or_exceeds_parent"));
        }
        let scope = &envelope["scope"];
        // Once a deployment registers result schemas, a delegation must name one of
        // them: an unknown reference would otherwise check nothing.
        if !self.result_schemas.is_empty()
            && !scope["output_schema_ref"]
                .as_str()
                .is_some_and(|r| self.result_schemas.contains_key(r))
        {
            return Err(reject("output_schema_unregistered"));
        }
        if !scope["allowed_intents"].as_array().is_some_and(|i| {
            i.iter()
                .any(|i| i.as_str() == Some(request.request.input.intent.as_str()))
        }) {
            return Err(reject("delegation_intent_not_allowed"));
        }
        let allowed: Vec<&str> = scope["allowed_capabilities"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect();
        if allowed.iter().any(|c| !parent.surfaced_capabilities.contains(*c)) {
            return Err(reject("delegation_scope_expanded"));
        }
        let ceiling =
            rank(text_in(scope, "data_classification_ceiling")).ok_or_else(|| reject("delegation_invalid"))?;
        let effect_policy = text("effect_policy").to_owned();

        // Sub-budget, reserved from the parent before the child exists.
        let budget = &envelope["sub_budget"];
        let limits = BudgetLimits {
            tokens: budget["total_tokens"].as_u64().unwrap_or(0),
            tool_calls: budget["max_tool_calls"].as_u64().unwrap_or(0),
            replans: budget["max_replan_attempts"].as_u64().unwrap_or(0),
            cost_cents: budget["max_cost_cents"].as_f64().unwrap_or(0.0),
        };
        let unit = json!({"currency": "USD", "units_per_cent": 100});
        let cost_units = match convert_legacy_cost_to_units(&json!(limits.cost_cents), &unit) {
            CostUnitConversion::Converted { units } => units,
            CostUnitConversion::Rejected { reason_code } => return Err(AdmissionError::Budget(reason_code)),
        };
        let parent_budget = DocKey::new(&parent.tenant_id, DocKind::BudgetLedger, &parent.budget_ledger_id);
        let reservation = json!({
            "ledger_id": parent.budget_ledger_id, "contract_id": parent.contract_id,
            "parent_run_id": parent.run_id, "tenant_id": parent.tenant_id,
            "mutation_id": format!("delegate:{child_run_id}"), "reservation_id": delegation_reservation_id(&child_run_id),
            "scope": "child", "run_id": child_run_id, "cost_unit": unit,
            "allocation": {"tokens": limits.tokens, "tool_calls": limits.tool_calls, "replans": limits.replans, "cost_units": cost_units},
            "deadline": expires_at, "expected_revision": 0, "executor_generation": parent.executor_generation,
            "evaluation_time": now,
        });
        let commit = transact(self.store.as_ref(), &parent_budget, |ledger| {
            let mut r = reservation.clone();
            r["expected_revision"] = ledger["revision"].clone();
            reserve_child_budget(ledger, &r)
        })
        .await?;
        match commit {
            Commit::Rejected { reason_codes } => return Err(AdmissionError::Delegation(reason_codes)),
            // The reservation already existed (a replayed or concurrent delegation of
            // this child). Never compensate a reservation this request did not create:
            // that would hand a live child's allocation back to the parent.
            Commit::Unchanged { .. } => return Err(reject("delegation_exists")),
            Commit::Written { .. } => {}
        }

        request.limits = limits;
        expires_at.clone_into(&mut request.deadline);
        let mut child = match admit_run(self.store.as_ref(), request).await {
            Ok(child) => child,
            Err(error) => {
                // Return the parent's capacity: this request created the reservation and the
                // child never ran.
                let zero = json!({"tokens": 0, "tool_calls": 0, "replans": 0, "cost_units": 0});
                let _ = self.settle_child(parent, &child_run_id, &zero, &now).await;
                return Err(error);
            }
        };
        child.surfaced_capabilities.retain(|capability| {
            allowed.contains(&capability.as_str())
                && self.manifest(capability).is_some_and(|m| {
                    m.action_risk.data_scope <= ceiling
                        && (effect_policy != "read_only"
                            || m.action_risk.effect == contextos_contract::types::ActionEffect::None)
                })
        });
        let mut links = vec![RunLink {
            child_run_id: child_run_id.clone(),
            parent_run_id: parent.run_id.clone(),
            subject: child.actor.clone(),
        }];
        if let Some(ancestry) = &parent.lineage {
            links.extend(ancestry.links.iter().cloned());
        }
        child.lineage = Some(Lineage {
            delegation_id: text("delegation_id").to_owned(),
            root_run_id: parent
                .lineage
                .as_ref()
                .map_or_else(|| parent.run_id.clone(), |l| l.root_run_id.clone()),
            parent_run_id: parent.run_id.clone(),
            effect_policy,
            links,
            output_schema_ref: envelope["scope"]["output_schema_ref"].as_str().map(str::to_owned),
        });
        let mut surfaced: Vec<&String> = child.surfaced_capabilities.iter().collect();
        surfaced.sort();
        self.audit
            .append(
                &parent.tenant_id,
                "delegation_admitted",
                json!({"delegation_id": text("delegation_id"), "parent_run_id": parent.run_id, "child_run_id": child_run_id,
                    "effect_policy": text("effect_policy"), "surfaced_capabilities": surfaced}),
                &now,
            )
            .await
            .map_err(|e| AdmissionError::Unavailable(e.to_string()))?;
        let child_run_id = child.run_id.clone();
        self.edit_run_state(parent, move |state| {
            if let Some(children) = state["child_run_ids"].as_array_mut()
                && !children.iter().any(|c| c == child_run_id.as_str())
            {
                children.push(json!(child_run_id));
            }
        })
        .await
        .map_err(|e| AdmissionError::Unavailable(e.to_string()))?;
        Ok(child)
    }

    /// Closes a child run and settles its usage into the parent. Idempotent.
    /// True unless the delegation names a registered result schema that the child's
    /// recorded decisions do not meet. A child with no recorded decision has no result
    /// to accept.
    async fn child_results_conform(&self, child: &RunAdmission) -> Result<bool, GatewayError> {
        let Some(schema) = child
            .lineage
            .as_ref()
            .and_then(|l| l.output_schema_ref.as_ref())
            .and_then(|r| self.result_schemas.get(r))
        else {
            return Ok(true);
        };
        let entries = self.recorded_decisions(child).await?;
        Ok(!entries.is_empty() && entries.iter().all(|e| schema.check(&e["record"]["outputs"]).is_ok()))
    }

    pub async fn close_delegation(
        &self,
        parent: &RunAdmission,
        child: &RunAdmission,
        decision: CloseDecision,
        closed_by: &str,
    ) -> Result<CloseOutcome, GatewayError> {
        let mut out = CloseOutcome {
            status: "rejected".into(),
            reason_codes: vec![],
            usage: None,
            audit_sequences: vec![],
        };
        if child.lineage.as_ref().map(|l| l.parent_run_id.as_str()) != Some(parent.run_id.as_str())
            || child.tenant_id != parent.tenant_id
        {
            out.reason_codes.push("delegation_unbound".into());
            return Ok(out);
        }
        // An accepted child's results must meet the delegation's output schema, when
        // this deployment has registered it; checked before anything settles, and again
        // once the child's capacity is locked, so a decision recorded in between counts.
        if decision == CloseDecision::Accept && !self.child_results_conform(child).await? {
            out.reason_codes.push("child_output_invalid".into());
            return Ok(out);
        }
        let now = self.now();
        // Lock the child's remaining capacity inside its own ledger, atomically.
        let child_budget = DocKey::new(&child.tenant_id, DocKind::BudgetLedger, &child.budget_ledger_id);
        let commit = transact(self.store.as_ref(), &child_budget, |ledger| {
            let closure_id = format!("closure:{}", child.run_id);
            let already = ledger["reservations"]
                .as_array()
                .into_iter()
                .flatten()
                .any(|r| r["reservation_id"] == closure_id.as_str());
            if already {
                // Closed before: the capacity is already locked.
                return TransitionResult::accepted(ledger.clone(), vec![]);
            }
            let open = ["tokens", "tool_calls", "replans", "cost_units"]
                .iter()
                .any(|k| ledger["reserved"][*k].as_i64() != Some(0));
            if open {
                return TransitionResult::rejected(ledger.clone(), "delegation_effects_unresolved");
            }
            let mut allocation = json!({});
            for k in ["tokens", "tool_calls", "replans", "cost_units"] {
                let remaining = ledger["ceiling"][k].as_i64().unwrap_or(0)
                    - ledger["used"][k].as_i64().unwrap_or(0)
                    - ledger["reserved"][k].as_i64().unwrap_or(0);
                allocation[k] = json!(remaining.max(0));
            }
            let request = json!({
                "ledger_id": child.budget_ledger_id, "contract_id": child.contract_id,
                "parent_run_id": child.run_id, "tenant_id": child.tenant_id,
                "mutation_id": closure_id, "reservation_id": closure_id, "scope": "run", "run_id": child.run_id,
                "cost_unit": {"currency": "USD", "units_per_cent": 100}, "allocation": allocation,
                "deadline": child.deadline, "expected_revision": ledger["revision"],
                "executor_generation": child.executor_generation, "evaluation_time": now,
            });
            reserve_budget(ledger, &request)
        })
        .await?;
        if let Commit::Rejected { reason_codes } = commit {
            out.reason_codes = reason_codes;
            return Ok(out);
        }
        if decision == CloseDecision::Accept && !self.child_results_conform(child).await? {
            // The capacity stays locked: the parent can still reject the child.
            out.reason_codes.push("child_output_invalid".into());
            return Ok(out);
        }
        let Some(final_ledger) = self.store.get(&child_budget).await? else {
            out.reason_codes.push("delegation_unbound".into());
            return Ok(out);
        };
        let usage = final_ledger.body["used"].clone();
        let parent_budget = DocKey::new(&parent.tenant_id, DocKind::BudgetLedger, &parent.budget_ledger_id);
        let reservation = delegation_reservation_id(&child.run_id);
        // Settled already: settled in the live ledger, or archived by compaction, which
        // only ever archives settled reservations.
        let settled = self.store.get(&parent_budget).await?.is_some_and(|l| {
            !l.body["reservations"]
                .as_array()
                .into_iter()
                .flatten()
                .any(|r| r["reservation_id"] == reservation.as_str() && r["status"] != "settled")
        });
        if settled {
            self.forget_child(parent, &child.run_id).await?;
            self.end_child(child, decision, closed_by).await?;
            "closed".clone_into(&mut out.status);
            out.usage = Some(usage);
            return Ok(out);
        }
        if let Commit::Rejected { reason_codes } = self.settle_child(parent, &child.run_id, &usage, &now).await? {
            out.reason_codes = reason_codes;
            return Ok(out);
        }
        let entry = self
            .audit
            .append(
                &parent.tenant_id,
                "delegation_closed",
                json!({"delegation_id": child.lineage.as_ref().map(|l| l.delegation_id.clone()),
                    "parent_run_id": parent.run_id, "child_run_id": child.run_id, "decision": decision,
                    "usage": usage, "child_ledger_digest": final_ledger.digest, "closed_by": closed_by}),
                &now,
            )
            .await?;
        out.audit_sequences.push(entry.sequence);
        self.forget_child(parent, &child.run_id).await?;
        self.end_child(child, decision, closed_by).await?;
        "closed".clone_into(&mut out.status);
        out.usage = Some(usage);
        Ok(out)
    }

    /// A closed child stops running: completed when its output is accepted, otherwise
    /// (or if completion is refused) cancelled. Its executor is fenced either way.
    async fn end_child(
        &self,
        child: &RunAdmission,
        decision: CloseDecision,
        closed_by: &str,
    ) -> Result<(), GatewayError> {
        let Some(state) = self.run_state(child).await? else {
            return Ok(());
        };
        if ["completed", "failed", "cancelled", "expired"].contains(&state["status"].as_str().unwrap_or_default()) {
            return Ok(());
        }
        if decision == CloseDecision::Accept
            && self
                .apply_event(child, "complete", None, None)
                .await?
                .reason_codes
                .is_empty()
        {
            return Ok(());
        }
        self.cancel_run(child, closed_by).await?;
        Ok(())
    }

    async fn forget_child(&self, parent: &RunAdmission, child_run_id: &str) -> Result<(), GatewayError> {
        self.edit_run_state(parent, |state| {
            if let Some(children) = state["child_run_ids"].as_array_mut() {
                children.retain(|c| c != child_run_id);
            }
        })
        .await
    }

    /// Settles the child reservation in the parent's ledger at `usage` (terminal).
    async fn settle_child(
        &self,
        parent: &RunAdmission,
        child_run_id: &str,
        usage: &Value,
        now: &str,
    ) -> Result<Commit, GatewayError> {
        let budget_key = DocKey::new(&parent.tenant_id, DocKind::BudgetLedger, &parent.budget_ledger_id);
        let valid_until = add_contract_seconds(now, OBSERVATION_VALIDITY_SECONDS).unwrap_or_else(|| now.to_owned());
        let evidence_ref = json!({"artifact_type": "child_usage", "artifact_id": child_run_id, "version": "1",
            "sha256": contextos_contract::canonical::sha256_canonical(usage).unwrap_or_default()});
        self.settle_scoped(
            parent,
            &budget_key,
            &delegation_reservation_id(child_run_id),
            &format!("close:{child_run_id}"),
            ("child", child_run_id),
            now,
            &valid_until,
            &evidence_ref,
            usage,
            true,
            None,
        )
        .await
    }
}

fn text_in<'a>(value: &'a Value, key: &str) -> &'a str {
    value[key].as_str().unwrap_or_default()
}

/// Run-link observations the gateway attests for a delegated run, from the run up
/// to the root's direct child.
pub(crate) fn attested_links(admission: &RunAdmission, now: &str, existing: &[Value]) -> Vec<Value> {
    let Some(lineage) = &admission.lineage else {
        return Vec::new();
    };
    let valid_until = add_contract_seconds(now, OBSERVATION_VALIDITY_SECONDS).unwrap_or_else(|| now.to_owned());
    lineage
        .links
        .iter()
        .filter(|link| !existing.iter().any(|e| e["child_run_id"] == link.child_run_id.as_str()))
        .map(|link| {
            json!({
                "parent_run_id": link.parent_run_id, "child_run_id": link.child_run_id,
                "root_run_id": lineage.root_run_id, "tenant_id": admission.tenant_id, "subject": link.subject,
                "observer": admission.gateway_observer, "verification_status": "verified",
                "verification_ref": {"artifact_type": "run_link", "artifact_id": link.child_run_id, "version": "1",
                    "sha256": contextos_contract::canonical::sha256_canonical(&json!([link.parent_run_id, link.child_run_id, link.subject])).unwrap_or_default()},
                "observed_at": now, "valid_until": valid_until,
            })
        })
        .collect()
}
