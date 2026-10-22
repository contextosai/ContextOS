//! The fleet model: every runtime tenant's verified audit entries folded into per-agent
//! activity, a bounded window of recent run summaries, and an organisation-wide feed of
//! governance changes. Pure: the collector feeds it entries in chain order.
//!
//! Memory is bounded by design. Agents keep counters and hourly buckets (bounded by
//! `hours`), runs are kept for the last `recent_runs` only, and raw evidence stays in
//! the runtime, reachable by run id. An effect whose run has left the window is counted
//! against its source as unattributed rather than guessed.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};

use contextos_audit::AuditEntry;
use serde::Serialize;
use serde_json::{Value, json};

pub type AgentKey = String;

/// Outcomes of an agent's governed effects for one capability.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct Counts {
    pub attempted: u64,
    pub applied: u64,
    pub not_applied: u64,
    pub unknown: u64,
    pub partial: u64,
    pub refused: u64,
    pub awaiting_approval: u64,
    pub escalated: u64,
}

/// One hour of one agent's activity.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct Hour {
    pub runs: u64,
    pub effects: u64,
    pub applied: u64,
    pub refused: u64,
    pub unknown: u64,
    pub approvals: u64,
    pub guard_hits: u64,
    pub failed_runs: u64,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct AgentActivity {
    pub key: AgentKey,
    pub agent_id: String,
    pub agent_urn: Option<String>,
    pub sources: BTreeSet<String>,
    pub tenants: BTreeSet<String>,
    pub packs: BTreeSet<String>,
    pub intents: BTreeSet<String>,
    /// `model_profile` release references, as `id@version`.
    pub models: BTreeSet<String>,
    /// `evaluator_suite` release references.
    pub evaluators: BTreeSet<String>,
    /// Control profiles runs were admitted under.
    pub admitted_profiles: BTreeSet<String>,
    pub admitted_controls: BTreeSet<String>,
    pub admitted_by: BTreeSet<String>,
    /// Capabilities surfaced to the agent's runs at admission.
    pub surfaced: BTreeSet<String>,
    pub first_seen: String,
    pub last_seen: String,
    pub runs: u64,
    pub runs_by_status: BTreeMap<String, u64>,
    pub child_runs: u64,
    pub delegates_to: BTreeSet<AgentKey>,
    pub capabilities: BTreeMap<String, Counts>,
    pub refusals: BTreeMap<String, u64>,
    pub approvals_required: u64,
    pub approvals_redeemed: u64,
    pub escalations: u64,
    pub decisions: u64,
    pub scores: u64,
    pub low_scores: u64,
    pub loops: u64,
    pub repeated_effects: u64,
    pub output_schema_violations: u64,
    pub memory_operations: u64,
    pub checkpoints: u64,
    /// Effects whose outcome is unknown or partial and not yet reconciled.
    pub unresolved: BTreeSet<String>,
    #[serde(skip)]
    pub hours: BTreeMap<i64, Hour>,
}

impl AgentActivity {
    fn hour(&mut self, at: &str) -> &mut Hour {
        self.hours.entry(hour_index(at)).or_default()
    }

    /// Hourly buckets from `from` (inclusive) to `to` (exclusive), zeros filled in.
    pub fn series(&self, from: i64, to: i64) -> Vec<(i64, Hour)> {
        (from..to)
            .map(|h| (h, self.hours.get(&h).cloned().unwrap_or_default()))
            .collect()
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct RunSummary {
    pub source: String,
    pub run_id: String,
    pub agent: AgentKey,
    pub trace_id: String,
    pub pack_ref: String,
    pub intent: Option<String>,
    pub parent_run_id: Option<String>,
    pub status: String,
    pub admitted_at: String,
    pub last_at: String,
    pub effects: u32,
    pub refused: u32,
    pub unknown: u32,
    pub decisions: u32,
    pub capabilities: BTreeSet<String>,
    pub refusal_reasons: BTreeSet<String>,
    /// First sequence of the run in its source chain.
    pub first_sequence: u64,
}

/// A change to how the fleet is governed, from any runtime's chain.
#[derive(Debug, Clone, Serialize)]
pub struct Change {
    pub source: String,
    pub sequence: u64,
    pub at: String,
    pub kind: String,
    pub summary: String,
    pub by: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct SourceState {
    pub id: String,
    pub tenant_id: Option<String>,
    pub verified_to: u64,
    pub head: u64,
    pub broken: Option<Value>,
    pub last_error: Option<String>,
    pub last_sync: Option<String>,
    /// Entries whose run left the recent window before they arrived.
    pub unattributed: u64,
    /// Kill-switch state from the chain: `kind:target` → reason.
    pub revoked: BTreeMap<String, String>,
    pub conformance: Vec<Value>,
    #[serde(skip)]
    pub deployment: Value,
    #[serde(skip)]
    pub packs: Value,
}

#[derive(Debug)]
struct Open {
    run: String,
    operation: String,
    capability: String,
}

#[derive(Debug)]
pub struct Fleet {
    pub sources: BTreeMap<String, SourceState>,
    pub agents: BTreeMap<AgentKey, AgentActivity>,
    runs: HashMap<(String, String), RunSummary>,
    order: VecDeque<(String, String)>,
    traces: HashMap<(String, String), String>,
    attempts: HashMap<(String, String), Open>,
    pub changes: VecDeque<Change>,
    recent_runs: usize,
    hours: usize,
    /// Bumped on every change, so readers can cache derived views.
    pub revision: u64,
}

const MAX_CHANGES: usize = 2_000;
const MAX_ATTEMPTS: usize = 200_000;

fn s(v: &Value) -> Option<&str> {
    v.as_str()
}

fn strs(v: &Value) -> Vec<String> {
    v.as_array()
        .map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_owned)).collect())
        .unwrap_or_default()
}

/// Days since 1970-01-01 of a civil date (proleptic Gregorian).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Hours since the epoch of a contract timestamp (`YYYY-MM-DDTHH:MM:SS…Z`); 0 if malformed.
pub fn hour_index(at: &str) -> i64 {
    let n = |r: std::ops::Range<usize>| at.get(r).and_then(|v| v.parse::<i64>().ok());
    match (n(0..4), n(5..7), n(8..10), n(11..13)) {
        (Some(y), Some(m), Some(d), Some(h)) => days_from_civil(y, m, d) * 24 + h,
        _ => 0,
    }
}

/// An agent's identity across the fleet: its URN when the run names one, else the
/// agent id within its tenant.
pub fn agent_key(tenant: &str, agent_id: &str, urn: Option<&str>) -> AgentKey {
    match urn {
        Some(urn) if !urn.is_empty() => urn.to_owned(),
        _ => format!("{tenant}/{agent_id}"),
    }
}

impl Fleet {
    pub fn new(recent_runs: usize, hours: usize) -> Self {
        Self {
            sources: BTreeMap::new(),
            agents: BTreeMap::new(),
            runs: HashMap::new(),
            order: VecDeque::new(),
            traces: HashMap::new(),
            attempts: HashMap::new(),
            changes: VecDeque::new(),
            recent_runs: recent_runs.max(1),
            hours: hours.max(24),
            revision: 0,
        }
    }

    pub fn source(&mut self, id: &str) -> &mut SourceState {
        self.sources.entry(id.to_owned()).or_insert_with(|| SourceState {
            id: id.to_owned(),
            ..SourceState::default()
        })
    }

    pub fn run(&self, source: &str, run_id: &str) -> Option<&RunSummary> {
        self.runs.get(&(source.to_owned(), run_id.to_owned()))
    }

    /// Recent runs, newest first, filtered.
    pub fn recent_runs<'a>(
        &'a self,
        filter: impl Fn(&RunSummary) -> bool + 'a,
    ) -> impl Iterator<Item = &'a RunSummary> + 'a {
        self.order
            .iter()
            .rev()
            .filter_map(|k| self.runs.get(k))
            .filter(move |r| filter(r))
    }

    fn agent_of(&self, source: &str, run_id: &str) -> Option<AgentKey> {
        self.runs
            .get(&(source.to_owned(), run_id.to_owned()))
            .map(|r| r.agent.clone())
    }

    fn agent(&mut self, key: &str) -> Option<&mut AgentActivity> {
        self.agents.get_mut(key)
    }

    fn change(&mut self, source: &str, entry: &AuditEntry, summary: String, by: Option<&str>) {
        self.changes.push_back(Change {
            source: source.to_owned(),
            sequence: entry.sequence,
            at: entry.emitted_at.clone(),
            kind: entry.kind.clone(),
            summary,
            by: by.map(str::to_owned),
        });
        while self.changes.len() > MAX_CHANGES {
            self.changes.pop_front();
        }
    }

    fn evict(&mut self) {
        while self.order.len() > self.recent_runs {
            if let Some(key) = self.order.pop_front()
                && let Some(run) = self.runs.remove(&key)
            {
                self.traces.remove(&(run.source, run.trace_id));
            }
        }
    }

    fn prune_hours(&mut self, now_hour: i64) {
        let oldest = now_hour - i64::try_from(self.hours).unwrap_or(i64::MAX);
        for agent in self.agents.values_mut() {
            while agent.hours.first_key_value().is_some_and(|(h, _)| *h < oldest) {
                agent.hours.pop_first();
            }
        }
    }

    /// Folds one verified entry from `source` into the model.
    pub fn apply(&mut self, source: &str, entry: &AuditEntry) {
        self.revision += 1;
        let p = &entry.payload;
        let at = entry.emitted_at.as_str();
        {
            let state = self.source(source);
            state.tenant_id.get_or_insert_with(|| entry.tenant_id.clone());
            state.verified_to = entry.sequence;
            state.head = state.head.max(entry.sequence);
        }
        let run_id = s(&p["run_id"]).map(str::to_owned);
        let agent = run_id.as_deref().and_then(|r| self.agent_of(source, r));
        if run_id.is_some() && agent.is_none() && entry.kind != "run_admitted" {
            self.source(source).unattributed += 1;
        }
        if let (Some(r), Some(_)) = (&run_id, &agent)
            && let Some(run) = self.runs.get_mut(&(source.to_owned(), r.clone()))
        {
            at.clone_into(&mut run.last_at);
        }
        if let Some(a) = agent.as_deref().and_then(|k| self.agents.get_mut(k)) {
            at.clone_into(&mut a.last_seen);
        }

        match entry.kind.as_str() {
            "run_admitted" => self.admitted(source, entry),
            "run_lifecycle" => {
                let status = s(&p["status"]).unwrap_or("unknown").to_owned();
                if let (Some(r), Some(k)) = (&run_id, &agent) {
                    if let Some(run) = self.runs.get_mut(&(source.to_owned(), r.clone())) {
                        run.status.clone_from(&status);
                    }
                    if let Some(a) = self.agent(k) {
                        if matches!(status.as_str(), "completed" | "failed" | "cancelled" | "expired") {
                            *a.runs_by_status.entry(status.clone()).or_default() += 1;
                        }
                        if status == "failed" || status == "expired" {
                            a.hour(at).failed_runs += 1;
                        }
                    }
                }
            }
            "delegation_admitted" => {
                let parent = s(&p["parent_run_id"]).and_then(|r| self.agent_of(source, r));
                let child = s(&p["child_run_id"]).and_then(|r| self.agent_of(source, r));
                if let Some(parent) = parent
                    && let Some(a) = self.agent(&parent)
                {
                    a.child_runs += 1;
                    if let Some(child) = child {
                        a.delegates_to.insert(child);
                    }
                }
            }
            "checkpoint_saved" => {
                if let Some(a) = agent.as_deref().and_then(|k| self.agents.get_mut(k)) {
                    a.checkpoints += 1;
                }
            }
            "authorization_decision" => {
                let verdict = s(&p["verdict"]).unwrap_or("error");
                let approved = verdict == "allow" && p["approval_refs"].as_array().is_some_and(|a| !a.is_empty());
                let reasons = strs(&p["reason_codes"]);
                if let Some(k) = &agent
                    && let Some(a) = self.agents.get_mut(k)
                {
                    match verdict {
                        "allow" if approved => {
                            a.approvals_redeemed += 1;
                            a.hour(at).approvals += 1;
                        }
                        "allow" => {}
                        "require_approval" => a.approvals_required += 1,
                        "escalate" => a.escalations += 1,
                        _ => {
                            for r in if reasons.is_empty() {
                                vec![format!("policy_{verdict}")]
                            } else {
                                reasons.clone()
                            } {
                                *a.refusals.entry(r).or_default() += 1;
                            }
                            a.hour(at).refused += 1;
                        }
                    }
                }
                if !matches!(verdict, "allow" | "require_approval" | "escalate")
                    && let Some(r) = &run_id
                    && let Some(run) = self.runs.get_mut(&(source.to_owned(), r.clone()))
                {
                    run.refused += 1;
                    run.refusal_reasons.extend(reasons);
                }
            }
            "operation_claim" => {
                let capability = s(&p["capability_id"]).unwrap_or("?").to_owned();
                if let (Some(r), Some(k)) = (&run_id, &agent) {
                    if let Some(a) = self.agents.get_mut(k) {
                        a.capabilities.entry(capability.clone()).or_default().attempted += 1;
                        a.hour(at).effects += 1;
                    }
                    if let Some(run) = self.runs.get_mut(&(source.to_owned(), r.clone())) {
                        run.effects += 1;
                        run.capabilities.insert(capability.clone());
                    }
                    if let Some(attempt) = s(&p["attempt_id"]) {
                        if self.attempts.len() >= MAX_ATTEMPTS {
                            self.attempts.clear();
                        }
                        self.attempts.insert(
                            (source.to_owned(), attempt.to_owned()),
                            Open {
                                run: r.clone(),
                                operation: s(&p["operation_id"]).unwrap_or_default().to_owned(),
                                capability,
                            },
                        );
                    }
                }
            }
            "effect_observation" => self.observed(source, entry),
            "effect_reconciliation" => {
                let Some(open) =
                    s(&p["attempt_id"]).and_then(|a| self.attempts.get(&(source.to_owned(), a.to_owned())))
                else {
                    return;
                };
                let key = format!("{source}|{}|{}", open.run, open.operation);
                if let Some(k) = self.agent_of(source, &open.run.clone())
                    && let Some(a) = self.agents.get_mut(&k)
                {
                    a.unresolved.remove(&key);
                }
            }
            "revocation_refusal"
            | "boundary_refusal"
            | "repeated_effect_refusal"
            | "loop_detected"
            | "loop_guard_saturated" => {
                let reasons = if entry.kind.starts_with("loop") {
                    vec![entry.kind.clone()]
                } else {
                    strs(&p["reason_codes"])
                };
                let capability = s(&p["capability_id"]).map(str::to_owned);
                if let Some(k) = &agent
                    && let Some(a) = self.agents.get_mut(k)
                {
                    for r in &reasons {
                        *a.refusals.entry(r.clone()).or_default() += 1;
                    }
                    if entry.kind.starts_with("loop") {
                        a.loops += 1;
                    }
                    if entry.kind == "repeated_effect_refusal" {
                        a.repeated_effects += 1;
                    }
                    if let Some(c) = &capability {
                        a.capabilities.entry(c.clone()).or_default().refused += 1;
                    }
                    let h = a.hour(at);
                    h.refused += 1;
                    h.guard_hits += 1;
                }
                if let Some(r) = &run_id
                    && let Some(run) = self.runs.get_mut(&(source.to_owned(), r.clone()))
                {
                    run.refused += 1;
                    run.refusal_reasons.extend(reasons);
                }
            }
            "data_flow_decision" if p["allowed"] == false => {
                if let Some(k) = &agent
                    && let Some(a) = self.agents.get_mut(k)
                {
                    for r in strs(&p["reason_codes"]) {
                        *a.refusals.entry(r).or_default() += 1;
                    }
                    a.hour(at).refused += 1;
                }
            }
            "output_schema_violation" => {
                if let Some(a) = agent.as_deref().and_then(|k| self.agents.get_mut(k)) {
                    a.output_schema_violations += 1;
                }
            }
            "memory_lifecycle" => {
                if let Some(a) = agent.as_deref().and_then(|k| self.agents.get_mut(k)) {
                    a.memory_operations += 1;
                }
            }
            "escalation_opened" => {
                if let Some(a) = agent.as_deref().and_then(|k| self.agents.get_mut(k)) {
                    a.escalations += 1;
                    if let Some(c) = s(&p["capability_id"]) {
                        a.capabilities.entry(c.to_owned()).or_default().escalated += 1;
                    }
                }
            }
            "decision_record" => {
                let run = s(&p["trace_id"]).and_then(|t| self.traces.get(&(source.to_owned(), t.to_owned())).cloned());
                if let Some(r) = run {
                    if let Some(k) = self.agent_of(source, &r)
                        && let Some(a) = self.agents.get_mut(&k)
                    {
                        a.decisions += 1;
                    }
                    if let Some(summary) = self.runs.get_mut(&(source.to_owned(), r)) {
                        summary.decisions += 1;
                    }
                }
            }
            "run_score" => {
                if let Some(a) = agent.as_deref().and_then(|k| self.agents.get_mut(k)) {
                    a.scores += 1;
                    let card = &p["scorecard"];
                    if card["policy"].as_f64().is_some_and(|v| v < 1.0)
                        || card["safety"].as_f64().is_some_and(|v| v < 0.9)
                    {
                        a.low_scores += 1;
                    }
                }
            }
            "revocation" | "revocation_restored" => {
                let target = format!("{}:{}", s(&p["kind"]).unwrap_or("?"), s(&p["target"]).unwrap_or("?"));
                let reason = s(&p["reason"]).unwrap_or_default().to_owned();
                let restored = entry.kind == "revocation_restored";
                {
                    let state = self.source(source);
                    if restored {
                        state.revoked.remove(&target);
                    } else {
                        state.revoked.insert(target.clone(), reason.clone());
                    }
                }
                let verb = if restored { "Restored" } else { "Revoked" };
                self.change(source, entry, format!("{verb} {target}: {reason}"), s(&p["operator"]));
            }
            "conformance_assessed" => {
                self.source(source)
                    .conformance
                    .push(json!({"workflow_id": p["workflow_id"], "outcome": p["outcome"],
                    "at": at, "sequence": entry.sequence}));
                self.change(
                    source,
                    entry,
                    format!(
                        "Conformance {} for {}",
                        s(&p["outcome"]).unwrap_or("?"),
                        s(&p["workflow_id"]).unwrap_or("?")
                    ),
                    None,
                );
            }
            "rollout_set" => self.change(
                source,
                entry,
                format!(
                    "Rollout {} → {} at {}%",
                    s(&p["baseline"]).unwrap_or("?"),
                    s(&p["candidate"]).unwrap_or("?"),
                    p["percent"]
                ),
                s(&p["by"]),
            ),
            "rollout_cleared" => self.change(
                source,
                entry,
                format!("Rollout of {} cleared", s(&p["baseline"]).unwrap_or("?")),
                s(&p["by"]),
            ),
            "config_proposed" => self.change(
                source,
                entry,
                format!("Configuration change proposed: {}", s(&p["summary"]).unwrap_or("")),
                s(&p["by"]),
            ),
            "config_reviewed" => self.change(
                source,
                entry,
                format!("Configuration change {}", s(&p["decision"]).unwrap_or("?")),
                s(&p["by"]),
            ),
            "signing_key_rotated" => self.change(
                source,
                entry,
                format!(
                    "Audit signing key rotated {} → {}",
                    s(&p["from_kid"]).unwrap_or("?"),
                    s(&p["to_kid"]).unwrap_or("?")
                ),
                None,
            ),
            "feedback_filed" => self.change(
                source,
                entry,
                format!(
                    "Feedback ({}) on {}",
                    s(&p["kind"]).unwrap_or("?"),
                    s(&p["target_surface"]).unwrap_or("?")
                ),
                s(&p["reporter"]),
            ),
            _ => {}
        }
        let now = hour_index(at);
        if self.revision.is_multiple_of(4096) {
            self.prune_hours(now);
        }
    }

    fn admitted(&mut self, source: &str, entry: &AuditEntry) {
        let p = &entry.payload;
        let Some(run_id) = s(&p["run_id"]) else { return };
        let agent_id = s(&p["agent_id"]).unwrap_or("unknown");
        let key = agent_key(&entry.tenant_id, agent_id, s(&p["agent_urn"]));
        let at = entry.emitted_at.clone();
        let a = self.agents.entry(key.clone()).or_insert_with(|| AgentActivity {
            key: key.clone(),
            agent_id: agent_id.to_owned(),
            first_seen: at.clone(),
            ..AgentActivity::default()
        });
        a.agent_urn = s(&p["agent_urn"]).map(str::to_owned).or(a.agent_urn.take());
        a.last_seen.clone_from(&at);
        a.runs += 1;
        a.sources.insert(source.to_owned());
        a.tenants.insert(entry.tenant_id.clone());
        if let Some(pack) = s(&p["pack_ref"]) {
            a.packs.insert(pack.to_owned());
        }
        if let Some(intent) = s(&p["intent"]) {
            a.intents.insert(intent.to_owned());
        }
        if let Some(by) = s(&p["admitted_by"]) {
            a.admitted_by.insert(by.to_owned());
        }
        a.admitted_profiles.extend(strs(&p["profiles"]));
        for control in p["required_controls"].as_array().into_iter().flatten() {
            if let Some(id) = control["control_id"].as_str() {
                a.admitted_controls.insert(id.to_owned());
            }
        }
        a.surfaced.extend(strs(&p["surfaced_capabilities"]));
        for r in p["release_refs"].as_array().into_iter().flatten() {
            let id = format!(
                "{}@{}",
                r["artifact_id"].as_str().unwrap_or("?"),
                r["version"].as_str().unwrap_or("?")
            );
            match r["artifact_type"].as_str() {
                Some("model_profile") => {
                    a.models.insert(id);
                }
                Some("evaluator_suite") => {
                    a.evaluators.insert(id);
                }
                _ => {}
            }
        }
        a.hour(&at).runs += 1;
        let trace = s(&p["trace_id"]).unwrap_or_default().to_owned();
        let summary = RunSummary {
            source: source.to_owned(),
            run_id: run_id.to_owned(),
            agent: key,
            trace_id: trace.clone(),
            pack_ref: s(&p["pack_ref"]).unwrap_or_default().to_owned(),
            intent: s(&p["intent"]).map(str::to_owned),
            parent_run_id: s(&p["parent_run_id"]).map(str::to_owned),
            status: "admitted".into(),
            admitted_at: at.clone(),
            last_at: at,
            effects: 0,
            refused: 0,
            unknown: 0,
            decisions: 0,
            capabilities: BTreeSet::new(),
            refusal_reasons: BTreeSet::new(),
            first_sequence: entry.sequence,
        };
        let key = (source.to_owned(), run_id.to_owned());
        if self.runs.insert(key.clone(), summary).is_none() {
            self.order.push_back(key);
        }
        // Delegated children share their parent's trace; decisions belong to the run
        // that first claimed it (the parent, admitted before its children).
        if !trace.is_empty() {
            self.traces
                .entry((source.to_owned(), trace))
                .or_insert_with(|| run_id.to_owned());
        }
        self.evict();
    }

    fn observed(&mut self, source: &str, entry: &AuditEntry) {
        let p = &entry.payload;
        let Some(open) = s(&p["attempt_id"]).and_then(|a| self.attempts.get(&(source.to_owned(), a.to_owned()))) else {
            return;
        };
        let (run, operation, capability) = (open.run.clone(), open.operation.clone(), open.capability.clone());
        let outcome = s(&p["outcome"]).unwrap_or("unknown");
        let definitive = p["finality"] == "definitive";
        let status = match outcome {
            "confirmed" if definitive => "applied",
            "not_applied" | "not_dispatched" if definitive => "not_applied",
            "partial" => "partial",
            _ => "unknown",
        };
        let key = format!("{source}|{run}|{operation}");
        if let Some(k) = self.agent_of(source, &run)
            && let Some(a) = self.agents.get_mut(&k)
        {
            let counts = a.capabilities.entry(capability).or_default();
            match status {
                "applied" => counts.applied += 1,
                "not_applied" => counts.not_applied += 1,
                "partial" => counts.partial += 1,
                _ => counts.unknown += 1,
            }
            let at = entry.emitted_at.clone();
            match status {
                "applied" => a.hour(&at).applied += 1,
                "unknown" | "partial" => {
                    a.hour(&at).unknown += 1;
                    a.unresolved.insert(key.clone());
                }
                _ => {}
            }
            if status == "applied" || status == "not_applied" {
                a.unresolved.remove(&key);
            }
        }
        if (status == "unknown" || status == "partial")
            && let Some(summary) = self.runs.get_mut(&(source.to_owned(), run))
        {
            summary.unknown += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn entry(sequence: u64, kind: &str, payload: Value) -> AuditEntry {
        AuditEntry {
            entry_version: "contextos.audit_entry.v1".into(),
            tenant_id: "acme".into(),
            sequence,
            prev_hash: None,
            kind: kind.into(),
            emitted_at: format!("2026-10-21T10:{:02}:00Z", sequence % 60),
            payload_digest: String::new(),
            payload,
            record_hash: String::new(),
            signature: contextos_audit::chain::EntrySignature {
                alg: "ed25519".into(),
                kid: "k".into(),
                sig: String::new(),
            },
        }
    }

    #[test]
    fn hours_count_from_the_epoch() {
        assert_eq!(hour_index("1970-01-01T00:00:00Z"), 0);
        assert_eq!(hour_index("1970-01-02T03:00:00.123Z"), 27);
        assert_eq!(hour_index("2026-10-21T10:00:00Z") % 24, 10);
        assert_eq!(hour_index("garbage"), 0);
    }

    #[test]
    fn runs_are_attributed_to_agents_and_effects_to_capabilities() {
        let mut fleet = Fleet::new(10, 48);
        fleet.apply(
            "eu",
            &entry(
                1,
                "run_admitted",
                json!({"run_id": "r1", "agent_id": "agt_support", "trace_id": "t1",
            "pack_ref": "ctxpack.support@5.2.0", "intent": "support.refund", "profiles": ["contextos.core"],
            "release_refs": [{"artifact_type": "model_profile", "artifact_id": "claude-opus-5-5", "version": "1"}],
            "surfaced_capabilities": ["adp_payments.issue_refund"], "admitted_by": "svc"}),
            ),
        );
        fleet.apply("eu", &entry(2, "authorization_decision", json!({"run_id": "r1", "operation_id": "op", "verdict": "allow", "approval_refs": [{"artifact_id": "apr"}]})));
        fleet.apply("eu", &entry(3, "operation_claim", json!({"run_id": "r1", "operation_id": "op", "attempt_id": "a1", "capability_id": "adp_payments.issue_refund"})));
        fleet.apply(
            "eu",
            &entry(
                4,
                "effect_observation",
                json!({"run_id": "r1", "attempt_id": "a1", "outcome": "unknown", "finality": "provisional"}),
            ),
        );
        let agent = &fleet.agents["acme/agt_support"];
        assert_eq!(agent.runs, 1);
        assert_eq!(agent.approvals_redeemed, 1);
        assert_eq!(agent.models, BTreeSet::from(["claude-opus-5-5@1".to_owned()]));
        assert_eq!(agent.capabilities["adp_payments.issue_refund"].unknown, 1);
        assert_eq!(agent.unresolved.len(), 1);
        fleet.apply(
            "eu",
            &entry(
                5,
                "effect_reconciliation",
                json!({"attempt_id": "a1", "outcome": "not_applied"}),
            ),
        );
        assert!(fleet.agents["acme/agt_support"].unresolved.is_empty());
        assert_eq!(fleet.run("eu", "r1").unwrap().unknown, 1);
    }

    #[test]
    fn the_run_window_is_bounded_and_late_effects_are_unattributed() {
        let mut fleet = Fleet::new(2, 48);
        for (i, run) in ["r1", "r2", "r3"].iter().enumerate() {
            fleet.apply(
                "eu",
                &entry(
                    i as u64 + 1,
                    "run_admitted",
                    json!({"run_id": run, "agent_id": "a", "trace_id": run}),
                ),
            );
        }
        assert!(fleet.run("eu", "r1").is_none());
        assert_eq!(fleet.recent_runs(|_| true).count(), 2);
        fleet.apply(
            "eu",
            &entry(
                9,
                "operation_claim",
                json!({"run_id": "r1", "attempt_id": "x", "capability_id": "c"}),
            ),
        );
        assert_eq!(fleet.sources["eu"].unattributed, 1);
        assert_eq!(fleet.agents["acme/a"].runs, 3, "counters survive the window");
    }

    #[test]
    fn decisions_belong_to_the_parent_run_of_a_shared_trace() {
        let mut fleet = Fleet::new(10, 48);
        for (i, run) in ["parent", "child"].iter().enumerate() {
            fleet.apply(
                "eu",
                &entry(
                    i as u64 + 1,
                    "run_admitted",
                    json!({"run_id": run, "agent_id": "a", "trace_id": "t"}),
                ),
            );
        }
        fleet.apply(
            "eu",
            &entry(3, "decision_record", json!({"trace_id": "t", "record_id": "d1"})),
        );
        assert_eq!(fleet.run("eu", "parent").unwrap().decisions, 1);
        assert_eq!(fleet.run("eu", "child").unwrap().decisions, 0);
    }

    #[test]
    fn kill_switch_state_and_changes_come_from_the_chain() {
        let mut fleet = Fleet::new(10, 48);
        fleet.apply(
            "eu",
            &entry(
                1,
                "revocation",
                json!({"kind": "capability", "target": "pay.send", "reason": "INC-1", "operator": "oncall"}),
            ),
        );
        assert_eq!(fleet.sources["eu"].revoked["capability:pay.send"], "INC-1");
        fleet.apply(
            "eu",
            &entry(
                2,
                "revocation_restored",
                json!({"kind": "capability", "target": "pay.send", "reason": "fixed"}),
            ),
        );
        assert!(fleet.sources["eu"].revoked.is_empty());
        assert_eq!(fleet.changes.len(), 2);
        assert_eq!(fleet.changes[0].by.as_deref(), Some("oncall"));
    }
}
