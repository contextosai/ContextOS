//! Shared findings: what a team's peers have learned, with explicit provenance, and
//! priority notices when it changes.
//!
//! A `claim` is a peer's assertion. An `observed` finding is bound to a tool call the
//! gateway recorded: the gateway copies its action digest, outcome and observation
//! evidence from the operation ledger, so a peer cannot cite a tool result that did not
//! happen. The statement remains the peer's interpretation of that call.
//!
//! Findings are immutable once published. A finding is falsified by invalidation: its
//! author may withdraw it, and any other peer must cite an active `observed` finding
//! that refutes it. Invalidation marks every active finding that depends on it,
//! transitively, as `suspect` (flagged for re-checking, not invalidated) and appends a
//! notice. Urgent findings append a notice when published.
//!
//! Notices are peeked, never consumed by reading: they ride on each team member's tool
//! results until its orchestrator acknowledges them, because delivering a notice does
//! not prove an agent acted on it. Everything here is peer data, never instructions.
//!
//! One bounded document per root holds findings, retained notices and acknowledgement
//! cursors, so an invalidation, its cascade and its notice commit together.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::coordination::WorkError;

pub const MAX_FINDINGS: usize = 256;
pub const MAX_FINDINGS_BYTES: usize = 1024 * 1024;
/// The document size up to which findings may be published. The rest is headroom
/// that invalidations, notices and acknowledgements always fit in (each bounded), so a
/// full team can still falsify and acknowledge.
pub const PUBLISH_BUDGET_BYTES: usize = 448 * 1024;
pub const MAX_REASON_BYTES: usize = 256;
/// Suspect ids a notice lists, and causes a suspect finding records, at most; the
/// counts are kept in full.
const MAX_LISTED: usize = 8;
const MAX_CAUSES: usize = 4;
/// Notices retained per root; older ones are dropped and reported as `missed`.
pub const MAX_NOTICES: usize = 256;
/// Notices attached to one tool result at most.
pub const NOTICES_PER_RESULT: usize = 5;
pub const MAX_STATEMENT_BYTES: usize = 2048;
/// Bytes of a statement quoted in a notice.
const NOTICE_EXCERPT_BYTES: usize = 280;

pub(crate) fn refuse<T>(code: &'static str) -> Result<T, WorkError> {
    Err(WorkError::Refused(code))
}

fn identifier(s: &str) -> bool {
    (1..=64).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
}

fn text(s: &str, max: usize) -> bool {
    !s.trim().is_empty() && s.len() <= max
}

/// Free text: no control characters but newline and tab (which bound its encoded size
/// and keep it from forging lines elsewhere).
fn prose(s: &str, max: usize) -> bool {
    text(s, max) && !s.chars().any(|c| c.is_control() && c != '\n' && c != '\t')
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingKind {
    /// A peer's assertion, with no recorded basis.
    Claim,
    /// Bound to a tool call the gateway recorded for a run of the team.
    Observed,
}

/// The tool call an `observed` finding rests on: a run of the team (the publisher's own
/// when omitted) and one of its operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BasisInput {
    #[serde(default)]
    pub run_id: Option<String>,
    pub operation_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FindingInput {
    pub finding_id: String,
    pub kind: FindingKind,
    pub statement: String,
    #[serde(default)]
    pub depends_on: Vec<String>,
    #[serde(default)]
    pub basis: Option<BasisInput>,
    /// Notify the team when published.
    #[serde(default)]
    pub urgent: bool,
    /// For an `observed` finding: the finding it refutes. Only such a finding can
    /// invalidate a peer's finding.
    #[serde(default)]
    pub refutes: Option<String>,
}

impl FindingInput {
    pub(crate) fn validate(&self) -> Result<(), WorkError> {
        let distinct: BTreeSet<_> = self.depends_on.iter().collect();
        let basis_ok = match (&self.kind, &self.basis) {
            (FindingKind::Claim, None) => true,
            (FindingKind::Observed, Some(b)) => {
                identifier_or_operation(&b.operation_id) && b.run_id.as_deref().is_none_or(|r| !r.is_empty())
            }
            _ => false,
        };
        if !identifier(&self.finding_id)
            || !prose(&self.statement, MAX_STATEMENT_BYTES)
            || self
                .refutes
                .as_ref()
                .is_some_and(|r| self.kind != FindingKind::Observed || !identifier(r) || *r == self.finding_id)
            || self.depends_on.len() > 16
            || distinct.len() != self.depends_on.len()
            || self.depends_on.iter().any(|d| !identifier(d) || *d == self.finding_id)
            || !basis_ok
        {
            return refuse("findings_invalid");
        }
        Ok(())
    }
}

/// Operation ids are caller-chosen idempotency keys: any nonblank id up to 256 bytes.
fn identifier_or_operation(s: &str) -> bool {
    text(s, 256)
}

/// What the gateway's operation ledger recorded for the cited call.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct Basis {
    pub run_id: String,
    pub operation_id: String,
    pub action_digest: Value,
    pub capability_ref: Value,
    pub outcome: String,
    pub observation_ref: Value,
    pub observed_at: Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Status {
    Active,
    /// Something it depends on was invalidated; re-check before relying on it.
    Suspect,
    Invalidated,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct Invalidation {
    pub by_run_id: String,
    pub at: String,
    pub reason: String,
    pub refuted_by: Option<String>,
}

// `finding_id` is the wire name, shared with `FindingInput`.
#[allow(clippy::struct_field_names)]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct Finding {
    pub finding_id: String,
    pub kind: FindingKind,
    pub statement: String,
    pub depends_on: Vec<String>,
    pub urgent: bool,
    pub basis: Option<Basis>,
    pub refutes: Option<String>,
    pub author_run_id: String,
    pub created_at: String,
    pub status: Status,
    /// Invalidated findings this one depends on, directly or transitively (the first
    /// few).
    pub suspect_because: Vec<String>,
    pub invalidation: Option<Invalidation>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct Notice {
    pub seq: u64,
    /// `finding_invalidated` or `finding_published` (urgent).
    pub kind: String,
    pub finding_id: String,
    pub by_run_id: String,
    pub at: String,
    /// Findings this notice made suspect (the first few) and how many.
    pub suspect: Vec<String>,
    pub suspect_count: usize,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub(crate) struct Ledger {
    pub findings: BTreeMap<String, Finding>,
    pub notices: VecDeque<Notice>,
    pub next_seq: u64,
    /// Highest notice sequence each run's orchestrator acknowledged.
    pub acks: BTreeMap<String, u64>,
}

fn excerpt(statement: &str) -> String {
    if statement.len() <= NOTICE_EXCERPT_BYTES {
        return statement.to_owned();
    }
    let mut end = NOTICE_EXCERPT_BYTES;
    while !statement.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &statement[..end])
}

impl Ledger {
    fn notify(&mut self, kind: &str, finding: &Finding, by: &str, at: &str, suspect: &[String]) {
        self.next_seq += 1;
        self.notices.push_back(Notice {
            seq: self.next_seq,
            kind: kind.to_owned(),
            finding_id: finding.finding_id.clone(),
            by_run_id: by.to_owned(),
            at: at.to_owned(),
            suspect: suspect.iter().take(MAX_LISTED).cloned().collect(),
            suspect_count: suspect.len(),
        });
        while self.notices.len() > MAX_NOTICES {
            self.notices.pop_front();
        }
    }

    /// Publishes a finding. Replaying the same input by the same author returns it;
    /// any other reuse of the id conflicts. `false` when nothing changed.
    pub(crate) fn publish(
        &mut self,
        input: &FindingInput,
        basis: Option<Basis>,
        author: &str,
        now: &str,
    ) -> Result<(Finding, bool), WorkError> {
        if let Some(existing) = self.findings.get(&input.finding_id) {
            let same = existing.author_run_id == author
                && existing.kind == input.kind
                && existing.statement == input.statement
                && existing.depends_on == input.depends_on
                && existing.urgent == input.urgent
                && existing.refutes == input.refutes
                && existing.basis.as_ref().map(|b| (&b.run_id, &b.operation_id))
                    == basis.as_ref().map(|b| (&b.run_id, &b.operation_id));
            return if same {
                Ok((existing.clone(), false))
            } else {
                refuse("findings_conflict")
            };
        }
        if self.findings.len() >= MAX_FINDINGS {
            return refuse("findings_full");
        }
        if let Some(target) = &input.refutes
            && !self.findings.contains_key(target)
        {
            return refuse("findings_not_found");
        }
        let mut suspect_because = BTreeSet::new();
        for dependency in &input.depends_on {
            let Some(found) = self.findings.get(dependency) else {
                return refuse("findings_not_found");
            };
            match found.status {
                Status::Invalidated => return refuse("finding_invalidated"),
                Status::Suspect => suspect_because.extend(found.suspect_because.iter().cloned()),
                Status::Active => {}
            }
        }
        let finding = Finding {
            finding_id: input.finding_id.clone(),
            kind: input.kind,
            statement: input.statement.clone(),
            depends_on: input.depends_on.clone(),
            urgent: input.urgent,
            basis,
            refutes: input.refutes.clone(),
            author_run_id: author.to_owned(),
            created_at: now.to_owned(),
            status: if suspect_because.is_empty() {
                Status::Active
            } else {
                Status::Suspect
            },
            suspect_because: suspect_because.into_iter().take(MAX_CAUSES).collect(),
            invalidation: None,
        };
        if finding.urgent {
            self.notify("finding_published", &finding, author, now, &[]);
        }
        self.findings.insert(finding.finding_id.clone(), finding.clone());
        Ok((finding, true))
    }

    /// Falsifies a finding and marks its active dependents suspect, with one notice.
    pub(crate) fn invalidate(
        &mut self,
        finding_id: &str,
        reason: &str,
        refuted_by: Option<&str>,
        by: &str,
        now: &str,
    ) -> Result<Finding, WorkError> {
        if !prose(reason, MAX_REASON_BYTES) || refuted_by.is_some_and(|r| !identifier(r) || r == finding_id) {
            return refuse("findings_invalid");
        }
        let target = self
            .findings
            .get(finding_id)
            .ok_or(WorkError::Refused("findings_not_found"))?;
        if target.status == Status::Invalidated {
            return refuse("finding_invalidated");
        }
        match refuted_by {
            Some(id) => {
                let refutation = self.findings.get(id).ok_or(WorkError::Refused("findings_not_found"))?;
                if refutation.kind != FindingKind::Observed || refutation.status != Status::Active {
                    return refuse("refutation_unobserved");
                }
                // The refuting observation must have been published against this finding.
                if refutation.refutes.as_deref() != Some(finding_id) {
                    return refuse("refutation_unrelated");
                }
            }
            // Only an author withdraws without evidence.
            None if target.author_run_id != by => return refuse("refutation_required"),
            None => {}
        }
        let mut target = target.clone();
        target.status = Status::Invalidated;
        target.invalidation = Some(Invalidation {
            by_run_id: by.to_owned(),
            at: now.to_owned(),
            reason: reason.to_owned(),
            refuted_by: refuted_by.map(str::to_owned),
        });
        self.findings.insert(finding_id.to_owned(), target.clone());
        // Everything resting on it, transitively, is suspect.
        let mut doubted = BTreeSet::from([finding_id.to_owned()]);
        let mut suspect = Vec::new();
        loop {
            let next: Vec<String> = self
                .findings
                .values()
                .filter(|f| f.status != Status::Invalidated && !doubted.contains(&f.finding_id))
                .filter(|f| f.depends_on.iter().any(|d| doubted.contains(d)))
                .map(|f| f.finding_id.clone())
                .collect();
            if next.is_empty() {
                break;
            }
            for id in next {
                let finding = self.findings.get_mut(&id).expect("listed");
                finding.status = Status::Suspect;
                if finding.suspect_because.len() < MAX_CAUSES
                    && !finding.suspect_because.iter().any(|b| b == finding_id)
                {
                    finding.suspect_because.push(finding_id.to_owned());
                }
                doubted.insert(id.clone());
                suspect.push(id);
            }
        }
        self.notify("finding_invalidated", &target, by, now, &suspect);
        Ok(target)
    }

    /// Notices for `run_id` it has not acknowledged, oldest first, excluding its own;
    /// `missed` when older unacknowledged notices were dropped from retention (possibly
    /// only the run's own). Excerpts are quoted from the (immutable) statements.
    pub(crate) fn pending(&self, run_id: &str, limit: usize) -> Value {
        let acked = self.acks.get(run_id).copied().unwrap_or(0);
        let pending: Vec<&Notice> = self
            .notices
            .iter()
            .filter(|n| n.seq > acked && n.by_run_id != run_id)
            .collect();
        let missed = self.notices.front().is_some_and(|n| n.seq > acked + 1);
        let shown: Vec<Value> = pending
            .iter()
            .take(limit)
            .map(|n| {
                let mut view = serde_json::to_value(n).expect("notice fields are plain JSON");
                view["excerpt"] = json!(
                    self.findings
                        .get(&n.finding_id)
                        .map_or_else(String::new, |f| excerpt(&f.statement))
                );
                view
            })
            .collect();
        json!({
            "notices": shown,
            "pending": pending.len(), "missed": missed, "acknowledged_seq": acked,
            "latest_seq": self.next_seq, "data_only": true,
        })
    }

    /// Records that `run_id` has seen notices through `through`; never moves back.
    pub(crate) fn acknowledge(&mut self, run_id: &str, through: u64) -> Result<bool, WorkError> {
        if through > self.next_seq {
            return refuse("findings_invalid");
        }
        let current = self.acks.entry(run_id.to_owned()).or_insert(0);
        if through <= *current {
            return Ok(false);
        }
        *current = through;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claim(id: &str, depends_on: &[&str]) -> FindingInput {
        FindingInput {
            finding_id: id.into(),
            kind: FindingKind::Claim,
            statement: format!("statement {id}"),
            depends_on: depends_on.iter().map(|d| (*d).to_owned()).collect(),
            basis: None,
            urgent: false,
            refutes: None,
        }
    }

    fn observed(id: &str) -> (FindingInput, Basis) {
        let input = FindingInput {
            kind: FindingKind::Observed,
            basis: Some(BasisInput {
                run_id: None,
                operation_id: "op".into(),
            }),
            ..claim(id, &[])
        };
        let basis = Basis {
            run_id: "b".into(),
            operation_id: "op".into(),
            action_digest: json!("sha256:x"),
            capability_ref: json!({}),
            outcome: "confirmed".into(),
            observation_ref: json!({}),
            observed_at: json!("t"),
        };
        (input, basis)
    }

    #[test]
    fn invalidation_needs_evidence_from_others_and_cascades_to_dependents() {
        let mut ledger = Ledger::default();
        ledger.publish(&claim("root_cause", &[]), None, "a", "t0").unwrap();
        ledger
            .publish(&claim("fix_plan", &["root_cause"]), None, "b", "t1")
            .unwrap();
        ledger
            .publish(&claim("rollout", &["fix_plan"]), None, "c", "t2")
            .unwrap();
        ledger.publish(&claim("unrelated", &[]), None, "c", "t2").unwrap();

        // A peer cannot falsify another's finding by assertion, nor by citing a claim.
        assert_eq!(
            ledger
                .invalidate("root_cause", "wrong", None, "b", "t3")
                .unwrap_err()
                .code(),
            "refutation_required"
        );
        assert_eq!(
            ledger
                .invalidate("root_cause", "wrong", Some("unrelated"), "b", "t3")
                .unwrap_err()
                .code(),
            "refutation_unobserved"
        );
        // An observation unrelated to the target does not refute it.
        let (elsewhere, basis) = observed("elsewhere");
        ledger.publish(&elsewhere, Some(basis), "b", "t3").unwrap();
        assert_eq!(
            ledger
                .invalidate("root_cause", "wrong", Some("elsewhere"), "b", "t3")
                .unwrap_err()
                .code(),
            "refutation_unrelated"
        );
        let (mut test_run, basis) = observed("test_run");
        test_run.refutes = Some("root_cause".into());
        ledger.publish(&test_run, Some(basis), "b", "t3").unwrap();
        let done = ledger
            .invalidate("root_cause", "tests disprove it", Some("test_run"), "b", "t4")
            .unwrap();
        assert_eq!(done.status, Status::Invalidated);
        assert_eq!(ledger.findings["fix_plan"].status, Status::Suspect);
        assert_eq!(ledger.findings["rollout"].status, Status::Suspect);
        assert_eq!(ledger.findings["rollout"].suspect_because, ["root_cause"]);
        assert_eq!(ledger.findings["unrelated"].status, Status::Active);
        let notice = ledger.notices.back().unwrap();
        assert_eq!(
            (notice.kind.as_str(), notice.suspect.clone(), notice.suspect_count),
            (
                "finding_invalidated",
                vec!["fix_plan".to_owned(), "rollout".to_owned()],
                2
            )
        );
        assert_eq!(ledger.pending("a", 5)["notices"][0]["excerpt"], "statement root_cause");

        // Nothing new may rest on it; resting on a suspect finding is suspect too.
        assert_eq!(
            ledger
                .publish(&claim("more", &["root_cause"]), None, "c", "t5")
                .unwrap_err()
                .code(),
            "finding_invalidated"
        );
        let (later, _) = ledger.publish(&claim("later", &["rollout"]), None, "c", "t5").unwrap();
        assert_eq!(later.status, Status::Suspect);
        // An author withdraws without evidence.
        ledger.invalidate("unrelated", "superseded", None, "c", "t6").unwrap();
    }

    #[test]
    fn notices_are_peeked_until_acknowledged_and_skip_their_author() {
        let mut ledger = Ledger::default();
        let mut urgent = claim("blocker", &[]);
        urgent.urgent = true;
        ledger.publish(&urgent, None, "a", "t0").unwrap();
        assert_eq!(ledger.pending("a", 5)["pending"], 0);
        assert_eq!(ledger.pending("b", 5)["pending"], 1);
        assert_eq!(ledger.pending("b", 5)["pending"], 1, "reading does not consume");
        assert!(ledger.acknowledge("b", 1).unwrap());
        assert!(!ledger.acknowledge("b", 1).unwrap());
        assert_eq!(ledger.pending("b", 5)["pending"], 0);
        assert!(ledger.acknowledge("b", 9).is_err());

        // Two notices each (urgent publication, then withdrawal) past retention.
        for i in 0..MAX_NOTICES / 2 + 2 {
            let mut more = claim(&format!("n{i}"), &[]);
            more.urgent = true;
            ledger.publish(&more, None, "a", "t1").unwrap();
            ledger
                .invalidate(&more.finding_id, "withdrawn", None, "a", "t2")
                .unwrap();
        }
        let view = ledger.pending("c", NOTICES_PER_RESULT);
        assert_eq!(view["missed"], true);
        assert_eq!(view["notices"].as_array().unwrap().len(), NOTICES_PER_RESULT);
        assert_eq!(view["pending"], MAX_NOTICES);
    }

    #[test]
    fn publication_is_idempotent_and_validated() {
        let mut ledger = Ledger::default();
        assert!(ledger.publish(&claim("x", &[]), None, "a", "t").unwrap().1);
        assert!(!ledger.publish(&claim("x", &[]), None, "a", "t").unwrap().1);
        assert_eq!(
            ledger.publish(&claim("x", &[]), None, "b", "t").unwrap_err().code(),
            "findings_conflict"
        );
        assert_eq!(
            ledger
                .publish(&claim("y", &["nope"]), None, "a", "t")
                .unwrap_err()
                .code(),
            "findings_not_found"
        );
        let (mut bad, _) = observed("z");
        bad.basis = None;
        assert!(bad.validate().is_err());
        let mut bad = claim("z", &[]);
        bad.statement = "x".repeat(MAX_STATEMENT_BYTES + 1);
        assert!(bad.validate().is_err());
        bad.statement = "fine\u{1}".into();
        assert!(bad.validate().is_err(), "control characters");
        bad.statement = "fine".into();
        bad.refutes = Some("x".into());
        assert!(bad.validate().is_err(), "only observations refute");
        assert_eq!(
            ledger
                .invalidate("x", &"r".repeat(MAX_REASON_BYTES + 1), None, "a", "t")
                .unwrap_err()
                .code(),
            "findings_invalid"
        );
        assert_eq!(excerpt(&"é".repeat(200)).len(), 280 + "…".len());
    }
}
