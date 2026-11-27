//! `ctx adapter-check`: verifies from a signed, hash-chained audit export that a custom
//! framework adapter obeys the four mandatory governance scenarios documented in
//! `docs/integrations/BUILD_AN_ADAPTER.md`:
//!
//! 1. `refusal`: a refused call (`authorization_decision` deny/block) is never dispatched
//!    (`operation_claim` absent for that operation).
//! 2. `approval_pause`: an `approval_requested` pauses until an exact-digest
//!    `approval_redeemed` (redeemed at most once for that operation), then claims.
//! 3. `duplicate_delivery`: a repeated or duplicate effect is stopped (`repeated_effect_refusal`,
//!    or multiple authorization/check attempts with at most one `operation_claim`), proving
//!    the provider was not invoked twice.
//! 4. `lost_response`: an `effect_observation` with `outcome = "unknown"` is followed by
//!    `effect_reconciliation`, with no second `operation_claim` for that operation before
//!    reconciliation settles it.
//!
//! Refuses any export that does not verify cryptographically against `--keys`.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::PathBuf;

use contextos_audit::AuditEntry;
use serde_json::{Value, json};

use crate::Failure;

pub(crate) const SCENARIOS: [&str; 4] = ["refusal", "approval_pause", "duplicate_delivery", "lost_response"];

pub(crate) struct Options<'a> {
    pub entries: &'a PathBuf,
    pub keys: &'a PathBuf,
    pub continues: Option<&'a PathBuf>,
    pub scenarios: &'a [String],
    pub markdown: Option<&'a PathBuf>,
}

#[derive(Debug)]
struct ScenarioResult {
    scenario: &'static str,
    passed: bool,
    status: &'static str,
    evidence_sequences: Vec<u64>,
    violations: Vec<String>,
}

impl ScenarioResult {
    fn to_json(&self) -> Value {
        json!({
            "scenario": self.scenario,
            "passed": self.passed,
            "status": self.status,
            "evidence_sequences": self.evidence_sequences,
            "violations": self.violations,
        })
    }
}

fn op_id(entry: &AuditEntry) -> Option<&str> {
    entry.payload["operation_id"].as_str().filter(|s| !s.is_empty())
}

fn check_refusal(chain: &[AuditEntry]) -> ScenarioResult {
    let mut claimed_ops: BTreeSet<&str> = BTreeSet::new();
    for entry in chain {
        if entry.kind == "operation_claim"
            && let Some(op) = op_id(entry)
        {
            claimed_ops.insert(op);
        }
    }
    let mut refused_seqs = Vec::new();
    let mut violations = Vec::new();
    for entry in chain {
        if entry.kind == "authorization_decision" {
            let verdict = entry.payload["verdict"]
                .as_str()
                .or_else(|| entry.payload["decision"].as_str())
                .unwrap_or_default();
            let denied = matches!(verdict, "deny" | "denied" | "blocked" | "refused");
            if denied {
                refused_seqs.push(entry.sequence);
                if let Some(op) = op_id(entry)
                    && claimed_ops.contains(op)
                {
                    violations.push(format!(
                        "operation `{op}` refused at #{} was still claimed for dispatch",
                        entry.sequence
                    ));
                }
            }
        }
    }
    let passed = !refused_seqs.is_empty() && violations.is_empty();
    let status = if !violations.is_empty() {
        "violated"
    } else if refused_seqs.is_empty() {
        "missing"
    } else {
        "passed"
    };
    ScenarioResult {
        scenario: "refusal",
        passed,
        status,
        evidence_sequences: refused_seqs,
        violations,
    }
}

fn check_approval_pause(chain: &[AuditEntry]) -> ScenarioResult {
    let mut requested_by_digest: BTreeMap<String, Vec<u64>> = BTreeMap::new();
    let mut redemptions_by_op: BTreeMap<String, Vec<(u64, Option<String>)>> = BTreeMap::new();
    let mut claims_by_op: BTreeMap<String, Vec<u64>> = BTreeMap::new();

    for entry in chain {
        match entry.kind.as_str() {
            "approval_requested" => {
                if let Some(digest) = entry.payload["action_digest"].as_str() {
                    requested_by_digest
                        .entry(digest.to_owned())
                        .or_default()
                        .push(entry.sequence);
                }
            }
            "approval_redeemed" => {
                if let Some(op) = op_id(entry) {
                    let digest = entry.payload["action_digest"].as_str().map(str::to_owned);
                    redemptions_by_op
                        .entry(op.to_owned())
                        .or_default()
                        .push((entry.sequence, digest));
                }
            }
            "operation_claim" => {
                if let Some(op) = op_id(entry) {
                    claims_by_op.entry(op.to_owned()).or_default().push(entry.sequence);
                }
            }
            _ => {}
        }
    }

    let mut evidence = Vec::new();
    let mut violations = Vec::new();
    for (op, redemptions) in &redemptions_by_op {
        if redemptions.len() > 1 {
            violations.push(format!(
                "operation `{op}` redeemed approvals {} times (must be single-use)",
                redemptions.len()
            ));
        }
        for (seq, digest) in redemptions {
            let matched = digest
                .as_deref()
                .and_then(|d| requested_by_digest.get(d))
                .and_then(|reqs| reqs.iter().copied().find(|r| *r < *seq));
            if let Some(req_seq) = matched {
                evidence.push(req_seq);
                evidence.push(*seq);
                if let Some(claim_seq) = claims_by_op
                    .get(op)
                    .and_then(|cs| cs.iter().copied().find(|c| *c > *seq))
                {
                    evidence.push(claim_seq);
                }
            } else {
                violations.push(format!(
                    "approval redemption for `{op}` at #{seq} had no prior matching approval_requested digest"
                ));
            }
        }
    }
    evidence.sort_unstable();
    evidence.dedup();

    let passed = !evidence.is_empty() && violations.is_empty();
    let status = if !violations.is_empty() {
        "violated"
    } else if evidence.is_empty() {
        "missing"
    } else {
        "passed"
    };
    ScenarioResult {
        scenario: "approval_pause",
        passed,
        status,
        evidence_sequences: evidence,
        violations,
    }
}

fn check_duplicate_delivery(chain: &[AuditEntry]) -> ScenarioResult {
    let mut evidence = Vec::new();
    let mut violations = Vec::new();
    let mut auth_per_op: BTreeMap<String, Vec<u64>> = BTreeMap::new();
    let mut claims_per_op: BTreeMap<String, Vec<u64>> = BTreeMap::new();
    let mut applied_per_op: BTreeMap<String, Vec<u64>> = BTreeMap::new();

    for entry in chain {
        match entry.kind.as_str() {
            "repeated_effect_refusal" => evidence.push(entry.sequence),
            "authorization_decision" => {
                if let Some(op) = op_id(entry) {
                    auth_per_op.entry(op.to_owned()).or_default().push(entry.sequence);
                }
            }
            "operation_claim" => {
                if let Some(op) = op_id(entry) {
                    claims_per_op.entry(op.to_owned()).or_default().push(entry.sequence);
                }
            }
            "effect_observation" => {
                if let Some(op) = op_id(entry)
                    && entry.payload["outcome"].as_str() == Some("applied")
                {
                    applied_per_op.entry(op.to_owned()).or_default().push(entry.sequence);
                }
            }
            _ => {}
        }
    }

    for (op, applied) in &applied_per_op {
        if applied.len() > 1 {
            violations.push(format!(
                "operation `{op}` was applied {} times (sequences {applied:?})",
                applied.len()
            ));
        }
    }
    for (op, auths) in &auth_per_op {
        if auths.len() >= 2 {
            let claims = claims_per_op.get(op).map_or(0, Vec::len);
            if claims <= 1 {
                evidence.extend(auths.iter().copied());
            }
        }
    }
    evidence.sort_unstable();
    evidence.dedup();

    let passed = !evidence.is_empty() && violations.is_empty();
    let status = if !violations.is_empty() {
        "violated"
    } else if evidence.is_empty() {
        "missing"
    } else {
        "passed"
    };
    ScenarioResult {
        scenario: "duplicate_delivery",
        passed,
        status,
        evidence_sequences: evidence,
        violations,
    }
}

fn check_lost_response(chain: &[AuditEntry]) -> ScenarioResult {
    let mut unknown_at: BTreeMap<String, u64> = BTreeMap::new();
    let mut reconciled_at: BTreeMap<String, u64> = BTreeMap::new();
    let mut claims: Vec<(String, u64)> = Vec::new();

    for entry in chain {
        match entry.kind.as_str() {
            "effect_observation" => {
                if entry.payload["outcome"].as_str() == Some("unknown")
                    && let Some(op) = op_id(entry)
                {
                    unknown_at.entry(op.to_owned()).or_insert(entry.sequence);
                }
            }
            "effect_reconciliation" => {
                if let Some(op) = op_id(entry) {
                    reconciled_at.entry(op.to_owned()).or_insert(entry.sequence);
                }
            }
            "operation_claim" => {
                if let Some(op) = op_id(entry) {
                    claims.push((op.to_owned(), entry.sequence));
                }
            }
            _ => {}
        }
    }

    let mut evidence = Vec::new();
    let mut violations = Vec::new();
    for (op, unk_seq) in &unknown_at {
        let rec_seq = reconciled_at.get(op).copied();
        for (claim_op, claim_seq) in &claims {
            if claim_op == op && *claim_seq > *unk_seq && rec_seq.is_none_or(|r| *claim_seq < r) {
                violations.push(format!(
                    "operation `{op}` was claimed again at #{claim_seq} after unknown outcome #{unk_seq} before reconciliation"
                ));
            }
        }
        if let Some(r) = rec_seq {
            if r > *unk_seq {
                evidence.push(*unk_seq);
                evidence.push(r);
            }
        } else {
            violations.push(format!(
                "operation `{op}` recorded unknown outcome at #{unk_seq} without reconciliation"
            ));
        }
    }
    evidence.sort_unstable();
    evidence.dedup();

    let passed = !evidence.is_empty() && violations.is_empty();
    let status = if !violations.is_empty() {
        "violated"
    } else if evidence.is_empty() {
        "missing"
    } else {
        "passed"
    };
    ScenarioResult {
        scenario: "lost_response",
        passed,
        status,
        evidence_sequences: evidence,
        violations,
    }
}

fn evaluate(chain: &[AuditEntry], selected: &[String]) -> Vec<ScenarioResult> {
    let names: Vec<&str> = if selected.is_empty() {
        SCENARIOS.to_vec()
    } else {
        selected.iter().map(String::as_str).collect()
    };
    names
        .into_iter()
        .map(|name| match name {
            "refusal" => check_refusal(chain),
            "approval_pause" => check_approval_pause(chain),
            "duplicate_delivery" => check_duplicate_delivery(chain),
            "lost_response" => check_lost_response(chain),
            _ => unreachable!("validated before evaluate"),
        })
        .collect()
}

fn render_markdown(results: &[ScenarioResult], verified_entries: usize) -> String {
    let mut md = String::from("# ContextOS Adapter Conformance Check\n\n");
    let _ = writeln!(
        md,
        "Verified `{verified_entries}` signed audit entries offline.\n\n\
         | Scenario | Status | Evidence sequences | Violations |\n|---|---|---|---|\n"
    );
    for r in results {
        let seqs = if r.evidence_sequences.is_empty() {
            "-".into()
        } else {
            r.evidence_sequences
                .iter()
                .map(|s| format!("#{s}"))
                .collect::<Vec<_>>()
                .join(", ")
        };
        let viols = if r.violations.is_empty() {
            "none".into()
        } else {
            r.violations.join("; ")
        };
        let _ = writeln!(md, "| `{}` | **{}** | {} | {} |", r.scenario, r.status, seqs, viols);
    }
    md
}

pub(crate) fn run(options: &Options<'_>) -> Result<Value, Failure> {
    if let Some(unknown) = options.scenarios.iter().find(|s| !SCENARIOS.contains(&s.as_str())) {
        return Err(Failure::Usage(format!(
            "unknown scenario `{unknown}`; expected one of: {}",
            SCENARIOS.join(", ")
        )));
    }
    let (verification, chain) = crate::audit_verify::verify(options.entries, options.keys, options.continues)?;
    let results = evaluate(&chain, options.scenarios);
    if let Some(path) = options.markdown {
        let md = render_markdown(&results, chain.len());
        std::fs::write(path, md).map_err(|e| Failure::Usage(format!("{}: {e}", path.display())))?;
    }
    let all_passed = results.iter().all(|r| r.passed);
    let report = json!({
        "verdict": if all_passed { "pass" } else { "fail" },
        "verified_entries": chain.len(),
        "verification": verification,
        "scenarios": results.iter().map(ScenarioResult::to_json).collect::<Vec<_>>(),
    });
    if all_passed {
        Ok(report)
    } else {
        Err(Failure::Rejected(report))
    }
}

#[cfg(test)]
mod tests {
    use contextos_audit::{AuditSigner, AuditWriter};
    use contextos_store::MemoryLog;

    use super::*;

    async fn build_chain(events: Vec<(&str, Value)>) -> Vec<AuditEntry> {
        let log = MemoryLog::new();
        let signer = AuditSigner::from_seed("k1", [7u8; 32]);
        let writer = AuditWriter::new(log, signer);
        let mut out = Vec::new();
        for (i, (kind, body)) in events.into_iter().enumerate() {
            let ts = format!("2026-11-27T10:00:{:02}Z", i % 60);
            out.push(writer.append("tenant_acme", kind, body, &ts).await.unwrap());
        }
        out
    }

    #[tokio::test]
    async fn all_four_scenarios_pass_on_conformant_audit_chain() {
        let chain = build_chain(vec![
            (
                "authorization_decision",
                json!({"operation_id": "op_refused", "verdict": "deny"}),
            ),
            (
                "approval_requested",
                json!({"operation_id": "op_appr", "action_digest": "sha256:abc"}),
            ),
            (
                "approval_redeemed",
                json!({"operation_id": "op_appr", "action_digest": "sha256:abc"}),
            ),
            ("operation_claim", json!({"operation_id": "op_appr"})),
            (
                "repeated_effect_refusal",
                json!({"operation_id": "op_dup_2", "original_operation_id": "op_appr"}),
            ),
            ("operation_claim", json!({"operation_id": "op_lost"})),
            (
                "effect_observation",
                json!({"operation_id": "op_lost", "outcome": "unknown"}),
            ),
            (
                "effect_reconciliation",
                json!({"operation_id": "op_lost", "outcome": "applied"}),
            ),
        ])
        .await;
        let results = evaluate(&chain, &[]);
        assert_eq!(results.len(), 4);
        assert!(results.iter().all(|r| r.passed), "{results:#?}");
    }

    #[tokio::test]
    async fn blind_retry_before_reconciliation_fails_lost_response() {
        let chain = build_chain(vec![
            ("operation_claim", json!({"operation_id": "op_lost"})),
            (
                "effect_observation",
                json!({"operation_id": "op_lost", "outcome": "unknown"}),
            ),
            ("operation_claim", json!({"operation_id": "op_lost"})),
            (
                "effect_reconciliation",
                json!({"operation_id": "op_lost", "outcome": "applied"}),
            ),
        ])
        .await;
        let res = check_lost_response(&chain);
        assert!(!res.passed);
        assert_eq!(res.status, "violated");
    }
}
