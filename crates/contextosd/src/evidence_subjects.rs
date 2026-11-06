//! Evidence subjects: an attestation counts for a requirement only if it is about what
//! the run is about.
//!
//! Under strict evidence an issuer's signature, permissions, content hash and validity
//! make an entry authentic (see [`crate::evidence_issuers`]). That does not make it
//! applicable: a genuine, current identity check for customer A says nothing about a
//! refund to customer B. An `[[evidence_subjects]]` entry binds a requirement to the
//! subject it concerns, read from the run's own state:
//!
//! ```toml
//! [[evidence_subjects]]
//! requirement = "identity_verified"
//! from = "/request/input/context/customer_id"   # JSON Pointer into {request, run_context}
//! prefix = "customer:"                           # the attestation's `sub` is "customer:<id>"
//! canonicalizer = "ascii_casefold"               # or "exact" (default)
//! ```
//!
//! Each requirement names its own subject: an identity check concerns a customer, an
//! eligibility check an order. When an entry's attestation `sub` is missing, the run's
//! state has no value at `from`, or the two differ after canonicalization, the entry no
//! longer satisfies that requirement (it is removed from the entry's `satisfies`); the
//! requirements it does concern are unaffected. Each entry's `verification` records
//! the check per bound requirement (`bound`, `evidence_subject_missing`,
//! `evidence_subject_mismatch`). The check runs before compiling, so the compiler stays
//! pure and the replay case keeps the result.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// How subjects are compared.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Canonicalizer {
    #[default]
    Exact,
    /// ASCII letters compared without case (`ORD_881` is `ord_881`).
    AsciiCasefold,
}

impl Canonicalizer {
    fn apply(self, value: &str) -> String {
        match self {
            Self::Exact => value.to_owned(),
            Self::AsciiCasefold => value.to_ascii_lowercase(),
        }
    }
}

/// `[[evidence_subjects]]`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvidenceSubject {
    /// The `required_evidence` name this binds.
    pub requirement: String,
    /// JSON Pointer into `{"request": …, "run_context": …}` to a string or number.
    pub from: String,
    /// Prepended to the run's value to form the expected `sub`.
    #[serde(default)]
    pub prefix: String,
    #[serde(default)]
    pub canonicalizer: Canonicalizer,
}

/// Startup check: well-formed, one binding per requirement.
pub fn check(subjects: &[EvidenceSubject]) -> Result<(), String> {
    let mut seen = BTreeSet::new();
    for subject in subjects {
        let name = &subject.requirement;
        if name.is_empty() || !seen.insert(name.as_str()) {
            return Err(format!("[[evidence_subjects]] requirement {name:?} must be named once"));
        }
        let root = subject.from.split('/').nth(1);
        if !subject.from.starts_with('/') || !matches!(root, Some("request" | "run_context")) {
            return Err(format!(
                "[[evidence_subjects]] {name}: from must be a JSON Pointer under /request or /run_context"
            ));
        }
    }
    Ok(())
}

/// The run's subject at `from`, canonicalized with its prefix.
fn expected(subject: &EvidenceSubject, state: &Value) -> Option<String> {
    let value = match state.pointer(&subject.from)? {
        Value::String(s) if !s.is_empty() => s.clone(),
        Value::Number(n) => n.to_string(),
        _ => return None,
    };
    Some(subject.canonicalizer.apply(&format!("{}{value}", subject.prefix)))
}

/// Removes from each verified entry's `satisfies` the bound requirements whose subject
/// is not the run's, recording each check in the entry's `verification`.
pub fn bind(subjects: &[EvidenceSubject], request: &Value, run_context: &Value, evidence: &mut [Value]) {
    if subjects.is_empty() {
        return;
    }
    let state = json!({"request": request, "run_context": run_context});
    for entry in evidence.iter_mut().filter(|e| e.is_object()) {
        let attested = entry["verification"]["subject"].as_str().map(str::to_owned);
        let mut checks = serde_json::Map::new();
        let mut kept = Vec::new();
        for name in entry["satisfies"].as_array().cloned().unwrap_or_default() {
            let Some(subject) = subjects.iter().find(|s| name == s.requirement.as_str()) else {
                kept.push(name);
                continue;
            };
            let check = match (expected(subject, &state), &attested) {
                (Some(expected), Some(sub)) if subject.canonicalizer.apply(sub) == expected => "bound",
                (Some(_), Some(_)) => "evidence_subject_mismatch",
                _ => "evidence_subject_missing",
            };
            checks.insert(subject.requirement.clone(), json!(check));
            if check == "bound" {
                kept.push(name);
            }
        }
        if !checks.is_empty() {
            entry["satisfies"] = json!(kept);
            entry["verification"]["subjects"] = Value::Object(checks);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding(requirement: &str, from: &str, prefix: &str, canonicalizer: Canonicalizer) -> EvidenceSubject {
        EvidenceSubject {
            requirement: requirement.into(),
            from: from.into(),
            prefix: prefix.into(),
            canonicalizer,
        }
    }

    fn entry(sub: Option<&str>, satisfies: &[&str]) -> Value {
        json!({"satisfies": satisfies, "verification": {"subject": sub}})
    }

    #[test]
    fn each_requirement_is_bound_to_its_own_subject() {
        let subjects = [
            binding(
                "identity_verified",
                "/request/input/context/customer_id",
                "customer:",
                Canonicalizer::Exact,
            ),
            binding(
                "order_eligible",
                "/request/input/context/order_id",
                "order:",
                Canonicalizer::AsciiCasefold,
            ),
        ];
        let request = json!({"input": {"context": {"customer_id": "cus_B", "order_id": "ORD_881"}}});
        let mut evidence = vec![
            entry(Some("customer:cus_A"), &["identity_verified"]),
            entry(Some("customer:cus_B"), &["identity_verified"]),
            entry(Some("order:ord_881"), &["order_eligible", "unbound_name"]),
            entry(None, &["identity_verified"]),
            json!("legacy string entry"),
        ];
        bind(&subjects, &request, &json!({}), &mut evidence);
        assert_eq!(evidence[0]["satisfies"], json!([]), "A's check does not count for B");
        assert_eq!(
            evidence[0]["verification"]["subjects"]["identity_verified"],
            "evidence_subject_mismatch"
        );
        assert_eq!(evidence[1]["satisfies"], json!(["identity_verified"]));
        assert_eq!(evidence[1]["verification"]["subjects"]["identity_verified"], "bound");
        assert_eq!(
            evidence[2]["satisfies"],
            json!(["order_eligible", "unbound_name"]),
            "aliases resolve"
        );
        assert_eq!(
            evidence[3]["verification"]["subjects"]["identity_verified"],
            "evidence_subject_missing"
        );
        assert_eq!(evidence[4], json!("legacy string entry"));

        // The run's state has no subject: nothing bound counts.
        let mut evidence = vec![entry(Some("customer:cus_B"), &["identity_verified"])];
        bind(&subjects, &json!({"input": {}}), &json!({}), &mut evidence);
        assert_eq!(evidence[0]["satisfies"], json!([]));
        assert_eq!(
            evidence[0]["verification"]["subjects"]["identity_verified"],
            "evidence_subject_missing"
        );
    }

    #[test]
    fn bindings_name_each_requirement_once_under_the_run_state() {
        let ok = binding(
            "identity_verified",
            "/run_context/user/user_id",
            "",
            Canonicalizer::Exact,
        );
        assert!(check(std::slice::from_ref(&ok)).is_ok());
        assert!(check(&[ok.clone(), ok.clone()]).is_err());
        for from in ["request/input", "/deps/evidence", "/"] {
            assert!(
                check(&[binding("x", from, "", Canonicalizer::Exact)]).is_err(),
                "{from}"
            );
        }
    }
}
