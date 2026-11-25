//! Legal holds and erasure by data subject.
//!
//! **Subjects.** With `[privacy] subject_pointers` (JSON pointers into a run's request,
//! such as `/input/context/customer_id`), each admitted run is indexed under the
//! subjects its request names. The index is keyed by a digest of the identifier and
//! never stores the identifier itself; it is how a deletion request finds every run
//! about one person.
//!
//! **Legal holds.** A hold names runs, subjects or the whole tenant. While a hold
//! covers a run, nothing erases its content: neither an operator's erasure nor the
//! retention sweep (`legal_hold`). Holds are placed and released with a reason, and
//! both are audited; a released hold stays listed.
//!
//! **Erasure by subject.** Every finished run indexed under the subject is erased
//! through [`Gateway::erase_run`], so each leaves the same tombstones and
//! `run_data_erased` entry; runs under a hold, and runs still active, are reported and
//! left. The audit chain is never rewritten and verifies after any erasure.

use contextos_contract::canonical::sha256_canonical;
use contextos_store::{AppendLog, DocKey, DocKind, DocumentStore};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::admission::RunAdmission;
use crate::erasure::ErasureError;
use crate::{Gateway, GatewayError};

/// Holds kept per tenant at most (placed and released).
pub const MAX_HOLDS: usize = 1024;
/// Runs indexed per subject at most; older runs stay indexed, newer ones beyond the
/// bound are not (and are reported by the index's `truncated`).
pub const MAX_RUNS_PER_SUBJECT: usize = 10_000;
/// Subject pointers at most.
pub const MAX_POINTERS: usize = 16;

/// The digest a subject identifier is indexed and audited under.
#[must_use]
pub fn subject_digest(subject: &str) -> String {
    sha256_canonical(&json!({"subject": subject})).unwrap_or_default()
}

fn holds_key(tenant_id: &str) -> DocKey {
    DocKey::new(tenant_id, DocKind::LegalHolds, "legal_holds")
}

fn subject_key(tenant_id: &str, digest: &str) -> DocKey {
    DocKey::new(tenant_id, DocKind::SubjectIndex, digest)
}

#[derive(Debug, thiserror::Error)]
pub enum PrivacyError {
    #[error("{0}")]
    Invalid(String),
    #[error("not found")]
    NotFound,
    #[error("{0}")]
    Conflict(String),
    #[error(transparent)]
    Gateway(#[from] GatewayError),
}

/// A hold to place.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HoldRequest {
    pub hold_id: String,
    pub reason: String,
    #[serde(default)]
    pub run_ids: Vec<String>,
    /// Subject identifiers; stored as digests.
    #[serde(default)]
    pub subjects: Vec<String>,
    #[serde(default)]
    pub tenant_wide: bool,
}

/// Validates the configured subject pointers.
pub fn validate_pointers(pointers: &[String]) -> Result<(), String> {
    if pointers.len() > MAX_POINTERS {
        return Err(format!("[privacy] subject_pointers: at most {MAX_POINTERS}"));
    }
    if let Some(p) = pointers.iter().find(|p| !p.starts_with('/') || p.len() > 256) {
        return Err(format!("[privacy] subject_pointers: {p} is not a JSON pointer"));
    }
    Ok(())
}

/// The subject identifiers `request` names at `pointers` (strings and integers).
#[must_use]
pub fn subjects_in(request: &Value, pointers: &[String]) -> Vec<String> {
    let mut out: Vec<String> = pointers
        .iter()
        .filter_map(|p| match request.pointer(p)? {
            Value::String(s) if !s.is_empty() && s.len() <= 512 => Some(s.clone()),
            Value::Number(n) if n.is_i64() || n.is_u64() => Some(n.to_string()),
            _ => None,
        })
        .collect();
    out.sort();
    out.dedup();
    out
}

fn active(hold: &Value) -> bool {
    hold["released_at"].is_null()
}

impl<S: DocumentStore + 'static, L: AppendLog + 'static> Gateway<S, L> {
    /// Indexes runs under the subjects `pointers` name in their requests.
    pub fn set_subject_pointers(&mut self, pointers: Vec<String>) {
        self.subject_pointers = pointers;
    }

    /// Adds the run to the index of each subject its request names.
    pub(crate) async fn index_subjects(&self, admission: &RunAdmission, request: &Value) -> Result<(), GatewayError> {
        for subject in subjects_in(request, &self.subject_pointers) {
            let key = subject_key(&admission.tenant_id, &subject_digest(&subject));
            for _ in 0..32 {
                let current = self.store.get(&key).await?;
                let mut body = current.as_ref().map_or_else(|| json!({"runs": []}), |c| c.body.clone());
                let runs = body["runs"].as_array().cloned().unwrap_or_default();
                if runs.iter().any(|r| r == admission.run_id.as_str()) {
                    break;
                }
                if runs.len() >= MAX_RUNS_PER_SUBJECT {
                    body["truncated"] = json!(true);
                } else {
                    let mut runs = runs;
                    runs.push(json!(admission.run_id));
                    body["runs"] = json!(runs);
                }
                let written = match &current {
                    None => self.store.create(&key, &body).await.map(|_| ()),
                    Some(c) => self.store.compare_and_swap(&key, c.revision, &body).await.map(|_| ()),
                };
                match written {
                    Ok(()) => break,
                    Err(e) if e.is_conflict() => {}
                    Err(e) => return Err(e.into()),
                }
            }
        }
        Ok(())
    }

    /// The runs indexed under `subject`, and whether the index was truncated.
    pub async fn subject_runs(&self, tenant_id: &str, subject: &str) -> Result<(Vec<String>, bool), GatewayError> {
        let doc = self
            .store
            .get(&subject_key(tenant_id, &subject_digest(subject)))
            .await?;
        let body = doc.map_or(Value::Null, |d| d.body);
        let runs = body["runs"]
            .as_array()
            .map(|r| r.iter().filter_map(|x| x.as_str().map(str::to_owned)).collect())
            .unwrap_or_default();
        Ok((runs, body["truncated"] == true))
    }

    /// The tenant's holds, placed and released.
    pub async fn legal_holds(&self, tenant_id: &str) -> Result<Vec<Value>, GatewayError> {
        Ok(self
            .store
            .get(&holds_key(tenant_id))
            .await?
            .and_then(|d| d.body["holds"].as_array().cloned())
            .unwrap_or_default())
    }

    /// The active hold covering the run, if any.
    pub(crate) async fn held_by(&self, admission: &RunAdmission) -> Result<Option<String>, GatewayError> {
        for hold in self
            .legal_holds(&admission.tenant_id)
            .await?
            .iter()
            .filter(|h| active(h))
        {
            let id = hold["hold_id"].as_str().unwrap_or_default().to_owned();
            if hold["tenant_wide"] == true
                || hold["run_ids"]
                    .as_array()
                    .is_some_and(|r| r.iter().any(|x| x == admission.run_id.as_str()))
            {
                return Ok(Some(id));
            }
            for digest in hold["subject_digests"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
            {
                let runs = self.store.get(&subject_key(&admission.tenant_id, digest)).await?;
                if runs.is_some_and(|d| {
                    d.body["runs"]
                        .as_array()
                        .is_some_and(|r| r.iter().any(|x| x == admission.run_id.as_str()))
                }) {
                    return Ok(Some(id));
                }
            }
        }
        Ok(None)
    }

    /// Places a hold (audited `legal_hold_placed`).
    pub async fn place_hold(&self, tenant_id: &str, request: &HoldRequest, by: &str) -> Result<Value, PrivacyError> {
        let id_ok = !request.hold_id.is_empty()
            && request.hold_id.len() <= 128
            && request
                .hold_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.:".contains(&b));
        if !id_ok || request.reason.trim().len() < 10 || request.reason.len() > 1024 {
            return Err(PrivacyError::Invalid(
                "hold_id (letters, digits, -_.:) and a reason of 10 to 1024 characters are required".into(),
            ));
        }
        if !request.tenant_wide && request.run_ids.is_empty() && request.subjects.is_empty() {
            return Err(PrivacyError::Invalid(
                "a hold names runs, subjects or the whole tenant".into(),
            ));
        }
        if request.run_ids.len() + request.subjects.len() > 1024 {
            return Err(PrivacyError::Invalid(
                "a hold names at most 1024 runs and subjects".into(),
            ));
        }
        let now = self.now();
        let digests: Vec<String> = request.subjects.iter().map(|s| subject_digest(s)).collect();
        let hold = json!({"hold_id": request.hold_id, "reason": request.reason, "run_ids": request.run_ids,
            "subject_digests": digests, "tenant_wide": request.tenant_wide, "placed_by": by, "placed_at": now,
            "released_at": null});
        let key = holds_key(tenant_id);
        let mut audited = false;
        for _ in 0..32 {
            let current = self.store.get(&key).await.map_err(GatewayError::from)?;
            let mut holds = current
                .as_ref()
                .and_then(|c| c.body["holds"].as_array().cloned())
                .unwrap_or_default();
            if holds.iter().any(|h| h["hold_id"] == request.hold_id.as_str()) {
                return Err(PrivacyError::Conflict(format!("hold {} exists", request.hold_id)));
            }
            if holds.len() >= MAX_HOLDS {
                return Err(PrivacyError::Conflict(format!("at most {MAX_HOLDS} holds per tenant")));
            }
            // Audited once, before it takes effect.
            if !audited {
                self.audit
                    .append(tenant_id, "legal_hold_placed", hold.clone(), &now)
                    .await
                    .map_err(GatewayError::from)?;
                audited = true;
            }
            holds.push(hold.clone());
            let body = json!({"holds": holds});
            let written = match &current {
                None => self.store.create(&key, &body).await.map(|_| ()),
                Some(c) => self.store.compare_and_swap(&key, c.revision, &body).await.map(|_| ()),
            };
            match written {
                Ok(()) => return Ok(hold),
                Err(e) if e.is_conflict() => {}
                Err(e) => return Err(GatewayError::from(e).into()),
            }
        }
        Err(PrivacyError::Conflict("too much contention".into()))
    }

    /// Releases a hold (audited `legal_hold_released`); it stays listed.
    pub async fn release_hold(
        &self,
        tenant_id: &str,
        hold_id: &str,
        reason: &str,
        by: &str,
    ) -> Result<Value, PrivacyError> {
        if reason.trim().len() < 10 || reason.len() > 1024 {
            return Err(PrivacyError::Invalid(
                "a reason of 10 to 1024 characters is required".into(),
            ));
        }
        let now = self.now();
        let key = holds_key(tenant_id);
        let mut audited = false;
        for _ in 0..32 {
            let current = self
                .store
                .get(&key)
                .await
                .map_err(GatewayError::from)?
                .ok_or(PrivacyError::NotFound)?;
            let mut holds = current.body["holds"].as_array().cloned().unwrap_or_default();
            let hold = holds
                .iter_mut()
                .find(|h| h["hold_id"] == hold_id)
                .ok_or(PrivacyError::NotFound)?;
            if !active(hold) {
                return Err(PrivacyError::Conflict(format!("hold {hold_id} was already released")));
            }
            if !audited {
                self.audit
                    .append(
                        tenant_id,
                        "legal_hold_released",
                        json!({"hold_id": hold_id, "reason": reason, "released_by": by}),
                        &now,
                    )
                    .await
                    .map_err(GatewayError::from)?;
                audited = true;
            }
            hold["released_at"] = json!(now);
            hold["released_by"] = json!(by);
            hold["release_reason"] = json!(reason);
            let released = hold.clone();
            let body = json!({"holds": holds});
            match self.store.compare_and_swap(&key, current.revision, &body).await {
                Ok(_) => return Ok(released),
                Err(e) if e.is_conflict() => {}
                Err(e) => return Err(GatewayError::from(e).into()),
            }
        }
        Err(PrivacyError::Conflict("too much contention".into()))
    }

    /// Erases every finished, unheld run indexed under `subject` (a deletion request),
    /// and audits the request (`subject_erasure`, with the subject's digest only).
    pub async fn erase_subject(
        &self,
        tenant_id: &str,
        subject: &str,
        by: &str,
        reason: &str,
    ) -> Result<Value, PrivacyError> {
        if subject.is_empty() || subject.len() > 512 {
            return Err(PrivacyError::Invalid("a subject of 1 to 512 bytes is required".into()));
        }
        if reason.trim().len() < 10 || reason.len() > 1024 {
            return Err(PrivacyError::Invalid(
                "a reason of 10 to 1024 characters is required".into(),
            ));
        }
        let (runs, truncated) = self.subject_runs(tenant_id, subject).await?;
        let (mut erased, mut held, mut active_runs, mut missing) = (Vec::new(), Vec::new(), Vec::new(), Vec::new());
        for run_id in &runs {
            let stored = self
                .store
                .get(&DocKey::new(tenant_id, DocKind::RunAdmission, run_id))
                .await
                .map_err(GatewayError::from)?;
            let Some(admission) = stored.and_then(|s| serde_json::from_value::<RunAdmission>(s.body).ok()) else {
                missing.push(run_id.clone());
                continue;
            };
            match self.erase_run(&admission, by, reason).await {
                Ok(_) => erased.push(run_id.clone()),
                Err(ErasureError::Held(hold)) => held.push(json!({"run_id": run_id, "hold_id": hold})),
                Err(ErasureError::RunActive) => active_runs.push(run_id.clone()),
                Err(ErasureError::Invalid) => return Err(PrivacyError::Invalid("invalid reason".into())),
                Err(ErasureError::Gateway(e)) => return Err(e.into()),
            }
        }
        let summary = json!({"subject_digest": subject_digest(subject), "runs": runs.len(), "erased": erased,
            "held": held, "active": active_runs, "missing": missing, "index_truncated": truncated,
            "requested_by": by, "reason": reason});
        self.audit
            .append(tenant_id, "subject_erasure", summary.clone(), &self.now())
            .await
            .map_err(GatewayError::from)?;
        Ok(summary)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subjects_are_read_by_pointer_and_deduplicated() {
        let request = json!({"input": {"context": {"customer_id": "cus_77", "account": 4211, "email": ""}},
            "user": {"id": "cus_77"}});
        let pointers = vec![
            "/input/context/customer_id".to_owned(),
            "/input/context/account".to_owned(),
            "/input/context/email".to_owned(),
            "/user/id".to_owned(),
            "/missing".to_owned(),
        ];
        assert_eq!(
            subjects_in(&request, &pointers),
            vec!["4211".to_owned(), "cus_77".to_owned()]
        );
        assert!(validate_pointers(&pointers).is_ok());
        assert!(validate_pointers(&["input/x".to_owned()]).is_err());
    }

    #[test]
    fn a_subject_is_kept_only_as_a_digest() {
        let d = subject_digest("cus_77");
        assert!(d.starts_with("sha256:") && !d.contains("cus_77"));
        assert_eq!(d, subject_digest("cus_77"));
        assert_ne!(d, subject_digest("cus_78"));
    }
}
