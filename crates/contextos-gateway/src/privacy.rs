//! Legal holds and erasure by data subject.
//!
//! **Subjects.** With `[privacy] subject_pointers` (JSON pointers into a run's request,
//! such as `/input/context/customer_id`), each admitted run is indexed under the
//! subjects its request names. The index is keyed by a digest of the identifier (a
//! pseudonym: keyed with HMAC under `[privacy] subject_key_env`, plain SHA-256
//! otherwise) and never stores the identifier itself; it is how a deletion request finds every run
//! about one person. The index grows in pages of [`RUNS_PER_PAGE`] runs, up to
//! [`MAX_RUNS_PER_SUBJECT`]. Each run also records the digests of its own subjects, so a
//! hold by subject covers a run however large its subject's index is.
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
/// Runs per page of a subject's index: well inside a stored document's bound on values
/// (`canonical::MAX_VALUES`) and bytes, for run ids of any permitted length.
pub const RUNS_PER_PAGE: usize = 5_000;
/// Pages per subject at most.
pub const MAX_SUBJECT_PAGES: usize = 200;
/// Runs indexed per subject at most; older runs stay indexed, newer ones beyond the
/// bound are not (and are reported by the index's `truncated`). A hold by subject
/// still covers them through each run's own subject record.
pub const MAX_RUNS_PER_SUBJECT: usize = RUNS_PER_PAGE * MAX_SUBJECT_PAGES;
/// Subject pointers at most.
pub const MAX_POINTERS: usize = 16;

/// The unkeyed digest of a subject identifier: plain SHA-256, used when no subject key
/// is configured. A pseudonym, not anonymous: a low-entropy identifier (an account
/// number, an e-mail address) can be found by hashing guesses.
#[must_use]
pub fn subject_digest(subject: &str) -> String {
    sha256_canonical(&json!({"subject": subject})).unwrap_or_default()
}

/// The deployment's subject key, and whether unkeyed digests still match while
/// migrating to it.
#[derive(Clone, Copy)]
pub struct SubjectKey {
    key: [u8; 32],
    match_unkeyed: bool,
}

impl std::fmt::Debug for SubjectKey {
    // Never prints the key.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SubjectKey")
            .field("match_unkeyed", &self.match_unkeyed)
            .finish_non_exhaustive()
    }
}

/// Separates subject digests from any other use of the key.
const SUBJECT_DOMAIN: &[u8] = b"contextos-subject-v1:";

/// The keyed digest of a subject identifier: HMAC-SHA256 under the deployment's subject
/// key, so it cannot be recomputed, or linked across deployments, without the key.
#[must_use]
pub fn keyed_subject_digest(key: &[u8; 32], subject: &str) -> String {
    let mut message = SUBJECT_DOMAIN.to_vec();
    message.extend_from_slice(subject.as_bytes());
    format!("hmac-sha256:{}", hex::encode(hmac_sha256(key, &message)))
}

/// HMAC-SHA256 (RFC 2104) with a 32-byte key.
fn hmac_sha256(key: &[u8; 32], message: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut block = [0u8; 64];
    block[..32].copy_from_slice(key);
    let pad = |byte: u8| block.iter().map(|k| k ^ byte).collect::<Vec<u8>>();
    let inner = Sha256::new().chain_update(pad(0x36)).chain_update(message).finalize();
    Sha256::new()
        .chain_update(pad(0x5c))
        .chain_update(inner)
        .finalize()
        .into()
}

fn holds_key(tenant_id: &str) -> DocKey {
    DocKey::new(tenant_id, DocKind::LegalHolds, "legal_holds")
}

/// One page of a subject's index; page 0 keeps the key used before pages existed.
fn page_key(tenant_id: &str, digest: &str, page: usize) -> DocKey {
    let id = if page == 0 {
        digest.to_owned()
    } else {
        format!("{digest}/p{page}")
    };
    DocKey::new(tenant_id, DocKind::SubjectIndex, id)
}

/// The digests of one run's subjects. Digests start with their algorithm, so a
/// `run:` id never collides with an index page.
fn run_subjects_key(tenant_id: &str, run_id: &str) -> DocKey {
    DocKey::new(tenant_id, DocKind::SubjectIndex, format!("run:{run_id}"))
}

fn run_list(body: &Value) -> Vec<String> {
    body["runs"]
        .as_array()
        .map(|r| r.iter().filter_map(|x| x.as_str().map(str::to_owned)).collect())
        .unwrap_or_default()
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

    /// Digests subjects with HMAC-SHA256 under `key`. With `match_unkeyed`, lookups,
    /// holds and erasure also match the unkeyed digests of runs indexed before the key
    /// was set (holds then keep those digests in the store, never in the audit chain).
    pub fn set_subject_key(&mut self, key: Option<[u8; 32]>, match_unkeyed: bool) {
        self.subject_key = key.map(|key| SubjectKey { key, match_unkeyed });
    }

    /// The digest this deployment indexes and audits `subject` under.
    #[must_use]
    pub fn subject_digest_of(&self, subject: &str) -> String {
        self.subject_key
            .as_ref()
            .map_or_else(|| subject_digest(subject), |k| keyed_subject_digest(&k.key, subject))
    }

    /// The unkeyed digest still matched for `subject`, while migrating to a key.
    fn legacy_digest_of(&self, subject: &str) -> Option<String> {
        self.subject_key
            .is_some_and(|k| k.match_unkeyed)
            .then(|| subject_digest(subject))
    }

    /// Records the run's subjects, and adds it to the index of each.
    pub(crate) async fn index_subjects(&self, admission: &RunAdmission, request: &Value) -> Result<(), GatewayError> {
        let digests: Vec<String> = subjects_in(request, &self.subject_pointers)
            .iter()
            .map(|s| self.subject_digest_of(s))
            .collect();
        if digests.is_empty() {
            return Ok(());
        }
        let record = run_subjects_key(&admission.tenant_id, &admission.run_id);
        match self.store.create(&record, &json!({"subject_digests": digests})).await {
            Ok(_) => {}
            Err(e) if e.is_conflict() => {}
            Err(e) => return Err(e.into()),
        }
        for digest in &digests {
            self.add_to_index(&admission.tenant_id, digest, &admission.run_id)
                .await?;
        }
        Ok(())
    }

    /// Appends `run_id` to the first page of `digest`'s index with room, unless a page
    /// already lists it. When every page is full the last one is marked `truncated`.
    async fn add_to_index(&self, tenant_id: &str, digest: &str, run_id: &str) -> Result<(), GatewayError> {
        'pages: for page in 0..MAX_SUBJECT_PAGES {
            let key = page_key(tenant_id, digest, page);
            for _ in 0..32 {
                let current = self.store.get(&key).await?;
                let mut body = current.as_ref().map_or_else(|| json!({"runs": []}), |c| c.body.clone());
                let mut runs = run_list(&body);
                if runs.iter().any(|r| r == run_id) {
                    return Ok(());
                }
                if runs.len() >= RUNS_PER_PAGE {
                    if page + 1 == MAX_SUBJECT_PAGES && body["truncated"] != true {
                        body["truncated"] = json!(true);
                    } else {
                        continue 'pages;
                    }
                } else {
                    runs.push(run_id.to_owned());
                    body["runs"] = json!(runs);
                }
                let written = match &current {
                    None => self.store.create(&key, &body).await.map(|_| ()),
                    Some(c) => self.store.compare_and_swap(&key, c.revision, &body).await.map(|_| ()),
                };
                match written {
                    Ok(()) => return Ok(()),
                    Err(e) if e.is_conflict() => {}
                    Err(e) => return Err(e.into()),
                }
            }
            // Contended: the run's own subject record still lets holds cover it.
            tracing::warn!("subject index contended; run not added to it");
            return Ok(());
        }
        Ok(())
    }

    /// The runs indexed under a subject digest, and whether the index was truncated.
    async fn digest_runs(&self, tenant_id: &str, digest: &str) -> Result<(Vec<String>, bool), GatewayError> {
        let (mut runs, mut truncated) = (Vec::new(), false);
        for page in 0..MAX_SUBJECT_PAGES {
            let Some(doc) = self.store.get(&page_key(tenant_id, digest, page)).await? else {
                break;
            };
            let listed = run_list(&doc.body);
            truncated |= doc.body["truncated"] == true;
            let full = listed.len() >= RUNS_PER_PAGE;
            runs.extend(listed);
            if !full {
                break;
            }
        }
        Ok((runs, truncated))
    }

    /// The runs indexed under `subject`, and whether the index was truncated.
    pub async fn subject_runs(&self, tenant_id: &str, subject: &str) -> Result<(Vec<String>, bool), GatewayError> {
        let (mut runs, mut truncated) = self.digest_runs(tenant_id, &self.subject_digest_of(subject)).await?;
        if let Some(legacy) = self.legacy_digest_of(subject) {
            let (older, cut) = self.digest_runs(tenant_id, &legacy).await?;
            runs.extend(older.into_iter().filter(|r| !runs.contains(r)).collect::<Vec<_>>());
            truncated |= cut;
        }
        Ok((runs, truncated))
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
        let holds: Vec<Value> = self
            .legal_holds(&admission.tenant_id)
            .await?
            .into_iter()
            .filter(active)
            .collect();
        let id = |hold: &Value| hold["hold_id"].as_str().unwrap_or_default().to_owned();
        if let Some(hold) = holds.iter().find(|hold| {
            hold["tenant_wide"] == true
                || hold["run_ids"]
                    .as_array()
                    .is_some_and(|r| r.iter().any(|x| x == admission.run_id.as_str()))
        }) {
            return Ok(Some(id(hold)));
        }
        let by_subject: Vec<(&Value, Vec<&str>)> = holds
            .iter()
            .map(|h| {
                (
                    h,
                    ["subject_digests", "legacy_subject_digests"]
                        .iter()
                        .flat_map(|k| h[*k].as_array().into_iter().flatten())
                        .filter_map(Value::as_str)
                        .collect(),
                )
            })
            .filter(|(_, digests): &(&Value, Vec<&str>)| !digests.is_empty())
            .collect();
        if by_subject.is_empty() {
            return Ok(None);
        }
        let record = self.run_subjects(admission).await?;
        for (hold, digests) in by_subject {
            for digest in digests {
                if self.run_has_subject(admission, digest, record.as_deref()).await? {
                    return Ok(Some(id(hold)));
                }
            }
        }
        Ok(None)
    }

    /// The digests the run recorded for its subjects; `None` for a run admitted before
    /// runs kept that record (or before subject pointers were configured).
    async fn run_subjects(&self, admission: &RunAdmission) -> Result<Option<Vec<String>>, GatewayError> {
        let doc = self
            .store
            .get(&run_subjects_key(&admission.tenant_id, &admission.run_id))
            .await?;
        Ok(doc.map(|d| {
            d.body["subject_digests"]
                .as_array()
                .map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_owned)).collect())
                .unwrap_or_default()
        }))
    }

    /// Whether a hold on `digest` covers the run. A run with its own subject record is
    /// covered exactly. One indexed before runs kept that record is looked up in the
    /// index, and counts as covered when that index is truncated: it cannot be ruled out.
    async fn run_has_subject(
        &self,
        admission: &RunAdmission,
        digest: &str,
        record: Option<&[String]>,
    ) -> Result<bool, GatewayError> {
        if let Some(digests) = record {
            return Ok(digests.iter().any(|d| d == digest));
        }
        let (runs, truncated) = self.digest_runs(&admission.tenant_id, digest).await?;
        Ok(truncated || runs.iter().any(|r| r == admission.run_id.as_str()))
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
        let digests: Vec<String> = request.subjects.iter().map(|s| self.subject_digest_of(s)).collect();
        let legacy: Vec<String> = request
            .subjects
            .iter()
            .filter_map(|s| self.legacy_digest_of(s))
            .collect();
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
            // Unkeyed digests, while migrating, are kept in the store only.
            let mut stored = hold.clone();
            if !legacy.is_empty() {
                stored["legacy_subject_digests"] = json!(legacy);
            }
            holds.push(stored);
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
        let summary = json!({"subject_digest": self.subject_digest_of(subject), "runs": runs.len(), "erased": erased,
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
    fn hmac_matches_rfc_4231() {
        // RFC 4231 test case 4: a 25-byte key, zero-padded here to 32 bytes, gives the
        // same MAC because HMAC pads keys shorter than a block with zeros.
        let mut key = [0u8; 32];
        for (i, k) in key.iter_mut().take(25).enumerate() {
            *k = u8::try_from(i + 1).unwrap();
        }
        assert_eq!(
            hex::encode(hmac_sha256(&key, &[0xcd; 50])),
            "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b"
        );
    }

    #[test]
    fn a_keyed_digest_depends_on_the_key() {
        let a = keyed_subject_digest(&[1; 32], "cus_77");
        assert!(a.starts_with("hmac-sha256:") && !a.contains("cus_77"));
        assert_eq!(a, keyed_subject_digest(&[1; 32], "cus_77"));
        assert_ne!(a, keyed_subject_digest(&[2; 32], "cus_77"));
        assert_ne!(a, subject_digest("cus_77"));
    }

    #[test]
    fn a_subject_is_kept_only_as_a_digest() {
        let d = subject_digest("cus_77");
        assert!(d.starts_with("sha256:") && !d.contains("cus_77"));
        assert_eq!(d, subject_digest("cus_77"));
        assert_ne!(d, subject_digest("cus_78"));
    }
}
