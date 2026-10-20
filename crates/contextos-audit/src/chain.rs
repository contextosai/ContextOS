//! Signed, hash-chained audit entries.
//!
//! Each entry commits to its tenant, sequence, predecessor hash, kind, emission time
//! and the digest of its payload. The record hash is `sha256` over RFC 8785 JSON of
//! those fields under the `contextos.audit_entry.v1` domain, and is signed with
//! ed25519. Verification detects edits, deletions, insertions, reordering, forks and
//! entries signed by unknown or revoked keys.

use std::collections::HashMap;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use contextos_contract::canonical::{CanonicalError, domain_digest, sha256_canonical};
use contextos_contract::validation::{compare_contract_times, is_contract_timestamp};
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const ENTRY_VERSION: &str = "contextos.audit_entry.v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntrySignature {
    pub alg: String,
    pub kid: String,
    pub sig: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditEntry {
    pub entry_version: String,
    pub tenant_id: String,
    pub sequence: u64,
    pub prev_hash: Option<String>,
    pub kind: String,
    pub emitted_at: String,
    pub payload_digest: String,
    pub payload: Value,
    pub record_hash: String,
    pub signature: EntrySignature,
}

/// The fields covered by `record_hash`. The payload is covered by its digest so a
/// verifier holding only the chain spine can still check linkage.
#[derive(Serialize)]
struct Spine<'a> {
    entry_version: &'a str,
    tenant_id: &'a str,
    sequence: u64,
    prev_hash: Option<&'a str>,
    kind: &'a str,
    emitted_at: &'a str,
    payload_digest: &'a str,
}

fn record_hash(entry: &Spine<'_>) -> Result<String, CanonicalError> {
    domain_digest(ENTRY_VERSION, entry)
}

/// An ed25519 signing key with a stable key id. Key material is zeroized on drop.
pub struct AuditSigner {
    kid: String,
    key: SigningKey,
}

impl std::fmt::Debug for AuditSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditSigner")
            .field("kid", &self.kid)
            .finish_non_exhaustive()
    }
}

impl AuditSigner {
    /// Builds a signer from a 32-byte seed held by a KMS/HSM-backed secret source.
    pub fn from_seed(kid: impl Into<String>, mut seed: [u8; 32]) -> Self {
        let key = SigningKey::from_bytes(&seed);
        zeroize::Zeroize::zeroize(&mut seed);
        Self { kid: kid.into(), key }
    }

    pub fn kid(&self) -> &str {
        &self.kid
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.key.verifying_key()
    }

    fn sign(&self, message: &str) -> EntrySignature {
        let signature = self.key.sign(message.as_bytes());
        EntrySignature {
            alg: "ed25519".into(),
            kid: self.kid.clone(),
            sig: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ChainError {
    #[error("entry {index}: {reason}")]
    Invalid { index: usize, reason: &'static str },
    #[error(transparent)]
    Encoding(#[from] CanonicalError),
}

fn invalid(index: usize, reason: &'static str) -> ChainError {
    ChainError::Invalid { index, reason }
}

/// The parts of a chain head the next entry links to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainHead {
    pub sequence: u64,
    pub record_hash: String,
    pub emitted_at: String,
}

impl From<&AuditEntry> for ChainHead {
    fn from(entry: &AuditEntry) -> Self {
        Self {
            sequence: entry.sequence,
            record_hash: entry.record_hash.clone(),
            emitted_at: entry.emitted_at.clone(),
        }
    }
}

/// Builds the next entry on top of `head` (or the genesis entry when `head` is None).
/// `emitted_at` comes from the runtime's trusted clock; it must not precede the head.
pub fn next_entry(
    head: Option<&AuditEntry>,
    tenant_id: &str,
    kind: &str,
    payload: Value,
    emitted_at: &str,
    signer: &AuditSigner,
) -> Result<AuditEntry, ChainError> {
    if head.is_some_and(|h| h.tenant_id != tenant_id) {
        return Err(invalid(0, "head belongs to another tenant"));
    }
    let payload_digest = sha256_canonical(&payload)?;
    link_entry(
        head.map(ChainHead::from).as_ref(),
        tenant_id,
        kind,
        payload,
        payload_digest,
        emitted_at,
        signer,
    )
}

/// The chain linkage and signature of the next entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Link {
    pub sequence: u64,
    pub prev_hash: Option<String>,
    pub record_hash: String,
    pub signature: EntrySignature,
}

/// Links and signs the next entry for a payload with a known canonical digest. This
/// is all of an append that has to happen in a chain's serial section.
pub fn link(
    head: Option<&ChainHead>,
    tenant_id: &str,
    kind: &str,
    payload_digest: &str,
    emitted_at: &str,
    signer: &AuditSigner,
) -> Result<Link, ChainError> {
    if !is_contract_timestamp(emitted_at) {
        return Err(invalid(0, "emitted_at is not a contract timestamp"));
    }
    if head.is_some_and(|h| compare_contract_times(emitted_at, &h.emitted_at) == Some(std::cmp::Ordering::Less)) {
        return Err(invalid(0, "emitted_at precedes the chain head"));
    }
    let sequence = head.map_or(1, |h| h.sequence + 1);
    let prev_hash = head.map(|h| h.record_hash.clone());
    let record_hash = record_hash(&Spine {
        entry_version: ENTRY_VERSION,
        tenant_id,
        sequence,
        prev_hash: prev_hash.as_deref(),
        kind,
        emitted_at,
        payload_digest,
    })?;
    let signature = signer.sign(&record_hash);
    Ok(Link {
        sequence,
        prev_hash,
        record_hash,
        signature,
    })
}

/// Assembles an entry from its linkage.
pub fn assemble_entry(
    link: Link,
    tenant_id: &str,
    kind: &str,
    emitted_at: &str,
    payload: Value,
    payload_digest: String,
) -> AuditEntry {
    AuditEntry {
        entry_version: ENTRY_VERSION.into(),
        tenant_id: tenant_id.into(),
        sequence: link.sequence,
        prev_hash: link.prev_hash,
        kind: kind.into(),
        emitted_at: emitted_at.into(),
        payload_digest,
        payload,
        record_hash: link.record_hash,
        signature: link.signature,
    }
}

/// As [`next_entry`] for a payload whose canonical digest is already known.
pub fn link_entry(
    head: Option<&ChainHead>,
    tenant_id: &str,
    kind: &str,
    payload: Value,
    payload_digest: String,
    emitted_at: &str,
    signer: &AuditSigner,
) -> Result<AuditEntry, ChainError> {
    let link = link(head, tenant_id, kind, &payload_digest, emitted_at, signer)?;
    Ok(assemble_entry(
        link,
        tenant_id,
        kind,
        emitted_at,
        payload,
        payload_digest,
    ))
}

/// Public keys accepted for verification, by key id.
#[derive(Debug, Clone, Default)]
pub struct KeyRing {
    keys: HashMap<String, VerifyingKey>,
    /// For retired keys: the last emission time they may have signed.
    retired_at: HashMap<String, String>,
}

impl KeyRing {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, kid: impl Into<String>, key: VerifyingKey) {
        self.keys.insert(kid.into(), key);
    }

    pub fn remove(&mut self, kid: &str) {
        self.keys.remove(kid);
        self.retired_at.remove(kid);
    }

    /// Trusts a retired key only for entries emitted at or before `retired_at` (a
    /// contract timestamp): a retired key that later leaks cannot sign new history.
    pub fn insert_retired(&mut self, kid: impl Into<String>, key: VerifyingKey, retired_at: impl Into<String>) {
        let kid = kid.into();
        self.keys.insert(kid.clone(), key);
        self.retired_at.insert(kid, retired_at.into());
    }

    /// When a key was retired, if it was.
    pub fn retired_at(&self, kid: &str) -> Option<&str> {
        self.retired_at.get(kid).map(String::as_str)
    }

    /// `(kid, base64url public key, retired_at)` for every trusted key, sorted by key
    /// id, so they can be published to independent verifiers.
    pub fn public_keys(&self) -> Vec<(String, String, Option<String>)> {
        let mut keys: Vec<(String, String, Option<String>)> = self
            .keys
            .iter()
            .map(|(kid, key)| {
                (
                    kid.clone(),
                    URL_SAFE_NO_PAD.encode(key.as_bytes()),
                    self.retired_at.get(kid).cloned(),
                )
            })
            .collect();
        keys.sort();
        keys
    }

    fn verify(&self, signature: &EntrySignature, message: &str) -> bool {
        let Some(key) = self.keys.get(&signature.kid) else {
            return false;
        };
        if signature.alg != "ed25519" {
            return false;
        }
        let Ok(bytes) = URL_SAFE_NO_PAD.decode(&signature.sig) else {
            return false;
        };
        let Ok(bytes) = <[u8; 64]>::try_from(bytes.as_slice()) else {
            return false;
        };
        key.verify_strict(message.as_bytes(), &Signature::from_bytes(&bytes))
            .is_ok()
    }
}

/// Verifies one entry in isolation (hashes and signature).
pub fn verify_entry(entry: &AuditEntry, keys: &KeyRing, index: usize) -> Result<(), ChainError> {
    if entry.entry_version != ENTRY_VERSION {
        return Err(invalid(index, "unsupported entry version"));
    }
    if sha256_canonical(&entry.payload)? != entry.payload_digest {
        return Err(invalid(index, "payload digest mismatch"));
    }
    let hash = record_hash(&Spine {
        entry_version: &entry.entry_version,
        tenant_id: &entry.tenant_id,
        sequence: entry.sequence,
        prev_hash: entry.prev_hash.as_deref(),
        kind: &entry.kind,
        emitted_at: &entry.emitted_at,
        payload_digest: &entry.payload_digest,
    })?;
    if hash != entry.record_hash {
        return Err(invalid(index, "record hash mismatch"));
    }
    if !keys.verify(&entry.signature, &entry.record_hash) {
        return Err(invalid(index, "signature invalid or key not trusted"));
    }
    if let Some(retired_at) = keys.retired_at(&entry.signature.kid) {
        // Only history the key signed before it was retired; unparseable times fail.
        let before = matches!(
            compare_contract_times(&entry.emitted_at, retired_at),
            Some(std::cmp::Ordering::Less | std::cmp::Ordering::Equal)
        );
        if !before {
            return Err(invalid(index, "signed by a key after it was retired"));
        }
    }
    Ok(())
}

/// Verifies a contiguous chain segment. When `anchor` is given (the entry just before
/// the segment, already trusted) linkage is checked across the boundary; otherwise the
/// segment must start at the genesis entry.
pub fn verify_chain(entries: &[AuditEntry], anchor: Option<&AuditEntry>, keys: &KeyRing) -> Result<(), ChainError> {
    let mut previous = anchor;
    for (index, entry) in entries.iter().enumerate() {
        verify_entry(entry, keys, index)?;
        match previous {
            None => {
                if entry.sequence != 1 || entry.prev_hash.is_some() {
                    return Err(invalid(index, "chain does not start at genesis"));
                }
            }
            Some(prev) => {
                if entry.tenant_id != prev.tenant_id {
                    return Err(invalid(index, "tenant changes within chain"));
                }
                if entry.sequence != prev.sequence + 1 {
                    return Err(invalid(index, "sequence gap or reorder"));
                }
                if entry.prev_hash.as_deref() != Some(prev.record_hash.as_str()) {
                    return Err(invalid(index, "broken hash link"));
                }
                if compare_contract_times(&entry.emitted_at, &prev.emitted_at) == Some(std::cmp::Ordering::Less) {
                    return Err(invalid(index, "emission time moves backwards"));
                }
            }
        }
        previous = Some(entry);
    }
    Ok(())
}
