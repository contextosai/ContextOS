//! `ctx audit-verify`: checks an audit export's linkage and signatures against the
//! published keys, offline. `ctx evidence-pack` builds on the same check.

use std::path::PathBuf;

use base64::Engine as _;
use contextos_audit::{AuditEntry, KeyRing, verify_chain_withheld};
use serde_json::{Value, json};

use crate::{Failure, read, typed};

/// Verifies the entries in `entries` (continuing `continues`, when given) against the
/// keys in `keys`. Returns the report and the verified entries.
pub(crate) fn verify(
    entries: &PathBuf,
    keys: &PathBuf,
    continues: Option<&PathBuf>,
) -> Result<(Value, Vec<AuditEntry>), Failure> {
    let loaded = read(entries)?;
    let list = loaded.get("entries").cloned().unwrap_or(loaded);
    // Entries an audit sink delivered with masked payloads say so; only their
    // spine (linkage and signature) can be verified.
    let withheld: Vec<bool> = list
        .as_array()
        .map(|l| l.iter().map(|e| e.get("masked").is_some()).collect())
        .unwrap_or_default();
    let chain: Vec<AuditEntry> = typed(list, "entries")?;
    let mut ring = KeyRing::new();
    let published = read(keys)?;
    let list = published["keys"]
        .as_array()
        .filter(|k| !k.is_empty())
        .ok_or_else(|| Failure::Usage(format!("{}: no keys", keys.display())))?;
    let mut seen = std::collections::HashSet::new();
    for key in list {
        // A malformed key entry must never silently become a fully trusted key.
        let kid = key["kid"].as_str().unwrap_or_default();
        let retired_ok = key.get("retired_at").is_none_or(|r| {
            r.as_str()
                .is_some_and(contextos_contract::validation::is_contract_timestamp)
        });
        if kid.is_empty() || key["alg"] != "ed25519" || !retired_ok || !seen.insert(kid.to_owned()) {
            return Err(Failure::Usage(format!(
                "{}: each key needs a unique kid, alg ed25519 and, if retired, a valid retired_at",
                keys.display()
            )));
        }
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(key["public_key"].as_str().unwrap_or_default())
            .ok()
            .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
            .and_then(|b| ed25519_dalek::VerifyingKey::from_bytes(&b).ok())
            .ok_or_else(|| Failure::Usage(format!("{}: invalid public key", keys.display())))?;
        match key["retired_at"].as_str() {
            Some(retired_at) => ring.insert_retired(kid, bytes, retired_at),
            None => ring.insert(kid, bytes),
        }
    }
    let anchor: Option<AuditEntry> = match continues {
        Some(path) => Some(typed(read(path)?, "anchor entry")?),
        None => None,
    };
    if chain.is_empty() {
        return Err(Failure::Rejected(
            json!({"verified": false, "error": "no entries to verify"}),
        ));
    }
    let unverified: Vec<u64> = chain
        .iter()
        .zip(&withheld)
        .filter(|(_, w)| **w)
        .map(|(e, _)| e.sequence)
        .collect();
    match verify_chain_withheld(&chain, anchor.as_ref(), &ring, &withheld) {
        // The anchor is assumed, not checked: report it so a reader sees which
        // verified prefix the result rests on.
        Ok(()) => Ok((
            json!({"verified": true, "entries": chain.len(),
            "anchor_sequence": anchor.as_ref().map(|a| a.sequence),
            "anchor_record_hash": anchor.as_ref().map(|a| a.record_hash.clone()),
            "tenant_id": chain.first().map(|e| e.tenant_id.clone()),
            "last_sequence": chain.last().map(|e| e.sequence),
            "last_record_hash": chain.last().map(|e| e.record_hash.clone()),
            "payload_unverified_sequences": unverified}),
            chain,
        )),
        Err(error) => Err(Failure::Rejected(
            json!({"verified": false, "error": error.to_string()}),
        )),
    }
}
