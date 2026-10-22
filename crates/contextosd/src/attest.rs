//! Signed conformance attestations.
//!
//! The kernel assesses an already-verified conformance report; this module is that
//! verification. Every attested object must carry an Ed25519 signature by the trusted
//! principal it names, made over a domain-separated digest:
//!
//! - the report, together with the contract and features it was assessed against, by
//!   the assessor named as its `evaluator` (so the caller cannot swap in a weaker
//!   contract);
//! - the report verification, by the evidence observer it names;
//! - each evidence observation, by the observer it names.
//!
//! Signed message: the UTF-8 text of `sha256_canonical({"domain": <domain>, "attested":
//! <object>})`. Keys are configured per principal; a caller cannot supply them.

use base64::Engine as _;
use contextos_contract::canonical::sha256_canonical;
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

pub const REPORT_DOMAIN: &str = "contextos.conformance_report_attestation.v1";
pub const VERIFICATION_DOMAIN: &str = "contextos.conformance_verification_attestation.v1";
pub const OBSERVATION_DOMAIN: &str = "contextos.control_evidence_attestation.v1";

/// A trusted principal and the Ed25519 key its attestations are signed with.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedSigner {
    pub principal: Value,
    /// Base64 (standard) of the 32-byte Ed25519 public key.
    pub public_key: String,
}

/// The message a signer signs for `attested` in `domain`.
pub fn message(domain: &str, attested: &Value) -> String {
    sha256_canonical(&json!({"domain": domain, "attested": attested})).unwrap_or_default()
}

fn key(signer: &TrustedSigner) -> Option<VerifyingKey> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(&signer.public_key)
        .ok()?;
    VerifyingKey::from_bytes(&bytes.try_into().ok()?).ok()
}

/// Whether `signature` (base64) over `attested` is by the key of the trusted signer
/// whose principal equals `named`.
pub fn verify(signers: &[TrustedSigner], named: &Value, domain: &str, attested: &Value, signature: &Value) -> bool {
    let Some(signature) = signature
        .as_str()
        .and_then(|s| base64::engine::general_purpose::STANDARD.decode(s).ok())
        .and_then(|b| Signature::from_slice(&b).ok())
    else {
        return false;
    };
    let message = message(domain, attested);
    signers
        .iter()
        .filter(|s| &s.principal == named)
        .filter_map(key)
        .any(|k| k.verify(message.as_bytes(), &signature).is_ok())
}
