//! Detached Ed25519 signatures over Context Packs.
//!
//! A pack is signed by its canonical digest (the `sha256` the runtime binds each pack
//! reference to), with a domain-separation prefix so a pack signature can never be
//! replayed as any other ContextOS signature. The signature file sits next to the pack
//! as `<pack file>.sig`:
//!
//! ```json
//! {"alg": "ed25519", "kid": "release-2026", "pack_sha256": "sha256:…", "signature": "<base64url>"}
//! ```
//!
//! `ctx pack-sign` writes it; `contextosd` with `[pack_signing]` refuses a pack whose
//! signature is missing, malformed, by an untrusted key or over other content.

use base64::Engine as _;
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use serde_json::{Value, json};

/// Prefixed to the digest before signing.
pub const DOMAIN: &str = "contextos-pack-signature-v1:";

fn message(pack_sha256: &str) -> Vec<u8> {
    format!("{DOMAIN}{pack_sha256}").into_bytes()
}

/// The signature document for a pack with this digest.
#[must_use]
pub fn sign(seed: &[u8; 32], kid: &str, pack_sha256: &str) -> Value {
    let key = SigningKey::from_bytes(seed);
    let signature = key.sign(&message(pack_sha256));
    json!({"alg": "ed25519", "kid": kid, "pack_sha256": pack_sha256,
        "signature": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature.to_bytes())})
}

/// The base64url public key for a seed, as a trusted-key entry names it.
#[must_use]
pub fn public_key(seed: &[u8; 32]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(SigningKey::from_bytes(seed).verifying_key().as_bytes())
}

/// Decodes a base64url Ed25519 public key.
pub fn decode_public_key(encoded: &str) -> Option<VerifyingKey> {
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(encoded).ok()?;
    VerifyingKey::from_bytes(&<[u8; 32]>::try_from(bytes.as_slice()).ok()?).ok()
}

/// Why a pack signature was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// Not a signature document of this format.
    Malformed,
    /// Signed by a key that is not trusted.
    UntrustedKey,
    /// Signs other content than this pack.
    OtherContent,
    /// The signature does not verify.
    Invalid,
}

impl Refusal {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Malformed => "pack_signature_malformed",
            Self::UntrustedKey => "pack_signature_untrusted",
            Self::OtherContent => "pack_signature_other_content",
            Self::Invalid => "pack_signature_invalid",
        }
    }
}

/// Verifies `signature` for a pack with digest `pack_sha256` against trusted
/// `(kid, key)` pairs. Returns the signing key's id.
pub fn verify<'a>(
    signature: &Value,
    pack_sha256: &str,
    trusted: impl IntoIterator<Item = (&'a str, &'a VerifyingKey)>,
) -> Result<String, Refusal> {
    let (Some(kid), Some(signed), Some(encoded)) = (
        signature["kid"].as_str(),
        signature["pack_sha256"].as_str(),
        signature["signature"].as_str(),
    ) else {
        return Err(Refusal::Malformed);
    };
    if signature["alg"] != "ed25519" {
        return Err(Refusal::Malformed);
    }
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| Refusal::Malformed)?;
    let sig = Signature::from_slice(&bytes).map_err(|_| Refusal::Malformed)?;
    let key = trusted
        .into_iter()
        .find(|(id, _)| *id == kid)
        .map(|(_, key)| key)
        .ok_or(Refusal::UntrustedKey)?;
    if signed != pack_sha256 {
        return Err(Refusal::OtherContent);
    }
    key.verify_strict(&message(pack_sha256), &sig)
        .map_err(|_| Refusal::Invalid)?;
    Ok(kid.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_signature_verifies_only_for_its_pack_and_a_trusted_key() {
        let seed = [3; 32];
        let key = decode_public_key(&public_key(&seed)).unwrap();
        let other = decode_public_key(&public_key(&[4; 32])).unwrap();
        let sig = sign(&seed, "release", "sha256:aa");
        assert_eq!(verify(&sig, "sha256:aa", [("release", &key)]), Ok("release".into()));
        assert_eq!(
            verify(&sig, "sha256:bb", [("release", &key)]),
            Err(Refusal::OtherContent)
        );
        assert_eq!(verify(&sig, "sha256:aa", [("other", &key)]), Err(Refusal::UntrustedKey));
        // The right kid with another key: the signature does not verify.
        assert_eq!(verify(&sig, "sha256:aa", [("release", &other)]), Err(Refusal::Invalid));
        // Claiming another digest does not help: the signature covers the real one.
        let mut forged = sig.clone();
        forged["pack_sha256"] = json!("sha256:bb");
        assert_eq!(verify(&forged, "sha256:bb", [("release", &key)]), Err(Refusal::Invalid));
        assert_eq!(
            verify(&json!({"kid": "release"}), "sha256:aa", [("release", &key)]),
            Err(Refusal::Malformed)
        );
    }
}
