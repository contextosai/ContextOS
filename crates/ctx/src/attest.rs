//! `ctx attest`: sign claims as an evidence issuer or outcome witness would.
//!
//! For building and testing an issuer: the claims (a JSON object, for example
//! `{iss, sub, satisfies, observed_at, valid_until, amount}`) are signed as a compact
//! JWS with EdDSA under a 32-byte seed read from an environment variable, never from
//! the command line. The output also carries the JWK Set to configure as the
//! issuer's `jwks` in `[[evidence_issuers]]`. A production issuer signs with its own
//! keys, in its own service.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{Value, json};

/// Signs `claims` under the hex `seed` with key id `kid`: `{attestation, jwks}`.
pub fn attest(claims: &Value, seed: &str, kid: &str) -> Result<Value, String> {
    if !claims.is_object() || !claims["iss"].is_string() {
        return Err("claims must be a JSON object with an iss".into());
    }
    let bytes: [u8; 32] = hex::decode(seed.trim())
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or("the seed must be 32 bytes, hex encoded")?;
    let key = SigningKey::from_bytes(&bytes);
    let header = json!({"alg": "EdDSA", "typ": "JWT", "kid": kid});
    let encode = |v: &Value| URL_SAFE_NO_PAD.encode(v.to_string());
    let input = format!("{}.{}", encode(&header), encode(claims));
    let signature = URL_SAFE_NO_PAD.encode(key.sign(input.as_bytes()).to_bytes());
    let public = URL_SAFE_NO_PAD.encode(key.verifying_key().to_bytes());
    Ok(json!({
        "attestation": format!("{input}.{signature}"),
        "jwks": {"keys": [{"kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "kid": kid, "x": public}]},
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signs_a_verifiable_compact_jws_and_publishes_its_key() {
        let out = attest(
            &json!({"iss": "https://ledger.test", "sub": "ord_881"}),
            &"11".repeat(32),
            "k1",
        )
        .unwrap();
        let token = out["attestation"].as_str().unwrap();
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3);
        let x = URL_SAFE_NO_PAD
            .decode(out["jwks"]["keys"][0]["x"].as_str().unwrap())
            .unwrap();
        let key = ed25519_dalek::VerifyingKey::from_bytes(&x.try_into().unwrap()).unwrap();
        let signature = ed25519_dalek::Signature::from_slice(&URL_SAFE_NO_PAD.decode(parts[2]).unwrap()).unwrap();
        key.verify_strict(format!("{}.{}", parts[0], parts[1]).as_bytes(), &signature)
            .unwrap();
        assert!(attest(&json!({"sub": "x"}), &"11".repeat(32), "k1").is_err());
        assert!(attest(&json!({"iss": "x"}), "abcd", "k1").is_err());
    }
}
