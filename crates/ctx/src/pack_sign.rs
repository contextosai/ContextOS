//! `ctx pack-sign`: a detached signature for a Context Pack, written next to it as
//! `<file>.sig`, for deployments that set `[pack_signing]` (see
//! [`contextos_audit::pack_signature`]).
//!
//! The pack is validated against context-pack.v2 and signed by the same canonical
//! digest the runtime binds its reference to. The seed is read from an environment
//! variable, never from the command line, so it stays out of shell history and logs.

use std::path::{Path, PathBuf};

use contextos_audit::pack_signature::{public_key, sign};
use contextos_contract::schema::{SchemaDoc, SchemaTarget, validate};
use serde_json::{Value, json};

use crate::{Failure, read};

/// The 32-byte seed in `var`, hex encoded (`openssl rand -hex 32`).
pub(crate) fn seed(var: &str) -> Result<[u8; 32], Failure> {
    let text = std::env::var(var).map_err(|_| Failure::Usage(format!("{var} is not set (64 hex characters)")))?;
    hex::decode(text.trim())
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
        .ok_or_else(|| Failure::Usage(format!("{var} must hold 32 bytes as hex")))
}

/// The trusted-key entry for the seed in `var`, for `[[pack_signing.trusted_keys]]`.
pub(crate) fn trusted_key(var: &str, kid: &str) -> Result<Value, Failure> {
    Ok(json!({"kid": kid, "public_key": public_key(&seed(var)?)}))
}

fn sig_path(pack: &Path) -> PathBuf {
    let mut p = pack.as_os_str().to_owned();
    p.push(".sig");
    PathBuf::from(p)
}

/// Signs `pack` and writes `<pack>.sig`.
pub(crate) fn sign_pack(pack: &PathBuf, var: &str, kid: &str) -> Result<Value, Failure> {
    let value = read(pack)?;
    if let Err(e) = validate(&SchemaTarget::document(SchemaDoc::ContextPack), &value) {
        return Err(Failure::Usage(format!(
            "{}: does not conform to context-pack.v2 ({} violation(s)); only a valid pack is signed",
            pack.display(),
            e.violations.len()
        )));
    }
    let digest = contextos_contract::canonical::sha256_canonical(&value).map_err(|e| Failure::Usage(e.to_string()))?;
    let seed = seed(var)?;
    let signature = sign(&seed, kid, &digest);
    let out = sig_path(pack);
    std::fs::write(&out, format!("{signature}\n")).map_err(|e| Failure::Usage(format!("{}: {e}", out.display())))?;
    Ok(
        json!({"pack_sha256": digest, "kid": kid, "signature_file": out.display().to_string(),
        "trusted_key": {"kid": kid, "public_key": public_key(&seed)}}),
    )
}
