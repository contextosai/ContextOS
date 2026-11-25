//! `ctx audit-pack`: one folder for an auditor, signed, that checks itself.
//!
//! It holds the evidence pack for the export (`evidence/`, see [`crate::evidence_pack`]),
//! the inventory the export shows (`inventory.json`, `inventory.csv`), every approval
//! event in it (`approvals.json`), the packs that were in force (`packs/`, with their
//! canonical digests and any `.sig` next to them), the configuration's digest
//! (`config.json`; never its contents, which can name secret locations), a manifest of
//! every file's SHA-256, its Ed25519 signature (`manifest.sig`) and `verify.py`, which
//! checks the signature and every file with Python's standard library alone.
//!
//! The manifest is signed over `contextos-audit-pack-v1:` and its own SHA-256, by a key
//! whose seed is read only from the environment. A pack is built only from an export
//! that verifies.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use base64::Engine as _;
use contextos_contract::schema::{SchemaDoc, SchemaTarget, validate};
use ed25519_dalek::{Signer as _, SigningKey};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

use crate::{Failure, audit_verify, evidence_pack, inventory, read};

/// Prefixed to the manifest's digest before signing.
pub(crate) const DOMAIN: &str = "contextos-audit-pack-v1:";
const VERIFIER: &str = include_str!("audit_pack_verify.py");
const APPROVAL_EVENTS: [&str; 7] = [
    "approval_requested",
    "approval_redeemed",
    "approval_denied",
    "approval_timed_out",
    "approval_review_too_fast",
    "approval_step_up_refused",
    "approval_escalated",
];

pub(crate) struct Options<'a> {
    pub entries: &'a PathBuf,
    pub keys: &'a PathBuf,
    pub continues: Option<&'a PathBuf>,
    pub frameworks: &'a [String],
    pub packs: &'a [PathBuf],
    pub config: Option<&'a PathBuf>,
    pub config_report: Option<&'a PathBuf>,
    pub declarations: Option<&'a PathBuf>,
    pub seed_env: &'a str,
    pub kid: &'a str,
    pub out: &'a PathBuf,
}

fn io(path: &Path, e: &std::io::Error) -> Failure {
    Failure::Usage(format!("{}: {e}", path.display()))
}

fn sha256(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

/// Every file under `dir`, as paths relative to it, in order.
fn files(dir: &Path, base: &Path, out: &mut BTreeMap<String, String>) -> Result<(), Failure> {
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .map_err(|e| io(dir, &e))?
        .filter_map(Result::ok)
        .map(|e| e.path())
        .collect();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            files(&path, base, out)?;
        } else {
            let name = path
                .strip_prefix(base)
                .map_err(|_| Failure::Usage("pack path".into()))?
                .to_string_lossy()
                .replace('\\', "/");
            if name != "manifest.json" && name != "manifest.sig" {
                out.insert(name, sha256(&std::fs::read(&path).map_err(|e| io(&path, &e))?));
            }
        }
    }
    Ok(())
}

pub(crate) fn build(o: &Options<'_>) -> Result<Value, Failure> {
    let seed = crate::pack_sign::seed(o.seed_env)?;
    if o.out.exists() && std::fs::read_dir(o.out).map_err(|e| io(o.out, &e))?.next().is_some() {
        return Err(Failure::Usage(format!("{}: not empty", o.out.display())));
    }
    // The evidence pack verifies the export first and refuses one that does not.
    let evidence_dir = o.out.join("evidence");
    let evidence = evidence_pack::build(&evidence_pack::Options {
        entries: o.entries,
        keys: o.keys,
        continues: o.continues,
        frameworks: o.frameworks,
        config_report: o.config_report,
        out: &evidence_dir,
    })?;
    let write = |name: &str, bytes: &[u8]| -> Result<(), Failure> {
        let path = o.out.join(name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| io(parent, &e))?;
        }
        std::fs::write(&path, bytes).map_err(|e| io(&path, &e))
    };
    let pretty = |v: &Value| serde_json::to_vec_pretty(v).unwrap_or_default();

    let csv = o.out.join("inventory.csv");
    let items = inventory::build(&inventory::Options {
        entries: o.entries,
        keys: o.keys,
        continues: o.continues,
        source: "export",
        environment: None,
        declarations: o.declarations,
        csv: Some(&csv),
        fail_on_shadow: false,
    })?;
    write("inventory.json", &pretty(&items))?;

    let (_, chain) = audit_verify::verify(o.entries, o.keys, o.continues)?;
    let approvals: Vec<Value> = chain
        .iter()
        .filter(|e| APPROVAL_EVENTS.contains(&e.kind.as_str()))
        .map(|e| json!({"sequence": e.sequence, "kind": e.kind, "emitted_at": e.emitted_at, "payload": e.payload}))
        .collect();
    write("approvals.json", &pretty(&json!({"approvals": approvals})))?;

    let mut pack_rows = Vec::new();
    for path in o.packs {
        let value = read(path)?;
        if validate(&SchemaTarget::document(SchemaDoc::ContextPack), &value).is_err() {
            return Err(Failure::Usage(format!("{}: not a valid context pack", path.display())));
        }
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .ok_or_else(|| Failure::Usage(format!("{}: no file name", path.display())))?;
        if pack_rows.iter().any(|r: &Value| r["file"] == format!("packs/{name}")) {
            return Err(Failure::Usage(format!("two packs named {name}")));
        }
        write(
            &format!("packs/{name}"),
            &std::fs::read(path).map_err(|e| io(path, &e))?,
        )?;
        let mut sig = path.as_os_str().to_owned();
        sig.push(".sig");
        let signed = Path::new(&sig).is_file();
        if signed {
            write(
                &format!("packs/{name}.sig"),
                &std::fs::read(&sig).map_err(|e| io(Path::new(&sig), &e))?,
            )?;
        }
        let digest =
            contextos_contract::canonical::sha256_canonical(&value).map_err(|e| Failure::Usage(e.to_string()))?;
        pack_rows.push(json!({"file": format!("packs/{name}"), "pack_ref": format!("{}@{}",
            value["pack_meta"]["pack_id"].as_str().unwrap_or("?"), value["pack_meta"]["pack_version"].as_str().unwrap_or("?")),
            "pack_sha256": digest, "signature": signed}));
    }
    write("packs.json", &pretty(&json!({"packs": pack_rows})))?;
    if let Some(config) = o.config {
        let bytes = std::fs::read(config).map_err(|e| io(config, &e))?;
        write(
            "config.json",
            &pretty(&json!({"file": config.file_name().map(|n| n.to_string_lossy()),
            "sha256": sha256(&bytes), "note": "The configuration's digest only: compare it with the deployed file."})),
        )?;
    }
    write("verify.py", VERIFIER.as_bytes())?;

    let mut listed = BTreeMap::new();
    files(o.out, o.out, &mut listed)?;
    let manifest = json!({"audit_pack_version": "contextos.audit_pack.v1", "period": evidence["period"],
        "frameworks": o.frameworks, "files": listed});
    let manifest_bytes = pretty(&manifest);
    write("manifest.json", &manifest_bytes)?;
    let digest = sha256(&manifest_bytes);
    let key = SigningKey::from_bytes(&seed);
    let b64 = |b: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b);
    let signature = key.sign(format!("{DOMAIN}{digest}").as_bytes());
    let public_key = b64(key.verifying_key().as_bytes());
    write(
        "manifest.sig",
        &pretty(&json!({"alg": "ed25519", "kid": o.kid, "manifest_sha256": digest,
        "public_key": public_key, "signature": b64(&signature.to_bytes())})),
    )?;
    Ok(
        json!({"written": o.out.display().to_string(), "manifest_sha256": digest, "files": listed.len(),
        "kid": o.kid, "public_key": public_key,
        "verify": "python3 verify.py --public-key <the publisher's key, obtained independently>"}),
    )
}
