//! `ctx pack-sign` writes a signature the runtime accepts: over the pack's canonical
//! digest, by the key whose trusted-key entry it prints, with the seed only ever read
//! from the environment.

use std::process::Command;

use contextos_audit::pack_signature::{decode_public_key, verify};
use serde_json::Value;

const SEED: &str = "1515151515151515151515151515151515151515151515151515151515151515";

fn pack() -> Value {
    let path = format!("{}/../../conformance/vectors/compiler.json", env!("CARGO_MANIFEST_DIR"));
    let vectors: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    vectors["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "grid:support.refund:true:4200:support_agent")
        .unwrap()["pack"]
        .clone()
}

fn ctx(args: &[&str], seed: Option<&str>) -> (i32, Value, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_ctx"));
    cmd.args(args).env_remove("CONTEXTOS_PACK_SIGNING_SEED");
    if let Some(seed) = seed {
        cmd.env("CONTEXTOS_PACK_SIGNING_SEED", seed);
    }
    let out = cmd.output().unwrap();
    (
        out.status.code().unwrap(),
        serde_json::from_slice(&out.stdout).unwrap_or(Value::Null),
        String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr),
    )
}

#[test]
fn a_signed_pack_verifies_against_the_printed_key() {
    let dir = std::env::temp_dir().join(format!("ctx-pack-sign-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("support.json");
    let pack = pack();
    std::fs::write(&file, pack.to_string()).unwrap();
    let path = file.display().to_string();

    let (code, report, output) = ctx(&["pack-sign", "--pack", &path, "--kid", "release"], Some(SEED));
    assert_eq!(code, 0, "{output}");
    assert!(!output.contains(SEED), "the seed is never printed");
    let digest = contextos_contract::canonical::sha256_canonical(&pack).unwrap();
    assert_eq!(report["pack_sha256"], digest.as_str());
    let signature: Value =
        serde_json::from_str(&std::fs::read_to_string(dir.join("support.json.sig")).unwrap()).unwrap();
    let key = decode_public_key(report["trusted_key"]["public_key"].as_str().unwrap()).unwrap();
    assert_eq!(
        verify(&signature, &digest, [("release", &key)]),
        Ok("release".to_owned())
    );

    let (code, entry, _) = ctx(&["pack-sign", "--public-key", "--kid", "release"], Some(SEED));
    assert_eq!((code, &entry), (0, &report["trusted_key"]));
    let (code, _, output) = ctx(&["pack-sign", "--pack", &path, "--kid", "release"], None);
    assert_ne!(code, 0);
    assert!(output.contains("CONTEXTOS_PACK_SIGNING_SEED is not set"), "{output}");
    std::fs::write(&file, "{\"not\": \"a pack\"}").unwrap();
    let (code, _, output) = ctx(&["pack-sign", "--pack", &path, "--kid", "release"], Some(SEED));
    assert_ne!(code, 0, "{output}");
    std::fs::remove_dir_all(dir).ok();
}
