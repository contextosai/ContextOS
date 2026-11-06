//! RFC 8785 canonical JSON, which every digest and signature covers: canonical text
//! parses back to the same value and is a fixed point.
#![no_main]

use contextos_contract::canonical::canonicalize;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(data) else {
        return;
    };
    let Ok(canonical) = canonicalize(&value) else {
        return;
    };
    let reparsed: serde_json::Value = serde_json::from_str(&canonical).expect("canonical text is JSON");
    let again = canonicalize(&reparsed).expect("canonical text canonicalizes");
    assert_eq!(canonical, again, "canonicalization is a fixed point");
});
