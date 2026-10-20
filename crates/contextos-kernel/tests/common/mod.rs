//! Shared loader for reference vectors (`conformance/vectors`, plain or gzipped JSON).

use std::io::Read;

use serde_json::Value;

pub fn load(name: &str) -> Value {
    let path = format!("{}/../../conformance/vectors/{name}", env!("CARGO_MANIFEST_DIR"));
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    let text = if std::path::Path::new(name)
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("gz"))
    {
        let mut text = String::new();
        flate2::read::GzDecoder::new(bytes.as_slice())
            .read_to_string(&mut text)
            .expect("gzip vector");
        text
    } else {
        String::from_utf8(bytes).expect("utf-8 vector")
    };
    serde_json::from_str(&text).expect("vector is JSON")
}
