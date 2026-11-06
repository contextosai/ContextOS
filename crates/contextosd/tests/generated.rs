//! Files generated from code must match it: the configuration schema and reference,
//! and the metric catalog. `CONTEXTOS_BLESS=1 cargo test -p contextosd --test generated`
//! rewrites them.

use std::path::PathBuf;

fn repo(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..").join(path)
}

fn matches(path: &str, generated: &str) {
    let file = repo(path);
    if std::env::var_os("CONTEXTOS_BLESS").is_some() {
        std::fs::write(&file, generated).unwrap();
        return;
    }
    let committed = std::fs::read_to_string(&file).unwrap_or_default();
    assert!(
        committed == generated,
        "{path} is stale: run CONTEXTOS_BLESS=1 cargo test -p contextosd --test generated and commit the result"
    );
}

#[test]
fn configuration_schema_and_reference_are_current() {
    let schema = contextosd::config_schema::schema();
    matches(
        "deploy/contextosd-config.schema.json",
        &format!("{}\n", serde_json::to_string_pretty(&schema).unwrap()),
    );
    matches("docs/CONFIG.md", &contextosd::config_schema::reference(&schema));
}

#[test]
fn metric_reference_is_current() {
    matches("docs/METRICS.md", &contextosd::metrics_reference::reference());
}

#[test]
fn the_example_configurations_satisfy_the_schema() {
    let schema = contextosd::config_schema::schema();
    let validator = jsonschema::validator_for(&schema).unwrap();
    for path in [
        "deploy/contextosd.example.toml",
        "examples/support-refund/contextosd.toml",
    ] {
        let Ok(text) = std::fs::read_to_string(repo(path)) else {
            continue;
        };
        let config: toml::Value = toml::from_str(&text).unwrap();
        let config = serde_json::to_value(config).unwrap();
        let errors: Vec<String> = validator
            .iter_errors(&config)
            .map(|e| format!("{}: {e}", e.instance_path()))
            .collect();
        assert!(errors.is_empty(), "{path}: {errors:#?}");
    }
}
