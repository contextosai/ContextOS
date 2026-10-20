#[test]
fn example_config_parses() {
    let path = format!("{}/../../deploy/contextosd.example.toml", env!("CARGO_MANIFEST_DIR"));
    contextosd::Config::load(std::path::Path::new(&path)).unwrap();
}
