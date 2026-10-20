fn main() {
    // Python resolves interpreter symbols at load time (macOS needs -undefined dynamic_lookup).
    pyo3_build_config::add_extension_module_link_args();
}
