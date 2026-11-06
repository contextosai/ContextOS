# Fuzz targets

Coverage-guided fuzzing of the inputs ContextOS does not control. The property tests
(`crates/contextos-embed/tests/fuzz.rs`, in every CI run) generate structured JSON;
these targets mutate raw bytes under coverage feedback, which finds parser and
evaluator paths that structured generators rarely reach.

| Target | Input | Property |
|---|---|---|
| `kernel_call` | operation byte + JSON | every kernel entry point answers one envelope, deterministically, without panicking |
| `jsonlogic` | `rule\0data` | evaluation and partial evaluation end without panicking, within their bounds |
| `canonical_json` | JSON | RFC 8785 output parses back and is a fixed point |
| `upstream_response` | content-type byte + body | an MCP server's JSON or SSE body yields only a well-formed response for the request's id |

```sh
rustup toolchain install nightly && cargo install cargo-fuzz
cargo +nightly fuzz run jsonlogic -- -dict=fuzz/json.dict -max_total_time=300
```

Run from the repository root. A crash is saved under `fuzz/artifacts/<target>/`;
reproduce it with `cargo +nightly fuzz run <target> <file>` and add the input as a
regression test next to the code it exercises. `.github/workflows/fuzz.yml` runs every
target weekly and on changes to the code they cover.
