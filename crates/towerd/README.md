# towerd

ContextOS Tower's service: the organisation's governance plane over ContextOS runtimes.
Start with the developer documentation in [docs/tower](../../docs/tower/README.md).

## Code map

| File | Responsibility | Pure? | Tests |
|---|---|---|---|
| `src/main.rs` | Load config, pick store and journal signer, start collectors, serve | | `examples/tower` |
| `src/lib.rs` | `Tower` (service state); `build` (from config) and `assemble` (sources given) | | e2e |
| `src/config.rs` | `towerd.toml`; refuses published example keys outside development | yes | |
| `src/source.rs` | Runtime client (`audit:read` reads, `control` revocations); `key_ring` | | e2e |
| `src/collector.rs` | `sync` one pass per source: refresh, pull, **verify**, fold; `run` loops it | | e2e |
| `src/fleet.rs` | `Fleet::apply`: folds verified entries into per-agent activity, run summaries, change feed | yes | unit |
| `src/authority.rs` | Authority graph from packs; required profiles and controls from the kernel registry | yes | unit |
| `src/governance.rs` | Agent views, facts, built-in findings, guardrails, waivers, anomalies | yes | unit |
| `src/records.rs` | Declarations, reviews, guardrails, waivers (compare-and-swap) and the signed journal | | e2e |
| `src/intel/mod.rs` | `Model` trait; `Anthropic` (Messages API) and `Scripted` (tests); `checked` | | unit |
| `src/intel/jobs.rs` | Ask Tower, guardrail drafting, intake review, anomaly brief, run explanation | | unit (scripted) |
| `src/api.rs` | Routes, roles and separation of duties, snapshots, the analyst's tools | | e2e |
| `src/console.rs` | Serves the UI build from memory with a strict content policy | | `tests/console.rs` |

```sh
cargo test -p towerd                  # unit + e2e (in-process contextosd) + console
./examples/tower/run.sh --serve       # live runtime + towerd + UI on :8090
```
