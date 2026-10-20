# ADR-0001: Rust kernel with protocol-first bindings

- Status: accepted
- Date: 2026-10-20

## Context

ContextOS (contextosai.com) is a published spec for the deterministic control boundary around probabilistic agent reasoning: bounded context compilation, authorized effects, typed outcomes, durable effect reconciliation, and evidence-scoped conformance. The spec repo ships a deterministic TypeScript *reference* (`src/lib/contextos/`) that is explicitly **not** a production runtime. Identity verification, protected stores, provider adapters and enforcement are left to implementers.

This repository builds that production runtime. Requirements that drive the stack choice:

1. **Sits on the hot path of every tool call.** Each governed effect passes compile → authorize → dispatch → reconcile. Added latency must be well under a millisecond at p99 so the harness is never the reason to skip governance.
2. **Embedded and remote.** Teams run agents in Python (LangGraph, OpenAI Agents SDK, ADK, CrewAI), TypeScript (Vercel AI SDK, Claude Agent SDK), Go and JVM. The same decision kernel must run *in-process* (no network hop) and as a *sidecar/gateway* at fleet scale, with bit-identical verdicts.
3. **Security boundary.** The gateway holds credential references, enforces egress, and verifies signatures. Memory-safety bugs here are authorization bypasses.
4. **Determinism.** The spec forbids ambient clock, randomness and silent fallbacks in decision logic. Hashes (`compiled_context_hash`, RFC 8785 action-binding digests) must be byte-identical across languages.
5. **Adoptable by large operators.** Predictable tail latency (no GC pauses), small static binaries, first-class OpenTelemetry, Postgres for durable state, Kubernetes-native deployment.

## Decision

- **Rust** for the kernel, gateway and control-plane server (edition 2024, MSRV pinned in `rust-toolchain.toml`).
  - The decision kernel (`contextos-kernel`) is pure and synchronous: no I/O, no clock, no RNG. Every input that the TS reference receives as a caller-supplied observation remains an explicit parameter (`evaluation_time`, verified observations). This makes it embeddable everywhere and replayable.
  - The runtime (`contextos-gateway`, `contextosd`) is async on `tokio`, with `axum` (HTTP/JSON) and `tonic` (gRPC) sharing one service layer.
- **Protocol-first contract.** The published JSON Schemas (`schemas/`, copied verbatim from the spec) are normative. Rust types are serde mirrors with `deny_unknown_fields` on closed envelopes. gRPC protos are a transport projection; JSON over HTTP is always supported.
- **Bindings, not rewrites.** Python via PyO3 (`contextos-py`), Node via napi-rs (`contextos-node`), and WASM (`contextos-wasm`) wrap the same kernel. Remote clients for other languages are generated from the protos.
- **Storage behind ports.** Durable state (operation ledger, budget ledger, approval redemption, checkpoints, audit chain) is defined as traits with compare-and-swap + fencing semantics. Adapters: in-memory (tests/embedded) and PostgreSQL (`sqlx`, serializable transactions). Other stores implement the same conformance suite.
- **Cryptography.** `sha2` for digests, RFC 8785 canonical JSON implemented in-tree with `ryu-js` for ECMAScript number formatting, `ed25519-dalek` for signed decision records and audit-chain heads.
- **Policy.** A bounded, deterministic JsonLogic evaluator in-tree (the spec's policy DSL), with explicit depth/operation limits and structured `policy_eval_error`. Policy composition follows the spec exactly: guardrails first, highest business priority wins, deny wins at equal priority, independent constraints stay conjunctive.
- **Observability.** `tracing` + OpenTelemetry (OTLP), W3C trace-context propagation on every envelope, Prometheus metrics named after the spec's metrics glossary.

## Alternatives considered

- **Go.** Strong for control planes (Kubernetes, Temporal, OPA). Rejected as the kernel language because a GC runtime is a poor fit for in-process embedding into Python/Node (cgo + two runtimes) and gives weaker tail-latency guarantees. A Go *client* is generated from protos.
- **TypeScript (extend the reference).** Fastest path, but single-language in-process reach, GC pauses, and no memory-safety boundary for the gateway. The TS reference remains the spec's conformance oracle: our golden vectors are generated from it.
- **JVM/Kotlin.** Excellent ecosystem in large enterprises but heavy for sidecars and embedding.

## Consequences

- Contributors need Rust for the core; SDK users do not.
- Cross-language parity is enforced by golden vectors produced from the TS reference (`conformance/vectors/`), checked in CI.
- Pure kernel + async runtime split keeps unsafe surface and I/O out of decision logic, and lets every verdict be replayed from its recorded inputs.
