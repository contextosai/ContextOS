# Shared business guarantees implementation plan

> **For agentic workers:** Use superpowers:executing-plans to implement this plan task by task. Execution is delegated by the user; proceed with repository-native Rust tooling and one fresh whole-change review.

**Goal:** Enforce and inspect a conserved numeric business-resource limit across independent agent runs.

**Architecture:** A pure exposure state machine is committed through the existing CAS store. The gateway reserves at the tool boundary and settles using existing observations/reconciliation. Server configuration supplies trusted bindings.

**Tech Stack:** Existing Rust workspace, serde, protected DocumentStore, axum, Python local demo; no new third-party dependencies.

**Spec:** `docs/superpowers/specs/2026-10-22-shared-business-guarantees-design.md`

## Global constraints

- `committed + held <= limit`; exact positive integers no greater than 2^53−1.
- Unknown and partial exposure never expires; only accepted definitive non-application releases it.
- One guarantee per capability; at most 1024 receipts per resource; one protected store per enforcement domain.
- Preserve normative schemas/conformance and existing behavior when no guarantees are configured.
- No public mutation endpoint, credentials, production deployment or changes outside this repository.

## Review focus

- Crash between binding persistence, reservation, audit and provider call must leave recovery information and cannot dispatch an unreserved effect.
- Reconciliation racing a retry cannot release the newer attempt; duplicate responses cannot double-settle.
- Resource and tenant identity must not alias through delimiter concatenation, upstream aliases or changed ids.
- Rules changed after state exists must not create unaccounted capacity; config review must show removed protections.
- Bounded receipts and integer limits must fail visibly under hostile or saturated input.

## Task 1: deterministic ledger

Files: new `crates/contextos-kernel/src/shared_exposure.rs`, kernel export and tests. Interface: typed `ExposureBinding`, a serialized exposure ledger, and reserve and settle functions returning existing `TransitionResult`; held/committed/released receipts with exact action and attempt binding.

- [x] Write tests for cross-operation conservation, outcomes, stale settlement, retry idempotency, rule mismatch, malformed ledger and saturation; observe missing-feature failure.
- [x] Implement pure validated transitions and run the focused tests.

## Task 2: gateway enforcement and recovery

Files: new gateway shared guarantees module; gateway dispatch and reconciliation; new store document kinds; pipeline tests. Interface: `SharedGuarantee` plus validated gateway builder; immutable operation link and CAS-backed resource transitions.

- [x] Add a real two-run provider-call counting test that fails without the gate.
- [x] Implement reservation/link/audit before dispatch, conservative settlement and reconciliation, without weakening existing checks.
- [x] Verify cross-instance contention, tenant/resource separation, restarts, invalid arguments, retries, unknown and partial holds, failure release and injected storage/audit failures.

## Task 3: operator integration

Files: server config, build, config review, HTTP handlers, OpenAPI, server tests. Interfaces: read-only `GET /v1/guarantees` and resource digest inspection under `audit:read`.

- [x] Test unknown capability, duplicate coverage, invalid rule, scope/tenant boundaries and safe config-change classification before adding behavior.
- [x] Add configuration and read APIs, API description and effective configuration; run server tests.

## Task 4: adoption and proof

Files: research, design and this plan; new guide and multi-agent demo; README, threat model, changelog and delivery roadmap.

- [x] Add a runnable local demo showing two independent agents competing for one ceiling, plus unknown-effect recovery and independent audit verification.
- [x] Reposition the README around the demonstrated business value; identify alpha limits and distinguish implemented and proposed capabilities.
- [x] Run demo, full Rust tests, fmt and clippy; obtain a fresh review, fix substantive findings, and record exact evidence.

## Execution record

Research and design are complete. User chose the strongest researched opportunity and delegated execution. RTK.md is absent from this checkout and checked instruction locations. The optional BMAD renderer and sibling setup skill are absent; use native Rust workflow. Work proceeds on a feature branch in the clean checkout, with no remote publishing.


Ruling: preserve inline execution after the user delegated the strongest researched opportunity. The optional BMAD workflow cannot run because its local renderer/setup skill are absent; do not install an unrelated project harness.

Ruling: safety review demonstrated reservation/dispatch and concurrent reconciliation races. Add exact-attempt activation/abort tombstones and first-definitive observation sealing, with signed refusals and deterministic pause-based regression tests. Require recorded observations before absence can free an active receipt. This intentionally limits orphaned active-dispatch recovery pending external fencing support.

Ruling: keep reconciliation available to current-generation authorized callers after terminal lifecycle events; it invokes no new effect.

Ruling: check unknown shared attempts in the authoritative operation-claim CAS as well as the initial read. Validate recovery evidence and sign abort intent before changing an unstarted receipt. When a started attempt has no usage observation, a confirmed assertion charges its protected original run-budget allocation rather than reconstructing a zero-cost reservation.

Completion: `scripts/check.sh` exited 0 with `ALL CHECKS PASSED`, including 266 Rust tests, 5 gate-script tests, formatting, lint, release builds, Tower, both clients and all examples. Fresh security review closed its substantive findings. See the [validation record](../../research/2026-10-22-shared-guarantees-validation.md) for demonstrated results and untested PostgreSQL/scale boundaries.
