# ContextOS Tower: developer documentation

Tower is the **governance plane** for an organisation's AI agents. ContextOS runtimes
(`contextosd`) decide every effect an agent attempts; Tower sits above all of them and
answers the questions an organisation has to answer about its agents as a whole:

| Question | Without Tower | With Tower |
|---|---|---|
| Which agents do we have, and who owns each? | A spreadsheet, out of date the day it is written | Discovered from signed runtime evidence, with owner declarations; an agent nobody owns is a finding |
| What can each one actually do? | Whatever its owner says | Its **authority graph**: every capability of every pack it runs under, with its five-dimensional ActionRisk, and whether it was offered or used |
| What controls does that require, and do we have them? | A policy document | Computed from the standard profile registry, compared against what each runtime declares, per runtime |
| What changed, and who approved it? | Change tickets, if any | Drift against the last review, a fleet change feed, and a signed journal of every governance decision |
| What is going wrong right now? | Dashboards per system | Findings with fixes, anomalies against each agent's own baseline, a fleet-wide kill switch |
| Can we prove it? | Screenshots | Every runtime entry verified (digest, hash link, Ed25519) before use; Tower's own decisions in a chain anyone can verify offline |
| How do we set rules for hundreds of agents? | Meetings | Guardrails written in plain language, drafted by Claude, checked against the real inventory, activated by a second reviewer |

**The value in one sentence:** Tower turns the evidence ContextOS runtimes already sign
into an organisation-wide, verifiable answer to "are our agents doing only what they
should, and who is accountable", without putting AI or a new trust anchor in the
enforcement path.

## Read in this order

| # | Document | You will learn | For |
|---|---|---|---|
| 1 | [Concepts and principles](01-concepts.md) | The problem, the twelve design principles, every term Tower uses | Everyone |
| 2 | [Architecture](02-architecture.md) | System context, components, deployment topologies, trust boundaries, what data lives where | Implementors, reviewers |
| 3 | [Flows](03-flows.md) | Step-by-step sequence diagrams of every path: admission to finding, review and drift, guardrail drafting, Ask Tower, kill switch, journal verification | Implementors |
| 4 | [Governance model](04-governance-model.md) | How audit entries become the fleet model, how required controls are derived, the facts schema, every built-in finding, guardrail and waiver semantics, anomaly detection | Contributors |
| 5 | [Intelligence](05-intelligence.md) | Where Claude is used and how it is bounded: tools, prompts, structured outputs, citation checks, refusals, testing | Contributors |
| 6 | [API reference](06-api.md) | Every `towerd` route with roles and examples; the runtime routes Tower relies on | Integrators |
| 7 | [Security](07-security.md) | Threat model, roles and separation of duties, keys, data minimisation, failure behaviour | Security reviewers |
| 8 | [Build it step by step](08-build-it.md) | A guided walkthrough, then how to extend Tower: a new finding, a new analyst tool, a new UI page, with tests | Contributors |
| 9 | [Operations](09-operations.md) | Configuration reference, deployment, sizing, monitoring, troubleshooting, limits and roadmap | Operators |

The design rationale, written before the code, is in
[docs/design/tower-governance-plane.md](../design/tower-governance-plane.md).

## Five-minute start

```sh
./examples/tower/run.sh --serve
```

This starts a ContextOS runtime with the quickstart pack, runs a governed agent four
times (the last one refused by the kill switch), then starts `towerd` over it with the
UI. Open <http://127.0.0.1:8090/tower/> and sign in as any of these development people
(keys are published in `examples/tower/towerd.toml` and refused outside development):

| Person | Key | Roles |
|---|---|---|
| ciso | `dev-ciso-0123456789abcdef0123456789abcde` | viewer |
| maya | `dev-owner-0123456789abcdef0123456789abcd` | owner of team `support-ai` |
| risk-a | `dev-risk-a-0123456789abcdef0123456789abc` | risk reviewer |
| risk-b | `dev-risk-b-0123456789abcdef0123456789abc` | risk reviewer |
| oncall | `dev-oncall-0123456789abcdef0123456789abc` | operator |

You will see one agent (`tenant_acme_prod/agt_support`) with six findings: it runs
without an owner, has never been reviewed, its runs are admitted under the `core`
profile although its authority needs `enterprise` and `durable-delegated`, the runtime
lacks nine of the seventeen controls that requires, its decisions record no model, and
no evaluator scored them. [Build it step by step](08-build-it.md) walks through
resolving them as each person.

## Where the code is

| Path | What |
|---|---|
| `crates/towerd/` | The service: collector, fleet model, governance engine, intelligence, API |
| `tower/` | The web UI (React, TypeScript, Vite), served by `towerd` |
| `crates/contextosd/src/app.rs` (`run_admitted`, `/v1/deployment`, `/v1/packs`) | What the runtime provides for Tower |
| `crates/contextosd/src/configs.rs` | Configuration review (`/v1/config`, `/v1/config/validate`) |
| `examples/tower/` | A runnable runtime-plus-Tower setup, also run by `scripts/check.sh` |
