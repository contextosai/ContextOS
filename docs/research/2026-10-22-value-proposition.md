# ContextOS: from agent governance to shared business guarantees

Research cut: 22 October 2026. This is a product and engineering assessment of public primary sources and this repository at `ac345a2`, not a market-size study, legal opinion, competitor implementation audit, or proof of worldwide novelty.

## Recommendation

**ContextOS coordinates the business limits that all your agents share, enforces them before tools act, and records attributable evidence of what happened—including what remains unknown.**

Start with support and operations teams running independent agents against the same customer or order. The first promise is narrow and testable: *within a configured ContextOS enforcement domain, committed exposure plus unresolved reservations cannot exceed a trusted business-resource limit, even across agents, runs and server replicas sharing a store.*

A concrete example: two independently authorized agents each request an $80 refund against one order with a $100 refund ceiling. Each request fits its own run budget. Together they do not fit the business ceiling. ContextOS must atomically admit at most one. A timeout must continue to hold $80 until an attributable reconciliation establishes the outcome. Starting another run, changing the operation key, or restarting a server must not create another $100 allowance.

## What exists already

The current repository has a deterministic Rust kernel, exact action-bound authorization and approval, run and delegated budgets, fenced operation claims, conservative unknown-effect handling, signed audit, independent scoring, release gates, framework adapters, and Tower fleet governance. The existing repeat-effect guard is scoped to a run. Run budgets and parent-funded delegated budgets do not coordinate unrelated runs acting on the same business object. The existing completion score gate is useful but an evaluator score is not a transaction-level business invariant.

The opportunity is to make those existing primitives serve a visible business result. Rebuilding identity, observability, orchestration, or a general governance dashboard would dilute that advantage.

## Evidence from the landscape

The table distinguishes documented capabilities from our interpretation. A blank or limitation is a research gap, never proof a competitor cannot implement something.

| Area and primary source | Documented capability | Implication for ContextOS |
|---|---|---|
| [Microsoft Agent 365](https://learn.microsoft.com/en-us/microsoft-agent-365/overview) and [Foundry Control Plane](https://azure.microsoft.com/en-us/products/ai-foundry/control-plane) | Organization-wide agent inventory, enterprise identity/security/governance; developer observability, runtime controls and fleet operations. | “Control plane for enterprise agents” is already occupied. Tower should present evidence and coverage for a focused runtime promise. |
| [AWS AgentCore Policy](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy-core-concepts.html) | Deterministic per-tool policies; Cedar-compatible Dogwood adds temporal and guardrail conditions. | Deterministic external enforcement and stateful policy alone are not differentiators. |
| [AWS temporal policies, 6 August 2026](https://aws.amazon.com/blogs/machine-learning/securing-ai-agents-with-temporal-policies-in-amazon-bedrock-agentcore/) | Session trajectories support ordering, output-to-input checks and cumulative financial thresholds. Sessions combine identity with session ID; a fresh session has fresh history. The article describes one concurrent authorization per session and a 24-hour look-back. | Our target boundary is a stable business resource shared across independent identities and sessions, with persistent pending exposure rather than a history window. Do not claim AWS policies are stateless. |
| [agentgateway authorization](https://agentgateway.dev/docs/standalone/latest/documentation/configuration/security/http-authz/) | CEL allow/deny/require policies and external authorization at the gateway. | Integrate at tool boundaries; competing on routing and policy syntax adds little. External authorization can host a shared ledger, so this is not an exclusivity claim. |
| [Open Policy Agent external data](https://www.openpolicyagent.org/docs/external-data) | Policy decisions can use synchronized or freshly fetched external state; OPA is not the source of truth for that state. | A fresh read alone does not reserve capacity. The product must combine a protected state transition with dispatch, not just evaluate a predicate. |
| [Delego](https://delegohq.com/) | Intent-bound deterministic authorization, exact approvals and signed hash-chained receipts. | “Authorize actions, not credentials” and signed receipts are already direct competition. |
| [Caracal](https://github.com/garudex-labs/caracal) | Open source scoped authority, narrowing delegation, revocation and tamper-evident audit. | Open source authority is necessary positioning context, not a new category invented here. Further code-level comparison is required before making exclusivity claims. |
| [Agent Passport System](https://agent-passport.org/) | Verifiable agent identity, bounded delegated authority and action receipts; explicitly separates permission from external completion. | Portable receipts and truthful completion claims are prior art. Reuse that distinction. |
| [Temporal AI](https://temporal.io/solutions/ai) | Durable orchestration across models, tools and long-running work. | Keep existing orchestrators. Durability by itself does not specify which aggregate business effects are allowed. A Temporal workflow can also implement the invariant; ContextOS packages a reusable enforcement boundary. |
| [LangSmith](https://www.langchain.com/resources/what-is-langsmith) | Framework-agnostic traces, offline and online evaluations, feedback, deployment and model gateway controls. | Do not become another trace store or evaluator. Export evidence and pair with existing evaluations. |
| [Relari agent-contracts](https://github.com/relari-ai/agent-contracts) and [Agent Behavioral Contracts](https://arxiv.org/abs/2602.22302) | Contracts, resource limits and runtime behavioral constraints already have open source and research precedents. | “Contracts for agents” cannot be an originality claim. Our wedge is operational coordination and recovery at a business-object boundary. |
| [agent-invariants](https://github.com/christian140903-sudo/agent-invariants) | Deterministic trace rules, including evidence before completion. | Offline trace validation complements pre-dispatch reservation; neither should be presented as the other. |
| [Counterworld evaluation](https://counterworld.dev/docs/evaluation.html) | Evaluates invariants such as total refunded versus captured payment, final state and delayed outcomes in simulated environments. | Business-outcome evaluation is also prior art. Our first deliverable enforces a configured cumulative exposure ceiling in a live gateway. It does not prove every business outcome. |
| [Microsoft Agent Control Specification](https://commandline.microsoft.com/agent-control-specification-runtime-governance/) | Portable runtime governance independent of framework, runtime and policy engine. | Preserve portable types and clear boundaries; do not invent a competing agent communication protocol. |
| [MCP authorization security considerations](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/docs/specification/draft/basic/authorization/security-considerations.mdx) | Audience-bound tokens and OAuth security requirements at MCP transport boundaries. | Identity and transport authorization remain complementary; they do not replace business exposure accounting. |

## Alternatives considered

| Direction | Customer value | Why not lead with it |
|---|---|---|
| Universal agent inventory and governance console | Ownership, review, fleet visibility | Strong incumbent overlap; Tower already supplies much of it. |
| Agent identity and intent authorization | Bound delegated access | Crowded and already substantially implemented in ContextOS. |
| Outcome verification and an autonomy score | More credible task completion | Generic outcome contracts already exist; a score risks hiding uncertainty and mixing business correctness with model judgment. Keep independent scoring, without selling it as proof. |
| Simulation and counterfactual release assurance | Catch failures before deployment | Valuable, but requires a realistic domain simulator and trustworthy ground truth; several adjacent platforms exist. Existing replay gates are a complement. |
| **Shared business limits with conservative recovery** | Prevent individually allowed agents collectively exceeding one business limit | Fits existing CAS stores, exact bindings and reconciliation; can be demonstrated without an LLM or a bespoke agent framework. Chosen as the initial wedge. |

## Differentiation hypothesis and novelty boundary

The hypothesis is that teams will adopt a small, self-hostable enforcement layer for **resource-scoped limits across unrelated agents, conservative accounting of unknown effects, and verifiable decision evidence**, while keeping their existing identity, agent framework and observability tools.

We did not establish that no other system offers this combination. Escrow accounting, reservation ledgers, database transactions, workflow coordination and shared quotas are established techniques. Policy engines can call external services; workflow engines can serialize a resource; business APIs can and should enforce their own invariants. ContextOS is differentiated by the reusable agent integration and explicit uncertainty/recovery contract, not by claiming to have invented transactions. The strongest competitor may be a well-designed business service rather than another agent startup.

## Customer and adoption

First user: an AI platform engineer enabling support automation across teams. Accountable owner: the support or payments operations lead. Security and risk reviewers benefit from a precise control and evidence trail. This is an assumed beachhead, not validated willingness to pay.

Jobs: enable more independent agents without multiplying total permitted exposure; see whether remaining capacity is committed or unresolved; reconcile lost responses without blindly retrying; show why a call was held and which rule applied. Start by governing one consequential tool and one shared resource. No framework migration or model key should be necessary for the demo.

Open source core: the deterministic ledger, adapters, runtime enforcement, configuration, audit and offline verification stay Apache-2.0. A future commercial offering could manage deployment and operations, but no essential safety rule should depend on a proprietary service. Do not implement a commercial offering in this change.

## Success and falsification

Engineering acceptance: a concurrent cross-run $80/$80 race under a $100 ceiling dispatches at most one provider call; new run IDs and changed keys cannot reset capacity; unknown and partial outcomes retain capacity; definitive non-application releases it once; confirmed exposure remains consumed across restarts; tenant isolation holds; missing or malformed bindings and storage/audit failures cannot dispatch an unreserved effect. Existing authorization and conformance behavior remains unchanged without configured guarantees.

Adoption experiments before further expansion: interview 5–8 platform/operations teams; ask for a recent real incident; run design-partner replays of duplicate refunds or shared purchasing limits; measure mediated tool coverage, prevented aggregate violations, false blocks, unresolved exposure age, reconciliation time and useful outcomes per human review. Do not invent ROI, market size or performance numbers. Stop or change direction if resource-level APIs already solve the problem cheaply, if buyers need identity/inventory first, or if stable resource binding cannot be established.

## Redesign sequence

1. **Implemented foundation in this repository:** opt-in numeric shared guarantees; protected resource ledgers; exact action and attempt binding; pre-dispatch reservation; conservative settlement and reconciliation; operator inspection; a local two-agent demonstration; research, design, API and security documentation.
2. **Next, contingent on pilot evidence:** trusted per-resource ceilings and initial balances from systems of record, alias-safe resource identity, bounded ledger rollover with permanent replay protection, Tower exposure views and coverage denominators, Postgres contention benchmarks, policy migration and incident recovery tooling.
3. **Later:** multiple simultaneous invariants, cross-region escrow allocations, independent business-outcome witnesses and standards interoperability. Each needs a separate threat model. Do not advertise these as implemented.

The new public promise must always state its domain: configured tools passing through runtimes using the same tenant and protected store. It cannot cover bypassed calls, normalize arbitrary upstream aliases, discover pre-existing spend, reverse external effects, or establish legal compliance.
