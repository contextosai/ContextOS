# Control map for security and compliance reviews

This page maps what ContextOS enforces to the frameworks reviewers ask about for
autonomous agents. Each row names the threat-model entry
([THREAT_MODEL.md](security/THREAT_MODEL.md)) and the configuration that turns the
control on. The tests named in each threat-model entry are the evidence. For what
ContextOS does not cover, see [SCOPE.md](SCOPE.md).

This is an evidence map, not legal advice. Which obligations apply depends on your
role (provider or deployer), your use case and your jurisdiction. ContextOS covers the
runtime part of a control. The organizational part (policies, risk assessments,
training, incident processes) is yours.

## OWASP Top 10 for Agentic Applications (2026)

| Risk | What ContextOS enforces | Threat model | Turn it on |
|---|---|---|---|
| **ASI01 Agent goal hijack** | Tool output and retrieved content are `data_only` and cannot grant authority. Approvals bind the exact action digest. Information-flow labels put effects after untrusted input behind approval, and refuse classified egress. Task authorization bounds what the principal asked for. | T1, T2, T28, T41 | `[guards.information_flow]`, `[guards] require_task_authorization` |
| **ASI02 Tool misuse and exploitation** | Default-deny dispatch of pinned, surfaced capabilities only. Reviewed `input_schema`. Pack rules on arguments, amounts and recipients. Loop guard and repeated-effect guard. An action monitor for contextual misuse. | T22, T28, T43 | `[guards] require_tool_schemas`, `[providers.action_monitor]` |
| **ASI03 Identity and privilege abuse** | Runs bound to the admitting principal, the agent its credential names, and the user its delegated token acts for, with the whole chain of agents between them recorded and revocable link by link. Grants must be verified, current and unrevoked. Credentials are brokered and never model-visible. | T4, T14, T18, T29, T30, T36 | `[guards] agent_binding = "required"`, `user_binding` |
| **ASI04 Agentic supply chain** | Reviewed manifests with digest-pinned adapters and capabilities. Upstream MCP tool pins with drift refusal. Pack versions are immutable once published. Locked dependencies checked by cargo-deny. | T16, T22, T32, T39 | `upstream_tool_digest` (required under the enterprise profile) |
| **ASI05 Unexpected code execution** | A boundary port that refuses effects outside an active isolation boundary. Pinned HTTPS endpoints with no redirects. The sandbox itself is the deployment's. | T13, T24 | `[providers.boundary]` |
| **ASI06 Memory and context poisoning** | Memory changes are governed lifecycle records: decided by the kernel, bound to the run, audited, and refused at recall once superseded or deleted. Context is compiled from pinned packs and admitted evidence. | T25, T37 | `[providers.memory]`, `[guards] evidence = "strict"` |
| **ASI07 Insecure inter-agent communication** | Delegation narrows authority, budget and deadline at every hop. Children's outputs need acceptance. Information-flow labels pass between parent and child. | T5, T21, T41 | Delegation envelopes (always on) |
| **ASI08 Cascading failures** | Conserved budgets and shared guarantees under concurrency. Unknown outcomes hold reservations. Circuit breakers stop effects or refusals per agent across runs. | T6, T7, T19, T42 | `[[guards.circuit_breakers]]`, `[[guarantees]]` |
| **ASI09 Human-agent trust exploitation** | Approvals bind the exact action, with single-use redemption, self-approval bans, step-up for large approvals, and a review-time floor. Escalation notifications cannot approve. | T2, T3, T31, T34, T44 | `[guards.approval_step_up]`, `[guards.approval_review]` |
| **ASI10 Rogue agents** | A kill switch by tenant, pack, principal, agent, adapter or capability. Circuit breakers that trip it automatically. Trusted monitoring with a per-run suspicion budget. A signed audit trail of every decision. | T12, T42, T43 | Revocations API, `trip = "revoke"`, `run_budget` |

## EU AI Act (Regulation 2024/1689)

| Article | Requirement, in short | What ContextOS provides |
|---|---|---|
| Art. 9 Risk management | Identify, estimate and mitigate risks across the life cycle | Release gates on packs and scorecards (GUIDE §5); multidimensional `action_risk` on every capability; guards sized to risk (approvals, step-up, flow labels, monitor) |
| Art. 12 Record-keeping | Automatic logs enabling traceability over the system's lifetime | An ed25519 hash-chained audit of every admission, decision, approval, effect and refusal, with offline verification (GUIDE §11, T12). Decision records cite the pack, policy, model and evaluator releases. |
| Art. 14(4)(a), (c) Understand and interpret output | Overseers can monitor operation and interpret what the system did | Decision records with reason codes and evidence references; escalations with the audited decision; the Tower approvals inbox |
| Art. 14(4)(b) Automation bias | Overseers remain aware of over-reliance | `[guards.approval_review]` refuses approvals faster than the review floor, and audits each one; `approval_requested` and `approval_redeemed` audit every approval's decision time, which Tower's Approvals page reports per capability and approver |
| Art. 14(4)(d) Override or reverse | Disregard, override or reverse the output | Approvals and denials on the exact action; compensation of applied effects; reconciliation of unknown outcomes (GUIDE §3) |
| Art. 14(4)(e) Stop | Interrupt the system through a stop procedure | Revocations take effect on the next call (GUIDE §8); circuit breakers trip them automatically |
| Art. 15 Accuracy, robustness, cybersecurity | Resilience to errors and to attempts to alter use or behaviour | Strict ingress, a total kernel, fail-closed providers, prompt-injection containment (T1, T41), adversarial monitoring (T43), fuzzing |
| Art. 26 Deployer obligations | Use per instructions, assign oversight, monitor operation, keep logs | Audit sinks to your SIEM (T40), Prometheus alerts with runbooks (INCIDENT.md), retention settings (GUIDE §9) |

## Singapore Model AI Governance Framework for Agentic AI (v1.5)

| Dimension | ContextOS controls |
|---|---|
| Assess and bound risks upfront | Capability manifests declare effect, reversibility, amount, recipients and flow labels; packs scope intents and tools; task authorization states what the principal asked for |
| Make humans meaningfully accountable | Every run has an accountable principal and agent; approvals bind exact actions, with step-up and a review floor; operators' changes are audited |
| Technical controls | Deterministic checks before every tool call; rate limits and circuit breakers; information-flow rules; trusted monitoring; the kill switch |
| End-user responsibility | Outside the runtime: what users are told is the deployment's |

## NIST AI Risk Management Framework

| Function | ContextOS evidence |
|---|---|
| Govern | Signed, versioned packs and configuration review in CI (GUIDE §13); two-person restore in Tower |
| Map | Capability risk dimensions; the threat model; this page and SCOPE.md |
| Measure | Evaluator scores and score gates (GUIDE §7); metrics and alerts (METRICS.md); audited guard decisions |
| Manage | Approvals, guards, budgets, breakers, the kill switch, compensation and incident runbooks |

## ISO/IEC 42001 (Annex A control areas)

| Area | ContextOS evidence |
|---|---|
| AI system life cycle | Pack release gates, staged rollouts, immutable versions, conformance assessment (GUIDE §5, §10) |
| Data for AI systems | Data-flow port, classification ceilings on egress, erasure and retention (T23, T41, GUIDE §9) |
| Use of AI systems | Task authorization, approvals, guards and the audit trail tie each use to its principal and purpose |
| Third-party relationships | Upstream tool pins and drift, provider trust domains, OAuth client credentials per adapter |
