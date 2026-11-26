# Control map for security and compliance reviews

This page maps what ContextOS enforces to the frameworks reviewers ask about for
autonomous agents. Each row names the threat-model entry
([THREAT_MODEL.md](security/THREAT_MODEL.md)) and the configuration that turns the
control on. The tests named in each threat-model entry are the evidence. For what
ContextOS does not cover, see [SCOPE.md](SCOPE.md).

`ctx evidence-pack` turns this map into a reviewer's folder for SOC 2, ISO/IEC 42001,
the EU AI Act, the OWASP agentic list or the NIST AI RMF: a verified audit export, the events recorded
for each control counted over the period, and a statement of what the evidence does not
cover (GUIDE §11). A control with events recorded acted in the period; the pack does not
show that the control was tested or is effective.

Every row says how much of the control the runtime covers: `covered`, `partial` (with
what is missing) or `organizational` (outside the runtime). ContextOS is not certified
against any of these frameworks, and this page is not an attestation: it maps what the
runtime enforces and records so your auditor can test it.

This is an evidence map, not legal advice. Which obligations apply depends on your
role (provider or deployer), your use case and your jurisdiction. ContextOS covers the
runtime part of a control. The organizational part (policies, risk assessments,
training, incident processes) is yours.

## OWASP Top 10 for Agentic Applications (2026)

| Risk | What ContextOS enforces | Threat model | Turn it on | Coverage |
|---|---|---|---|---|
| **ASI01 Agent goal hijack** | Tool output and retrieved content are `data_only` and cannot grant authority. Approvals bind the exact action digest. Information-flow labels put effects after untrusted input behind approval, and refuse classified egress; presets label GitHub, database and CRM tools (`ctx init-tool --preset`). Task authorization bounds what the principal asked for. | T1, T2, T28, T41 | `[guards.information_flow]`, `[guards] require_task_authorization` | partial: Cannot stop the model being hijacked; stops a hijacked agent's effects without approval. |
| **ASI02 Tool misuse and exploitation** | Default-deny dispatch of pinned, surfaced capabilities only. Reviewed `input_schema`. Pack rules on arguments, amounts and recipients. Loop guard and repeated-effect guard. An action monitor for contextual misuse. | T22, T28, T43 | `[guards] require_tool_schemas`, `[providers.action_monitor]` | covered |
| **ASI03 Identity and privilege abuse** | Runs bound to the admitting principal, the agent its credential names, and the user its delegated token acts for, with the whole chain of agents between them recorded and revocable link by link; capabilities can require a role the user holds (`required_user_roles`), not only the agent's access. Grants must be verified, current and unrevoked. Credentials are brokered and never model-visible. | T4, T14, T18, T29, T30, T36 | `[guards] agent_binding = "required"`, `user_binding` | covered |
| **ASI04 Agentic supply chain** | Reviewed manifests with digest-pinned adapters and capabilities. Upstream MCP tool pins with drift refusal and quarantine until re-pinned or released. Pack versions are immutable once published, and can be required to carry a trusted signature. Agent releases run only after their evaluations pass. Release assets are Sigstore-signed. Locked dependencies checked by cargo-deny. | T16, T22, T32, T39, T62, T66, T67, T68 | `upstream_tool_digest` (required under the enterprise profile), `[pack_signing]`, `[guards.release_evaluations]` | partial: Covers packs, tools and agent releases; the agent framework's own dependencies are the deployment's. |
| **ASI05 Unexpected code execution** | A boundary port that refuses effects outside an active isolation boundary. Pinned HTTPS endpoints with no redirects. The sandbox itself is the deployment's. | T13, T24 | `[providers.boundary]` | partial: Refuses effects outside a boundary; the sandbox is the deployment's. |
| **ASI06 Memory and context poisoning** | Memory changes are governed lifecycle records: decided by the kernel, bound to the run, audited, and refused at recall once superseded or deleted. Context is compiled from pinned packs and admitted evidence. | T25, T37 | `[providers.memory]`, `[guards] evidence = "strict"` | partial: Covers memories written through the memory port; retrieval stores outside it are not governed. |
| **ASI07 Insecure inter-agent communication** | Delegation narrows authority, budget and deadline at every hop. Children's outputs need acceptance. Information-flow labels pass between parent and child. | T5, T21, T41 | Delegation envelopes (always on) | partial: Covers delegation through the runtime; agent-to-agent channels outside it are not. |
| **ASI08 Cascading failures** | Conserved budgets and shared guarantees under concurrency. Unknown outcomes hold reservations. Circuit breakers stop effects or refusals per agent across runs. | T6, T7, T19, T42 | `[[guards.circuit_breakers]]`, `[[guarantees]]` | covered |
| **ASI09 Human-agent trust exploitation** | Approvals bind the exact action, with single-use redemption, self-approval bans, step-up for large approvals, and a review-time floor. Escalation notifications cannot approve. | T2, T3, T31, T34, T44 | `[guards.approval_step_up]`, `[guards.approval_review]` | partial: Binds and paces approvals; how approvers are trained and what their screens show is the deployer's. |
| **ASI10 Rogue agents** | A kill switch by tenant, pack, principal, agent, adapter or capability. Circuit breakers that trip it automatically. Trusted monitoring with a per-run suspicion budget. A signed audit trail of every decision. | T12, T42, T43 | Revocations API, `trip = "revoke"`, `run_budget` | covered |

## SOC 2 Trust Services Criteria

| Criterion | What ContextOS enforces and records | Coverage |
|---|---|---|
| CC6.1 Logical access to protected assets | Every tool call is admitted to a run bound to its principal and agent, authorized against pinned packs and grants, and refused once revoked. | covered |
| CC6.3 Authorization and least privilege | Grants narrow at every delegation; task authorization bounds what the principal asked for; a capability that requires user roles refuses a delegated run whose user lacks them; amendments and revocations are recorded. | covered |
| CC6.6 Boundaries against external threats | Effects outside the isolation boundary or the gateway's environment are refused; data flows are labelled and classified egress refused. | partial: Network perimeter, host hardening and the isolation boundary itself are the deployment's. |
| CC6.8 Unauthorized or malicious software | Only pinned packs and reviewed, digest-pinned capabilities run; pack loads and rollouts are recorded. | partial: Covers packs and tools the runtime loads; malware on hosts and in dependencies is the deployment's. |
| CC7.2 Monitoring for anomalies | Trusted monitoring scores actions; circuit breakers trip on bursts; repeated effects and shared-limit breaches are refused. | partial: Covers agent actions; infrastructure and host monitoring are the deployment's. |
| CC7.3 Evaluation of security events | Escalations hand blocked or unusual calls to a human with the audited decision. | partial: Escalations reach a person; the triage process and its staffing are the deployer's. |
| CC7.4 Incident response | Revocations stop an agent, pack or tenant on the next call; unknown outcomes are reconciled and applied effects compensated. | partial: Stops, holds and reconciles effects; the incident response process is the deployer's. |
| CC8.1 Change management | Pack versions are immutable and released through gates; rollouts, conformance assessments and task amendments are recorded. | partial: Covers packs, releases and configuration the runtime loads; change management of the deployment's own code is the deployer's. |
| PI1.3 Processing integrity: complete and accurate processing | Each effect is claimed once, its outcome observed or reconciled, and shared limits settled from the outcome. | covered |
| CC1-CC5 Control environment, communication, risk assessment and monitoring of controls | Outside the runtime. | organizational: Policies, training, risk assessment and oversight. |

## EU AI Act (Regulation 2024/1689)

| Article | Requirement, in short | What ContextOS provides | Coverage |
|---|---|---|---|
| Art. 9 Risk management | Identify, estimate and mitigate risks across the life cycle | Release gates on packs and scorecards (GUIDE §5); multidimensional `action_risk` on every capability; guards sized to risk (approvals, step-up, flow labels, monitor) | partial: risk management as a process is the provider's; the runtime supplies gates, risk dimensions and evaluation evidence. |
| Art. 12 Record-keeping | Automatic logs enabling traceability over the system's lifetime | An ed25519 hash-chained audit of every admission, decision, approval, effect and refusal, with offline verification (GUIDE §11, T12). Decision records cite the pack, policy, model and evaluator releases. | partial: Records actions and decisions; model prompts and completions are not recorded by the runtime (keep them in the model gateway's logs if your obligations need them). |
| Art. 14(4)(a), (c) Understand and interpret output | Overseers can monitor operation and interpret what the system did | Decision records with reason codes and evidence references; escalations with the audited decision; the Tower approvals inbox | partial: Explains each runtime decision; interpreting the model's own reasoning is outside it. |
| Art. 14(4)(b) Automation bias | Overseers remain aware of over-reliance | `[guards.approval_review]` refuses approvals faster than the review floor, and audits each one; `approval_requested` and `approval_redeemed` audit every approval's decision time, which Tower's Approvals page reports per capability and approver | covered |
| Art. 14(4)(d) Override or reverse | Disregard, override or reverse the output | Approvals and denials on the exact action; compensation of applied effects; reconciliation of unknown outcomes (GUIDE §3) | covered |
| Art. 14(4)(e) Stop | Interrupt the system through a stop procedure | Revocations take effect on the next call (GUIDE §8); circuit breakers trip them automatically | covered |
| Art. 15 Accuracy, robustness, cybersecurity | Resilience to errors and to attempts to alter use or behaviour | Strict ingress, a total kernel, fail-closed providers, prompt-injection containment (T1, T41), adversarial monitoring (T43), fuzzing | partial: Contains and screens what the model does; the model's own accuracy and robustness are the provider's. |
| Art. 26 Deployer obligations | Use per instructions, assign oversight, monitor operation, keep logs | Audit sinks to your SIEM (T40), Prometheus alerts with runbooks (INCIDENT.md), retention settings (GUIDE §9) | organizational: Instructions for use, assigned overseers and log retention. |

## Singapore Model AI Governance Framework for Agentic AI (v1.5)

| Dimension | ContextOS controls | Coverage |
|---|---|---|
| Assess and bound risks upfront | Capability manifests declare effect, reversibility, amount, recipients and flow labels; packs scope intents and tools; task authorization states what the principal asked for | partial: the runtime part; governance processes are the organization's. |
| Make humans meaningfully accountable | Every run has an accountable principal and agent; approvals bind exact actions, with step-up and a review floor; operators' changes are audited | partial: the runtime part; governance processes are the organization's. |
| Technical controls | Deterministic checks before every tool call; rate limits and circuit breakers; information-flow rules; trusted monitoring; the kill switch | covered |
| End-user responsibility | Outside the runtime: what users are told is the deployment's | organizational: what users are told is the deployment's. |

## NIST AI Risk Management Framework

| Function | ContextOS evidence | Coverage |
|---|---|---|
| Govern | Signed, versioned packs (`[pack_signing]`) and configuration review in CI (GUIDE §13); lifecycle approval, access reviews and two-person restore in Tower; time-boxed, reviewed break-glass | partial: Policies, roles and training are the organization's; the runtime enforces and records them. |
| Map | The inventory of agents, tools and models (Tower, `ctx inventory`); agent risk tiers; capability risk dimensions and data categories; the threat model; this page and SCOPE.md | partial: Context mapping and impact assessment are the organization's; the runtime supplies the inventory and risk tiers they start from. |
| Measure | Evaluation results per agent release that gate admission (`[guards.release_evaluations]`); evaluator scores and score gates (GUIDE §7); metrics and alerts (METRICS.md); audited guard decisions | partial: Choosing what to measure and the evaluation suites themselves are the organization's. |
| Manage | Approvals, guards, budgets, breakers, the kill switch, compensation and incident runbooks | covered |

## ISO/IEC 42001 (Annex A control areas)

| Area | ContextOS evidence | Coverage |
|---|---|---|
| AI system life cycle | Pack release gates, staged rollouts, immutable versions, conformance assessment (GUIDE §5, §10) | partial: Covers agent releases, packs and evaluation gates; model development and training are outside. |
| Data for AI systems | Data-flow port, classification ceilings on egress, erasure and retention (T23, T41, GUIDE §9) | partial: Covers data in agent actions (categories, holds, erasure); training data is outside. |
| Use of AI systems | Task authorization, approvals, guards and the audit trail tie each use to its principal and purpose | covered |
| Third-party relationships | Upstream tool pins and drift, provider trust domains, OAuth client credentials per adapter | partial: Pins and quarantines upstream tools; supplier assessment and contracts are the deployer's. |
