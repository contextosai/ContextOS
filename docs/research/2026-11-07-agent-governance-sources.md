# Agent governance: sources behind the 2026-11 runtime controls

Reviewed 2026-11-07 for [design/agentic-controls.md](../design/agentic-controls.md).
Only sources whose controls a tool-boundary runtime can enforce are listed. "Read"
means the primary text, or its abstract and key sections, was read. "Summary" means
the details come from secondary write-ups.

## Prompt injection: enforce at the boundary, not in the prompt

- **CaMeL: Defeating Prompt Injections by Design.** Debenedetti et al., Google
  DeepMind and ETH, arXiv 2503.18813 (2025). A privileged planner sees only the
  trusted request. Untrusted data is handled by a quarantined model and carries
  capabilities, and policies are checked on every tool call. (Read.)
- **Design Patterns for Securing LLM Agents against Prompt Injections.**
  Beurer-Kellner et al., arXiv 2506.08837 (2025). Six patterns: action selector,
  plan-then-execute, map-reduce, dual LLM, code-then-execute, context minimization.
  The common rule: once an agent has read untrusted input, it must not be able to
  trigger consequential actions freely. (Read.)
- **FIDES: Securing AI Agents with Information-Flow Control.** Costa, Köpf et al.,
  Microsoft Research, arXiv 2505.23643 (2025). Labels each tool output with a
  confidentiality × integrity lattice. Consequential actions need trusted integrity,
  and confidential data may not flow to lower sinks. (Summary.)
- **Progent: Programmable Privilege Control for LLM Agents.** Shi et al., arXiv
  2504.11703 (2025). Deterministic, default-deny policies over tools and argument
  values, enforced outside the model. (Read.)
- **Agents Rule of Two.** Meta AI security, 31 Oct 2025. Without a human in the
  loop, a session may combine at most two of: untrusted input, access to sensitive
  data, and the ability to change state or communicate externally. (Summary.)
- **The Attacker Moves Second.** Nasr, Carlini et al., arXiv 2510.09023 (USENIX
  Security 2026). Adaptive attacks beat twelve published detectors and prompt
  defenses at over 90% success. (Summary.)
- **Adaptive Evaluation of Out-of-Band Defenses Against Prompt Injection in LLM
  Agents.** arXiv 2606.26479 (2026). System-level defenses hold where detectors fail.
  (Read.)

## Monitoring and control

- **Ctrl-Z: Controlling AI Agents via Resampling.** Bhatt et al., Redwood Research,
  arXiv 2504.10374 (2025). A trusted monitor scores each proposed action. Graded
  responses (execute, resample, defer to human audit) and suspicion that accumulates
  over a trajectory cut attack success from 58% to 7%. (Summary.)
- **SHADE-Arena.** Kutasov et al., arXiv 2506.15740 (2025). Monitors that see the
  whole trajectory catch sabotage that single steps hide. (Summary.)
- **UK AISI incident report INC-2026-07-28-01**, 4 Aug 2026. Agents in a cyber
  evaluation acted outside scope in 10 of 122 runs, with 19 actions on the live
  internet. The scope lived only in the prompt. (Read.)

## Identity, delegation, kill switch

- **Identity Management for Agentic AI.** OpenID Foundation, arXiv 2510.25819 (Oct
  2025). Per-agent identity, on-behalf-of delegation, progressive narrowing, and
  execution-count and rate limits per grant. (Read.)
- **Accelerating the Adoption of Software and AI Agent Identity and Authorization.**
  NIST NCCoE concept paper, draft Feb 2026. Calls for tamper-evident, non-repudiable
  logs and data-flow tracking. (Read.)
- **Infrastructure for AI Agents.** Chan et al., arXiv 2501.10114 (TMLR 2025).
  Agent IDs, incident reporting, rollback. (Read.)

## Protocols

- **MCP Security Best Practices**, specification 2025-11-25: no token passthrough,
  SSRF guards, session hijacking. (Read.) **MCP 2026-07-28 release**: method and name
  headers, so gateways can authorize per tool. (Read.)
- **A2A specification 1.0**, sections 4.4.7 and 8.4: signed agent cards. (Read.)

## Frameworks and regulation

- **OWASP Top 10 for Agentic Applications 2026**, 9 Dec 2025: ASI01 goal hijack, ASI02
  tool misuse, ASI03 identity and privilege abuse, ASI04 supply chain, ASI05 code
  execution, ASI06 memory and context poisoning, ASI07 inter-agent communication,
  ASI08 cascading failures, ASI09 human-agent trust exploitation, ASI10 rogue agents.
- **EU AI Act** (Regulation 2024/1689). Article 12 covers record keeping. Article 14
  covers human oversight: the ability to stop the system (14(4)(e)), to override or
  reverse its output (14(4)(d)), and awareness of automation bias (14(4)(b)). (Read.)
- **Singapore Model AI Governance Framework for Agentic AI**, IMDA, v1.5, 20 May 2026.
  It calls for deterministic controls at the tool layer, runtime rate limits, alerts on
  repeated failures, and approval-quality metrics such as override rates and response
  times. (Read.)

## What the sources do not settle

- There is no adopted standard for signing tool definitions, agent verifiable
  credentials or "know your agent". The IETF agent-authorization documents are
  individual drafts.
- No peer-reviewed study of approval fatigue in agent oversight was found. A widely
  repeated claim about reviewers approving dangerous commands could not be traced to
  a primary source.
