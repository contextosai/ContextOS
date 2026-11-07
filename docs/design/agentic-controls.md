# Runtime controls from the 2025–26 agent-security literature

Status: plan, 2026-11-07. Baseline: main `b917d000`. Sources: see
[2026-11-07-agent-governance-sources.md](../research/2026-11-07-agent-governance-sources.md).

## 1. What the literature asks of a runtime, and where ContextOS stands

The 2025–26 work on securing agents agrees on one point. Content classifiers and
prompt rules are beaten by adaptive attacks. What holds is deterministic enforcement at
the tool boundary. The table maps the fifteen controls the sources rank highest to
what ContextOS enforces today.

| # | Control | ContextOS today |
|---|---|---|
| 1 | Default-deny authorization over tool and arguments | Kernel authorization, pack rules, `input_schema`, task authorization (T28) |
| 2 | Provenance or taint tracking with rules on sinks | **Gap.** `data_only` labels and the data-flow port, but nothing remembers what a run has read |
| 3 | Per-agent identity bound to an owner | Agent binding (T30), user binding (T36), delegated act tokens |
| 4 | Delegation that only narrows | Delegation narrowing (T5, T21) |
| 5 | Risk-tiered approval bound to the exact action | Digest-bound approvals (T2, T3), step-up (T34) |
| 6 | Kill switch that propagates | Revocations by tenant, pack, agent, adapter and capability (GUIDE §8) |
| 7 | Budgets, rate limits and **automatic circuit breakers** | Budgets, loop guard, tenant rate limits. **Gap:** no cross-run rate of effects per agent, and no breaker that trips the kill switch |
| 8 | Tamper-evident attributable audit | Signed hash chain (T12), SIEM sinks (T40) |
| 9 | **Trusted monitoring with graded responses** | **Gap.** Result screening judges outputs; nothing scores an action before it is sent |
| 10 | Tool and server supply-chain integrity | Reviewed manifests, upstream pins and drift (T22, T32) |
| 11 | Plan or intent locking | Task authorization (T28), pack intents (T35) |
| 12 | Reversibility classes and rollback | `action_risk.reversibility`, compensation, outcome contracts |
| 13 | Sandboxed execution and egress control | Boundary port (T24); the sandbox itself is the deployment's |
| 14 | Governed memory writes | Memory lifecycle (T25) |
| 15 | **Oversight quality** (time-to-approve, outlier approvers) | **Partial.** Step-up and self-approval bans; no review-time floor and no approval metrics |

A sixteenth item is for the buyer rather than the runtime. Reviewers are asked to map
controls to the OWASP Top 10 for Agentic Applications, EU AI Act Articles 12 and 14,
and the Singapore agentic framework. That map does not exist yet.

## 2. Who this is for

- **Security engineer.** Needs to know that an agent which read an attacker's email
  cannot pay or send data without a human, and that data is not exfiltrated through a
  search box. (Workstream A.)
- **On-call engineer.** Needs a runaway agent stopped automatically before it does a
  thousand things, with a page and a deliberate restore. (Workstream B.)
- **AI-risk team.** Already runs a monitor model and needs its score to gate actions
  instead of filling a dashboard. (Workstream C.)
- **Compliance or audit.** Needs to show that human oversight is real, not rubber
  stamping, and to map each control to the regulation. (Workstreams D and E.)

Scale assumption: tens of thousands of effects per hour per tenant, hundreds of
agents, 3 to 30 replicas sharing one store.

## 3. Workstreams

### A. Information-flow labels (control 2, OWASP ASI01/ASI02)

Each run carries an integrity label and a classification label. Both rise with every
tool output the agent receives. Capabilities declare `flow` labels in their manifests.
Undeclared output is untrusted `INTERNAL`. Three rules compose a guardrail outcome:
an effect after untrusted input, egress above a sink's ceiling, and the "rule of two"
combination. The guard is per run, not per value. It is the coarse, deterministic part
of CaMeL and FIDES, the part a gateway can enforce without owning the planner. Labels
pass to delegated children and back. Each run pins the policy it was admitted under.

### B. Circuit breakers (control 7, OWASP ASI08/ASI10)

`[[guards.circuit_breakers]]` rules count events per agent across runs in a sliding
pair of fixed windows: new effects, refusals, or the amount an effect moves. Over the
threshold, the next matching call is refused (`circuit_open`). With `trip = "revoke"`,
the breaker also writes an agent revocation into the kill-switch document, with the
breaker as its author, so the agent stays stopped until an operator restores it. A
trip is audited (`circuit_breaker_tripped`) and exported as a metric, so it pages.

### C. Action monitor port (control 9)

`[providers.action_monitor]` is sent every effectful call's binding and the run's
recent trajectory: its last capability calls and verdicts, and its flow labels. It
answers with a suspicion score from 0 to 1 and reason codes. Thresholds set the
response: at or above `ask_at`, the call needs an approval of the exact action; at or
above `deny_at`, it is denied. Scores accumulate per run, so a run can reach a
threshold that no single call reaches. An unavailable or malformed monitor fails
closed (`ask`, configurable to `deny`). Every score above `ask_at` is audited.

### D. Oversight quality (control 15, EU AI Act Art. 14(4)(b))

`[guards.approval_review]` sets `min_review_seconds`. A decision made faster than that
after the gateway requested the approval is not counted (`approval_review_too_fast`),
which stops reflexive clicks on high-risk actions. It is scoped like step-up, by
capabilities or amounts. Each refusal is audited with the measured seconds, so the
audit chain shows who rubber-stamps. Follow-ups: approval-latency metrics, and a cap
on approvals per approver per hour, once a deployment shows which one its approvers
need.

### E. Control map for reviewers

`docs/COMPLIANCE.md` maps each ContextOS control to OWASP ASI01–ASI10, EU AI Act
Articles 9, 12, 14, 15 and 26, NIST AI RMF functions, ISO/IEC 42001 Annex A, and the
Singapore framework. Each entry names the test that proves the control.

## 4. What this does not do

- Value-level taint, which requires the planner to hold untrusted values as
  references. Agents that use such a planner keep it. ContextOS adds the guarantee
  at the boundary.
- Train or ship a monitor model. ContextOS ships the port and the thresholds.
- Behavioural baselines learned from traces. The breaker is a deterministic rate.
  Learned baselines belong to a monitor behind port C.
