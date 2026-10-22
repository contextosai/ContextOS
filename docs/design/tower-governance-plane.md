# ContextOS Tower: the organisation's governance plane

Status: built (see "Build order"); increments 1 to 4 are implemented. This is the
design record; the developer documentation is in [docs/tower](../tower/README.md). Non-normative: the
spec defines the Trust plane as "the control plane over the other four" but ships no
control plane; this is the runtime project's implementation of it, using the spec's
own concepts wherever the spec has one.

## 1. The problem

An organisation deploys many agents: different teams, frameworks, models and business
units, some through ContextOS runtimes and some not. Leadership, risk and security
need to answer, at any time and with evidence:

1. **What agents do we have**, who owns each, and what can each one actually do: to
   which systems, with which data, with how much money or reach?
2. **Is each one only doing what it is allowed to do**, and do the controls it needs
   for what it does actually exist?
3. **What changed** (new agents, new capabilities, looser policy, new models) and who
   approved it?
4. **What is going wrong right now**, how far does it reach, and how do we stop it?
5. **Can we prove it** to an auditor or regulator?
6. **How do we change the rules** safely across hundreds of agents?

A console that shows one runtime's audit stream answers none of these. They are
questions about the *fleet*, asked by people who are not runtime engineers.

## 2. Who uses it, for what

| Role | Their questions | What they need from Tower |
|---|---|---|
| Head of AI risk / CISO | Are we safe? Where are we exposed? What do I tell the board? | Posture summary, exposure ranked by consequence, trends, evidence by framework |
| Risk / compliance reviewer | Can this agent go to production? Is this policy change safe? | Intake review with required controls and gaps, policy change impact on real history |
| Agent owner (team lead) | What does my agent need before launch? Why was it blocked? | Their agents' gaps and findings in plain language, run explanations |
| Platform / on-call | Something is wrong; contain it | Anomalies with briefings, blast radius, fleet-wide kill switch |
| Auditor | Show me the controls and the evidence | Read-only evidence packs that verify independently |

## 3. First principles

1. **Govern at chokepoints, and measure coverage.** Governance is only real where
   effects pass a control point (the Tool Gateway, the model gateway, identity
   issuance). An agent whose effects bypass the gateway is *ungoverned*, not
   *compliant*. Coverage is the first metric, and unknown agents are the first
   finding.
2. **Every agent has an accountable owner.** No owner means no production.
3. **Risk is multi-dimensional; never collapse it into a score.** (Spec: ActionRisk
   has five independent dimensions; "a risk tier tells us when a human must approve"
   is a listed misconception.) Tower derives each agent's *required control profile*
   from the risk of what it can do (spec control profiles: core, enterprise,
   durable-delegated, high-assurance) and reports exposure per dimension.
4. **Required controls come from what an agent can do, not from what its owner
   declares.** Declarations are inputs to review, never evidence.
5. **Effective authority is a graph, and change to it is drift.** (Spec:
   effective authority = principal chain ∩ delegation ∩ manifest ceiling ∩ policy ∩
   surfaced capability ∩ containment ∩ approval.) A new or widened edge needs an
   owner, a review and an expiry.
6. **Enforcement is deterministic; intelligence is advisory.** LLMs never sit in
   the enforcement path. They help people author, triage, explain and investigate.
   Everything an AI produces is a *proposal* that passes deterministic checks and a
   human decision before it changes anything. (Spec: NL-to-policy is an optional
   accelerator with required drift and satisfiability checks; machine reviewers may
   recommend but approve only where policy names an automated principal.)
7. **The governance AI is itself governed.** It is read-only, scoped to what the
   asking person may see, treats agent data as untrusted, cites evidence for every
   claim (and Tower checks the citations exist), and every use is journalled.
8. **Evidence over assertion.** Tower verifies every audit chain it ingests (digest,
   hash link, Ed25519) and records its own governance actions in its own signed
   journal. A finding links to the entries that support it.
9. **Exceptions are first-class.** Real organisations need them. A waiver is scoped,
   owned, justified, time-boxed, approved by someone other than the requester, and
   expires on its own.
10. **Separation of duties.** Builders do not approve their own agents' risk; policy
    authors do not approve their own policies; the AI never approves anything.
11. **Federated by default.** Runtimes stay in their region or business unit and keep
    content. Tower ingests metadata (identifiers, references, outcomes, counts),
    never prompts, tool arguments or personal data. Content stays one click away, in
    the runtime, under its own access control.
12. **Change is simulated before it lands.** A policy change is evaluated against the
    current inventory and against recorded real cases (the release gate) before
    rollout, with the drift it causes named.

## 4. Architecture

```
  business unit A          business unit B             org
 ┌──────────────┐        ┌──────────────┐        ┌──────────────────────────────┐
 │ contextosd   │──────▶ │ contextosd   │──────▶ │ towerd (governance plane)    │
 │ (data plane) │ audit  │ (data plane) │ audit  │  collector: verify + index   │
 │ packs, gate, │ chain, │              │ chain, │  inventory + authority graph │
 │ kill switch  │ packs, │              │ packs, │  required profiles + gaps    │
 └──────────────┘ deploy └──────────────┘ deploy │  guardrails, waivers         │
        ▲                                         │  anomalies, oversight        │
        │ kill switch, rollouts (scoped tokens)   │  intelligence (Claude)       │
        └─────────────────────────────────────────│  signed journal              │
                                                  └──────────────┬───────────────┘
                                                                 │ API
                                                           Tower (web UI)
```

- **Runtimes (`contextosd`)** remain the only place effects are decided. Tower reads
  them through their API with tenant-scoped `audit:read` keys, and acts on them only
  through their own scoped endpoints (`control` for the kill switch), so every action
  is also in the runtime's own audit chain.
- **`towerd`** is a separate service: a governance outage never stops agents, and a
  compromised Tower cannot forge runtime history.
- **The collector** tails each source's audit chain from a persisted, verified cursor
  and folds entries into per-agent aggregates. It keeps aggregates (per agent per hour)
  and a bounded window of recent run summaries, not raw events: raw evidence stays in
  the runtime, reachable by id. Memory is proportional to agents × time buckets, not to
  traffic.
- **`run_admitted`** (added to the runtime for this) attributes each run to its agent,
  pack, contract, required controls, surfaced capabilities and release references
  (which model, which evaluators), signed before the run starts.

## 5. The governance model

- **Agent.** Identified by `agent_urn` when present, else `agent_id` within a tenant.
  Discovered from `run_admitted`; enriched by a *declaration* (owner, team, business
  unit, purpose, users served, lifecycle stage, data categories, regulatory context).
- **Authority graph.** For each agent: the packs it runs under; each pack's surfaced
  capabilities with their ActionRisk (effect, authority, reversibility, interaction,
  data scope); approval gates and guardrails that cover them; adapters; the runtimes
  and tenants it runs in. Observed edges (capabilities actually used) are compared
  with declared edges (capabilities pinned in packs). Drift = an edge that appeared
  or widened since the agent's last review.
- **Required control profile.** Derived deterministically from the authority graph
  (the spec's workflow applicability: external effects → enterprise; irreversible or
  human-approved external effects, physical effects, restricted data → high-assurance;
  delegation → durable-delegated controls), compared with the controls the runtime
  declares and the conformance evidence it holds. Output: missing controls and
  `insufficient_evidence` where support is only declared.
- **Findings.** Built-in checks (no owner, ungoverned, missing controls, unreviewed
  drift, irreversible effect without an approval gate, unresolved effect outcomes,
  vacuous oversight, broken chain) plus **org guardrails**: JsonLogic rules over agent
  facts, evaluated with the same bounded evaluator the kernel uses. Each finding has
  a severity, the evidence behind it, a remediation, and an owner.
- **Waivers.** Scoped to (finding rule, agent), with reason, requester, approver
  (not the requester) and expiry.
- **Oversight quality.** Per approval gate: how often approval is required, how often
  it is redeemed. Spec "oversight non-vacuity": a gate that is always approved in
  seconds is reported, because it may be rubber-stamped.
- **Anomalies.** Deterministic detectors on per-agent hourly aggregates: refusal or
  unknown-outcome spikes against the agent's own baseline, first use of a capability,
  loop and repeated-effect guards firing, sudden volume change.

## 6. Where intelligence helps, and how it is bounded

| Job | What the model does | What makes it safe |
|---|---|---|
| **Ask Tower** (analyst) | Answers questions about the fleet by calling read-only tools (inventory, findings, authority, activity, runs) | Tools are read-only and scoped to the asker; answers must cite agent, finding and run ids, and uncited or unknown ids are flagged; tool output is data, never instructions |
| **Draft a guardrail** | Turns a stated intent ("no agent may move money without human approval") into a JsonLogic rule over agent facts, with test cases | The rule is parsed and evaluated by the kernel's evaluator; its impact on the current inventory is shown (which agents it flags, which it no longer flags); unsatisfiable or always-true rules are rejected; adoption needs a second person |
| **Intake review** | Drafts a review of an agent: what it can do, its exposure, required controls, gaps, questions for the owner, applicable regulatory context | The deterministic profile and findings are authoritative; the draft is labelled AI-generated, cites the facts it used, and the reviewer decides |
| **Brief an anomaly** | Explains what changed, the likely cause, the blast radius and containment options | Containment is offered as a proposal that runs through the normal scoped kill switch, by a person |
| **Explain a run** | Plain-language account of what happened and why (which rule, which guard) | Built from the run's evidence, fetched from its runtime under the asker's scope |

Every model call is journalled (who asked, which model, input and output digests,
token usage) in towerd's signed journal. The model is `claude-opus-5-5` through the
Anthropic Messages API, with refusal handling and server-side fallback. Without a
configured key, Tower runs with intelligence off and everything deterministic still
works.

## 7. Roles

`viewer` (read), `owner` (declare and fix their team's agents, request waivers),
`risk` (review agents, approve waivers, adopt guardrails), `operator` (contain:
fleet-wide kill switch), `admin` (sources and configuration). Separation of duties is
enforced in towerd: no approving your own waiver, guardrail or agent review.
Identities come from API keys (service use) or OIDC bearer tokens with group-to-role
mapping (people).

## 8. Honest limits

- Tower governs what passes a ContextOS runtime. Agents that never touch one appear
  only through declarations or other discovery feeds, and are marked unverified.
- Approvals happen in the organisation's approval service; Tower sees requirements and
  redemptions, not refusals there, so oversight metrics are partial.
- Aggregates rebuild from the verified chains after a restart without persistence; the
  persistence layer for cursors and aggregates is part of the next increment.
- Regulatory mappings are informative (as in the spec). They organise evidence; they do
  not establish legal compliance.

## 9. Build order

1. Runtime: `run_admitted` audit entry. **Done.**
2. `towerd`: sources, verified incremental ingest, agent inventory, authority graph,
   required profiles, findings, guardrails, waivers, anomalies, signed journal, roles.
   **Done.**
3. Intelligence: Ask Tower, guardrail drafting with impact, intake review, anomaly
   briefs, run explanation; scripted provider for tests. **Done.**
4. Tower UI on `towerd`: Posture, Agents, Agent, Findings, Activity, Guardrails,
   Waivers, Ask, Runtimes, Journal. **Done.**
5. Next: persistence of cursors and aggregates (PostgreSQL), OIDC login in the UI,
   discovery feeds (model-gateway traffic without a run id), evidence packs per
   framework, policy-bundle distribution to runtimes.
