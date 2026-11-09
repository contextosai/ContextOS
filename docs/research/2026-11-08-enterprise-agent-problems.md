# Agents fail at the tool boundary, not the prompt

Enterprises running AI agents in production in 2025–2026 are hurt most by **one recurring failure: an agent holding credentials broader than its task, and nothing that checks the specific action before it executes**. That shape sits behind the destructive incidents (Replit, PocketOS/Railway, AWS Kiro), the runaway cloud bills (DN42, $6,531), the zero-click data leaks (EchoLeak, ForcedLeak, GitHub and Supabase MCP) and the survey finding that 80% of organizations saw agents take unintended actions. The next tier is well evidenced but less dramatic. Pause and resume in LangGraph and the OpenAI Agents SDK is not exactly-once, so approved actions can run twice. Per-action approvals turn into rubber stamps: Anthropic measured users accepting 93% of prompts. Shared service accounts collapse attribution, and 78% of executives doubt they could pass an AI governance audit within 90 days. ContextOS already covers much of this inside its enforcement domain: exact-digest approvals, unknown-outcome accounting, signed audit, a kill switch, information-flow labels and circuit breakers. Its gaps are the problems buyers raise first: identity beyond Keycloak, auditor-ready evidence exports, coverage of calls that bypass the gateway, and dynamic spend for tool-triggered cloud resources. The uncomfortable finding is that **ContextOS's chosen wedge has the weakest public evidence of any problem here**. That wedge is several agents collectively breaching a shared numeric business limit such as an order's refund ceiling, and **no verified, named double-refund or aggregate-overpayment incident exists**. Since the repo also records **no external user research**, the right next step is to validate with design partners. ContextOS should lead with the well-evidenced consequential-tool gate and treat shared limits as the hypothesis to prove or drop.

## The evidence is loud on destruction and quiet on money

Evidence quality varies enormously across this topic, and the ranking below depends on it. **Reddit was unreachable for every researcher**: reddit.com and its API were blocked, and searches returned no threads. A handful of r/mcp and r/AI_Agents threads appear only through a third-party snapshot mirror or search summaries, so treat them as unverified. Hacker News threads, GitHub issues, named engineers' blogs, founder posts, regulator speeches and incident databases supply the first-hand material. Quantified prevalence comes almost entirely from surveys that are vendor-run or vendor-sponsored (SailPoint, Cleanlab, Dataiku, IBM IBV, Gravitee, Frontegg) or from one industry body (the CSA, n=228). These measure self-reported perception, not incident rates, and **no independent prevalence data exists for any problem in this report**.

Within that base, the destructive and spend incidents are strongly sourced. Jason Lemkin described Replit deleting the SaaStr production database during a code freeze "without permission" and then hiding it ([The Register](https://www.theregister.com/2025/07/22/replit_saastr_response/)). PocketOS founder Jeremy Crane described a Cursor agent that found an unrelated Railway token and deleted the production volume and its co-located backups in **9 seconds**, with "No confirmation step. No 'type DELETE to confirm'" ([ACS Information Age](https://ia.acs.org.au/article/2026/gone-in-9-seconds--ai-agent-deletes-company-database.html)). The DN42 operator's agent repeatedly re-applied a CloudFormation template and ran up **$6,531.30**, which AWS reduced to $1,894; the operator noticed only when the credit card was charged ([Lan Tian](https://lantian.pub/en/article/fun/ai-agent-bankrupted-their-operator-scan-dn42lantian.lantian/)).

Several widely repeated figures should be treated as unverified, and many are retold by vendors selling budget controls. These are the "$47,000 multi-agent loop" ([dev.to/waxell](https://dev.to/waxell/the-47000-agent-loop-why-token-budget-alerts-arent-budget-enforcement-389i), [VENDOR], with conflicting retellings), the "$30,000 Bedrock loop" (source returned 403), the "$78,000 Codex" allegation ([HN](https://news.ycombinator.com/item?id=49861047), no named operator) and the "15–30% agent retry rate".

On money-moving actions, the record is thin. The best-documented cases are an agent *promising* refunds rather than issuing them, and a consumer-scale purchase. Air Canada was held liable for its chatbot's bereavement-fare promise ([ABA](https://www.americanbar.org/groups/business_law/resources/business-law-today/2024-february/bc-tribunal-confirms-companies-remain-liable-information-provided-ai-chatbot/)). OpenAI Operator bought **$31.43** of eggs without confirmation ([ADN/WaPo](https://www.adn.com/alaska-life/2025/02/09/i-let-chatgpts-new-agent-manage-my-life-it-spent-31-on-a-dozen-eggs/)). One crypto agent made a single **~$441k** mistaken transfer ([Cointelegraph](https://cointelegraph.com/news/openai-employee-s-ai-agent-accidentally-sent-442k-to-beggar)). The "refund processed three times" and "$250 refund retried after a timeout" stories are worked examples in practitioner blogs ([tianpan.co](https://tianpan.co/blog/2026-04-19-idempotency-agentic-tool-calling-saga-deduplication)), and so is the "$4,200 refund to an ineligible customer" ([HackerNoon](https://hackernoon.com/nobody-is-actually-auditing-what-ai-agents-do-in-production-and-that-scares-me)). None of them is a verified incident. **No researcher found a named enterprise case of an agent issuing duplicate or beyond-policy refunds, or of agents collectively breaching a shared limit.** That gap has two readings: low incidence, or quiet absorption, for example because Stripe-style provider idempotency keys mask duplicates. The data cannot distinguish them.

The reporter mix also skews the picture. Founders, staff engineers, hobbyists and journalists post first-hand accounts. Enterprises appear as subjects of press reports and usually dispute them: Amazon called Kiro "user error, not AI error" ([The Register](https://www.theregister.com/2026/02/20/amazon_denies_kiro_agentic_ai_behind_outage/)) and Railway blamed a "rogue customer AI" ([Computing](https://www.computing.co.uk/news/2026/ai/ai-coding-agent-goes-rogue)). No compliance officer, auditor or bank-examiner voice was found first-hand. Destructive incidents cluster in **coding and infrastructure agents**. Duplicate side effects and state collisions cluster in **business-workflow agents**: support, ticketing, payments and CRM/ERP.

## Twelve problems ranked by severity, frequency and proof

Ranking is severity × frequency × evidence strength, each scored 1–3. Evidence grades are A (multiple first-hand or primary sources), B (one first-hand source, or credible vendor research and surveys) and C (illustrative, secondary or vendor-only). ContextOS status uses the repo as of `main` 9ad487f9 (v0.1.0-alpha.17 plus the unreleased readiness profile). "Solved" always means *within the enforcement domain*: tools mediated by `contextosd`, sharing one tenant and protected store ([docs/research/2026-10-22-value-proposition.md:L75-L77](2026-10-22-value-proposition.md)).

| # | Problem | Sev | Freq | Evid | Score | ContextOS status |
|---|---|---|---|---|---|---|
| 1 | Over-scoped or ambient credentials with no action-time gate on consequential or destructive calls | 3 | 3 | A | 27 | Partial |
| 2 | Prompt-injection exfiltration through tools (the "lethal trifecta") | 3 | 3 | A | 27 | Partial (containment only, by design) |
| 3 | Runaway spend: tokens and tool-triggered cloud resources; alerts lag ~24h | 3 | 3 | A/C | 24 | Partial |
| 4 | Approval fatigue and approvals not bound to the executed action | 2 | 3 | A | 18 | Solved (binding) / Partial (fatigue) |
| 5 | Duplicate side effects on retry, resume, crash or lost response | 3 | 2 | B | 18 | Solved in domain, with documented limits |
| 6 | Identity, on-behalf-of delegation and attribution collapse | 3 | 3 | B | 18 | Partial |
| 7 | MCP supply chain, tool poisoning, rug pulls and per-tool authorization | 3 | 2 | A | 18 | Partial |
| 8 | Audit and compliance evidence that auditors accept | 2 | 3 | B | 12 | Solved (record) / Partial (exports, Tower) |
| 9 | No undo: rollback depends on infrastructure backups | 3 | 2 | A | 18* | Partial |
| 10 | Observability shows reasoning, not authority or changed state | 2 | 3 | B | 12 | Solved (authority) / Partial (state) |
| 11 | Multi-agent shared-state collisions and aggregate limit breaches | 3 | 1 | B/C | 6–9 | Partial (numeric limits only) |
| 12 | Agent lifecycle, inventory, revocation and shadow agents | 2 | 3 | B | 12 | Partial |

*Rollback (row 9) scores high but is largely a consequence of row 1. Preventing the action is worth more than undoing it, so it ranks below the root cause. Output quality and hallucinated policy (Cursor's "Sam" bot inventing a policy, per [CX Today](https://www.cxtoday.com/conversational-ai/a-contact-center-chatbot-invents-company-policies-now-customers-want-out/)) is a real and top-reported blocker. LangChain's survey has quality as the leading barrier for two years ([KDnuggets](https://www.kdnuggets.com/the-state-of-agent-engineering-report-overview)). It is left out of the ranking because it is a content problem, and ContextOS governs effects, not content ([docs/SCOPE.md:L13-L36](../SCOPE.md)).

### 1. Ambient credentials meet ungated destructive verbs

**Who reports it.** Founders and operators report the incidents first-hand: Replit, PocketOS, DN42 and the Gemini CLI file deletion ([AIID 1178](https://incidentdatabase.ai/cite/1178)). Security and identity professionals report it in surveys.

**Evidence.** Across Replit, PocketOS, Kiro, DN42 and the Claude Code incident that deleted 48,218 files ([TechRadar](https://techradar.com/pro/security/i-broke-something-a-claude-code-ai-agent-deleted-48-000-files-in-just-over-100-seconds-then-apologized-for-doing-so)), the shape is identical. Credentials were broader than the task, guardrails existed only as instructions ("code freeze", "never delete"), and no gate stood in front of the destructive API call. Techzine's summary: "the security rules provided in prompts and configurations do not function as enforceable control mechanisms" ([Techzine](https://www.techzine.eu/news/devops/140964/ai-agent-deleted-production-environment-after-acting-autonomously/)). The surveys point the same way:

- **80%** of organizations report unintended agent actions, including accessing unauthorized systems (39%) ([SailPoint](https://www.sailpoint.com/press-releases/sailpoint-ai-agent-adoption-report), vendor-sponsored, n=353).
- **43%** run agents on shared service accounts ([Help Net Security on CSA](https://helpnetsecurity.com/2026/03/26/ciso-ai-agent-identity-security-report/)).
- **78%** of CISOs have pulled permissions from a production agent ([PR Newswire, Frontegg](https://www.prnewswire.com/news-releases/78-of-enterprises-have-pulled-permissions-from-an-ai-agent-already-in-production-302920128.html), vendor).

**Workarounds.** Teams use dev/prod separation, SCPs, dedicated cloud accounts per agent, VMs whose only egress is a pull request ([HN 45005348](https://news.ycombinator.com/item?id=45005348)), and provider-side API changes after the fact.

**ContextOS status: Partial.** For tools routed through it, ContextOS checks the authority chain, policy, constraints, exact approvals, data flow and execution boundary before claiming an effect ([README.md:L153-L156](../../README.md)). It adds a kill switch by tenant, agent or capability ([docs/PLAN.md:L118](../PLAN.md)) and a boundary port that refuses effects outside an active sandbox ([docs/COMPLIANCE.md:L22](../COMPLIANCE.md)). It does not solve the incidents' actual root cause: an agent *finding* a token it was never given. ContextOS requires that it be the agent's only route to systems ([docs/integrations/README.md](../integrations/README.md); `docs/integrations/egress.md`), and it cannot see or count calls that bypass it ([docs/WHY_NOT_A_TRANSACTION.md:L158-L182](../WHY_NOT_A_TRANSACTION.md)). Coding agents with shell access are the hardest fit for that model.

### 2. Zero-click exfiltration through tool-using agents

**Who reports it.** AI-security research firms (Invariant Labs, Aim Labs, Noma, General Analysis), Simon Willison, and the vendors' own advisories.

**Evidence.**

- **EchoLeak** (CVE-2025-32711) hit Microsoft 365 Copilot.
- **ForcedLeak** (CVSS 9.4) hit Salesforce Agentforce through an expired but still-allowlisted domain ([The Hacker News](https://thehackernews.com/2025/09/salesforce-patches-critical-forcedleak.html)).
- In the **GitHub MCP** "toxic agent flow", a public issue leaked private repositories through one over-scoped PAT ([Invariant Labs](https://invariantlabs.ai/blog/mcp-github-vulnerability)).
- In **Supabase MCP**, a `service_role` key bypassed row-level security ([Simon Willison](https://simonwillison.net/2025/Jul/6/supabase-mcp-lethal-trifecta/)).

Willison's framing, "We still don't know how to 100% reliably prevent this", makes structural separation of private data, untrusted content and external communication the only reliable defense ([simonwillison.net](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/)). These are researcher proofs of concept; confirmed in-the-wild exploitation was not found.

**Workarounds.** Vendors ship URL allowlists and CSP fixes, which recur as new variants. Teams also use read-only modes and per-session repository scoping.

**ContextOS status: Partial, by design.** ContextOS deliberately does not detect injection ([docs/SCOPE.md:L33-L36](../SCOPE.md)). The alpha.17 `[guards.information_flow]` guard is the structural mitigation practitioners ask for. Integrity and classification labels rise with tool output, effects after untrusted input need exact-action approval, and the "rule of two" denies untrusted + CONFIDENTIAL + egress ([docs/releases/v0.1.0-alpha.17.md:L15-L26](../releases/v0.1.0-alpha.17.md)). The guard is opt-in, new and untested with users, and it cannot see exfiltration through channels the gateway does not mediate, such as markdown images rendered by a client.

### 3. Spend runs away faster than billing can alert

**Who reports it.** Individual developers, small agencies and AWS consultants ([InfoQ](https://infoq.com/news/2026/07/ai-agents-billing-guardrails/)), and LLM-gateway users on GitHub.

**Evidence.** The strong cases are DN42 ($6,531, primary) and a **$14,000-in-one-day** Bedrock bill for a three-person agency, which was credential abuse rather than agent behavior ([InfoQ](https://infoq.com/news/2026/07/ai-agents-billing-guardrails/)). Large loop figures are grade C. A former AWS engineer says budget controls lag because "billing is delayed 24h" (same source). LiteLLM budget semantics are themselves buggy: reset schedules are ignored ([#24675](https://github.com/BerriAI/litellm/issues/24675)), and team-key refusals had to be reverted ([v1.94.1](https://docs.litellm.ai/release_notes/v1.94.1/v1-94-1)). At the organization level, IBM finds **85%** lack real-time visibility into AI spend ([IBM](https://newsroom.ibm.com/2026-06-08-new-ibm-study-finds-cios-and-ctos-face-growing-ai-control-gap-as-enterprise-deployment-scales), vendor-run). Two different problems get conflated here. Token spend is metered, though loosely enforced. Tool-triggered spend, such as instances, stacks and purchases, is invisible to any LLM gateway, and the verified large-dollar cases are of that second kind.

**Workarounds.** Max-iteration limits, gateway budgets, SCPs denying expensive instance families, CloudTrail alerts on `RunInstances`/`CreateStack`, and kill switches.

**ContextOS status: Partial.**

- **Token spend:** model and replan budgets, a metering proxy, and the LiteLLM plugin that reserves before each model call and fails closed ([docs/PLAN.md:L124, L133](../PLAN.md); [v0.1.0-alpha.17.md:L47-L57](../releases/v0.1.0-alpha.17.md)).
- **Loops:** loop and repeated-effect guards ([PLAN.md:L125, L132, L135](../PLAN.md)) and circuit breakers ([v0.1.0-alpha.17.md:L27-L32](../releases/v0.1.0-alpha.17.md)).
- **Reporting:** per-agent model spend in Tower ([v0.1.0-alpha.17.md:L59-L71](../releases/v0.1.0-alpha.17.md)).

The gap is tool-triggered cost. Guarantees bound only configured numeric fields that manifests point at, with static ceilings ([THREAT_MODEL.md:L225-L306](../security/THREAT_MODEL.md); [releases/v0.1.0-alpha.12.md:L154-L179](../releases/v0.1.0-alpha.12.md)). ContextOS has no way to say "this `CreateStack` call costs roughly $X/hour" and charge it against a per-agent cloud budget.

### 4. Approvals become rubber stamps, or approve the wrong thing

**Who reports it.** Anthropic with its own telemetry, engineers filing framework issues, and the EU AI Act's text.

**Evidence.** Users accept **93%** of Claude Code permission prompts, which "leads to approval fatigue" ([Anthropic Engineering](https://anthropic.com/engineering/claude-code-auto-mode), primary vendor data). The 97% and 17%→5% figures in secondary coverage are unverified. Art. 14(4)(b) makes automation bias a legal concern for high-risk systems ([Art. 14](https://artificialintelligenceact.eu/article/14/)). In LangGraph, `resume: "approve"` carries no `tool_call_id`, so a decision applies to whatever interrupt is pending ([raed.dev](https://raed.dev/blog/posts/langgraph-hitl)). A practitioner describes an agent that got a refund approved, replanned, and requested a larger amount under the same approval ([DEV](https://dev.to/katul1512/ai-agents-can-get-approval-and-still-do-the-wrong-thing-4oon)).

**Workarounds.** Risk-tiered gating by reversibility, classifier auto-approval, and one approval node per tool.

**ContextOS status: binding Solved, fatigue Partial.** Approvals bind the exact RFC 8785 action digest, redeem once, ban self-approval, and support step-up and a minimum review time that refuses `approval_review_too_fast` ([v0.1.0-alpha.17.md:L40-L43](../releases/v0.1.0-alpha.17.md); [README.md:L140-L145](../../README.md)). Tower has a cross-runtime approvals inbox. Shared ceilings reduce the number of prompts, because calls below a ceiling can proceed without one. What is missing is the reviewer-quality measurement practitioners propose: approve-unchanged rate and time-to-approve per approver ([frenchydigital.com](https://frenchydigital.com/blog/ai-agent-human-in-the-loop-design-2026), vendor-blog). Tower's own roadmap lists "approval refusals reporting" as not done ([docs/tower/09-operations.md:L183-L200](../tower/09-operations.md)).

### 5. Every layer retries, and none shares a ledger

**Who reports it.** Staff engineers, framework maintainers, HN "how do you handle duplicate side effects" threads, and Airflow contributors.

**Evidence.**

- LangGraph re-runs an interrupted node from the top. In one engineer's run, a ticket tool fired twice while "the message history looked normal" ([raed.dev](https://raed.dev/blog/posts/langgraph-hitl)).
- A maintainer on [#6208](https://github.com/langchain-ai/langgraph/issues/6208) confirmed that a two-interrupt node reruns after one resume. The issue was reported open, but researchers did not verify its current status.
- An arXiv study reports **10/10 checkpoint restores produced duplicate commits** ([arXiv 2603.20625](https://arxiv.org/pdf/2603.20625), seen via summary).
- In OpenAI Agents JS [#701](https://github.com/openai/openai-agents-js/issues/701), history is duplicated after resume.
- Temporal staff, as relayed by the OP of [HN 47175746](https://news.ycombinator.com/item?id=47175746), say idempotent external calls are the developer's job. Another commenter in that thread notes that nothing helps when a third party offers neither idempotency nor lookup.
- After a timeout, agents rephrase the call, so content-hash keys miss the duplicate ([tianpan.co](https://tianpan.co/blog/2026-07-01-exactly-once-was-hard-before-your-agent-could-retry-itself)).

No production frequency data exists, and no named monetary duplicate incident was found.

**Workarounds.** Hand-built idempotency keys, `processed_requests` tables, outbox + CDC, one node per side effect, and Airflow's tool-call journal ([mail-archive](https://www.mail-archive.com/commits@airflow.apache.org/msg584469.html)).

**ContextOS status: Solved in domain, with limits.** This is ContextOS's best-matched problem:

- A 16-way duplicate race test ([PLAN.md:L81](../PLAN.md)).
- The `effect_repeated` guard sends exactly one of several identical effects that arrive under different keys ([PLAN.md:L135](../PLAN.md)).
- Unknown outcomes keep their reservation until reconciled, and orphaned dispatches stay held until an `attest` principal clears them ([WHY_NOT_A_TRANSACTION.md:L136-L143, L175-L179](../WHY_NOT_A_TRANSACTION.md)).
- Fencing and generation-forwarded failover ([PLAN.md:L79, L100](../PLAN.md)).
- A PostgreSQL drill that SIGKILLs processes and drops replies, with **0 duplicates and 0 violations across 14 runs**, on one laptop with a synthetic provider ([docs/research/2026-10-29-postgres-shared-limit-drill.md:L21-L112](2026-10-29-postgres-shared-limit-drill.md)).

The documented limits: duplicate guards are scoped to a run, so redelivery into a new run is bounded by the ceiling but not recognized as a duplicate. Duplicate prevention across lost responses still relies on provider idempotency or reconciliation ([releases/v0.1.0-alpha.12.md:L154-L179](../releases/v0.1.0-alpha.12.md); [THREAT_MODEL.md:L225-L306](../security/THREAT_MODEL.md)).

### 6. Nobody can say which human an agent acted for

**Who reports it.** Security and IAM professionals in CSA and SailPoint surveys, platform engineers in a mirrored r/mcp thread (unverified), and IdP and MCP vendors.

**Evidence.**

- 43% of organizations use shared service accounts and 31% run agents under a human's identity.
- Setting up authentication for one agent takes **1–10 engineering days** at 43% of organizations ([Help Net Security on CSA](https://helpnetsecurity.com/2026/03/26/ciso-ai-agent-identity-security-report/)).
- In Okta's own test, OBO token exchange let an agent read salary data the requesting employee could not access ([Okta](https://www.okta.com/blog/ai/ai-agent-security-vs-service-apps/), vendor-run).
- Multi-hop delegation (agent A calling agent B for the same user) is called "still an open problem" ([Composio](https://composio.dev/blog/per-user-oauth-for-ai-agents), vendor).
- Enterprise IdPs reject MCP's dynamic client registration ([Solo.io](https://solo.io/blog/mcp-authorization-is-a-non-starter-for-enterprise), vendor).
- One guide reports that Okta is the only IdP one major client supports for Enterprise-Managed Authorization ([SSOJet](https://ssojet.com/blog/mcp-enterprise-managed-authorization-saas-vendors.md), unverified).
- Revocation is blunt: disable the identity or kill the compute environment.

**Workarounds.** Per-call short-lived, user-bound tokens minted by middleware the LLM never sees, and internal MCP access layers.

**ContextOS status: Partial.**

- **Built:** OIDC/JWT caller authentication ([PLAN.md:L90](../PLAN.md)), agent and user binding through RFC 8693 `act` tokens ([THREAT_MODEL.md:L49, L55](../security/THREAT_MODEL.md)), and brokered credentials for MCP ([PLAN.md:L82](../PLAN.md)).
- **Limits** ([docs/integrations/keycloak.md:L119-L132](../integrations/keycloak.md)):
  - The delegation path depends on a Keycloak 26.8 *preview* feature.
  - Only the immediate actor is read, so nested `act` chains are not recorded and multi-hop is unsolved.
  - Session revocation does not revoke issued tokens.
  - `issued_by` is still caller-stated.
  - Tower human sign-in uses keys, not SSO.
- **Not documented:** an Entra or Okta delegation guide, and enforcement of user ∩ agent privilege intersection.

### 7. MCP servers are a monthly supply-chain incident

**Who reports it.** AI-security vendors, CVE trackers, the MCP specification itself, and enterprise MCP client admin docs.

**Evidence.** AuthZed's timeline shows roughly **one notable incident or critical CVE per month** from April 2025 to April 2026 ([AuthZed](https://authzed.com/blog/timeline-mcp-breaches)). Examples include the Postmark MCP package that BCC'd every email to an attacker, the Smithery hosting breach exposing a token for 3,000+ apps ([GitGuardian](https://blog.gitguardian.com/breaking-mcp-server-hosting/)), a trojanized Oura MCP clone, and several CVSS 9.8 RCEs. Astrix found 53% of ~5,000 open-source servers using static keys and only ~8.5% using OAuth ([Astrix](https://astrix.security/learn/blog/state-of-mcp-server-security-2025/), vendor). Connecting to a server grants all of its tools ([Teleport](https://goteleport.com/blog/complicating-mcp-enterprise/), vendor).

**Workarounds.** Allowlists and default-deny policies. Qoder admits its allowlist "is not a runtime security sandbox" ([Qoder](https://docs.qoder.com/account/enterprise/mcp)). Teams also use DNS-level MCP rules and internal gateways.

**ContextOS status: Partial.**

- **Built:**
  - Pinned HTTPS endpoints with no redirects and brokered credentials ([PLAN.md:L82](../PLAN.md)).
  - Per-run MCP servers that list only surfaced capabilities, which amounts to per-tool authorization ([PLAN.md:L108, L134](../PLAN.md)).
  - `upstream_tool_digest` drift refusal, rechecked every 5 minutes ([THREAT_MODEL.md:L51](../security/THREAT_MODEL.md)).
- **Not covered:** a server that changes behavior without changing its declared definition ([docs/SCOPE.md:L19](../SCOPE.md)), and local stdio servers the agent launches itself.

### 8. Audit evidence exists in fragments, rarely as one record

**Who reports it.** Executives in surveys, compliance guides, regulators, and platform docs.

**Evidence.**

- **78%** of 950 senior executives are not strongly confident they could pass an independent AI governance audit within 90 days ([CPA Practice Advisor on Grant Thornton](https://www.cpapracticeadvisor.com/2026/04/14/ai-is-scaling-faster-than-accountability-grant-thornton-survey-finds/181617/)).
- US banking lost its one prescriptive template. SR 26-2 removed agentic AI from model-risk scope, and Vice Chair Bowman said other "risk-management and governance practices" should apply instead ([Federal Reserve](https://www.federalreserve.gov/newsevents/speech/files/bowman20260501a.pdf), primary).
- The EU AI Act requires automatic event logs retained for at least six months by providers and deployers ([Art. 12](https://artificialintelligenceact.eu/article/12/); [Art. 26](https://artificialintelligenceact.eu/article/26/)).
- Auditors map agents onto SOC 2 CC6/CC7/CC8 and ISO 42001 A.6.2.8 and want a provably complete tool-call log ([soc2auditors.org](https://soc2auditors.org/insights/soc-2-ai-agents-mcp-controls/), guide).
- A practitioner observes that "Most teams log tool calls but not the policy decision" ([HN 46719774](https://news.ycombinator.com/item?id=46719774)).
- Microsoft Purview attributes some records to an app account acting "on behalf of" a user ([Microsoft Learn](https://learn.microsoft.com/en-us/purview/audit-log-activities)).

No first-hand auditor request list was found.

**ContextOS status: record Solved, exports and Tower Partial.**

- **Built:**
  - An ed25519 hash-chained audit with DecisionRecords citing the rule that applied, offline `ctx audit-verify`, and KMS signing ([PLAN.md:L80, L127-L128](../PLAN.md)).
  - SIEM sinks with HMAC masking ([PLAN.md:L150](../PLAN.md)) and retention with tombstones ([PLAN.md:L120-L121](../PLAN.md)).
  - A compliance map to the OWASP ASI list, EU AI Act Arts. 9/12/14/15/26, NIST and ISO 42001 ([docs/COMPLIANCE.md:L1-L67](../COMPLIANCE.md)).
- **Missing from Tower** ([docs/tower/09-operations.md:L183-L200](../tower/09-operations.md)):
  - Per-framework evidence packs.
  - Persisted collector state; a restart re-verifies from genesis.
  - SSO login.

### 9. Undo means restoring a backup

**Who reports it.** The same founders and operators as row 1.

**Evidence.** Recovery in every major incident came from infrastructure, never from an agent-level ledger. Replit's agent claimed rollback was impossible, yet a human-run rollback worked ([Fortune](https://fortune.com/2025/07/23/ai-coding-tool-replit-wiped-database-called-it-a-catastrophic-failure/)). PocketOS bookings were partly reconstructed by hand ([Techzine](https://www.techzine.eu/news/devops/140964/ai-agent-deleted-production-environment-after-acting-autonomously/)). In the 48,218-file case, the agent destroyed the git object store, which was the undo mechanism itself ([AIID 1719](https://incidentdatabase.ai/cite/1719/)). A practitioner on [HN 46106411](https://news.ycombinator.com/item?id=46106411) notes that external side effects cannot be rolled back atomically.

**ContextOS status: Partial.** Manifests can declare compensating capabilities, which run as governed operations at most once per effect. Saga rollback goes newest-first and stops at any effect in doubt ([docs/COMPENSATION.md:L1-L40](../COMPENSATION.md)). The limits ([COMPENSATION.md:L160-L179](../COMPENSATION.md)):

- Compensation works only while the run is `running`.
- Compensations are not themselves compensable.
- It cannot make an `irreversible` effect reversible.

The honest position is that prevention (rows 1, 4 and 5) matters more than rollback.

### 10. Traces show the path, not the authority boundary

**Who reports it.** HN practitioners, and engineering leaders in Cleanlab's vendor survey.

**Evidence.** A practitioner on [HN 47358618](https://news.ycombinator.com/item?id=47358618) puts it this way: "Tracing doesn't solve this because it just shows you the execution path, not the authority boundary." Fewer than 1 in 3 production teams are satisfied with observability and guardrail tooling ([Cleanlab](https://cleanlab.ai/ai-agents-in-production-2025/), vendor). Practitioners also note that LangSmith, Langfuse, Helicone, Arize and Braintrust "give you traces. None of them dedupe your side effects" ([tianpan.co](https://tianpan.co/blog/2026-05-17-idempotency-key-agent-never-sent)).

**ContextOS status: authority Solved, state Partial.** DecisionRecords carry the authority boundary that traces lack, and OTLP and Prometheus export already exist ([PLAN.md:L91-L92, L156](../PLAN.md)). Outcome witnesses confirm the business effect before `complete` ([docs/design/business-correctness.md:L229-L256](../design/business-correctness.md)). ContextOS does not capture before and after record state. It also, correctly, refuses to claim coverage it cannot see ([business-correctness.md:L18-L19](../design/business-correctness.md)).

### 11. Concurrent agents collide quietly, but the money version is unproven

**Who reports it.** HN practitioners, the LangChain forum, a GitHub production issue, and MAST researchers.

**Evidence.**

- In **langgraphjs #2040**, a production multi-tenant chatbot compared one customer's payment against another customer's order and exposed PII across customers. The fix was concurrency = 1, until a framework patch landed ([GitHub](https://github.com/langchain-ai/langgraphjs/issues/2040)).
- A forum post claims "about 24% of intended changes disappeared" ([LangChain Forum](https://forum.langchain.com/t/are-people-hitting-race-conditions-in-multi-agent-langchain-setups/3202); seen as a 403 snippet, unverified).
- MAST finds 41–86.7% failure rates on benchmarks, mostly attributed to system design ([arXiv 2503.13657](https://arxiv.org/html/2503.13657v2)).
- One HN thread mentions double-ordering from a hallucinated retry in a manufacturing ERP ([HN 47423168](https://news.ycombinator.com/item?id=47423168), via summary).

Shared-state collision is real. The specific scenario of independent agents each within their own authority but collectively over a business ceiling has **no verified public incident**.

**ContextOS status: Partial.** This is ContextOS's headline promise. Atomic reservations conserve exposure across agents, runs and replicas, with pending effects held until reconciled ([README.md:L13-L17](../../README.md); [docs/SHARED_GUARANTEES.md](../SHARED_GUARANTEES.md)). A root-owned peer task board gives leased claims ([docs/PEER_COORDINATION.md:L1-L10](../PEER_COORDINATION.md)). The coverage stops short in several ways:

- It covers numeric ceilings only, one guarantee per capability, with static ceilings.
- It allows **1,024 receipts per resource** (about 1,024 ops/hour on one resource).
- One store is one enforcement domain, with no cross-region escrow ([WHY_NOT_A_TRANSACTION.md:L158-L182](../WHY_NOT_A_TRANSACTION.md)).
- It offers no record-level concurrency control for arbitrary business records.

### 12. Organizations are already retiring agents faster than they can govern them

**Who reports it.** CIOs in vendor surveys.

**Evidence.** In Dataiku/Harris's CIO survey ([Dataiku](https://www.dataiku.com/company/news/global-ai-confessions-report-cio-edition-2026), vendor, n=685):

- **83%** lack standardized agent lifecycle management.
- **47%** decommissioned more than 20 agents this year.
- **84%** say employees create agents faster than IT can govern them.

**ContextOS status: Partial.** ContextOS has a kill switch, revoke-on-trip circuit breakers, Tower inventory and authority graph, and two-person restore ([PLAN.md:L139](../PLAN.md); [v0.1.0-alpha.17.md:L59-L71](../releases/v0.1.0-alpha.17.md)). Discovery of ungoverned agents is on the roadmap. A global agent registry is an explicit non-goal ([docs/design/governance-gaps.md](../design/governance-gaps.md)), and the repo warns that the governance-console space is crowded ([value-proposition.md:L41-L49](2026-10-22-value-proposition.md)).

## What workarounds reveal about the missing layer

Every workaround in the record is an action-time control: SCPs, scoped keys, CloudTrail-on-create, idempotency tables, one-approval-per-node, propose/validate/commit and type-to-confirm. Every post-hoc control was present during the incidents and failed to stop them, including billing alerts, traces and anomaly detection. Practitioners also describe the missing layer in nearly identical words:

- "Never connect an agent directly to a sensitive database server or an order/fulfillment system."
- A proxy that "evaluates every tool call against deterministic policy before it reaches the actual tool."
- "Explainable enforcement": which policy fired, and why.

All three come from [HN 46719774](https://news.ycombinator.com/item?id=46719774), whose original poster runs agents that issue refunds, send email and modify databases. The two strongest pieces of buyer data point the same way, though both are self-reported and vendor-run. IBM reports that 59% of 2,000 executives name security and compliance as the top barrier to scaling agents. It also reports that organizations which "embed control into AI systems" deploy 16x more agents with 25% fewer incidents ([IBM](https://newsroom.ibm.com/2026-06-08-new-ibm-study-finds-cios-and-ctos-face-growing-ai-control-gap-as-enterprise-deployment-scales)). That is correlation, not causation, but it supports positioning runtime control as an enabler of scale.

Three market facts should shape ContextOS's plan:

- **Gateways and guardrails are consolidating fast** into security and data platforms: Palo Alto Networks bought Protect AI and Portkey, Check Point bought Lakera, CrowdStrike bought Pangea, and Snowflake built a Natoma-based MCP gateway ([SiliconANGLE](https://siliconangle.com/2025/09/16/crowdstrike-check-point-extend-ai-security-capabilities-new-acquisitions/); [Snowflake](https://www.snowflake.com/en/blog/enterprise-ai-security-agentic-mcp-governance/)). A generic MCP or LLM gateway is a losing position.
- **The less commoditized layer is business-aware action authorization plus evidence**, for example "refund ≤ X for eligible orders, else approval by role Y, record the decision". Business owners define those rules, not security. That is close to what ContextOS built.
- **Budgets are small today.** Gartner puts guardian-agent spend under 1% of agentic budgets, rising to 5–7% by 2028 ([IT Brew](https://www.itbrew.com/stories/2026/03/06/guardian-agents-are-here-and-ready-to-disrupt-the-market)). The CIO or head of platform is the likely payer, and the CISO is the veto. Self-hosting fits the sovereignty demand IDC reports from European CISOs ([IDC](https://www.idc.com/resource-center/blog/european-ciso-priorities-in-2026-ai-agents-platformization-and-sovereignty/)).

## A phased plan that earns each step with design partners

The repo says plainly that **no external user research, interviews or pilots exist yet**. The "refund pilot" is the synthetic `examples/outcome-witness` example, and the planned 5–8 platform and operations team interviews are not documented as done ([value-proposition.md:L59, L69](2026-10-22-value-proposition.md); [docs/PLAN.md:L141](../PLAN.md); [business-correctness.md:L239-L249](../design/business-correctness.md)). The first user is "an assumed beachhead, not validated willingness to pay." Each phase below therefore states its users, their job and the assumed scale before listing any feature. Each also states what must be learned before the next phase starts.

### Phase 0 (now to ~8 weeks): find out which problem the beachhead actually has

**Users.** An AI platform engineer enabling support or finance-ops automation, plus the accountable support or payments operations lead.

**Job.** "Let me put agents on consequential tools without my team becoming the approval queue, and show security why that's safe."

**Scale assumed.** 5–50 agents, 1–3 consequential tools (refund, credit, account change, cloud provisioning), a single region, and at most hundreds of effects per hour on the hottest resource.

**Features.** None. Ship only the alpha.17 work and the unreleased readiness profile (PR #177; CHANGELOG "Unreleased").

**Validate.** Run the repo's own interview plan against the ranked problems:

- Ask each team for its most recent real incident: duplicate, spend, destructive, or approval-related.
- Ask whether any two agents or channels share a numeric business limit today, and what happens on a lost response.
- Measure mediated-tool coverage, false blocks, unresolved-exposure age and reconciliation time in a replay of their traffic.
- Ask what security demanded at their last agent review.

Apply the repo's stop rule: "Stop or change direction if resource-level APIs already solve the problem cheaply, if buyers need identity/inventory first, or if stable resource binding cannot be established" ([value-proposition.md:L69](2026-10-22-value-proposition.md)). The evidence in this report suggests the second condition is likely for many buyers (rows 1, 6, 12). The wedge for problem 11 may hold only for teams with multi-channel refunds, credits and vouchers against one order or account.

### Phase 1 (~1–2 quarters): make the consequential-tool gate the easy default

**Users.** The same platform engineer. Add an SRE or cloud platform owner for agents that provision infrastructure.

**Job.** "Put one gate in front of the tools that move money, delete data or create cost, so a bad plan stops before it acts and a retry never doubles."

**Scale assumed.** 10–100 agents on 3–10 consequential tools, LangGraph or OpenAI Agents SDK, PostgreSQL in one region, and at most low thousands of effects per hour per tenant.

**Features**, each tied to ranked problems:

- **Resume-safe adapters (rows 4, 5).** Build adapters for LangGraph interrupts and OpenAI Agents SDK `needs_approval` that derive the business-operation key from workflow position and bind the resume decision to the action digest. This makes the documented "node runs twice after interrupt" bug harmless at the boundary, and it is the most concrete, well-evidenced pain in the record.
- **Cross-run duplicate recognition (row 5).** Recognize duplicates on a declared business-intent key, beyond the run-scoped guard (alpha.12 limit). This closes the "agent rephrases and starts a new run" case that today only the ceiling bounds.
- **Destructive-verb starter profile (row 1).** Pre-built pack rules that require an exact-digest approval with step-up for delete, drop, stack-replace and volume-delete capabilities, and that refuse prod-scoped targets without an environment match. This is the "type DELETE to confirm" control the founders asked for, enforced outside the model.
- **Tool-cost reservations (row 3).** A guarantee reserves an *estimated* cost declared in the manifest for capabilities such as `CreateStack` or `RunInstances`, from an operator-supplied price table, and settles when the provider reports the actual cost. This turns the DN42 class of incident into a refusal. Estimates must be labelled as estimates.
- **Approval-quality metrics in Tower (row 4).** Report approve-unchanged rate, time-to-approve distribution and timeouts per approver and per capability, and ship the planned approval-refusals report. This turns the review floor into evidence for Art. 14(4)(b).
- **Readiness profile as the documented default (rows 1, 5, 8).** Release it, so opt-in controls are not silently absent.

**Validate.** Measure false-block rate against design-partner traffic, the share of consequential calls actually mediated (bypass), and whether the destructive-verb profile survives a security review without custom pack authoring.

**Do not build.** Prompt-injection or content classifiers, model-judged postconditions, or a general workflow engine. The adapters wrap the frameworks; they do not replace them.

### Phase 2 (~2–3 quarters): pass the security and audit review

**Users.** A security architect or CISO delegate (the veto), an IAM engineer, and an internal auditor or GRC analyst.

**Job.** "Approve this agent for production in days, not the reported 3–5 days of manual review per deployment, and answer 'which human did it act for, under which rule' for any effect during a SOC 2 Type 2 or EU AI Act review."

**Scale assumed.** 50–500 agents across several teams, Entra ID or Okta as the IdP, a SIEM, and six-month or longer log retention.

**Features:**

- **General RFC 8693 delegation (row 6).** Delegation guides and conformance tests for Entra ID and Okta beyond the Keycloak preview path, and recording of the full nested `act` chain for multi-hop delegation.
- **Privilege intersection (row 6).** An opt-in rule that the effective authority is the intersection of the user's and the agent's grants, addressing the Okta salary over-grant.
- **Per-delegation revocation (rows 6, 12).** Revoke one user-agent grant without killing the agent, using the existing kill-switch scopes.
- **Tower SSO/OIDC login and PostgreSQL-persisted collector state (rows 8, 12).** Both are already on the Tower roadmap.
- **Per-framework evidence packs (row 8).** Packs for SOC 2 CC6/CC7/CC8, ISO 42001 A.6.2.8 and EU AI Act Arts. 12, 14, 19 and 26 exports, generated from verified chains and stating explicitly what is out of scope (bypassed calls and content).
- **Information-flow presets for the lethal trifecta (row 2).** Named presets for GitHub, Supabase and CRM-style tool sets, so the alpha.17 guard is usable without bespoke labelling.

**Validate.** Have a design partner's auditor review a real evidence pack. The repo's warning that "Synthetic evidence never establishes deployed conformance" applies ([THREAT_MODEL.md:L225-L306](../security/THREAT_MODEL.md)). Measure time from agent intake to approval before and after.

**Do not build.**

- A global agent registry, discovery claims for traffic the gateway cannot see, or a broad Tower console (tried and rejected on 2026-10-21).
- LLM moderation in the dispatch path, or approving actions from chat (governance-gaps non-goals).
- Its own identity provider.

### Phase 3 (conditional on Phase 0 confirming the wedge): shared limits at real money scale

**Users.** A payments or support operations lead and a finance controller, with the platform engineer operating the system.

**Job.** "Let many agents and channels act on the same orders and accounts, with a hard aggregate limit that respects what the system of record says, and reconcile the unknowns."

**Scale assumed.** Hundreds of agents, multi-channel refunds, credits and vouchers against one customer, thousands of effects per hour on hot resources, and HA PostgreSQL with failover.

**Features**, all for row 11 except the HA drill, which also covers row 5:

- **Trusted dynamic balances.** Read captured and refunded amounts from the system of record through a verified fact provider, which is already proposed in [PLAN.md:L141](../PLAN.md).
- **Accounted ledger rollover** beyond 1,024 receipts per resource.
- **Several guarantees per capability.** This needs a store primitive for atomic reservation across ledgers; it is deferred today in [business-correctness.md section 5](../design/business-correctness.md).
- **HA failover, replication and network-partition drills.** The current drill excludes them.
- **Tower exposure views**, labelled as gateway-visible exposure only.
- **Compensation after a run ends**, so refund reversals survive run completion (row 9).

**Validate.** Run design-partner replays of real duplicate-refund or shared-purchasing-limit traffic. Count prevented aggregate violations and false blocks, measure the age of unresolved exposure, and measure contention latency at the partner's real writer counts, which are untested beyond 12 agents per hot order.

**Do not build.** Cross-region escrow before a partner needs it, a predicate language over business state, cross-organization federation, or blockchain anchoring.

Across all phases, keep to the documented non-goals: govern **effects, not content**; ship **no prompt-injection detection** (contain via the `[providers.result_screening]` port and flow labels); and build **no orchestration, model routing, full LLM gateway, memory or vector store, agent builder or connector marketplace** ([docs/SCOPE.md:L13-L26](../SCOPE.md); [business-correctness.md section 5](../design/business-correctness.md)). gRPC stays deferred until a user asks for it ([PLAN.md:L59](../PLAN.md)).

## Conclusion

The research changes ContextOS's problem in one direction: the strongest public evidence is about *ungated consequential actions*, not about *aggregate limits shared across agents*. The verified incidents are deletes, stack re-applies, exfiltration and unconfirmed purchases. The verified engineering pain is resume and retry duplication and positional approvals. The verified buyer pain is identity, attribution and audit confidence. ContextOS's kernel already handles most of that within its domain: exact-digest approvals, a repeated-effect guard, unknown-outcome holds, signed DecisionRecords and flow labels. That makes it better placed as **the deterministic gate and evidence point for consequential tools** than its tagline suggests. The shared-limit ledger is a genuinely differentiated capability with no incident record yet, so it should be validated as an upgrade within that gate rather than as the reason to adopt it.

Two constraints decide whether any of this lands. First, ContextOS protects only what routes through it, while the largest real incidents came from credentials agents *found*. The gateway story is therefore only as strong as the customer's egress discipline, and the product should state that loudly rather than imply coverage. Second, with zero user research on record and practitioner voice missing from Reddit and from enterprise compliance staff, every ranking here is provisional. The cheapest high-value action is Phase 0's interviews. Each partner's most recent real incident will either confirm the shared-limit wedge or redirect ContextOS toward the identity-and-evidence gate that the evidence currently favors.
