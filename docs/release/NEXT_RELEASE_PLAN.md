# Next release plan: 0.1.0-alpha.22

Status: **approved by the maintainer on 2026-11-25** (see "Decisions").
Written 2026-11-25 against main at `4fa23575` (alpha.21 plus the Failure Lab and its
runtime follow-ups, unreleased).

The goal of this release is to cover governance across an agent's whole lifecycle:
who it is, what it may do, what it did, what data it touched, what it cost, whether
it behaved, who approved it, and whether that can be proved to an auditor offline.
Refunds stay one reference workflow among several.

Most of the runtime already exists. This plan lists what exists per theme, the gaps,
and the smallest change that closes each gap by **extending** an existing mechanism.
Anything not built in this release is listed as planned, with a reason.

## Guarantees this release must not weaken

Pre-action authorization; shared aggregate limits across agents and runs; hold and
compensate on unknown outcomes; signed, hash-chained evidence verifiable offline;
digest-bound, single-use approvals; tenant isolation and separation of duties;
fail-closed behaviour. Every new feature below gets a threat-model entry (T45 onward)
and a regression test that shows the guarantee still holds with the feature on.
New parsers get a fuzz target.

Design rules for the release:

- The kernel stays pure (no I/O, clock or RNG). Anything that needs a clock (change
  windows, break-glass expiry, legal holds) is decided in the gateway against the
  server clock and recorded in the audit entry, as the approval timeout is today.
- New features are off unless configured, except where they only add audit detail.
  The enterprise profile may require them.
- The inventory is a view over evidence (the audit chain and Tower's signed journal),
  not a second source of truth.

## Users this release serves

Following the rule that product work starts from named users and their questions:

| User | Questions they need answered |
|---|---|
| Compliance / internal audit | Which agents exist, who owns them, what may they do? Show me evidence for control X, offline. |
| Platform / on-call | What is held, denied or anomalous right now? Stop this agent, tool, tenant or everything. |
| Agent developer | Will my new pack break production decisions? Does my framework adapter behave correctly? |
| Security / privacy | Where can classified data go? Who holds unused grants? Erase this person's data and prove the chain still verifies. |
| Finance / team lead | What did each team's agents spend, and will they stop before the ceiling? |

## Inventory: what exists, gaps, planned work

Status: **E** exists, **P** partial, **M** missing. PR numbers are placeholders
assigned when opened.

### A. Agent inventory and lifecycle

| Item | Today | Gap | Planned |
|---|---|---|---|
| Inventory | P: Tower fleet built from verified audit chains (first/last seen, packs, intents, models, capabilities, tenants, delegates) plus owner declarations (team, purpose, data categories) | No view of tools, MCP servers and models as first-class rows; environment is per source, not per agent; no offline form | A1: inventory rows for agents, capabilities/tools, adapters (MCP servers), models and owners, each with first/last seen, environment, risk tier, owner team. Same view offline: `ctx inventory --entries --keys` from an audit export |
| Lifecycle | P: states proposed, pilot, production, deprecated, retired; `agent_declared` journal entry; separate review with SoD; not enforced at runtime | No suspended state; transitions need no approval; retired agents can still run | A2: states proposed → approved → active → suspended → retired (pilot/production kept as active sub-stages; migration maps old values). Transitions need an approval by someone other than the requester, are signed into Tower's journal, and suspend/retire issue an `agent` revocation on every source so the runtime refuses them |
| Shadow agents | P: `undeclared_agent` finding; `agent_binding`; unpinned tools refused | No finding for undeclared tools, adapters or models in traffic | A3: `undeclared_tool`, `undeclared_model`, `undeclared_adapter` findings, and `--fail-on-shadow` on `ctx inventory` for CI |

Threats: T45 (lifecycle change without approval or a retired agent still acting).

### B. Risk classification and policy packs

| Item | Today | Gap | Planned |
|---|---|---|---|
| Risk tiers | P: multi-dimension `ActionRisk`; profile per agent in Tower | No tier label; no rules by tier | B1: `risk_tier` (low, limited, high, prohibited) on agent declarations and capability manifests; `[guards.risk_tiers]` maps a tier to required controls (approval, step-up, evidence, model allow-list); `prohibited` is refused at admission and dispatch. Fail closed: a high-tier capability with no tier rules refuses to start under the enterprise profile |
| Ready-made packs | P: one refund pack, one rule library, two starter profiles | Library of packs per control family | B2: `packs/` rule libraries and profiles: spend and rate limits, data egress, destructive actions (delete, send email, deploy, transfer), PII-touch, environment separation, change-freeze windows, human-in-the-loop thresholds. Each ships with `ctx test` suites |
| Change windows | M: no clock in policy | Time-of-day and freeze windows | B3: `[[guards.change_windows]]` evaluated in the gateway on the server clock (deny or require approval inside a window), recorded in the decision. Kernel unchanged |
| Simulation | P: `ctx gate` compares packs on replay cases; rollouts have shadow mode | No bulk re-decision of recorded traffic with a readable diff | B4: `ctx simulate --cases DIR --baseline P --candidate Q` re-decides every recorded replay case and writes a diff report (Markdown + JSON: newly denied, newly allowed, approval changes, by capability). Staged rollout stays `/v1/rollouts` (shadow then percent) |
| Policy tests | E: `ctx test --junit` | — | Extend suites to the new packs; no new code |

Threats: T46 (tier mislabelled to dodge controls), T47 (change window bypass by clock skew or unset time zone).

### C. Data governance and privacy

| Item | Today | Gap | Planned |
|---|---|---|---|
| Classification | E: levels public < internal < confidential < restricted; `[guards.information_flow]` | No data categories (PII, PHI, PCI, secrets) | C1: `data_categories` on manifest inputs and outputs, tracked per run beside the level |
| Data-flow rules | P: by tool (`egress_ceiling`), data-governance port, residency | No declarative vendor/region/tenant boundary | C2: `[[guards.data_boundaries]]`: category → allowed adapters, vendors, regions; block or hold for approval |
| Masking | E: sink masking with HMAC tokens; signatures still verify | No written proof procedure | C3: `ctx audit-verify --masked-ok` report and a test that verifies a masked export end to end; documented proof |
| Retention, legal hold, DSAR | P: run content retention; per-run erase with store tombstone and `run_data_erased` audit entry | No legal hold; no erase by data subject | C4: `POST /v1/legal-holds` (scoped by tenant, run, subject ref) blocks retention and erasure; `POST /v1/subjects/{ref}/erase` erases every run tagged with that subject, each with a signed tombstone entry; `ctx audit-verify` passes after both |
| Screening port | E: `[providers.result_screening]` | No reference adapter; CONFIG lacks a `[providers]` section | C5: reference pattern-based screener (examples), off by default; document `[providers]` |

SCOPE.md will say plainly: rule- and metadata-based enforcement, not content
moderation. Threats: T48 (erasure under legal hold, or erasure that breaks
verification), T49 (category dropped between tools to escape a boundary).

### D. Identity, access and delegation

| Item | Today | Gap | Planned |
|---|---|---|---|
| Workload identity | E: JWT-SVID agent binding, OIDC, act-token delegation (Keycloak) | X.509 SVID only gates the connection | D1: `agent_binding` source `x509_svid`: the SPIFFE ID in the mTLS client certificate must name the declared agent |
| Short-lived tokens | P: inbound verification only; outbound OAuth client credentials | contextosd issues no tokens | Planned, not this release: issuing tokens makes contextosd an authorization server; deferred with a written reason |
| Visible chain | P: chain digest on `run_admitted` only | Not on each decision | D2: every decision and dispatch entry carries the delegation chain (principals and agents, narrowing-only) |
| Access reviews | P: agent reviews with expiry; used/surfaced per capability | No report of unused grants, stale delegations, expiring waivers | D3: `GET /api/access-review` and `ctx access-review` (offline): held vs used capabilities over N days, stale delegations, waivers expiring; revoke and waiver expiry from the report |
| Break-glass | M | — | D4: `POST /v1/break-glass`: named capability, justification, TTL capped by config; lifts approval gates only, never budgets, shared ceilings, tenant isolation or revocations; audited; opens a mandatory post-review item in Tower |

Threats: T50 (break-glass abuse), T51 (SVID substitution).

### E. Human oversight and approvals

| Item | Today | Gap | Planned |
|---|---|---|---|
| Delivery | P: signed CloudEvents webhooks; Slack relay example | Teams, email; inbound callbacks | E1: reference approval relay (examples) for Slack, Teams and email that implements the existing approval-service contract, verifies signed callbacks and maps the clicker to an OIDC subject. The runtime contract does not change |
| SoD, identity | E | — | Tests only |
| Escalation, timeout | P: `approval_timeout` escalate or deny | No tiered chain | E2: `escalate_to` list with per-step timeouts |
| Approver delegation | M | — | E3: out-of-office delegation in the reference approval service, time-boxed, never to the requester |
| Analytics | E: time to approve, too-fast | No override rate | E4: override rate and per-approver load in `/api/approvals` |
| Kill switch | E for agent, tool (capability/adapter), tenant; P for global | No single global switch | E5: `global` revocation kind (admin scope, two-person restore), tested and documented at all four scopes |

Threats: T52 (forged approval callback, delegated approver used for self-approval).

### F. Observability, evaluation and assurance

| Item | Today | Gap | Planned |
|---|---|---|---|
| Dashboard | P: Posture, Spend, Approvals, Waivers, Inbox, chain health | Held effects and spend vs ceilings not on one page | F1: Posture adds held effects, denials by reason, policy drift, approvals backlog, spend vs configured ceilings, top risky agents |
| Baselines | E: per-agent 4σ hourly | New tools, new destinations, unusual hours | F2: those three flags; every flag opens a review, never a block |
| Incidents | P: INCIDENT.md, Inbox, Journal | No case object | F3: Tower cases: from a denial, hold, finding or anomaly; timeline, linked audit entries, owner, status; export as a signed report |
| Failure Lab | E: five recorded failures | Timeout injection | F4: add a timeout path, recorded from the runtime like the others |
| Eval-gated promotion | P: gates are CLI only; rollouts gate packs | Agent release promotion | F5: `POST /v1/agent-releases/{ref}/evaluations` records signed eval results; `[guards.release_evaluations]` refuses runs of an agent release that lacks a passing required suite |

Threats: T53 (case or report edited after export), T54 (unevaluated release promoted).

### G. Cost and resource governance

| Item | Today | Gap | Planned |
|---|---|---|---|
| Model budgets | E per run; P across runs | No per agent/team/tenant model ceiling | G1: guarantees accept usage resources (tokens, cost units, model calls) with `resource_from = actor | team | tenant`, reserved before the call, same shared-ceiling ledger |
| Chargeback | P: Tower spend by agent, team, model | Tenant grouping, export | G2: group by tenant; CSV export; `ctx chargeback` offline |
| Model allow-lists | M | — | G3: `[guards.models]` allow-list per risk tier, refused at usage reserve |

Threats: T55 (model spend split across runs or teams to dodge a ceiling).

### H. Supply chain and tool governance

| Item | Today | Gap | Planned |
|---|---|---|---|
| Allow-lists, pinning, drift | E | Changed descriptions only reported | H1: quarantine state for drifted tools (refused until a reviewed re-pin), visible in Tower |
| Signed manifests and packs | M | — | H2: `ctx sign` (Ed25519) and `[packs] require_signature` with trusted keys |
| Release signing | P: image cosign; provenance and SBOM for all | Archives and packages not cosign-signed; no reproducibility check; no cargo-audit job | H3: cosign `sign-blob` for archives; a reproducible-build job (build twice, compare digests, report differences honestly); cargo-audit job |

Threats: T56 (unsigned or re-signed pack loaded).

### I. Compliance mapping and evidence export

| Item | Today | Gap | Planned |
|---|---|---|---|
| Mappings | E: OWASP, EU AI Act Arts. 9/12/14/15/26, Singapore, NIST, ISO 42001; SOC 2 only in the evidence pack | SOC 2 not in the docs; NIST not in the pack; partial controls not marked | I1: add SOC 2 to COMPLIANCE.md, NIST to the pack; mark every control `covered` or `partial` with what is missing; never claim certification |
| Audit pack | P: `ctx evidence-pack` (verified, deterministic, manifest digests); manifest not signed; no bundled verifier | One command, signed, readable offline | I2: `ctx audit-pack`: evidence pack + packs + inventory + approvals + config digest + signed manifest + a standalone verification script |
| Spec repo | Private | — | Maintainer decision (see below); docs/status states it either way |

Threats: T57 (forged or altered audit pack).

### J. Interoperability and developer experience

| Item | Today | Gap | Planned |
|---|---|---|---|
| ext_authz | M | — | J1: ext_authz HTTP check backend for agentgateway and other Envoy-compatible proxies, over the existing `/tool-calls/check` path; "agentgateway governs the wire; ContextOS governs the effect" |
| OTel GenAI | E for spans | Metrics | J2: GenAI semantic-convention metrics |
| SIEM | P: signed webhooks | Native formats | J3: sink `format = splunk_hec | datadog | elastic_bulk`, masking unchanged |
| Policy import | M | — | J4: experimental `ctx import-policy` for a documented subset of OPA (data and decision tables) and Cerbos (resource policies); anything else refused with a reason. Full Rego and CEL are out of scope |
| Adapters | E: 11 frameworks with guides | Build-your-own guide, conformance kit | J5: `docs/integrations/BUILD_AN_ADAPTER.md` and `ctx adapter-check` (lost response, duplicate delivery, approval pause, refusal) |
| gRPC | Deferred | — | Stays deferred |
| Quickstart | E: one script | Not timed or tested on a clean macOS | J6: 10-minute quickstart page; CI job on ubuntu and macos runners from the docs alone |

Threats: T58 (ext_authz check treated as permission without dispatch).

## Order and cut line

Build in theme order A → J. Each item is one small PR with tests, docs and a
CHANGELOG line. If time runs out, cut from the bottom item by item (J4 and J1 first,
then H3's reproducibility job), never tests or docs. Cut items move to "planned" in
docs/status with a reason.

## Quality gates before tagging

1. All CI jobs green: unit, integration, kind e2e, fuzz smoke, cargo-deny, cargo-audit.
2. Upgrade test: an alpha.21 store and packs migrate and still verify offline (new CI job).
3. Strict `--check-config` passes on the reference deployment; a bad config refuses to start.
4. `ctx audit-verify` passes after masking, retention, legal hold release, DSAR erase and tombstones.
5. Quickstart passes on clean Linux and macOS runners from the docs alone.
6. Docs: a guide per theme, SCOPE and THREAT_MODEL current, docs/status updated,
   conformance page licences (Apache-2.0 code, CC BY 4.0 prose) checked.

## Release steps

Continue the alpha series: **0.1.0-alpha.22**. Release-prep PR, then annotated tag on
the merge commit; release.yml builds a draft. The maintainer publishes it as a
prerelease (never Latest), which triggers npm and PyPI publishing. Site update
(docs/status, changelog, blog post "What ContextOS governs now", guides, llms.txt)
follows in the site repo after publication. Announcements are drafted, not posted.

## Not in this release (also stated in SCOPE.md)

Blockchain anchoring, an LLM that moderates everything, hosted SaaS, agent passports,
broad cross-organization federation, token issuance by contextosd, gRPC, full Rego or CEL evaluation.

## Decisions

1. **Integrations are named.** J1 is an ext_authz backend for agentgateway (and any
   Envoy-compatible proxy): "agentgateway governs the wire; ContextOS governs the
   effect". J4 imports a documented subset of OPA and Cerbos policies. Both are
   built from the projects' public documentation.
2. **Publishing.** Pushing the tag, publishing the GitHub release, npm/PyPI and site
   posts are public actions the maintainer runs; the release report gives the exact
   commands.
3. **Public spec repo.** Opening it is the maintainer's decision; docs/status states
   the current position either way.
4. **Size.** Roughly 35 PRs, built theme by theme with a report after each. Themes
   A–E ship as alpha.22; F–J follow as alpha.23, unless the maintainer asks for one
   release.
5. **Dependencies.** The open Dependabot PRs are combined into one PR before release
   prep.
