# Closing the governance gaps: implementation plan

Status: plan, 2026-10-30. Baseline: main `7e85393` (v0.1.0-alpha.5).

This plan follows the external assessment "Agent governance: the real must-haves" and
corrects it where reading the code changed the picture. Each workstream names who it
is for, what it changes, the files it touches, how it is tested, and what it does not
do.

## 1. What the code says about the assessed gaps

| # | Assessment | After reading the code |
|---|---|---|
| 12 Alerting | "Pure config" | **Partly wrong.** `contextosd/src/metrics.rs` exports counters only. Denial spikes and `shared_guarantee_saturated` refusals can be alerted on today. Open holds, hold age and nearness to the 1024-receipt cap (`MAX_EXPOSURE_RECEIPTS`) are not exported anywhere: they live in per-resource `SharedExposure` ledgers, readable only through the paginated inspection API (`gateway/shared_inspection.rs`). New code is needed. |
| 9 Agent identity | Partial | **Real gap, cheaper than it looks.** The admission's `actor` is built from `run_context.agent.agent_id` (`app.rs:748`), which the caller names. The token proves the principal (`admitted_by`), not the agent. Revocation by `agent` therefore revokes a name, not a workload. Binding the agent id to a token claim fixes this, and SPIFFE JWT-SVIDs already fit the existing OIDC verifier. |
| 11 MCP drift | Gap: live servers reshape tools | **Narrower than stated.** Agents only ever see ContextOS's reviewed manifests (`contextosd/src/mcp.rs` `tools/list`), and the upstream adapter only sends `tools/call` and `tasks/get`. A new or reshaped upstream tool cannot reach an agent. The real gap is that the same upstream tool name can change its meaning (arguments, output, annotations) without anyone noticing. |
| Tier 3 MCP OAuth | Missing | **Inbound side is small.** contextosd already validates bearer JWTs with issuer, audience and tenant binding. What is missing is the discovery part of the MCP authorization spec: Protected Resource Metadata (RFC 9728) and `WWW-Authenticate: Bearer resource_metadata=…` on 401 (today it sends a bare `Bearer`, `app.rs:213`). On the outbound side the `CredentialBroker` port (`adapters/src/transport.rs`) is where an OAuth client-credentials broker belongs. |
| 13 Data flow | Partial | **Outbound is covered; inbound is the gap.** `DataFlowProvider` (`gateway/src/lib.rs:167`) already lets a data-governance service evaluate every call that sends data, and blocks when it says nothing. Nothing screens tool *results* before they reach the agent, except `output_schema` conformance. |
| 15 Memory | Partial: no provenance | **Understated.** Memory writes are lifecycle records bound to contract, run and tenant, decided by the kernel with a trusted context from `MemoryPolicyProvider` and audited (`gateway/src/memory.rs`). Provenance exists. Poisoning detection does not, and belongs to the memory-governance service, not the runtime. |
| 5 Approval delivery | Partial | Confirmed. Escalations are records with an open index (`gateway/src/escalation.rs`). Nothing leaves the process when one opens. |

Constraint across all of this: `contextosd/src/app.rs` (3447 lines) and
`contextos-gateway/src/lib.rs` (2382 lines) are already past the 600-line limit in
`AGENTS.md`. New work goes into new modules and adds route wiring only. Step 0 of
workstream A moves the metrics and auth wiring out of `app.rs` so later PRs don't make
it bigger.

## 2. Who this is for

- **On-call engineer.** "Is governance holding money or blocking traffic right now, and
  is it getting worse?" Works in Prometheus and PagerDuty, not Tower.
- **Business approver** (refund lead, finance). "Something needs my decision: what is
  it, and where do I act?" Doesn't watch a console.
- **Platform or security engineer.** "Is the caller the agent it claims to be? Has the
  upstream tool changed since we reviewed it? Do our MCP hosts connect without custom
  glue?"
- **Buyer or security reviewer.** "What does this *not* protect against?"

Scale assumption for design: thousands of resources under a guarantee per tenant,
tens of tenants per deployment, 3 to 30 replicas, Prometheus scraping each pod.

## 3. Workstreams, in order

### A. Governance alerts (launch, on-call engineer)

**A0. Extract wiring (refactor, no behavior change).** Move the `/metrics` route,
metric hooks and 401 construction out of `app.rs` into `contextosd/src/http/`
modules. This must land first, because A2 and D1 touch exactly these places.

**A1. Rules for what is already exported.** Ship
`deploy/helm/contextosd/templates/prometheusrule.yaml` behind
`prometheusRule.enabled` (next to `serviceMonitor`) and the same rules as a plain
file under `deploy/prometheus/contextos-rules.yaml` for clusters without the operator.

| Alert | Expression shape | Why it pages |
|---|---|---|
| `ContextOSBlockedSpike` | blocked share of dispatches over 15m against a 6h baseline, with a minimum volume | A policy or pack change is denying real traffic; it looks like an agent bug. |
| `ContextOSSharedGuaranteeSaturated` | `increase(contextos_dispatch_refusals_total{reason="shared_guarantee_saturated"}[10m]) > 0` | A resource has hit its receipt cap and refuses all new effects. |
| `ContextOSUnknownOutcomes` | rate of `status="unknown"` above a threshold | Responses are being lost and each one becomes a hold. |
| `ContextOSGuardSaturated` | refusals with `loop_guard_saturated`, `effect_guard_saturated`, `task_limits_saturated` or `too_many_unresolved_effects` | Runs are hitting hard caps. |
| `ContextOSRevocationActive` (info) | refusals with `revoked_capability` | Confirms the kill switch is containing. |

Each alert carries a `runbook_url` annotation pointing to an anchor in
`docs/INCIDENT.md`, and each anchor says what to check and what *not* to do (for
example: do not retry a held effect).

**A2. Hold and saturation gauges (new code).** A leader-only task, built like
`retention.rs`, sweeps the `SharedExposure` ledgers of each configured tenant, one
page (`MAX_INSPECTION_SCAN`) per tick. It reuses `shared_inspection::diagnose` so each
hold is classified the same way the inspection API classifies it. When a full pass
finishes, it publishes:

- `contextos_shared_holds{guarantee,state}`: count of holds by diagnosed state
  (`dispatch_active`, `unknown`, `partial`, `conflicting_facts`, …). Both labels are
  bounded: guarantees are configured, states are a fixed list.
- `contextos_shared_hold_oldest_seconds{guarantee}`: age of the oldest hold, taken
  from the attempt's start time in its operation record. No kernel ledger change is
  needed.
- `contextos_shared_receipts_fill_ratio{guarantee}`: the largest live-receipt count
  divided by 1024 across that guarantee's resources. This gives a warning before
  saturation rather than after.
- `contextos_escalations_open`: read from the escalation open index.
- `contextos_governance_sweep_completed_timestamp_seconds`: lets an alert fire when
  the sweep itself stalls.

Only the leader exports these series, so rules aggregate with `max without
(instance, pod)`, which survives a leader change. Tenants stay off labels, which
`metrics.rs` already promises.

The age is used only for paging. The inspection module states that elapsed time
proves nothing about an effect, and this keeps that true: no alert and no runbook step
resolves a hold by waiting.

New alerts: `ContextOSHeldEffectsAging` (oldest hold above 15m),
`ContextOSConflictingFacts` (any `conflicting_facts`, critical),
`ContextOSReceiptsNearCap` (fill above 0.8), `ContextOSGovernanceSweepStale`.

**A3. Dashboard.** `deploy/grafana/contextos-governance.json` with one row per
question: traffic and blocked share; refusals by reason; holds by state and oldest age;
escalations open. Nothing else; deep detail stays in the inspection API and Tower.

Tests:
- `promtool check rules` and `promtool test rules` with fixture series, in CI.
- A Rust test asserting that every metric name used in the rules is one `render()`
  emits, so a rename cannot silently break an alert.
- A sweep test on the memory store covering each diagnosed state, cursor resume,
  leader loss mid-pass (nothing published), and an unreadable ledger (counted, doesn't
  hide others).
- An end-to-end test: lose a response, then see the gauge reach 1 and return to 0
  after reconciliation.

Effort: A0 and A1 take about 2 days, A2 about 4 days, A3 about 1 day.

### B. "What ContextOS does not govern" (launch, buyer and reviewer)

Add `docs/SCOPE.md`, linked from the README and the threat model. It covers:
- content of tool results and prompts (no injection screening; see F for the port);
- semantic data taint;
- cross-organization trust;
- agent identity beyond what the token proves, until C lands;
- upstream MCP tool meaning changes, until D3 lands;
- poisoning detection in memory (it is the memory-governance service's job).

For each item it gives the compensating control or the integration point. Every
statement must cite a threat-model entry or say "not modeled".

Effort: about 1 day.

### C. Agent bound to the workload (next quarter, platform engineer)

**Built** (see GUIDE, "Bind runs to the agent the credential is issued for", and
threat T30). How it differs from the first draft:
- **One deployment-level setting.** `[guards] agent_binding` replaces a per-issuer
  setting, because a deployment's identity posture should be one decision.
- **API keys can be bound too.** An API key names its agents with `agent_ids`; a key
  issued to one agent service is a workload credential.
- **No new kernel control.** `identity.agent_bound` is not in the profile registry: the
  registry is parity-locked with the spec. The enterprise default is enforced by
  contextosd, and the control belongs in a spec proposal.
- **The verdict goes in `run_admitted`** (`agent_binding`), not in the admission's
  `actor`, whose shape is the spec's `PrincipalRef`.

X.509 SVIDs (mTLS) and build attestation remain out of scope.

### D. MCP authorization and drift (next quarter, platform engineer)

**D1. Inbound discovery.** *Built* (GUIDE, "Or connect any MCP host"). The audience is not
forced to the public URL. The operator sets each issuer's `audience` to it, because one issuer
may serve the API and MCP alike. No passthrough is structural: `AdapterCall` carries no caller
credential, and the adapter tests assert the brokered one.
- Add `server.public_url` to config.
- Serve `GET /.well-known/oauth-protected-resource` and the path-suffixed form for
  `/v1/runs/{run_id}/mcp`. The response lists `resource`, `authorization_servers` (the
  configured issuers) and `scopes_supported` (`dispatch`).
- Return `WWW-Authenticate: Bearer resource_metadata="…"` on 401, and
  `error="insufficient_scope", scope="dispatch"` on 403.
- In MCP mode, require the token audience to be the canonical resource URI.
- Never pass the caller's token upstream. Credentials already come from the broker;
  add a test that pins this.

**D2. Outbound OAuth broker.** Add `OAuthClientCredentials` as a `CredentialBroker`
for each adapter: a token endpoint, a client secret from an environment variable, the
RFC 8707 `resource` parameter, and a cache that refreshes before expiry. Fetch errors
surface as `PortError`, which the gateway already treats as fail-closed. On-behalf-of
token exchange (RFC 8693) waits for a customer who needs the user, not the gateway, as
the upstream subject.

**D3. Upstream drift detection.**
- Add `upstream_tool_digest` to the manifest: SHA-256 over the canonical (RFC 8785)
  upstream definition of `name`, `inputSchema`, `outputSchema` and `annotations`. Add a
  separate `upstream_description_digest` over the description (see decision 3).
- The adapter calls `tools/list` at startup and on an interval.
- On a mismatch the capability is marked drifted and refuses with
  `upstream_tool_drifted` until the manifest is re-reviewed. The drift also emits a
  finding and a `contextos_upstream_drift{capability}` gauge, with an A1-style alert.
- `contextosd --pin-mcp-tools <adapter>` prints current digests for review in Git.

A changed description doesn't refuse: it raises a finding and an alert, and the
manifest is re-reviewed. Pinning is required for every MCP capability that is not
read-only under the enterprise profile and opt-in elsewhere; `--check-config` warns for MCP capabilities
without a digest.

Tests: metadata documents, 401/403 headers, audience enforcement, broker caching and
expiry, drift refusal and recovery after the manifest is updated.

Effort: D1 about 3 days, D2 about 3 days, D3 about 4 days.

### E. Escalation delivery (next quarter, business approver)

**Built** (GUIDE, policy escalations; `contextosd/src/notifications.rs`). The audit chain
is the outbox. `escalation_opened` and `escalation_resolved` are appended exactly when
a transition commits. The leader delivers them with a cursor per webhook and tenant
(`Escalation` document `delivery:<webhook>`). Nothing needed to change in the
escalation records, and a notification can neither be lost nor sent for a transition
that did not happen.

Approvals stay where SSO identifies the approver. Notifications carry a link and grant
nothing. Slack and PagerDuty are relays in `examples/notify/`, not core integrations.
Step-up authentication for large approvals (decision 4) belongs to Tower and is still
to do.

### F. Result screening port (after D, platform engineer)

Add a `ResultScreeningProvider` port next to `DataFlowProvider`. It is called after an
effect is confirmed and before output reaches the agent, and returns
`pass | withhold | redact(pointers)`. It is enforced like `output_schema`: the effect is
recorded, the output is withheld or redacted, and the verdict is audited. ContextOS
ships the port, the remote-facts adapter and a test double, not a classifier. This
turns B's "we don't screen content" into "screening plugs in here".

Effort: about 4 days.

## 4. Sequence

| When | Work | Why this order |
|---|---|---|
| Before launch | A0, A1, B | Cheap, closes the loudest buyer question, unblocks A2 and D1. |
| Launch + 2 weeks | A2, A3 | Needs A0; the most valuable on-call signal. |
| Next quarter, first half | C, D1 | Identity is what every other control trusts; D1 is small and depends on the same auth code as C. |
| Next quarter, second half | E, D2, D3 | E needs the outbox design reviewed; D3 needs a real MCP server in tests. |
| After | F | Depends on demand from a design partner with a classifier. |

Each item ships as its own PR, under the commit gate (`scripts/check.sh`), with a
CHANGELOG entry, a GUIDE section and threat-model updates where it changes a
residual.

## 5. Not doing

A global agent registry, LLM moderation in the dispatch path, blockchain anchoring,
cross-organization federation, and approving actions from chat. The reasons are in the
assessment and in workstream E above.

## 6. Decisions

Decided 2026-10-30. Rule applied throughout: secure by default, with a measured path to
turn it on, and no control that depends on someone remembering to configure it.

1. **No tenant label on metrics, not even opt-in.** The scrape endpoint is
   unauthenticated, Prometheus is usually shared, and for a provider hosting many
   customers, tenant ids in metrics leak who the customers are and how much they do.
   In a single-tenant deployment the label adds nothing. Alerts say *which guarantee*
   and *which state*. *Which tenant* comes from two places: the inspection API, behind
   `audit:read`, and a structured log event the sweep emits for each hold past the age
   threshold. That event carries tenant, guarantee and resource digest (never
   arguments) and goes to the SIEM, where access control and retention already apply.
2. **Agent binding is `required` under the enterprise profile, `observe` under core.**
   - **Enterprise.** The `identity.agent_bound` control is required. An enterprise
     deployment with an OIDC issuer that has no `agent_claim` fails `--check-config`,
     and static-key callers cannot admit agent runs.
   - **Core.** Every mismatch is counted (`contextos_agent_binding_mismatches_total`)
     and audited, so an operator can see what would be refused before turning
     `required` on.
   - **`off`** stays, for development only, and `--check-config` warns when it is set.

   Every other control trusts identity, so an attestation that can be skipped by
   default is one attackers will skip.
3. **Two digests: schema drift refuses, description drift alerts.** Changes to schemas
   and annotations change what a call *does*, so they refuse with
   `upstream_tool_drifted` for every pinned capability. Descriptions are an injection
   vector only when a model reads them, and agents never read the upstream one: they
   see the reviewed manifest description. So a changed upstream description is a
   signal (the server owner changed something, or the server was compromised), not a
   live injection path. It raises a finding and an alert and forces re-review, but
   doesn't take the tool down. Separately, pinning becomes required for every
   non-read-only MCP capability under the enterprise profile. Opt-in pinning on the
   tools that move money is the gap that matters.
4. **Refund leads first, with the controls finance needs built in from day one.**
   - **Why refund leads.** They approve high volumes of small actions, which is where
     approval fatigue (OWASP ASI09) happens and where a weak screen shows up within a
     week. A design that holds for them holds for the rarer, larger finance approvals.
   - **What the landing page shows.** It is the decision, not a dashboard: the exact
     action and amount, the destination, the remaining headroom under the shared limit,
     why policy escalated, and the bound action digest. Approve and deny are single
     actions, one escalation at a time. No batch approval, because a batch makes a
     human approve a list instead of an action.
   - **What already holds.** The kernel already enforces eligible approvers, no
     self-approval (approver differs from both the actor and the requester), quorum
     and single redemption (`contextos-kernel/src/authorization.rs`).
   - **What's added.** Tower requires step-up authentication (the token's `acr`/`amr`
     claims) for approvals above a configured risk or amount, so a stolen session
     cannot approve a large refund. Finance's two-person rule is the existing quorum,
     configured through policy rather than as a separate feature.
