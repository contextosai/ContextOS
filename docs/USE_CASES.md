# Where ContextOS applies

ContextOS governs one thing: a consequential tool call, decided before it acts and
recorded after. The mechanics do not depend on what the tool does. A refund, a cluster
change, a vendor payment, a record export and a merged pull request are all effects on
a system the agent cannot take back, and they fail in the same few ways: a response is
lost and the call is repeated, a limit is spread across runs or agents, an approval is
stretched over a different action, a tool changes under the agent, or data goes where
it should not.

The examples in this repository use a synthetic payment provider because money makes
those failures easy to read. This page maps the same controls onto four kinds of
enterprise work. Every control named here is in the runtime today; the links go to the
section of the [guide](GUIDE.md) that configures it. What ContextOS does not govern is
in [SCOPE.md](SCOPE.md).

| Workload | Without a boundary | Enforced by ContextOS |
|---|---|---|
| [Cloud, infrastructure and SRE](#cloud-infrastructure-and-sre) | A remediation agent changes a cluster during a freeze, retries a failover whose first attempt did land, or calls an MCP tool whose definition changed overnight | Change windows, time-boxed break-glass, environment guard, unknown outcomes held until reconciled, upstream tool pins with quarantine, kill switch |
| [Finance, payments and ERP](#finance-payments-and-erp) | Two agents each stay under their own limit and together exceed the business one; a lost response becomes a duplicate payout; approvals are clicked through | Shared business ceilings across runs and replicas, intent keys, provider reconciliation, approvals bound to the exact action, review floors and approval analytics |
| [Regulated data, privacy and compliance](#regulated-data-privacy-and-compliance) | An agent that read a patient record is steered into mailing it out; tools and models nobody declared appear in production; an auditor asks for proof | Information-flow boundaries per data category, shadow inventory, legal holds, erasure by data subject, signed audit packs verified offline |
| [Autonomous coding and engineering fleets](#autonomous-coding-and-engineering-fleets) | Parallel subagents burn through model spend; a delegated agent acts with more of the repository than its task needs; a new agent version ships on one lucky run | Usage ceilings per agent and tenant with metered overage and chargeback, workload-bound identity and delegation, presets for GitHub tools, reliability gates, simulation on recorded traffic |

The same gateway, pack format, audit chain and Tower findings serve all four. A
deployment can start with one workload and add the others as packs.

## Cloud, infrastructure and SRE

Agents that operate infrastructure act on systems with no transaction to roll back.
The failures are timing (acting during a freeze), repetition (retrying an action
whose first attempt landed) and drift (a third-party tool that changed).

- **Change freezes and out-of-hours windows.** Hold consequential capabilities during a
  release freeze or outside office hours.
  [Guide](GUIDE.md#change-freezes-and-out-of-hours-windows)
- **Break-glass.** A separate credential lifts the change window or a circuit breaker,
  and only those, for named capabilities and at most one hour. Every call it lets
  through is audited, and Tower reports the grant until a reviewer other than its
  opener records a review. [Guide](GUIDE.md#break-glass)
- **Effects aimed at another environment.** A gateway serving staging refuses an effect
  aimed at production, even with a production credential in hand.
  [Guide](GUIDE.md#effects-aimed-at-another-environment)
- **Unknown outcomes.** A call whose response was lost stays held, is never resent, and
  is resolved by asking the provider or by an operator citing evidence.
  [Guide](GUIDE.md#reconciling-unknown-effects)
- **Upstream tool pins and quarantine.** Each capability is pinned to the MCP tool
  definition you reviewed. A changed definition is refused before anything is reserved
  or sent, and stays quarantined until re-pinned or released with a reason.
  [Guide](GUIDE.md#when-a-dependency-fails)
- **Kill switch and circuit breakers.** Revoke a tenant, pack, principal, agent, user,
  delegation chain, adapter or capability; a circuit breaker pulls it automatically
  when an agent, principal or tenant sends too many effects or refusals too fast.
  [Guide](GUIDE.md#8-kill-switch)

## Finance, payments and ERP

Money moves at the provider, not in your database, so a row lock in one service does
not hold a limit that spans agents, runs and systems
([why](WHY_NOT_A_TRANSACTION.md)).

- **Shared business ceilings.** Capacity is reserved atomically across independent
  runs, agents and replicas on one protected store; pending and unknown effects keep
  their reservation until reconciled. [Shared guarantees](SHARED_GUARANTEES.md)
- **Spend caps per agent and window.**
  [Shared guarantees](SHARED_GUARANTEES.md#spend-caps-per-agent-per-window-by-estimate)
- **Intent keys.** The same business request redelivered into a new run (a queue
  redelivery, a retried webhook) is recognised as a repeat, not a new effect.
  [Guide](GUIDE.md#the-same-request-from-another-run)
- **Exact approvals.** An approval binds the digest of one complete proposal; changing
  the amount, payee or arguments voids it. A review floor refuses decisions made too
  quickly to be reviews, and Tower's Approvals page shows decision times, denial and
  override rates per approver. [Guide](GUIDE.md#4-integrate-your-services)
- **Outcome contracts and compensation.** Count an effect as done only when the system
  of record confirms it, and undo a half-finished workflow as governed compensations.
  [Guide](GUIDE.md#outcome-contracts), [compensation](COMPENSATION.md)

Run it: `./examples/shared-guarantees/run.sh`, `./examples/why-not-a-row-lock/run.sh`,
`./examples/outcome-witness/run.sh`.

## Regulated data, privacy and compliance

The risk is less the single call than the path: an agent that reads regulated data,
also reads text an outsider wrote, and can send data out.

- **Information-flow boundaries.** A run tracks the categories it has read (`pii`,
  `phi`, `pci`, `secrets`). Boundaries say which capabilities, vendors and regions may
  receive each one; any other egress is denied or needs an approval of the exact call.
  Categories are declared in manifests; the runtime does not inspect the data.
  [Guide](GUIDE.md#regulated-data-categories-and-where-they-may-go)
- **Gate effects on what the agent has read.** Untrusted input lowers what a run may do
  next. [Guide](GUIDE.md#gate-effects-on-what-the-agent-has-read)
- **Shadow inventory.** `ctx inventory --fail-on-shadow` lists every agent, capability
  and model in a verified export and fails CI when any ran undeclared.
  [Guide](GUIDE.md#list-what-an-export-shows)
- **Retention, legal holds and erasure.** Erase personal content by data subject while
  the audit chain still verifies; a legal hold keeps what a case needs.
  [Guide](GUIDE.md#legal-holds), [erasure](GUIDE.md#deletion-requests-by-data-subject)
- **Evidence for auditors.** `ctx audit-pack` signs one folder for a review period;
  `ctx evidence-pack` maps it to SOC 2, ISO/IEC 42001, the EU AI Act and the OWASP
  agentic list. [Guide](GUIDE.md#hand-an-auditor-one-signed-folder),
  [control map](COMPLIANCE.md)

## Autonomous coding and engineering fleets

Coding agents fan out into subagents, hold repository credentials and ship often. The
controls are cost, scope and release evidence.

- **Usage ceilings across runs.** Cap model tokens or spend per agent or per tenant and
  window. Usage measured by an LLM gateway holding the `meter` scope is settled as
  audited overage; self-reported usage is not trusted.
  [Guide](GUIDE.md#usage-ceilings-across-runs)
- **Chargeback.** `ctx chargeback` groups verified model spend by team or business
  unit. [Guide](GUIDE.md#bill-model-spend-from-an-export)
- **Workload identity and delegation.** Bind runs to the agent a credential is issued
  for, including SPIFFE IDs over mutual TLS, and to the user it acts for; delegated
  child runs get sub-budgets and only the capabilities their envelope names.
  [Agent binding](GUIDE.md#bind-runs-to-the-agent-the-credential-is-issued-for),
  [user binding](GUIDE.md#bind-runs-to-the-user-the-agent-acts-for),
  [child runs](GUIDE.md#delegating-to-child-runs-subagent-lanes)
- **Presets for GitHub, databases and CRMs.** `ctx init-tool --preset github` labels
  drafted manifests with flow and egress rules for review.
  [Guide](GUIDE.md#presets-for-github-databases-and-crms)
- **Release gates.** `ctx simulate` replays recorded traffic against a candidate pack;
  `ctx reliability-gate` requires pass^k over repeated trials before an agent ships.
  [Simulate](GUIDE.md#simulate-a-pack-change-on-recorded-traffic),
  [reliability](GUIDE.md#gate-on-reliability)

Run it: `./examples/evaluation-loop/run.sh`, `./examples/agent-loop/run.sh`.

## Start with your own traffic

[Replay recorded tool calls](../examples/replay) through a local gateway to see what it
would have refused, held or sent for approval, before anything is placed in the call
path. The [Agent Failure Lab](../lab) shows five of these failures stepped through with
and without a gateway.
