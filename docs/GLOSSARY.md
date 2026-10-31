# Glossary

The terms ContextOS uses in its docs, API and `--check-config` output, in the order you
meet them.

**Run.** One task an agent performs under governance, from admission to completion.
Every tool call names its run.

**Admission.** Starting a run (`POST /v1/runs`). `contextosd` compiles the run's Context
Pack, checks the execution contract and the caller's credential, opens the run's
budget, and records `run_admitted` in the audit chain.

**Context Pack.** A versioned JSON document (`ctxpack.<name>@<version>`) that says what
a kind of agent may do: its tools and their permissions, policy rules, the evidence a
decision needs, and budgets. The quickstart's is `examples/support-refund/pack.json`.

**Intent.** What the run is for, such as `support.refund`. The caller declares it in the
request. Policy rules can be scoped to an intent (`applies_to.intent`); see **pack
intents**.

**Capability.** One tool the gateway can call for an agent, such as
`adp_payments.issue_refund`: an adapter (`adp_payments`) plus the capability name.

**Capability manifest.** The reviewed description of a capability: its arguments and
result schemas, its risk (effect, reversibility, data scope), how it is retried and
reconciled, and what it reserves from the budget. Files in `capabilities/`.

**Adapter.** How the gateway reaches a provider: HTTP or MCP, with a pinned endpoint and
a credential the agent never sees.

**Execution contract.** What the run promises to honour: the control profiles and
controls it requires, and the releases (model, evaluators) it pins. Part of the
admission body.

**Profile.** A named set of required controls, such as `contextos.core`. Declaring
`contextos.enterprise` in `[support] profiles` turns several guards from observing to
refusing by default.

**Effect.** A tool call that changes something outside ContextOS (a refund, an email).
Read-only calls are not effects.

**Operation and attempt.** An operation is one intended effect, with a stable id (from
the idempotency key). Each try at sending it is an attempt. An operation applies at most
once however many attempts it takes.

**Outcome.** What happened to an effect: `confirmed` (applied), `not_applied`, `partial`,
or `unknown` (for example the provider's answer was lost). Unknown and partial outcomes
are never retried blindly; they wait for reconciliation.

**Reconciliation.** Deciding an unknown outcome from evidence: asking the provider
whether the operation happened, or an operator's assertion citing the provider's
records.

**Executor generation.** Which process currently owns a run. Taking over a run (after a
crash) raises the generation, and calls from an older generation are refused. This is
**fencing**: a stale process cannot act after it has been replaced.

**Shared guarantee.** A limit several runs share, such as "refunds per order at most
INR 1,000". Each effect reserves capacity before it is sent; an unknown outcome keeps its
capacity **held** until reconciled.

**Reservation.** Budget or limit capacity set aside for an effect before it is sent,
then settled to what was used.

**Exact approval.** A human approval bound to one action's digest (a hash of the
complete call: capability, arguments, amount, evidence, policy). Any change to the
call voids it.

**Evidence gate.** A decision's requirement for named facts (for example an order
lookup) before it may commit. See SCOPE.md for what the gate does and does not check.

**Audit chain.** The signed, hash-chained log of everything governance decided, per
tenant. `ctx audit-verify` checks it offline.

**Decision record.** The signed record of a business decision an agent made, linked to
the tool calls and evidence behind it.

**Agent binding.** Checking that a run's declared agent is one the caller's credential
is issued for. `observe` records mismatches; `required` refuses them.

**Pack intents.** Checking that a run's intent is one its Context Pack's rules name, so
intent-scoped rules cannot be skipped by declaring another intent. `observe` records
mismatches; `required` refuses them.

**Upstream pin.** A capability's `upstream_tool_digest`: the MCP tool definition it was
reviewed against. Calls are refused while the server's definition differs.

**Tower.** The governance plane over many runtimes: fleet inventory, findings, the kill
switch and evidence, built from each runtime's verified audit chain.
