# Incident response

How to contain, investigate and close an incident in a `contextosd` deployment. Every
action here is an API call the runtime audits, so the response itself becomes evidence.
Commands assume `$CONTEXTOS` is the server URL, `$OPS_TOKEN` a credential with the
`control` scope, and `$AUDIT_TOKEN` one with `audit:read`.

Report suspected vulnerabilities in the runtime itself privately (see
[SECURITY.md](../SECURITY.md)); this runbook is for operating a deployment.

## Roles

| Role | Holds | Does |
|---|---|---|
| Incident commander | — | owns the incident, its severity and its updates; decides when it is closed |
| Operator | `control` | revokes and restores, cancels and erases, clears rollouts, closes feedback |
| Reconciler | `reconcile` | resolves unknown effects with provider evidence |
| Investigator | `audit:read` | exports and verifies the audit chain, evidence bundles and replay cases |

Keep these credentials separate from executors' (`admit`, `dispatch`): the runtime
refuses a principal that both runs agents and evaluates or meters them, and an
incident is exactly when you need the separation.

## Severity

| Sev | Examples | Contain within | Update cadence |
|---|---|---|---|
| 1 | Effects dispatched without authority, approval or budget; cross-tenant access; audit chain fails verification; signing key compromised | 15 min | 30 min |
| 2 | An agent, tool or pack acting wrongly at scale (bad refunds, runaway spend, prompt injection followed); a provider returning unknown outcomes en masse | 30 min | 1 h |
| 3 | One run or a few wrong decisions, a degraded provider, elevated refusals or latency | 4 h | daily |
| 4 | Operator corrections, quality drift with no harmful effect | next release | — |

When in doubt, start one level higher and lower it once contained.

## First 15 minutes

1. **Open the incident**: number, commander, severity, a shared timeline.
2. **Stop the effect** with the narrowest revocation that covers it (below). Revocation
   takes effect at the next dispatch and admission on every replica; a call already
   past authorization completes.
3. **Preserve evidence** before changing anything else: the audit chain and the
   affected runs' evidence (see *Evidence*). Do not erase content under investigation.
4. **Check the trail is intact**: `GET /v1/audit/verify`. A failure is Sev 1 on its own.
5. **Communicate** scope, containment and next update time.

## Containment

### The kill switch

```sh
curl -X POST "$CONTEXTOS/v1/revocations" -H "Authorization: Bearer $OPS_TOKEN" \
  -d '{"kind": "capability", "target": "adp_payments.issue_refund", "reason": "INC-4711"}'
```

| Kind | Stops | Use when |
|---|---|---|
| `capability` | calls to one tool action | one action misbehaves or is being abused |
| `adapter` | every capability of one provider integration | the provider or its credentials are suspect |
| `agent` | effects and new runs of runs declaring that agent id | one agent's behaviour is wrong |
| `principal` | new runs of a caller and the runs it admitted | an executor or its credential is compromised |
| `pack` | effects and new runs on a Context Pack release | a pack version is at fault (often with *Roll back*) |
| `tenant` | everything for the tenant | scope unknown, or Sev 1 inside one tenant |

Refusals report `revoked_<kind>`. `GET /v1/revocations` lists what is revoked, with who
and why; `POST /v1/revocations/restore` with the same body lifts it. Put the incident
number in every `reason`.

### Roll back a release

A candidate pack in a staged rollout: `POST /v1/rollouts/clear` with
`{"baseline": "<pack>", "reason": "INC-4711"}` returns new runs to the baseline. Runs
already admitted keep their pinned pack, so also revoke the candidate `pack` to stop
them acting.

### Stop runs

`POST /v1/runs/{run_id}/cancel` (`admit` scope) cancels a run and its children and stops
its dispatch. A compromised executor cannot keep going after another takes over: the
takeover fences its generation (`executor_stale`).

### Unknown effects

When a provider times out or fails mid-call, the effect is `unknown`, retries are
refused, and the run cannot complete until it is reconciled. Query the provider
(`POST /v1/runs/{run_id}/operations/{operation_id}/reconcile` with
`{"source": "provider"}`) or, with provider evidence, assert it as an operator (see the guide's *Reconciling unknown
effects*). Never re-run an effect to find out whether it happened.

### Escalations

Policy escalations are listed at `GET /v1/escalations`; a growing list is a signal in
itself. Resolve each with what was done (`POST /v1/escalations/{id}/resolve`).

## Alerts

The Helm chart ships alerting rules (`prometheusRule.enabled`, or load
`deploy/helm/contextosd/files/contextos-rules.yaml` directly). Each alert links here.
Metrics carry no tenant label, so the tenant and resource come from the APIs below,
called with `$AUDIT_TOKEN` for each tenant you operate.

### ContextOSSharedGuaranteeSaturated

A resource under a shared guarantee has 1024 live receipts, and every new effect on it
is refused (`shared_guarantee_saturated`) until some settle. Usually holds are piling
up because responses were lost and nobody reconciled them. Find the resources with
`GET /v1/guarantees/{id}/holds` and each hold's next safe step with
`GET /v1/guarantees/{id}/resources/{resource_digest}/holds`, then follow that step
(see *Unknown effects*). Raising the cap or deleting ledger rows by hand is never the
fix: a held receipt is capacity that may already be spent at the provider.

### ContextOSUnknownOutcomes

Calls are ending with an unknown outcome: the provider timed out, failed mid-call or
its response was lost. Each one holds its reservation and blocks retries of that
operation. Check the provider's health first; a burst usually means a degraded
provider (Sev 2 at scale). Reconcile the operations (*Unknown effects*). Do not ask
agents or executors to retry.

### ContextOSBlockedSpike

Governance is blocking far more dispatches than its 6-hour norm. Read
`contextos_dispatch_refusals_total` by `reason` to see why:
- `revoked_*`: the kill switch is working (see the alert below);
- policy or approval reasons, after a pack or rollout change: roll the release back
  (*Roll back a release*);
- limits, budgets or authority reasons: a limit is set too tight or an executor is
  misbehaving.

Blocks are the system working as configured, so fix the configuration. Bypassing
governance is never the fix.

### ContextOSGuardSaturated

Runs are hitting a hard cap: the loop guard or effect guard is full, task limits are
saturated, or a run has too many unresolved effects. One runaway run is the usual
cause. Find it in `GET /v1/audit/entries`, cancel it if it is looping
(*Stop runs*), and reconcile its unresolved effects.

### ContextOSRevocationEnforced

Informational: revocations are refusing dispatches. During an incident this confirms
containment. Outside one, list `GET /v1/revocations` and check each `reason` names an
incident or change.

### ContextOSHeldEffectsAging

A held effect under a shared guarantee has waited more than 15 minutes. The leader
replica's sweep also logged it once, with its tenant, guarantee, resource digest and
reservation id ("shared-guarantee hold is aging"), so your log search names the
tenant. Look the hold up with
`GET /v1/guarantees/{id}/resources/{resource_digest}/holds` and follow its
`next_safe_step`. Age alone proves nothing about whether the effect applied, so never
release a hold because it is old.

### ContextOSConflictingFacts

Sev 2. Contradictory outcomes were recorded for one operation, for example a provider
reporting it applied and an attestation that it did not. The runtime keeps the
capacity held and refuses to choose. Find the hold (state `conflicting_facts`) as
above, preserve the run's evidence, and establish with the provider what happened
before anyone reconciles.

### ContextOSReceiptsNearCap

A resource's ledger is using more than 80% of its 1024 live receipts. Settled receipts
are archived an hour after settling, so the usual cause is many holds on one resource.
Reconcile them before the cap refuses new effects (see
*ContextOSSharedGuaranteeSaturated*).

### ContextOSUnreadableLedgers

Sev 1 candidate. An exposure ledger does not parse, so its resource refuses every
effect and its holds are unknown. Ledgers are only written by the runtime, so suspect
access around it, as for a failed audit verification. Do not repair it by hand.
Export the audit chain and restore the document from backup.

### ContextOSGovernanceSweepStale

No replica has completed the governance sweep for 15 minutes, so the hold alerts
cannot fire. The leader replica runs it. Check that replicas are up and heartbeating
(`contextos_replicas`), that the store is reachable (`GET /readyz`), and the leader's
logs for "governance sweep failed".

### ContextOSEscalationsWaiting

Escalations have waited an hour. List them with `GET /v1/escalations` and route them
to their owners. The calls they block stay blocked, which is safe, but the work
waits too.

### ContextOSServerErrors

More than 1% of requests are failing. The runtime fails closed, so agents get errors,
not ungoverned effects. Check `GET /readyz` (store and identity keys), the store's
health, and the logs (see *Store or provider outage*).

## Evidence

- **Audit chain**: page it out with `GET /v1/audit/entries?from=1&limit=1000` (follow
  `next`), fetch keys from `GET /v1/audit/keys`, and verify offline:
  `ctx audit-verify --entries entries.json --keys keys.json`. Later exports verify as a
  continuation with `--continues <last verified entry>`. Keep exports immutable.
- **Runs**: `GET /v1/runs/{run_id}/evidence` (admission, run state, budget ledger and
  its archives, decisions with their tool lineage and scores) and
  `GET /v1/runs/{run_id}/replay-case`.
- **What the chain shows**: admissions, authorization decisions with policy and grant
  references, approvals and their redemption, dispatches and effect observations,
  revocations, rollouts and their gate results, erasures, feedback, key rotations.
- **Metrics** (`/metrics`): `contextos_dispatch_outcomes_total{capability,status}`,
  `contextos_dispatch_refusals_total{reason}` (e.g. a spike of `revoked_capability`
  confirms containment), `contextos_admissions_total{pack}`, and request rates and
  latencies by route show onset and blast radius.

## Specific incidents

**Signing key compromise.** Rotate (guide, *Operate*): new `key_id`, and list the old
key under `[audit] retired_keys` with `retired_at` set to the last moment it is known
to have been safe. Entries it signed after that stop verifying, which marks exactly the
history to distrust. With a KMS-held key, also revoke the Vault token and the key
version. Re-verify every tenant's chain.

**Audit verification fails.** Sev 1. Do not write to the store by hand. Export the
chain, verify offline to find the first failing sequence, and compare with backups.
The table rejects updates and deletes by trigger; a failure means access around the
runtime, so treat the database credentials as compromised.

**Prompt injection followed.** Revoke the capability or agent. Tool output and
retrieved evidence are labelled `data_only` and approvals are bound to the exact action
digest, so check in the chain which effects were authorized and on what grounds. File
the run as feedback (below) so the fix is gated on it.

**Personal data exposed.** Erase the affected runs once evidence is preserved
(`POST /v1/runs/{run_id}/erase`; it also redacts their feedback text). Signed records
are not rewritten: if personal data reached decision outputs or rationales, record that
in the postmortem and fix the pack so they cite evidence by reference.

**Store or provider outage.** The runtime fails closed: admissions and dispatches are
refused with `503`/`store_unavailable` or `*_unavailable` reason codes rather than run
ungoverned. `GET /readyz` reports store reachability. Effects caught mid-call surface as
unknown and wait for reconciliation.

## Recovery and closure

1. Fix the cause (pack, policy, tool, credential, provider).
2. **Gate the fix on the incident.** File each affected run as feedback
   (`POST /v1/runs/{run_id}/feedback`, an independent reviewer), then release the fix
   through a staged rollout: the server's release gate replays every open feedback case
   before the candidate takes live traffic.
3. Restore revoked targets one at a time, watching dispatch outcomes.
4. Close the feedback with the passing gate report's digest as evidence
   (`POST /v1/feedback/{feedback_id}/close`).
5. Hold the postmortem within five working days for Sev 1–2.

## Postmortem template

```markdown
# INC-<number>: <title>

Severity: <1–4>   Commander: <name>   Status: <closed | monitoring>
Detected: <time, how>   Contained: <time>   Resolved: <time>

## Summary
What happened, to whom, and the impact, in three sentences.

## Timeline
| Time (UTC) | Event | Audit sequence / evidence |

## Impact
Runs, tenants, effects (with operation ids), money, data, users.

## Root cause
The technical cause, and why governance did or did not stop it.

## What worked / what did not
Including which control fired (revocation, approval, budget, loop guard, gate).

## Actions
| Action | Owner | Due | Tracked in |
Every fix that changes a pack or policy is gated on the incident's feedback cases.

## Evidence
Audit export digests, verified ranges, evidence bundles, gate report digests.
```
