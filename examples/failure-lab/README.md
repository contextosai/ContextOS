# Agent Failure Lab: recording

The [Agent Failure Lab](../../lab) is a static page: someone picks a way for a refund
agent to go wrong, steps through it, and sees what was paid with and without a gateway.
It needs no install or account because it plays back a recording. This directory makes
that recording from the real runtime, and fails the build when the runtime stops matching
it.

```sh
./examples/failure-lab/run.sh     # re-record lab/story.js
./examples/failure-lab/check.sh   # fail if the runtime's behaviour drifted (scripts/check.sh and CI run this)
```

[record.py](record.py) runs each scenario in [scenarios.py](scenarios.py) against its own
`contextosd` (in-memory store, development fact services, the support-refund pack) and a
synthetic card processor ([provider.py](provider.py)) that keeps a ledger, honours
idempotency keys and refuses refunds above what is left of a payment.

| Scenario | What the agent does | What is configured | Baselines |
|---|---|---|---|
| `lost_response` | Refund whose response is lost, a retry, the ticket redelivered into a new run; on-call confirms from the provider's ledger | Intent key (order and amount), `manual_reconcile` recovery, a ceiling per order | fresh requests; an idempotency key per run |
| `over_reach` | Refunds the whole order, then another order, then what was asked | A task authorization on the run: one order, up to INR 800 | fresh requests |
| `approval` | Sends INR 4,200, splits it into two smaller refunds, sends it again once approved | The pack's rule: a refund request above INR 3,000 needs approval | a check in the tool that makes amounts above INR 3,000 wait |
| `daily_cap` | Four refunds on four orders in four runs | A guarantee per agent per day | fresh requests |
| `runaway` | Refunds in a loop, then starts another run; on-call restores the agent | A circuit breaker per agent that revokes on trip | fresh requests |

Each step records the request, the gateway's answer, the guarantee's balance where there
is one, the new audit entries, and for every world (the gateway and each baseline in
[worlds.py](worlds.py)) the provider's ledger, what was paid and how much of it nobody
authorised. That last figure follows the scenario's `rightful` rule: what the customer
was owed, what was approved, the daily limit, or the breaker's threshold. The baselines
receive the same attempts as the gateway, sent straight to their own provider. Each
scenario's configuration and full audit log are kept so visitors can read them and verify
the log with `ctx audit-verify`; recording and `--check` both run that verification.

`--check` re-runs everything and compares what must not change: statuses, reason codes,
balances, provider calls, paid and excess amounts, baseline outcomes, configuration and
audit entry kinds. Identifiers, times, hashes and signatures differ on every run and are
not compared. When the runtime's behaviour changes on purpose, re-record and review the
page's words in [words.js](../../lab/words.js), which are keyed by scenario and step
name; `scripts/test_failure_lab.py` fails if a recorded step has no words or the words
state an amount the recording does not contain.

The approval and authority services are the development stand-ins from the
support-refund example: they vouch for whatever they are asked, and the page says so.
