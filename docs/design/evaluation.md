# Evaluation: what the runtime gates, records and leaves to evaluators

Status: plan, 2026-11-12. Baseline: main `b1794ae3`. Sources: see
[2026-11-12-agent-evaluation-sources.md](../research/2026-11-12-agent-evaluation-sources.md).

## 1. Three layers

Agent evaluation asks three different questions, and ContextOS answers each in a
different place.

| Question | Example | Where it lives |
|---|---|---|
| Must this never happen? | A refund without approval; a tool outside the task | **Policy.** The runtime refuses it. An invariant that can be enforced is not measured. |
| Did the effect really happen? | The refund posted to the right order for the right amount | **Outcome contracts.** A witness's signed reading closes the effect; until then the run cannot complete. |
| Was it good? | The right tool, the right arguments, a helpful reply | **Independent evaluators.** ContextOS records their verdicts, pins and checks the evaluators, and gates on what they report. |

The literature agrees on the second row: an outcome is the final state of the
system of record, not what the agent said. A witnessed reading is that state with
a signature. ContextOS does not build judges. It makes their verdicts count, and
it makes sure the verdicts come from evaluators fit to give them.

## 2. Where ContextOS stands

| Evaluation need | Today |
|---|---|
| Outcome (final state) | Outcome contracts with witnesses (GUIDE §3) |
| Trajectory | `ctx trajectory-gate` over evidence bundles and the signed audit chain |
| Decision quality | Independent decision scores (GUIDE §7), `completion_requires_scores` |
| Policy regressions | `ctx test`, `ctx gate` |
| Production failures become tests | Feedback with replay obligations, not waivable |
| Traces | OpenTelemetry spans with GenAI attributes |
| **Reliability over repeated trials** | **Gap.** Trials of a case accumulate, but no gate measures consistency |
| **Path efficiency** | **Gap.** Only a tool-call ratio against the baseline's worst trial |
| **Tool-call verdicts** | **Gap.** Scores attach to decisions, not to the call that was wrong |
| **Evaluator fitness** | **Gap.** The evaluator suite is pinned, but nothing shows it agrees with people |

## 3. Workstreams

### E1. Reliability gate (`ctx trials`, `ctx reliability-gate`)

A trial is one run of a case. `ctx trials` decides pass or fail from the runtime's
own record: the run completed, every outcome it owed was witnessed, and every
independent score meets the owner's criteria. `ctx reliability-gate` compares
baseline and candidate per case:

- **pass^k** = C(c, k)/C(n, k) per case, averaged over cases. pass@k is reported
  and never gated: one success in `k` is not good enough for an action that moves
  money.
- The comparison is the mean of the paired per-case differences with a normal
  interval. With margin `δ`, the gate passes when the lower bound is at least `−δ`,
  fails as a **regression** when the upper bound is below `−δ`, and otherwise fails
  as **inconclusive**. The report names the drop the suite could detect at 80%
  power, so a pass on 20 cases is not read as proof of no regression.
- **Path convergence** over passing trials (`s_min / s_i`, `s_min` pooled across
  both sides), with an optional limit on its drop.
- `must_pass` cases (every trial), a suite floor, `min_cases`, cases short of `k`
  trials, missing cases. Flaky and never-passing cases are listed.

`k`, the margin and the floors have no defaults: they are the release owner's
decision, as the scorecard gate's floors are.

### E2. Tool-call evaluations

`POST /v1/runs/{run_id}/operations/{operation_id}/evaluations` (`evaluate` scope,
same independence rule as decision scores) records one evaluator's verdict on one
governed tool call, named as OpenTelemetry names it: `name`, `score` and/or
`label`, and an `explanation_ref` (explanations are cited, not carried, because
signed records are never rewritten on erasure). Each is signed into the audit chain, listed in the evidence
bundle beside the operation, and emitted as a `gen_ai.evaluation.result` event.
ContextOS adds what the convention lacks: which pinned evaluator gave the verdict.
This is where tool selection and argument correctness go, and where an external
evaluation platform posts its span-level results.

### E3. Evaluator calibration

`ctx calibrate` checks a judge against human labels: TPR, TNR, Youden's J and
Cohen's kappa from paired verdicts, with the label counts. It writes a calibration
record bound to the evaluator ref and the label set's digest. With
`[guards.evaluator_calibration]`, contextosd loads these records at startup and
refuses scores and evaluations from an evaluator ref with no record meeting the
floors (`evaluator_uncalibrated`), so an unvalidated judge cannot hold or release a
run. A new judge version needs a new record.

### E4. An evaluation platform as an independent evaluator

An example in which an external evaluator reads a run's evidence, judges the tool
calls and decisions, and posts tool-call evaluations and decision scores with an
`evaluate`-only credential. Its verdicts then count toward completion and release
gates.

## 4. Not planned

- **Building judges, online sampling or drift dashboards.** These are an evaluation
  platform's job; ContextOS emits the spans and signed records they read.
- **A bootstrap or Bayesian interval.** The normal interval is too narrow below a
  few hundred cases. `min_cases`, `z` and the reported detectable drop are the
  owner's guard for now.
- **Correcting pass rates for judge error.** `ctx calibrate` reports what the
  correction needs (TPR, TNR); applying it to gate inputs waits for a user who
  gates on judge-only pass rates.
