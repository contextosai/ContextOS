# Evaluation loop

An evaluation platform judges two versions of a refund agent, and its verdicts gate
the release. The platform is a stand-in that holds only the `evaluate` scope. It does
what a real one does with the traces it reads: it judges each refund call's arguments
and each decision, then posts its verdicts to ContextOS. Synthetic and local: no model
key, cloud account or evaluation service.

From the repository or release archive root:

```sh
./examples/evaluation-loop/run.sh
```

Expected output (payment service lines omitted):

```text
Judge evaluator.refund_arguments@1 calibrated on 120 human labels: TPR 1.00, TNR 0.97, kappa 0.97 (fit).
Verdict from uncalibrated evaluator.refund_arguments@2 refused: evaluator_uncalibrated.
baseline: 3 cases x 3 trials run and judged.
candidate: 3 cases x 3 trials run and judged.
Candidate trials failed: 2, e.g. evaluator.refund_arguments@1 arguments of refund:ord_883: fail
pass^3: baseline 1.00, candidate 0.67 (pass@3 1.00 would have hidden it).
Gate failure must_pass: 1 of 3 candidate trial(s) passed
Gate failure inconclusive: pass^3 changed by -0.3333 [-0.9867, 0.3200]: cannot rule out a drop beyond 0.05; this suite detects drops of 0.9339
evaluation loop complete
```

What it shows:

1. **The judge is calibrated first.** `ctx calibrate` compares the judge's verdicts
   with reviewers' on 120 past calls. The deployment lists the record under
   `[guards.evaluator_calibration]`, so verdicts from any other judge release are
   refused.
2. **Each run is a trial.** Both versions run three cases three times. On two trials
   the candidate puts the customer id in the order id field. Policy cannot see this:
   the call is well-formed and within limits. The platform's argument check can, and
   it posts a `fail` evaluation on that tool call
   (`POST /v1/runs/{run_id}/operations/{operation_id}/evaluations`) and a low-utility
   decision score.
3. **Trials come from signed evidence.** `ctx trials` reads each run's evidence bundle.
   A trial fails when the run did not complete, an owed outcome was not witnessed, a
   score is under the criteria, or a tool-call evaluation is labelled `fail`.
4. **The gate compares consistency, not best-of-k.** `ctx reliability-gate` computes
   pass^3 per case. pass@3 is still 1.00, because the candidate succeeded once on
   every case. The `must_pass` case fails the release. On three cases the statistical
   comparison is `inconclusive`: the suite would detect only drops of about 0.93. A
   real suite needs more cases to rule out a small regression.

See [docs/GUIDE.md](../../docs/GUIDE.md), "Gate on reliability", "Evaluate tool calls"
and "Require calibrated evaluators".
