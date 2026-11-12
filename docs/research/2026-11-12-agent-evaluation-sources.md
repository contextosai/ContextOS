# Agent evaluation: sources behind the 2026-11 evaluation gates

Reviewed 2026-11-12 for [design/evaluation.md](../design/evaluation.md). Only
sources that bear on what a runtime that gates tool calls and releases should
measure, record or enforce are listed. Numbers marked *inferred* are arithmetic or
design choices made here, not stated by the source.

## Reliability over repeated trials

- **Evaluating Large Language Models Trained on Code.** Chen et al., arXiv
  [2107.03374](https://arxiv.org/abs/2107.03374) (2021). Unbiased
  `pass@k = E[1 − C(n−c, k)/C(n, k)]` from `n ≥ k` samples with `c` passes. The
  plug-in `1 − (1 − p̂)^k` underestimates.
- **τ-bench.** Yao et al., arXiv [2406.12045](https://arxiv.org/abs/2406.12045)
  (2024). `pass^k = E[C(c, k)/C(n, k)]`, the chance that all `k` trials succeed.
  gpt-4o retail: pass^1 61.2, pass^8 under 25%. Grades by comparing the final
  database with the goal state.
- **τ²-bench.** arXiv [2506.07982](https://arxiv.org/abs/2506.07982) (2025). Four
  trials per task. Grading combines database checks, assertion functions and action
  matching, and checks the task is not already solved before the agent runs.
- **Demystifying evals for AI agents.** Anthropic, 2026-01
  ([link](https://www.anthropic.com/engineering/demystifying-evals-for-ai-agents)).
  Use pass^k where consistency matters; outcome is the final environment state;
  regression suites near 100%; start from 20–50 real failures; a case that never
  passes is usually broken.
- **Adding Error Bars to Evals.** Miller, arXiv
  [2411.00640](https://arxiv.org/abs/2411.00640) (2024). The question is the unit
  of analysis, comparisons are paired and clustered, and power is planned. About
  1,000 questions to detect a 3-point gap at 80% power. *Inferred* from the same
  formula: about 350 cases for 5 points and about 87 for 10, so a 20–50 case suite
  detects only 15–25 point drops.
- **Don't Use the CLT in LLM Evals With Fewer Than a Few Hundred Datapoints.**
  Bowyer et al., ICML 2025, arXiv [2503.01747](https://arxiv.org/abs/2503.01747).
  A nominal 95% normal interval at N = 100 covers about 92.5%.
- **Towards a Science of AI Agent Reliability.** Rabanser et al., arXiv
  [2602.16666](https://arxiv.org/abs/2602.16666) (2026). Reliability improved far
  less than accuracy over 18 months. Outcome, trajectory and resource consistency
  are measured over 5 runs per task.

## Trajectory and tool calls

- **Agent evaluation.** Arize
  ([link](https://arize.com/ai-agents/agent-evaluation/)). Outcome, trajectory,
  decision and router scopes. Path convergence `C = (1/n) Σ s_min/s_i` over
  successful runs, with `s_min` pooled across versions. Regression cases come from
  production failures.
- **Vertex AI agent evaluation**
  ([link](https://docs.cloud.google.com/vertex-ai/generative-ai/docs/models/evaluation-agents)).
  Trajectory exact, in-order and any-order match, precision and recall.
- **Berkeley Function Calling Leaderboard**
  ([link](https://gorilla.cs.berkeley.edu/blogs/8_berkeley_function_calling_leaderboard.html)).
  AST checks on function name, required and hallucinated parameters and types, and
  an irrelevance category where no call is the right answer.
- **OpenTelemetry GenAI events**
  ([link](https://opentelemetry.io/docs/specs/semconv/gen-ai/gen-ai-events/)).
  `gen_ai.evaluation.result` (Development status), parented to the evaluated
  operation's span, with `gen_ai.evaluation.name`, `gen_ai.evaluation.score.value`,
  `gen_ai.evaluation.score.label` and `gen_ai.evaluation.explanation`. There is no
  attribute for which evaluator produced the result.

## Judges and human labels

- **Using LLM-as-a-judge.** Husain
  ([link](https://hamel.dev/blog/posts/llm-judge/)), and the validate-evaluator
  skill
  ([link](https://github.com/hamelsmu/evals-skills/blob/main/skills/validate-evaluator/SKILL.md)).
  Validate a judge as a classifier against expert labels, reporting TPR and TNR
  separately. The target is above 0.90 on both, the minimum 0.80. Use about 100
  labels and never fewer than 60. Correct the pass rate with
  `θ = (p + TNR − 1)/(TPR + TNR − 1)`. Re-validate after any model or prompt
  change.
- **Judging the Judges.** Thakur et al., arXiv
  [2406.12624](https://arxiv.org/abs/2406.12624) (2024). Percent agreement hides
  large score differences; report a chance-corrected statistic.
- **Who Validates the Validators?** Shankar et al., arXiv
  [2404.12272](https://arxiv.org/abs/2404.12272) (2024). Human criteria drift as
  people grade.
- **Confidence intervals for judge-corrected rates.** Lee et al., arXiv
  [2511.21140](https://arxiv.org/abs/2511.21140). Calibration labels dominate the
  interval; about 200 are needed for a width under 0.1.
- **Judge version drift.** arXiv [2608.29517](https://arxiv.org/abs/2608.29517)
  (2026). Every judge version change shifted scores, by up to 133 points on a
  0–1000 scale.

## Enforce versus measure

- **Guardrails vs evals.** Arize
  ([link](https://arize.com/blog/ai-agent-guardrails-vs-evals/)). Evals judge,
  guardrails constrain; code-level controls hold for irreversible actions.
- **EU AI Act Article 14**
  ([link](https://ai-act-service-desk.ec.europa.eu/en/ai-act/article-14)). Human
  oversight must guard against automation bias.

No source sets a production `k`, a non-inferiority margin or a judge threshold that
vendors endorse. These remain the release owner's parameters.
