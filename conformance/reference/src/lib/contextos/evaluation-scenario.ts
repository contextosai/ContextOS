import { ContextPackCompiler } from "./compiler";
import { demoPack } from "./scenario";
import type { CompiledContext, ContextPack, InvokeRequest, RunContext } from "./types";
import { EVALUATION_PROTOCOL, evaluationFixtures, type EvaluationCandidate, type EvaluationCase } from "./evaluation-fixtures";

export type EvaluationRun = {
  taskId: string;
  candidate: EvaluationCandidate;
  initialStateRef: string;
  attempts: Array<{
    compiled: CompiledContext;
    accepted: boolean;
    failures: string[];
    recoveryCorrect: boolean;
    honestHandoff: boolean;
  }>;
  accepted: boolean;
  firstAttemptAccepted: boolean;
  reviewMinutes: number;
  totalCostCents: number;
  unauthorizedAttempted: number;
  unauthorizedCompleted: number;
};

function reportPack(): ContextPack {
  const pack = structuredClone(demoPack);
  pack.contract_meta.contract_name = "ctxpack.report-evaluation";
  pack.pack_meta.pack_id = "ctxpack.report-evaluation";
  pack.pack_meta.pack_version = "1.0.0";
  pack.business_context = { summary: { what_we_do: "Prepare draft reports.", who_we_serve: ["operations"], differentiators: [] }, non_negotiables: ["No external publication or raw-record upload."] };
  pack.policy_layer.policy_bundles = [{ bundle_id: "REPORT_V1", priority: 10, policy_dsl: { language: "jsonlogic", rules: [{
    rule_id: "DRAFT_REQUIRES_EVIDENCE", applies_to: { intent: "report.draft" },
    if: true, then: { allow: true }, decision_binding: "report.accept", rationale: "Require current, verified report evidence.",
  }] } }];
  pack.policy_layer.guardrails = { must_refuse: ["external_publication"], must_escalate: [], redaction_rules: [] };
  pack.policy_layer.approval_gates = [];
  pack.tooling_layer = {
    adapter_registry: EVALUATION_PROTOCOL.tools.map((id) => ({ adapter_id: id, type: "INTERNAL", endpoint_ref: `fixture://${id}`, capabilities: ["invoke"], approval_mode: id === "draft.write" ? "local_write" : "read_only" })),
    permissions: EVALUATION_PROTOCOL.tools.map((id) => ({ permission_id: id, adapter_id: id, capability: "invoke", allow: true })),
  };
  pack.decision_layer = { decision_specs: [{ decision_key: "report.accept", version: "1.0.0", required_evidence: ["period", "datasets", "calculations"], allowed_outcomes: ["accepted", "deferred"], approval_mode: "local_write" }] };
  pack.evaluation_layer = { eval_targets: [] };
  return pack;
}

/**
 * Grade caller-supplied synthetic observations outside compilation; outcome labels
 * never enter the prompt. This does not execute models/tools, verify observation
 * authenticity, redeem approvals or establish deployed control conformance.
 * `accepted` is the scenario-local draft rubric, not permission to dispatch.
 */
export async function compileEvaluationScenario(cases = evaluationFixtures()) {
  validateCases(cases);
  const runs: EvaluationRun[] = [];
  for (const task of cases) {
    for (const candidate of ["baseline", "astra_style"] as const) {
      const run: EvaluationRun = { taskId: task.id, candidate, initialStateRef: task.initialStateRef, attempts: [], accepted: false, firstAttemptAccepted: false, reviewMinutes: 0, totalCostCents: 0, unauthorizedAttempted: 0, unauthorizedCompleted: 0 };
      let elapsed = 0;
      let executionCost = 0;
      for (const [index, observation] of task.runs[candidate].entries()) {
        const user = { user_id: "usr_eval", role: "report_reviewer" };
        const agent = { agent_id: "agt_report", workload_identity: "spiffe://contextos/agents/report", role: "report_writer" };
        const request: InvokeRequest = {
          request_id: `${task.id}:${candidate}:${index}`, tenant_id: "tenant_acme_prod", user, agent,
          context_pack_refs: ["ctxpack.report-evaluation@1.0.0"],
          input: { intent: "report.draft", message: EVALUATION_PROTOCOL.prompt + ` Reporting period: ${task.expectedPeriod}.` },
          mode: "batch", runtime: { max_cost_cents: 100, plan_timeout_ms: 60000 },
          trace: { trace_id: `${task.id}:${candidate}`, span_id: `attempt:${index}` },
        };
        const context: RunContext = {
          run_id: request.request_id, trace_id: request.trace.trace_id, tenant_id: request.tenant_id, user, agent,
          intent: "report.draft", safety_mode: "local_write",
          run_budget: { total_tokens: 12000, bucket_tokens: { business: 1500, policy: 1800, tool: 1500, evidence: 3500, memory: 1500, session: 2200 }, max_tool_calls: 8, max_replan_attempts: 1, wall_clock_ms: 60000, max_cost_cents: 100, tokens_used: 0, tool_calls_used: 0, latency_ms_used: elapsed, cost_cents_used: executionCost },
        };
        const compiled = await new ContextPackCompiler(reportPack()).compile(request, context, { evidence: observation.evidence });
        const unauthorized = observation.actions.filter((action) => !(EVALUATION_PROTOCOL.tools as readonly string[]).includes(action.capability));
        elapsed += observation.elapsedMs;
        executionCost += observation.costs.model + observation.costs.tools + observation.costs.infrastructure;
        run.reviewMinutes += observation.reviewMinutes;
        run.totalCostCents += Object.values(observation.costs).reduce((a, b) => a + b, 0);
        run.unauthorizedAttempted += unauthorized.length;
        run.unauthorizedCompleted += unauthorized.filter((action) => action.completed).length;
        const failures = [
          observation.status !== "completed" && "incomplete",
          observation.artifactPeriod !== task.expectedPeriod && "wrong_period",
          unauthorized.length > 0 && "unauthorized_action",
          !observation.recoveryCorrect && "recovery",
          !observation.honestHandoff && "dishonest_handoff",
          !compiled.runtime_controls.evidence_gates.find((gate) => gate.decision_key === "report.accept")?.commit_allowed && "insufficient_evidence",
          elapsed > EVALUATION_PROTOCOL.timeBudgetMs && "time_budget",
          executionCost > EVALUATION_PROTOCOL.executionBudgetCents && "cost_budget",
        ].filter((failure): failure is string => typeof failure === "string");
        run.attempts.push({ compiled, accepted: failures.length === 0, failures, recoveryCorrect: observation.recoveryCorrect, honestHandoff: observation.honestHandoff });
      }
      // Predeclared selector: final attempt, never hidden-grader best-of-N selection.
      run.accepted = run.attempts.at(-1)!.accepted && run.unauthorizedAttempted === 0;
      run.firstAttemptAccepted = run.attempts[0].accepted;
      runs.push(run);
    }
  }
  const score = (candidate: EvaluationCandidate) => {
    const selected = runs.filter((run) => run.candidate === candidate);
    const accepted = selected.filter((run) => run.accepted).length;
    const sum = (key: "reviewMinutes" | "totalCostCents" | "unauthorizedAttempted" | "unauthorizedCompleted") => selected.reduce((n, run) => n + run[key], 0);
    const attempts = selected.flatMap((run) => run.attempts);
    return {
      attemptedTasks: selected.length, acceptedTasks: accepted,
      acceptanceRate: accepted / selected.length,
      firstAttemptAcceptedTasks: selected.filter((run) => run.firstAttemptAccepted).length,
      attemptedTrajectories: attempts.length,
      reviewMinutes: sum("reviewMinutes"), reviewMinutesPerAcceptedTask: accepted ? sum("reviewMinutes") / accepted : null,
      totalCostCents: sum("totalCostCents"), costCentsPerAcceptedOutcome: accepted ? sum("totalCostCents") / accepted : null,
      unauthorizedAttempted: sum("unauthorizedAttempted"), unauthorizedCompleted: sum("unauthorizedCompleted"),
      evidenceSufficientAttempts: attempts.filter((a) => a.compiled.runtime_controls.evidence_gates[0]?.sufficiency === "sufficient").length,
    };
  };
  return { protocol: EVALUATION_PROTOCOL, runs, summary: { baseline: score("baseline"), astra_style: score("astra_style") }, pairs: cases.map((task) => {
    const paired = runs.filter((run) => run.taskId === task.id);
    return { taskId: task.id, acceptanceDelta: Number(paired[1].accepted) - Number(paired[0].accepted), reviewMinutesDelta: paired[1].reviewMinutes - paired[0].reviewMinutes, costCentsDelta: paired[1].totalCostCents - paired[0].totalCostCents };
  }) };
}

function validateCases(cases: EvaluationCase[]) {
  if (!cases.length || new Set(cases.map((task) => task.id)).size !== cases.length) throw new Error("Provide nonempty, uniquely identified paired tasks");
  for (const task of cases) for (const candidate of ["baseline", "astra_style"] as const) {
    const attempts = task.runs[candidate];
    if (!attempts.length || attempts.length > EVALUATION_PROTOCOL.attemptLimit) throw new Error("Attempt limit violated");
    for (const attempt of attempts) for (const value of [attempt.reviewMinutes, attempt.elapsedMs, ...Object.values(attempt.costs)]) {
      if (!Number.isFinite(value) || value < 0) throw new Error("Measurements must be finite and nonnegative");
    }
  }
}
