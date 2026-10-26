import { createHash } from "node:crypto";

export interface ContextCompileErrorDetail {
  code: "policy_eval_error";
  stage: "policy_resolution";
  bundle_id: string;
  rule_id: string;
  expression_path: "if";
  message: string;
}

const POLICY_ERROR_MESSAGE = "An applicable policy predicate could not be evaluated.";

function safeErrorId(value: string): string {
  return value.length <= 256
    ? value
    : `sha256:${createHash("sha256").update(value, "utf8").digest("hex")}`;
}

/** A failed enforcing predicate never produces a successful compiled context. */
export class ContextCompileError extends Error {
  readonly code = "policy_eval_error" as const;
  readonly stage = "policy_resolution" as const;
  readonly bundle_id: string;
  readonly rule_id: string;
  readonly expression_path = "if" as const;

  constructor(detail: ContextCompileErrorDetail) {
    super(POLICY_ERROR_MESSAGE);
    this.name = "ContextCompileError";
    this.bundle_id = safeErrorId(detail.bundle_id);
    this.rule_id = safeErrorId(detail.rule_id);
  }

  toJSON(): ContextCompileErrorDetail {
    return {
      code: this.code,
      stage: this.stage,
      bundle_id: this.bundle_id,
      rule_id: this.rule_id,
      expression_path: this.expression_path,
      message: POLICY_ERROR_MESSAGE,
    };
  }
}
