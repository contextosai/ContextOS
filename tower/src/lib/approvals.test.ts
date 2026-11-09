import { describe, expect, it } from "vitest";
import { bucketLabels, medianBucket, rubberStampShare } from "./approvals";

const row = (decision_seconds: number[]) => ({
  requested: 4, redeemed: 4, decision_seconds, untimed: 0, refused_too_fast: 0, refused_step_up: 0,
  within_ten_seconds: decision_seconds[0] ?? 0,
});

describe("approvals", () => {
  it("labels buckets", () => {
    expect(bucketLabels([10, 30, 60, 300, 1800, 3600])).toEqual(["≤10s", "≤30s", "≤1m", "≤5m", "≤30m", "≤1h", ">1h"]);
  });
  it("finds the median bucket and the rubber-stamp share", () => {
    const labels = bucketLabels([10, 30, 60, 300, 1800, 3600]);
    expect(medianBucket(row([3, 0, 0, 0, 1, 0, 0]), labels)).toBe("≤10s");
    expect(medianBucket(row([1, 0, 0, 0, 3, 0, 0]), labels)).toBe("≤30m");
    expect(rubberStampShare(row([3, 0, 0, 0, 1, 0, 0]))).toBe(0.75);
    expect(rubberStampShare(row([0, 0, 0, 0, 0, 0, 0]))).toBeUndefined();
  });
});
