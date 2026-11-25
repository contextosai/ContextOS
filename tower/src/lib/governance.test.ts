import { describe, expect, it } from "vitest";
import { NEAR_CEILING, nearCeiling } from "../components/Governance";

describe("governance dashboard", () => {
  it("flags ceilings at or above the threshold and skips unavailable sources", () => {
    const rows = [
      { source: "eu", guarantee: "a", fullest_share: 0.95 },
      { source: "eu", guarantee: "b", fullest_share: NEAR_CEILING },
      { source: "eu", guarantee: "c", fullest_share: 0.2 },
      { source: "us", unavailable: "timed out" },
    ];
    expect(nearCeiling(rows).map((r) => r.guarantee)).toEqual(["a", "b"]);
  });
});
