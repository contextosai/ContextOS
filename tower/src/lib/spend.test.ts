import { describe, expect, it } from "vitest";
import { measuredShare, metering, money, tokens } from "./spend";

const usage = (tokens: number, verified_tokens: number) => ({ tokens, verified_tokens });

describe("money", () => {
  it("rounds hundredths of a cent up to the cent", () => {
    expect(money(0)).toBe("$0.00");
    expect(money(1)).toBe("$0.01");
    expect(money(12_345)).toBe("$1.24");
    expect(money(123_456_700)).toBe("$12,345.67");
  });
  it("shows a dash for missing values", () => {
    expect(money(undefined)).toBe("—");
  });
});

describe("tokens", () => {
  it("is compact", () => {
    expect(tokens(950)).toBe("950");
    expect(tokens(12_300)).toBe("12.3k");
    expect(tokens(4_000_000)).toBe("4M");
    expect(tokens(250_000)).toBe("250k");
  });
});

describe("metering", () => {
  it("says how much of the spend was measured", () => {
    expect(metering(usage(0, 0))).toBe("none");
    expect(metering(usage(10, 10))).toBe("measured");
    expect(metering(usage(10, 0))).toBe("self-reported");
    expect(metering(usage(10, 4))).toBe("mixed");
    expect(measuredShare(usage(10, 4))).toBeCloseTo(0.4);
    expect(measuredShare(usage(0, 0))).toBeUndefined();
  });
});
