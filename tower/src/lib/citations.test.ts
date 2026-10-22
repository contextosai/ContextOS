import { describe, expect, it } from "vitest";
import { linkify } from "./citations";

describe("linkify", () => {
  it("splits citations out and marks ids Tower could not find", () => {
    const parts = linkify("See [agent:acme/bot] and [finding:x:acme/ghost].", [
      { kind: "agent", id: "acme/bot", exists: true },
      { kind: "finding", id: "x:acme/ghost", exists: false },
    ]);
    expect(parts).toEqual(["See ", { kind: "agent", id: "acme/bot", exists: true }, " and ", { kind: "finding", id: "x:acme/ghost", exists: false }, "."]);
  });

  it("treats a citation the server did not check as unverified", () => {
    expect(linkify("[run:eu/r1]", [])).toEqual(["", { kind: "run", id: "eu/r1", exists: false }, ""]);
  });

  it("leaves other brackets alone", () => {
    expect(linkify("a [note] b", [])).toEqual(["a [note] b"]);
  });
});
