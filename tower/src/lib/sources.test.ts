import { describe, expect, it } from "vitest";
import { actionsFor, attentionOrder, definition, EMPTY_FORM, keyText, stateBadge, syncText, type SourceHealthRow } from "./sources";

const row = (over: Partial<SourceHealthRow>): SourceHealthRow => ({
  id: "a",
  url: "https://rt",
  origin: "console",
  state: "current",
  paused: false,
  collecting: true,
  tenant_id: "t",
  verified_to: 1,
  head: 1,
  lag: 0,
  last_sync: null,
  last_sync_age_seconds: 5,
  last_error: null,
  broken: null,
  unattributed: 0,
  can_revoke: false,
  business_unit: null,
  region: null,
  environment: null,
  added_by: null,
  added_at: null,
  last_change: null,
  ...over,
});

describe("definition", () => {
  const form = { ...EMPTY_FORM, id: "eu-1", url: "https://rt.example", read: "/run/secrets/read" };

  it("builds the probe body from references only", () => {
    expect(definition({ ...form, controlKind: "env", control: "EU_CONTROL", business_unit: " Ops " })).toEqual({
      ok: true,
      value: { id: "eu-1", url: "https://rt.example", token_file: "/run/secrets/read", control_token_env: "EU_CONTROL", business_unit: "Ops" },
    });
  });

  it("refuses what towerd would refuse", () => {
    const bad = [
      { ...form, id: "-x" },
      { ...form, url: "ftp://rt" },
      { ...form, url: "https://u:p@rt" },
      { ...form, read: "" },
      { ...form, read: "relative" },
      { ...form, read: "/a/../b" },
      { ...form, readKind: "env" as const, read: "lower_case" },
      { ...form, controlKind: "file" as const, control: "" },
    ];
    for (const f of bad) expect(definition(f).ok).toBe(false);
  });
});

describe("health", () => {
  it("orders by urgency and offers the actions the state allows", () => {
    const rows = [row({ id: "b" }), row({ id: "a", state: "broken" }), row({ id: "c", state: "unavailable" })];
    expect(attentionOrder(rows).map((r) => r.id)).toEqual(["a", "c", "b"]);
    expect(actionsFor(row({ state: "broken" }))).toEqual(["pause", "retry", "reload", "remove"]);
    expect(actionsFor(row({ origin: "config", paused: true, state: "paused" }))).toEqual(["resume", "reload"]);
    expect(actionsFor(row({ state: "unavailable" }))).toEqual(["pause", "remove"]);
  });

  it("describes states, sync age and key references", () => {
    expect(stateBadge("broken")).toEqual(["bad", "chain broken"]);
    expect(stateBadge("odd")).toEqual(["", "odd"]);
    expect(syncText(row({ last_sync_age_seconds: null }))).toBe("never");
    expect(syncText(row({ last_sync_age_seconds: 125 }))).toBe("2m ago");
    const refs = { token_env: null, token_file: "/k", control_token_env: "C", control_token_file: null };
    expect([keyText(refs, false), keyText(refs, true), keyText(undefined, false)]).toEqual(["/k", "$C", "—"]);
  });
});
