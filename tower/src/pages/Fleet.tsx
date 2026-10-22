import { useQuery } from "@tanstack/react-query";
import { api, can, useMe } from "../lib/api";
import { ago, n } from "../lib/format";
import { openAction } from "../components/actions";
import { Badge, Card, ErrorNote, Kv, PageHead } from "../components/ui";

interface SourceRow {
  id: string;
  url: string;
  business_unit: string | null;
  region: string | null;
  environment: string | null;
  can_revoke: boolean;
  mode: string | null;
  tenant: string | null;
  packs: string[] | null;
  guards: Record<string, unknown> | null;
  controls: { control_id: string }[] | null;
  state: { verified_to: number; head: number; broken: { sequence: number; reason: string } | null; last_error: string | null; last_sync: string | null; revoked: Record<string, string>; unattributed: number } | null;
}

export function Fleet() {
  const me = useMe().data;
  const { data, error } = useQuery({ queryKey: ["sources"], queryFn: () => api<{ sources: SourceRow[] }>("/api/sources"), refetchInterval: 10_000 });
  const fleetAction = (revoke: boolean, kind = "capability", target = "") =>
    openAction({
      title: revoke ? "Fleet kill switch" : "Restore across the fleet",
      description: revoke
        ? "Revokes the target on every runtime Tower holds a control key for. Each runtime refuses it at the next admission and dispatch, and records the change in its own audit chain."
        : "Restores the target on every runtime Tower controls.",
      role: "operator",
      danger: revoke,
      confirm: revoke ? target || undefined : undefined,
      submit: revoke ? "Revoke everywhere" : "Restore everywhere",
      fields: [
        { name: "kind", label: "Kind", kind: "select", options: [["agent", "Agent"], ["capability", "Capability"], ["adapter", "Adapter"], ["pack", "Context Pack"], ["principal", "Principal"]], initial: kind },
        { name: "target", label: "Target (exact id)", required: true, initial: target },
        { name: "reason", label: "Reason", kind: "textarea", required: true },
      ],
      run: (v) => api(revoke ? "/api/fleet/revoke" : "/api/fleet/restore", { body: { kind: v.kind, target: v.target, reason: v.reason } }),
      invalidate: [["sources"], ["posture"]],
    });
  return (
    <div className="stack">
      <PageHead
        title="Runtimes"
        sub="Every ContextOS runtime tenant Tower governs. Tower reads each audit chain through the runtime's API and verifies every entry (digest, hash link, Ed25519 signature) before using it; a chain that fails stops being read."
        actions={
          <>
            <button disabled={!can(me, "operator")} onClick={() => fleetAction(false)}>
              Restore…
            </button>
            <button className="danger" disabled={!can(me, "operator")} onClick={() => fleetAction(true)}>
              Kill switch…
            </button>
          </>
        }
      />
      <ErrorNote error={error} />
      <div className="grid two">
        {(data?.sources ?? []).map((s) => (
          <Card
            key={s.id}
            title={
              <span className="row wrap">
                <h2 className="mono">{s.id}</h2>
                {s.state?.broken ? <Badge tone="bad">chain broken</Badge> : s.state?.last_error ? <Badge tone="warn">unreachable</Badge> : <Badge tone="ok">verified</Badge>}
                {s.mode && <Badge tone={s.mode === "production" ? "primary" : "warn"}>{s.mode}</Badge>}
              </span>
            }
          >
            <div className="stack tight">
              {s.state?.broken && (
                <div className="banner bad">
                  Entry #{s.state.broken.sequence}: {s.state.broken.reason}
                </div>
              )}
              {s.state?.last_error && <div className="banner warn small">{s.state.last_error}</div>}
              <Kv
                rows={[
                  ["Business unit", s.business_unit],
                  ["Tenant", s.tenant],
                  ["Region / environment", [s.region, s.environment].filter(Boolean).join(" / ") || null],
                  ["Verified", s.state ? `#${n(s.state.verified_to)} of ${n(s.state.head)}${s.state.last_sync ? `, ${ago(s.state.last_sync)}` : ""}` : "—"],
                  ["Packs", s.packs?.join(", ")],
                  ["Controls declared", s.controls ? `${s.controls.length}` : "—"],
                  ["Kill switch", s.can_revoke ? "Tower holds a control key" : "read-only"],
                ]}
              />
              {s.state && Object.keys(s.state.revoked).length > 0 && (
                <div className="stack tight">
                  <h3>Revoked here</h3>
                  {Object.entries(s.state.revoked).map(([t, reason]) => (
                    <div key={t} className="row small">
                      <Badge tone="bad">{t}</Badge>
                      <span className="grow muted">{reason}</span>
                      <button className="small" disabled={!can(me, "operator")} onClick={() => fleetAction(false, t.split(":")[0], t.split(":").slice(1).join(":"))}>
                        Restore
                      </button>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </Card>
        ))}
      </div>
    </div>
  );
}
