import { Link } from "react-router";
import { useQuery } from "@tanstack/react-query";
import { api, can, useMe } from "../lib/api";
import { ago, time } from "../lib/format";
import type { Waiver } from "../lib/types";
import { openAction } from "../components/actions";
import { Badge, Card, Empty, ErrorNote, PageHead } from "../components/ui";
import { label } from "./FindingsPage";

export function Waivers() {
  const me = useMe().data;
  const { data, error } = useQuery({ queryKey: ["waivers"], queryFn: () => api<{ waivers: Waiver[] }>("/api/waivers"), refetchInterval: 30_000 });
  const list = [...(data?.waivers ?? [])].reverse();
  const decide = (w: Waiver, approve: boolean) =>
    openAction({
      title: approve ? "Approve waiver" : "Reject waiver",
      description: approve ? `The finding is suppressed for ${w.agent} for ${w.days} days, then returns on its own.` : "The finding stays open.",
      role: "risk",
      submit: approve ? "Approve" : "Reject",
      fields: [{ name: "reason", label: "Reason", kind: "textarea", required: true }],
      run: (v) => api(`/api/waivers/${w.id}/decide`, { body: { approve, reason: v.reason } }),
      invalidate: [["waivers"], ["findings"], ["posture"]],
    });
  return (
    <div className="stack">
      <PageHead title="Waivers" sub="Accepted exceptions: one finding, one agent, a reason, an expiry. Requested by an owner, decided by a risk reviewer who is not the requester." />
      <ErrorNote error={error} />
      {list.length === 0 ? (
        <Card>
          <Empty title="No waivers">Owners request one from a finding.</Empty>
        </Card>
      ) : (
        <Card flush>
          <table>
            <thead>
              <tr>
                <th>Finding</th>
                <th>Agent</th>
                <th>Reason</th>
                <th>Status</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {list.map((w) => (
                <tr key={w.id}>
                  <td className="small">{label(w.rule)}</td>
                  <td className="mono small">
                    <Link to={`/agents/${encodeURIComponent(w.agent)}`}>{w.agent}</Link>
                  </td>
                  <td className="small">
                    {w.reason}
                    <div className="faint">
                      {w.requested_by} {ago(w.requested_at)}, for {w.days} days
                    </div>
                  </td>
                  <td className="small">
                    <Badge tone={w.status === "approved" ? "ok" : w.status === "requested" ? "warn" : ""}>{w.status}</Badge>
                    {w.decided_by && <div className="faint">by {w.decided_by}</div>}
                    {w.expires_at && w.status === "approved" && <div className="faint">until {time(w.expires_at)}</div>}
                  </td>
                  <td className="nowrap">
                    {w.status === "requested" && (
                      <>
                        <button className="small primary" disabled={!can(me, "risk") || w.requested_by === me?.principal_id} onClick={() => decide(w, true)}>
                          Approve
                        </button>{" "}
                        <button className="small" disabled={!can(me, "risk") || w.requested_by === me?.principal_id} onClick={() => decide(w, false)}>
                          Reject
                        </button>
                      </>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      )}
    </div>
  );
}
