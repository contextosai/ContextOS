// The governance dashboard (GET /api/dashboard): what is held, refused, waiting for a
// person and close to a ceiling right now, and whether the evidence is whole.
// For the on-call engineer and the compliance lead; each card links to its source.

import { Link } from "react-router";
import { useQuery } from "@tanstack/react-query";
import { api } from "../lib/api";
import { n } from "../lib/format";
import { Card, Empty, ErrorNote, HBars, Kpi } from "./ui";

interface Ceiling {
  source: string;
  guarantee?: string;
  unit?: string;
  limit?: number;
  resources_held?: number;
  fullest?: number;
  fullest_share?: number | null;
  unavailable?: string;
}

export interface Dashboard {
  held_effects: { total: number; agents: { agent: string; held: number }[] };
  denials: { total: number; by_reason: { reason: string; count: number }[] };
  approvals_backlog: { waiting: number; by_capability: { capability_id: string; waiting: number }[] };
  waivers: { active: number };
  policy_drift: number;
  break_glass_unreviewed: number;
  evidence: { sources: number; broken: number; chains: { source: string; behind: number; broken: boolean }[] };
  ceilings: Ceiling[];
}

/** Ceilings at or above this share of their limit are flagged. */
export const NEAR_CEILING = 0.8;

export function nearCeiling(rows: Ceiling[]): Ceiling[] {
  return rows.filter((r) => (r.fullest_share ?? 0) >= NEAR_CEILING);
}

export function Governance() {
  const { data: d, error } = useQuery({ queryKey: ["dashboard"], queryFn: () => api<Dashboard>("/api/dashboard"), refetchInterval: 30_000 });
  if (!d) return <ErrorNote error={error} />;
  const near = nearCeiling(d.ceilings);
  const lagging = d.evidence.chains.filter((c) => c.behind > 0).length;
  return (
    <>
      <div className="grid kpis">
        <Kpi label="Held effects" value={n(d.held_effects.total)} hint="outcome unknown, capacity held until reconciled" plane="action" alert={d.held_effects.total > 0} to="/findings?rule=unresolved_effects" />
        <Kpi label="Refused" value={n(d.denials.total)} hint={d.denials.by_reason[0] ? `most: ${d.denials.by_reason[0].reason}` : "no refusals"} plane="decision" to="/activity" />
        <Kpi label="Approvals waiting" value={n(d.approvals_backlog.waiting)} hint="asked and not yet decided" plane="decision" alert={d.approvals_backlog.waiting > 0} to="/approvals" />
        <Kpi label="Near a ceiling" value={n(near.length)} hint={`shared limits at ${Math.round(NEAR_CEILING * 100)}% or more`} plane="action" alert={near.length > 0} />
        <Kpi label="Policy drift" value={n(d.policy_drift)} hint={`${n(d.waivers.active)} waivers active · ${n(d.break_glass_unreviewed)} break-glass to review`} plane="context" alert={d.policy_drift + d.break_glass_unreviewed > 0} to="/findings" />
        <Kpi label="Evidence" value={d.evidence.broken ? `${d.evidence.broken} broken` : "intact"} hint={`${n(d.evidence.sources)} chains verified${lagging ? `, ${lagging} catching up` : ""}`} plane="trust" alert={d.evidence.broken > 0} to="/fleet" />
      </div>
      <div className="grid two">
        <Card title="Refusals by reason">
          <HBars rows={d.denials.by_reason.map((r) => [r.reason, r.count])} plane="decision" empty="No refusals recorded" />
        </Card>
        <Card title="Shared ceilings" flush>
          {d.ceilings.length === 0 ? (
            <Empty title="No shared guarantees configured" />
          ) : (
            <table>
              <tbody>
                {d.ceilings.map((c) => (
                  <tr key={`${c.source}:${c.guarantee ?? "?"}`}>
                    <td className="mono small">{c.source}</td>
                    <td className="mono small">{c.guarantee ?? "—"}</td>
                    <td className="num small">
                      {c.unavailable ? `unavailable: ${c.unavailable}` : `${n(c.resources_held ?? 0)} held, fullest ${Math.round((c.fullest_share ?? 0) * 100)}% of ${n(c.limit ?? 0)} ${c.unit ?? ""}`}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Card>
      </div>
      {d.held_effects.agents.length > 0 && (
        <Card title="Agents with held effects">
          <ul className="small">
            {d.held_effects.agents.map((a) => (
              <li key={a.agent}>
                <Link to={`/agents/${encodeURIComponent(a.agent)}`} className="mono">
                  {a.agent}
                </Link>{" "}
                {n(a.held)} held
              </li>
            ))}
          </ul>
        </Card>
      )}
    </>
  );
}
