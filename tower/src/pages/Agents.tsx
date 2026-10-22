import { useMemo, useState } from "react";
import { useNavigate, useSearchParams } from "react-router";
import { useQuery } from "@tanstack/react-query";
import { api } from "../lib/api";
import { ago, n } from "../lib/format";
import type { AgentRow } from "../lib/types";
import { Badge, Card, Empty, ErrorNote, FindingCounts, PageHead, ProfileBadge } from "../components/ui";

const FILTERS: [string, string, (a: AgentRow) => boolean][] = [
  ["all", "All", () => true],
  ["attention", "Needs attention", (a) => a.findings.critical + a.findings.high > 0],
  ["undeclared", "No owner", (a) => a.lifecycle === "undeclared"],
  ["unreviewed", "Not reviewed", (a) => !a.reviewed],
  ["irreversible", "Can act irreversibly", (a) => a.irreversible > 0],
  ["production", "In production", (a) => a.lifecycle === "production"],
];

export function Agents() {
  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();
  const filter = params.get("filter") ?? "all";
  const [q, setQ] = useState("");
  const { data, error } = useQuery({ queryKey: ["agents", ""], queryFn: () => api<{ agents: AgentRow[] }>("/api/agents"), refetchInterval: 15_000 });
  const rows = useMemo(() => {
    const test = FILTERS.find(([id]) => id === filter)?.[2] ?? (() => true);
    const needle = q.trim().toLowerCase();
    return (data?.agents ?? [])
      .filter((a) => test(a) && (!needle || [a.key, a.owner, a.team, a.purpose, a.business_unit, ...a.models].some((v) => v?.toLowerCase().includes(needle))))
      .sort((x, y) => y.findings.critical - x.findings.critical || y.findings.high - x.findings.high || y.irreversible - x.irreversible);
  }, [data, filter, q]);

  return (
    <div className="stack">
      <PageHead title="Agents" sub="Every agent Tower has seen run, or that an owner declared. What each can do comes from its packs and its runs, and that decides the controls it needs." />
      <ErrorNote error={error} />
      <div className="row wrap">
        <div className="seg">
          {FILTERS.map(([id, label]) => (
            <button key={id} className={filter === id ? "on" : ""} onClick={() => setParams(id === "all" ? {} : { filter: id })}>
              {label}
            </button>
          ))}
        </div>
        <input placeholder="Agent, owner, team, purpose, model" value={q} onChange={(e) => setQ(e.target.value)} style={{ minWidth: 260 }} />
        <span className="right small faint">{n(rows.length)} agents</span>
      </div>
      <Card flush>
        {rows.length === 0 ? (
          <Empty title="No agents match" />
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Agent</th>
                  <th>Owner</th>
                  <th>Lifecycle</th>
                  <th>Needs</th>
                  <th>Can do</th>
                  <th>Findings</th>
                  <th>Last run</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((a) => (
                  <tr key={a.key} className="link" onClick={() => navigate(`/agents/${encodeURIComponent(a.key)}`)}>
                    <td>
                      <div className="mono">{a.key}</div>
                      <div className="small muted ellipsis" style={{ maxWidth: 340 }}>
                        {a.purpose ?? "no declared purpose"}
                      </div>
                    </td>
                    <td className="small">{a.owner ? `${a.owner} · ${a.team}` : <Badge tone="bad">no owner</Badge>}</td>
                    <td>
                      <Badge tone={a.lifecycle === "production" ? "primary" : a.lifecycle === "undeclared" ? "warn" : ""}>{a.lifecycle}</Badge>
                      {a.reviewed && (
                        <Badge tone="ok" title="Passed a risk review">
                          reviewed
                        </Badge>
                      )}
                    </td>
                    <td>
                      <ProfileBadge profile={a.required_profile} />
                    </td>
                    <td className="small nowrap">
                      {a.capabilities} capabilities
                      {a.external > 0 && <div className="faint">{a.external} external{a.irreversible ? `, ${a.irreversible} irreversible` : ""}</div>}
                    </td>
                    <td>
                      <FindingCounts counts={a.findings} />
                    </td>
                    <td className="small muted nowrap">{a.runs ? ago(a.last_seen) : "never"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
}
