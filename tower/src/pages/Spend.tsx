import { useNavigate, useSearchParams } from "react-router";
import { useQuery } from "@tanstack/react-query";
import { api } from "../lib/api";
import { n, pct } from "../lib/format";
import { bucketLabel, measuredShare, money, tokens, WINDOWS } from "../lib/spend";
import type { SpendGroup, SpendReport, SpendRow, SpendUsage } from "../lib/types";
import { Badge, Card, Empty, ErrorNote, HBars, Kpi, PageHead, Spark } from "../components/ui";
import { MeteringBadge } from "../components/AgentSpend";

const GROUPS: [SpendGroup, string][] = [
  ["agent", "Agents"],
  ["team", "Teams"],
  ["model", "Models"],
];

export function Spend() {
  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();
  const hours = Number(params.get("hours") ?? 168);
  const group = (params.get("group") ?? "agent") as SpendGroup;
  const set = (key: string, value: string) => setParams((p) => ({ ...Object.fromEntries(p), [key]: value }));
  const { data, error } = useQuery({
    queryKey: ["spend", hours, group],
    queryFn: () => api<SpendReport>(`/api/spend?hours=${hours}&group=${group}`),
    refetchInterval: 30_000,
  });
  const t = data?.totals;
  const share = t ? measuredShare(t) : undefined;
  const refusals = Object.entries(data?.refusals ?? {}).sort((x, y) => y[1] - x[1]);
  const series = data?.series ?? [];

  return (
    <div className="stack">
      <PageHead
        title="Model spend"
        sub="What agents spend on model calls, from the runtimes' budget settlements. Measured spend was settled by a metering gateway from the provider's own usage; self-reported spend was settled by the agent and charged as reserved."
        actions={
          <div className="seg">
            {WINDOWS.map(([h, label]) => (
              <button key={h} className={hours === h ? "on" : ""} onClick={() => set("hours", String(h))}>
                {label}
              </button>
            ))}
          </div>
        }
      />
      <ErrorNote error={error} />
      <div className="grid kpis">
        <Kpi label="Spend" value={money(t?.cost_units)} hint={`${n(t?.calls)} model calls`} plane="action" />
        <Kpi label="Tokens" value={tokens(t?.tokens)} hint={`${tokens(t?.verified_tokens)} measured`} plane="intelligence" />
        <Kpi
          label="Measured"
          value={pct(share)}
          hint={`${tokens(t?.self_reported_tokens)} tokens self-reported`}
          plane="trust"
          alert={share !== undefined && share < 0.5}
          to="/findings"
        />
        <Kpi
          label="Uncovered"
          value={money(t?.uncovered_cost_units)}
          hint={`${tokens(t?.uncovered_tokens)} tokens past the budget`}
          plane="decision"
          alert={(t?.uncovered_tokens ?? 0) + (t?.uncovered_cost_units ?? 0) > 0}
          to="/findings"
        />
        <Kpi label="Refused" value={n(t?.refused)} hint="reservations the budget refused" plane="decision" alert={(t?.refused ?? 0) > 0} />
        <Kpi label="Awaiting settlement" value={n(t?.unsettled_claims)} hint="metered calls still reserved" plane="action" />
      </div>
      <div className="grid two">
        <Card title="Spend over time" actions={<span className="small faint">{data && series[0] ? `${bucketLabel(series[0].hour, data.bucket_hours)} – now` : ""}</span>}>
          <Spark values={series.map((p) => p.cost_units)} plane="action" />
          <div className="small faint">Tokens</div>
          <Spark values={series.map((p) => p.tokens)} plane="intelligence" />
        </Card>
        <Card title="Budget refusals by reason">
          <HBars rows={refusals} plane="decision" empty="No reservation was refused." />
        </Card>
      </div>
      <div className="row wrap">
        <div className="seg">
          {GROUPS.map(([g, label]) => (
            <button key={g} className={group === g ? "on" : ""} onClick={() => set("group", g)}>
              {label}
            </button>
          ))}
        </div>
        {data && data.total_rows > data.rows.length && (
          <span className="small faint">
            top {n(data.rows.length)} of {n(data.total_rows)}
          </span>
        )}
      </div>
      <Card flush>
        {!data || data.rows.length === 0 ? (
          <Empty title="No model spend in this window">Spend appears once runs reserve and settle model calls.</Empty>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>{GROUPS.find(([g]) => g === group)?.[1].replace(/s$/, "")}</th>
                  {group !== "agent" && <th>Agents</th>}
                  <th className="num">Spend</th>
                  <th className="num">Tokens</th>
                  <th className="num">Calls</th>
                  <th>Metering</th>
                  {group !== "model" && <th className="num">Uncovered</th>}
                  {group !== "model" && <th className="num">Refused</th>}
                </tr>
              </thead>
              <tbody>
                {data.rows.map((r) => (
                  <Row key={r.key} row={r} group={group} onOpen={() => group === "agent" && navigate(`/agents/${encodeURIComponent(r.key)}`)} />
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
}

function Row({ row, group, onOpen }: { row: SpendRow; group: SpendGroup; onOpen: () => void }) {
  const u = row.usage;
  const full = "uncovered_tokens" in u ? (u as SpendUsage) : undefined;
  return (
    <tr className={group === "agent" ? "link" : ""} onClick={onOpen}>
      <td>
        <div className="mono">{row.key}</div>
        {group === "agent" && (
          <div className="small muted">
            {row.owner ? `${row.owner} · ${row.team}` : row.team}
            {row.models?.length ? ` · ${row.models.join(", ")}` : ""}
          </div>
        )}
      </td>
      {group !== "agent" && <td className="num">{n(row.agents)}</td>}
      <td className="num">{money(u.cost_units)}</td>
      <td className="num">{tokens(u.tokens)}</td>
      <td className="num">{n(u.calls)}</td>
      <td>
        <MeteringBadge usage={u} />
      </td>
      {full && <td className="num">{full.uncovered_tokens ? <Badge tone="bad">{tokens(full.uncovered_tokens)}</Badge> : "—"}</td>}
      {full && <td className="num">{full.refused ? n(full.refused) : "—"}</td>}
    </tr>
  );
}
