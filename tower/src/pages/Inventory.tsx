import { useMemo, useState } from "react";
import { useNavigate } from "react-router";
import { useQuery } from "@tanstack/react-query";
import { api } from "../lib/api";
import { ago, n } from "../lib/format";
import { KINDS, downloadCsv, isShadow, matches, type InventoryItem, type Kind } from "../lib/inventory";
import { Badge, Card, Empty, ErrorNote, PageHead } from "../components/ui";

export function Inventory() {
  const navigate = useNavigate();
  const [kind, setKind] = useState<Kind | "all">("all");
  const [shadow, setShadow] = useState(false);
  const [q, setQ] = useState("");
  const [exportError, setExportError] = useState<unknown>(null);
  const { data, error } = useQuery({
    queryKey: ["inventory"],
    queryFn: () => api<{ items: InventoryItem[]; shadow: number; generated_at: string }>("/api/inventory"),
    refetchInterval: 30_000,
  });
  const rows = useMemo(
    () => (data?.items ?? []).filter((i) => (kind === "all" || i.kind === kind) && (!shadow || isShadow(i)) && matches(i, q)),
    [data, kind, shadow, q],
  );

  return (
    <div className="stack">
      <PageHead
        title="Inventory"
        sub="Every agent, tool, adapter, model and owning team the runtimes' verified audit chains show or an owner declared. Shadow rows ran without a declaration or pin."
        actions={
          <button onClick={() => downloadCsv(kind, shadow).catch(setExportError)} title="The rows as filtered by kind and shadow, as CSV">
            Export CSV
          </button>
        }
      />
      <ErrorNote error={error ?? exportError} />
      <div className="row wrap">
        <div className="seg">
          {(["all", ...KINDS] as const).map((k) => (
            <button key={k} className={kind === k ? "on" : ""} onClick={() => setKind(k)}>
              {k}
            </button>
          ))}
        </div>
        <label className="small">
          <input type="checkbox" checked={shadow} onChange={(e) => setShadow(e.target.checked)} /> Shadow only ({n(data?.shadow ?? 0)})
        </label>
        <input placeholder="Id, team, agent, environment" value={q} onChange={(e) => setQ(e.target.value)} style={{ minWidth: 240 }} />
        <span className="right small faint">{n(rows.length)} rows</span>
      </div>
      <Card flush>
        {rows.length === 0 ? (
          <Empty title="Nothing matches" />
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Kind</th>
                  <th>Id</th>
                  <th>Status</th>
                  <th>Risk tier</th>
                  <th>Owner teams</th>
                  <th>Environments</th>
                  <th>Used by</th>
                  <th>First seen</th>
                  <th>Last seen</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((i) => (
                  <tr
                    key={`${i.kind}:${i.id}`}
                    className={i.kind === "agent" ? "link" : ""}
                    onClick={i.kind === "agent" ? () => navigate(`/agents/${encodeURIComponent(i.id)}`) : undefined}
                  >
                    <td className="small">{i.kind}</td>
                    <td className="mono">{i.id}</td>
                    <td>
                      {isShadow(i) ? <Badge tone="bad">shadow</Badge> : i.declared ? <Badge tone="ok">declared</Badge> : <Badge>not seen</Badge>}
                      {i.lifecycle && <Badge>{i.lifecycle}</Badge>}
                    </td>
                    <td className="small">{i.risk_tier ?? "—"}</td>
                    <td className="small">{i.owner_teams.join(", ") || "—"}</td>
                    <td className="small">{i.environments.join(", ") || "—"}</td>
                    <td className="small">{i.kind === "agent" ? "—" : n(i.agents.length)}</td>
                    <td className="small faint">{i.first_seen ? ago(i.first_seen) : "—"}</td>
                    <td className="small faint">{i.last_seen ? ago(i.last_seen) : "—"}</td>
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
