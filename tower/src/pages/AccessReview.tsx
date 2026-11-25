import { useState } from "react";
import { Link } from "react-router";
import { useQuery } from "@tanstack/react-query";
import { api, can, enc, session, useMe } from "../lib/api";
import { ago, n, time } from "../lib/format";
import { openAction } from "../components/actions";
import { Badge, Card, Empty, ErrorNote, Kpi, PageHead } from "../components/ui";

interface Grant {
  agent: string;
  owner_team: string | null;
  capability: string;
  adapter: string;
  packs: string[];
  last_used: string | null;
  status: "used" | "unused" | "never_used";
}
interface Review {
  window_days: number;
  generated_at: string;
  grants: Grant[];
  stale_delegations: { agent: string; delegate: string; delegate_last_seen: string | null }[];
  dormant_agents: { agent: string; lifecycle: string; last_seen: string | null }[];
  expiring_waivers: { id: string; agent: string; rule: string; expires_at: string }[];
  expiring_reviews: { agent: string; expires_at: string }[];
  summary: { grants: number; unused_grants: number; stale_delegations: number; dormant_agents: number; expiring_waivers: number; expiring_reviews: number };
  digest: string;
}

async function downloadCsv(days: number) {
  const token = session.token();
  const response = await fetch(`/api/access-review?days=${days}&format=csv`, {
    headers: token ? { authorization: `Bearer ${token}` } : {},
    credentials: "omit",
    cache: "no-store",
    referrerPolicy: "no-referrer",
  });
  if (!response.ok) throw new Error(`export failed (${response.status})`);
  const url = URL.createObjectURL(await response.blob());
  const a = document.createElement("a");
  a.href = url;
  a.download = "access-review.csv";
  a.click();
  URL.revokeObjectURL(url);
}

export function AccessReview() {
  const { data: me } = useMe();
  const [days, setDays] = useState(90);
  const [onlyUnused, setOnlyUnused] = useState(true);
  const [exportError, setExportError] = useState<unknown>(null);
  const { data: r, error } = useQuery({ queryKey: ["access-review", days], queryFn: () => api<Review>(`/api/access-review?days=${days}`) });
  const grants = (r?.grants ?? []).filter((g) => !onlyUnused || g.status !== "used");

  return (
    <div className="stack">
      <PageHead
        title="Access review"
        sub="Which agents hold which capabilities and whether they used them, delegations nobody uses, agents in production that stopped running, and waivers and reviews about to expire. Derived from verified evidence on every read."
        actions={
          <>
            <button onClick={() => downloadCsv(days).catch(setExportError)}>Export CSV</button>
            <button
              className="primary"
              disabled={!r || !can(me, "risk")}
              title={can(me, "risk") ? "Record that you reviewed exactly these findings" : "needs the risk role"}
              onClick={() =>
                r &&
                openAction({
                  title: "Attest to this access review",
                  description: `Signs into Tower's journal that you reviewed these findings (${r.digest.slice(0, 19)}…). If they change before you submit, read the review again.`,
                  role: "risk",
                  submit: "Attest",
                  fields: [{ name: "notes", label: "Notes and decisions", kind: "textarea", required: true, placeholder: "What you will revoke, suspend or keep, and why" }],
                  run: (v) => api("/api/access-review/attest", { body: { days, digest: r.digest, notes: v.notes } }),
                  invalidate: [["access-review", days]],
                })
              }
            >
              Attest
            </button>
          </>
        }
      />
      <ErrorNote error={error ?? exportError} />
      <div className="row wrap">
        <div className="seg">
          {[30, 90, 180].map((d) => (
            <button key={d} className={days === d ? "on" : ""} onClick={() => setDays(d)}>
              {d} days
            </button>
          ))}
        </div>
        <label className="small">
          <input type="checkbox" checked={onlyUnused} onChange={(e) => setOnlyUnused(e.target.checked)} /> Unused grants only
        </label>
      </div>
      {r && (
        <div className="grid three">
          <Kpi label="Unused grants" value={`${n(r.summary.unused_grants)} / ${n(r.summary.grants)}`} alert={r.summary.unused_grants > 0} />
          <Kpi label="Stale delegations" value={n(r.summary.stale_delegations)} alert={r.summary.stale_delegations > 0} />
          <Kpi label="Dormant agents in production" value={n(r.summary.dormant_agents)} alert={r.summary.dormant_agents > 0} />
        </div>
      )}
      <Card title="Grants" flush>
        {grants.length === 0 ? (
          <Empty title={onlyUnused ? "Every grant was used in the window" : "No grants"} />
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Agent</th>
                  <th>Capability</th>
                  <th>Packs</th>
                  <th>Status</th>
                  <th>Last used</th>
                </tr>
              </thead>
              <tbody>
                {grants.map((g) => (
                  <tr key={`${g.agent}:${g.capability}`}>
                    <td>
                      <Link to={`/agents/${enc(g.agent)}`} className="mono">
                        {g.agent}
                      </Link>
                      <div className="small faint">{g.owner_team ?? "no owner"}</div>
                    </td>
                    <td className="mono">{g.capability}</td>
                    <td className="small">{g.packs.join(", ") || "surfaced at admission"}</td>
                    <td>
                      <Badge tone={g.status === "used" ? "ok" : "warn"}>{g.status.replace("_", " ")}</Badge>
                    </td>
                    <td className="small faint">{g.last_used ? ago(g.last_used) : "never"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
      <div className="grid three">
        <Card title="Stale delegations">
          {r?.stale_delegations.length ? (
            <ul className="small">
              {r.stale_delegations.map((d) => (
                <li key={`${d.agent}>${d.delegate}`}>
                  <span className="mono">{d.agent}</span> → <span className="mono">{d.delegate}</span> ({d.delegate_last_seen ? ago(d.delegate_last_seen) : "never ran"})
                </li>
              ))}
            </ul>
          ) : (
            <Empty title="None" />
          )}
        </Card>
        <Card title="Dormant agents">
          {r?.dormant_agents.length ? (
            <ul className="small">
              {r.dormant_agents.map((d) => (
                <li key={d.agent}>
                  <Link to={`/agents/${enc(d.agent)}`} className="mono">
                    {d.agent}
                  </Link>{" "}
                  {d.lifecycle}, last ran {d.last_seen ? ago(d.last_seen) : "never"}: request a suspension or retirement on its page
                </li>
              ))}
            </ul>
          ) : (
            <Empty title="None" />
          )}
        </Card>
        <Card title="Expiring soon">
          {r && r.expiring_waivers.length + r.expiring_reviews.length > 0 ? (
            <ul className="small">
              {r.expiring_waivers.map((w) => (
                <li key={w.id}>
                  waiver {w.rule} for <span className="mono">{w.agent}</span>, expires {time(w.expires_at)}
                </li>
              ))}
              {r.expiring_reviews.map((v) => (
                <li key={v.agent}>
                  review of <span className="mono">{v.agent}</span>, expires {time(v.expires_at)}
                </li>
              ))}
            </ul>
          ) : (
            <Empty title="Nothing within 30 days" />
          )}
        </Card>
      </div>
      <p className="small faint">
        Act through the existing routes: remove a grant from the agent's pack, revoke on every runtime from Fleet, or suspend through the agent's lifecycle. A capability revocation applies to every agent.
      </p>
    </div>
  );
}
