import { useState } from "react";
import { Link } from "react-router";
import { useMutation, useQuery } from "@tanstack/react-query";
import { api, can, useMe } from "../lib/api";
import { ago } from "../lib/format";
import type { Anomaly, Change, RunSummary } from "../lib/types";
import { openAction } from "../components/actions";
import { Badge, Card, Empty, ErrorNote, PageHead, Tabs } from "../components/ui";

type Tab = "anomalies" | "runs" | "changes";

interface Brief {
  what_happened: string;
  likely_causes: string[];
  blast_radius: string;
  options: { action: string; target: string; why: string }[];
  confidence: string;
}

export function Activity() {
  const [tab, setTab] = useState<Tab>("anomalies");
  const anomalies = useQuery({ queryKey: ["anomalies"], queryFn: () => api<{ anomalies: Anomaly[] }>("/api/anomalies"), refetchInterval: 15_000 });
  const runs = useQuery({ queryKey: ["runs"], queryFn: () => api<{ runs: RunSummary[] }>("/api/runs?limit=200"), refetchInterval: 10_000 });
  const changes = useQuery({ queryKey: ["changes"], queryFn: () => api<{ changes: Change[] }>("/api/changes"), refetchInterval: 15_000 });
  return (
    <div className="stack">
      <PageHead title="Activity" sub="Behaviour that departs from each agent's own baseline, recent governed runs across every runtime, and changes to how the fleet is governed." />
      <Tabs<Tab>
        value={tab}
        onChange={setTab}
        tabs={[
          ["anomalies", `Anomalies (${anomalies.data?.anomalies.length ?? 0})`],
          ["runs", "Recent runs"],
          ["changes", "Governance changes"],
        ]}
      />
      <ErrorNote error={anomalies.error ?? runs.error ?? changes.error} />
      {tab === "anomalies" && <Anomalies list={anomalies.data?.anomalies ?? []} />}
      {tab === "runs" && <Runs list={runs.data?.runs ?? []} />}
      {tab === "changes" && (
        <Card flush>
          {!changes.data?.changes.length ? (
            <Empty title="No governance changes yet" />
          ) : (
            <table>
              <tbody>
                {changes.data.changes.map((c) => (
                  <tr key={c.source + c.sequence}>
                    <td className="small muted nowrap">{ago(c.at)}</td>
                    <td className="mono small">{c.source}</td>
                    <td>{c.summary}</td>
                    <td className="small muted">{c.by}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Card>
      )}
    </div>
  );
}

function Anomalies({ list }: { list: Anomaly[] }) {
  const me = useMe().data;
  const [briefs, setBriefs] = useState<Record<string, Brief>>({});
  const brief = useMutation({
    mutationFn: (a: Anomaly) => api<{ brief: Brief }>("/api/anomalies/brief", { body: { agent: a.agent, metric: a.metric } }),
    onSuccess: (out, a) => setBriefs((b) => ({ ...b, [a.agent + a.metric]: out.brief })),
  });
  if (!list.length) return <Card><Empty title="Every agent is within its usual behaviour">Tower compares each agent's last hour with its own previous week.</Empty></Card>;
  return (
    <div className="stack">
      <ErrorNote error={brief.error} />
      {list.map((a) => {
        const b = briefs[a.agent + a.metric];
        return (
          <Card
            key={a.agent + a.metric}
            title={
              <span className="row wrap">
                <Badge tone="warn">{a.metric.replace(/_/g, " ")}</Badge>
                <Link to={`/agents/${encodeURIComponent(a.agent)}`} className="mono">
                  {a.agent}
                </Link>
              </span>
            }
            actions={
              me?.intelligence && (can(me, "operator") || can(me, "risk")) ? (
                <button className="small" disabled={brief.isPending} onClick={() => brief.mutate(a)}>
                  {brief.isPending && brief.variables === a ? "Briefing…" : b ? "Brief again" : "Brief me"}
                </button>
              ) : undefined
            }
          >
            <p>
              {a.value} in the last hour; its usual is {a.baseline.toFixed(1)}.
            </p>
            {b && (
              <div className="stack tight" style={{ marginTop: 10 }}>
                <div className="row">
                  <Badge tone="primary">AI brief</Badge>
                  <Badge>confidence {b.confidence}</Badge>
                </div>
                <p>{b.what_happened}</p>
                <div className="small">
                  <strong>Likely causes:</strong> {b.likely_causes.join("; ")}
                </div>
                <div className="small">
                  <strong>Blast radius:</strong> {b.blast_radius}
                </div>
                <div className="stack tight">
                  {b.options.map((o) => (
                    <div key={o.action + o.target} className="row wrap">
                      <Badge tone={o.action.startsWith("revoke") ? "bad" : ""}>{o.action.replace(/_/g, " ")}</Badge>
                      <span className="mono small">{o.target}</span>
                      <span className="small muted grow">{o.why}</span>
                      {o.action.startsWith("revoke") && (
                        <button
                          className="small danger"
                          disabled={!can(me, "operator")}
                          onClick={() =>
                            openAction({
                              title: `Revoke ${o.action === "revoke_agent" ? "agent" : "capability"} ${o.target}`,
                              description: "Suggested by the AI brief. You decide: the revocation applies on every runtime Tower controls and is restorable.",
                              role: "operator",
                              danger: true,
                              confirm: o.target,
                              submit: "Revoke everywhere",
                              fields: [{ name: "reason", label: "Reason", kind: "textarea", required: true, initial: `Anomaly on ${a.agent}: ${a.metric}` }],
                              run: (v) => api("/api/fleet/revoke", { body: { kind: o.action === "revoke_agent" ? "agent" : "capability", target: o.target, reason: v.reason } }),
                            })
                          }
                        >
                          Revoke…
                        </button>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </Card>
        );
      })}
    </div>
  );
}

function Runs({ list }: { list: RunSummary[] }) {
  if (!list.length) return <Card><Empty title="No runs in Tower's recent window" /></Card>;
  return (
    <Card flush>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Run</th>
              <th>Agent</th>
              <th>Status</th>
              <th>Capabilities</th>
              <th>Refused / unknown</th>
              <th>When</th>
            </tr>
          </thead>
          <tbody>
            {list.map((r) => (
              <tr key={r.source + r.run_id}>
                <td className="mono small">
                  {r.run_id}
                  <div className="faint">{r.source}</div>
                </td>
                <td className="mono small">
                  <Link to={`/agents/${encodeURIComponent(r.agent)}`}>{r.agent}</Link>
                </td>
                <td>
                  <Badge tone={r.status === "completed" ? "ok" : r.status === "failed" ? "bad" : "info"}>{r.status}</Badge>
                </td>
                <td className="small">{r.capabilities.join(", ") || "—"}</td>
                <td className="small">
                  {r.refused > 0 && <span style={{ color: "var(--bad)" }}>{r.refusal_reasons.join(", ") || `${r.refused} refused`}</span>}
                  {r.unknown > 0 && <Badge tone="bad">{r.unknown} unknown</Badge>}
                </td>
                <td className="small muted nowrap">{ago(r.last_at)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Card>
  );
}
