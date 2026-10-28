import { useMemo } from "react";
import { Link, useSearchParams } from "react-router";
import { useQuery } from "@tanstack/react-query";
import { api } from "../lib/api";
import type { Finding, Severity } from "../lib/types";
import { Badge, Card, Empty, ErrorNote, PageHead, SeverityBadge } from "../components/ui";

export function FindingsPage() {
  const [params, setParams] = useSearchParams();
  const severity = params.get("severity") ?? "";
  const waived = params.get("waived") === "1";
  const { data, error } = useQuery({
    queryKey: ["findings", waived],
    queryFn: () => api<{ findings: Finding[] }>(`/api/findings${waived ? "?include_waived=true" : ""}`),
    refetchInterval: 15_000,
  });
  const groups = useMemo(() => {
    const out = new Map<string, Finding[]>();
    for (const f of data?.findings ?? []) {
      if (severity && f.severity !== severity) continue;
      out.set(f.rule, [...(out.get(f.rule) ?? []), f]);
    }
    return [...out.entries()].sort((a, b) => order(a[1][0]!.severity) - order(b[1][0]!.severity) || b[1].length - a[1].length);
  }, [data, severity]);

  return (
    <div className="stack">
      <PageHead title="Findings" sub="What is wrong across the fleet, grouped by cause so one fix can close many. Each finding names its evidence and its fix; waivers are time-boxed and shown, never hidden." />
      <ErrorNote error={error} />
      <div className="row wrap">
        <div className="seg">
          {["", "critical", "high", "medium", "low"].map((s) => (
            <button key={s} className={severity === s ? "on" : ""} onClick={() => setParams({ ...(s ? { severity: s } : {}), ...(waived ? { waived: "1" } : {}) })}>
              {s || "All"}
            </button>
          ))}
        </div>
        <label className="row small muted">
          <input type="checkbox" checked={waived} onChange={(e) => setParams({ ...(severity ? { severity } : {}), ...(e.target.checked ? { waived: "1" } : {}) })} /> Include waived
        </label>
      </div>
      {groups.length === 0 && (
        <Card>
          <Empty title="Nothing open" />
        </Card>
      )}
      {groups.map(([rule, list]) => (
        <Card
          key={rule}
          title={
            <span className="row wrap">
              <SeverityBadge severity={list[0]!.severity} />
              <h2>{rule.startsWith("guardrail:") ? `Guardrail: ${list[0]!.title.split(": ").slice(1).join(": ")}` : label(rule)}</h2>
              <Badge>{list.length}</Badge>
            </span>
          }
          flush
        >
          <div className="card-body small muted" style={{ paddingBottom: 6 }}>
            <strong>Fix:</strong> {list[0]!.remediation}
          </div>
          <table>
            <tbody>
              {list.map((f) => (
                <tr key={f.id}>
                  <td className="mono small" style={{ width: "30%" }}>
                    {f.agent ? <Link to={`/agents/${encodeURIComponent(f.agent)}`}>{f.agent}</Link> : <Link to="/fleet">{f.source}</Link>}
                  </td>
                  <td className="small">{f.detail}</td>
                  <td className="nowrap">{f.waiver && <Badge tone="info">waived</Badge>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      ))}
    </div>
  );
}

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low"];
function order(s: Severity) {
  return SEVERITY_ORDER.indexOf(s);
}

const LABELS: Record<string, string> = {
  undeclared_agent: "Agents running without an owner",
  unreviewed: "Agents without a risk review",
  authority_drift: "Authority changed since review",
  capability_risk_conflict: "Packs disagree on risk",
  controls_missing: "Required controls missing on a runtime",
  profile_understated: "Runs admitted under a weaker profile than needed",
  irreversible_without_approval: "Irreversible actions with no human approval",
  unresolved_effects: "Actions with unknown outcome",
  model_unpinned: "Decisions without a recorded model",
  unscored_decisions: "Decisions no evaluator scored",
  low_scores: "Decisions scored below the floor",
  oversight_possibly_vacuous: "Approvals that never say no",
  agent_looping: "Agents repeating themselves",
  ungoverned_or_dormant: "Production agents with no governed runs",
  retired_but_running: "Retired agents still running",
  chain_broken: "Audit chain failed verification",
};

export function label(rule: string) {
  return LABELS[rule] ?? (rule.startsWith("guardrail:") ? `Guardrail: ${rule.slice(10)}` : rule.replace(/_/g, " "));
}
