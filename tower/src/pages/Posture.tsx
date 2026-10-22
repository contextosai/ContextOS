import { Link, useNavigate } from "react-router";
import { ago, n } from "../lib/format";
import { PROFILE_LABEL, type Posture as PostureData } from "../lib/types";
import { usePosture } from "../components/Shell";
import { Badge, Card, Empty, ErrorNote, FindingCounts, HBars, Kpi, PageHead, ProfileBadge, SeverityBadge } from "../components/ui";

function pct(part: number, total: number) {
  return total ? Math.round((part / total) * 100) : 0;
}

function headline(p: PostureData): string {
  const a = p.agents;
  const crit = p.findings.by_severity.critical ?? 0;
  if (a.total === 0) return "No agents yet. Connect a runtime and Tower discovers agents from their first governed run.";
  const parts = [
    `${a.total} agent${a.total === 1 ? "" : "s"}`,
    `${a.external_effects} can act on external systems`,
    `${a.irreversible_external} irreversibly`,
  ];
  return `${parts.join(", ")}. ${crit ? `${crit} critical finding${crit === 1 ? " needs" : "s need"} attention.` : "No critical findings."}`;
}

export function Posture() {
  const { data: p, error } = usePosture();
  const navigate = useNavigate();
  if (!p) return <ErrorNote error={error} />;
  const a = p.agents;
  const profiles = Object.entries(a.by_required_profile).map(([k, v]) => [k.split("+").map((p) => PROFILE_LABEL[p] ?? p).join(" + "), v] as [string, number]);
  const brokenSources = p.sources.filter((s) => s.broken);
  return (
    <div className="stack" style={{ gap: 18 }}>
      <PageHead title="Posture" sub={headline(p)} actions={<span className="small faint">updated {ago(p.now)}</span>} />
      {brokenSources.length > 0 && (
        <div className="banner bad">
          <strong>Audit chain verification failed</strong> for {brokenSources.map((s) => s.id).join(", ")}. Tower stopped reading those runtimes; treat it as a security incident.
          <Link to="/fleet" className="right">
            Runtimes →
          </Link>
        </div>
      )}
      <div className="grid kpis">
        <Kpi label="Agents" value={n(a.total)} hint={`${pct(a.declared, a.total)}% have an owner`} plane="intelligence" alert={a.declared < a.total} to="/agents" />
        <Kpi label="Reviewed" value={`${pct(a.reviewed, a.total)}%`} hint={`${n(a.reviewed)} passed a risk review`} plane="trust" alert={a.reviewed < a.external_effects} to="/agents?filter=unreviewed" />
        <Kpi label="Critical findings" value={n(p.findings.by_severity.critical ?? 0)} hint={`${n(p.findings.by_severity.high ?? 0)} high · ${n(p.findings.waived)} waived`} plane="decision" alert={(p.findings.by_severity.critical ?? 0) > 0} to="/findings?severity=critical" />
        <Kpi label="Can act irreversibly" value={n(a.irreversible_external)} hint={`of ${n(a.external_effects)} with external effects`} plane="action" to="/agents?filter=irreversible" />
        <Kpi label="Anomalies" value={n(p.anomalies)} hint="against each agent's own baseline" plane="action" alert={p.anomalies > 0} to="/activity" />
        <Kpi label="Guardrails active" value={n(p.guardrails)} hint="organisation rules over every agent" plane="context" to="/guardrails" />
      </div>

      <div className="grid two">
        <Card title="What needs attention" actions={<Link to="/findings">All findings →</Link>} flush>
          {p.top_findings.length === 0 ? (
            <Empty title="Nothing open">Every agent meets the governance model and the organisation's guardrails.</Empty>
          ) : (
            <table>
              <tbody>
                {p.top_findings.map((f) => (
                  <tr key={f.id} className="link" onClick={() => navigate(f.agent ? `/agents/${encodeURIComponent(f.agent)}` : "/fleet")}>
                    <td style={{ width: 80 }}>
                      <SeverityBadge severity={f.severity} />
                    </td>
                    <td>
                      <div style={{ fontWeight: 600 }}>{f.title}</div>
                      <div className="small muted">{f.remediation}</div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Card>
        <Card title="Most exposed agents" actions={<Link to="/agents">Inventory →</Link>} flush>
          {p.riskiest.length === 0 ? (
            <Empty title="No agents yet" />
          ) : (
            <table>
              <tbody>
                {p.riskiest.map((r) => (
                  <tr key={r.key} className="link" onClick={() => navigate(`/agents/${encodeURIComponent(r.key)}`)}>
                    <td>
                      <div className="mono">{r.key}</div>
                      <div className="small muted">{r.owner ? `${r.owner} · ${r.team}` : "no owner"}</div>
                    </td>
                    <td>
                      <ProfileBadge profile={r.required_profile} />
                    </td>
                    <td className="small nowrap">
                      {r.irreversible > 0 ? <span style={{ color: "var(--bad)" }}>{r.irreversible} irreversible</span> : `${r.external} external`}
                    </td>
                    <td>
                      <FindingCounts counts={r.findings} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Card>
      </div>

      <div className="grid three">
        <Card title="Controls their authority requires">
          <HBars rows={profiles} plane="trust" empty="No agents yet." />
          <p className="small faint" style={{ marginTop: 8 }}>
            Derived from what each agent can do (ActionRisk of its capabilities), not from what owners declare.
          </p>
        </Card>
        <Card title="Lifecycle">
          <HBars rows={Object.entries(a.by_lifecycle)} plane="intelligence" />
        </Card>
        <Card title="Runtimes" actions={<Link to="/fleet">Details →</Link>}>
          <div className="stack tight">
            {p.sources.map((s) => (
              <div key={s.id} className="row">
                <span className="mono grow ellipsis">{s.id}</span>
                {s.broken ? (
                  <Badge tone="bad">chain broken</Badge>
                ) : s.last_error ? (
                  <Badge tone="warn" title={s.last_error}>
                    unreachable
                  </Badge>
                ) : (
                  <Badge tone="ok">verified #{n(s.verified_to)}</Badge>
                )}
                {s.revoked > 0 && <Badge tone="bad">{s.revoked} revoked</Badge>}
              </div>
            ))}
            {p.unattributed > 0 && <p className="small faint">{n(p.unattributed)} entries arrived after their run left Tower's recent window; their counts are kept per runtime.</p>}
          </div>
        </Card>
      </div>
    </div>
  );
}
