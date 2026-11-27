import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api, download, enc } from "../lib/api";
import { n, time } from "../lib/format";
import { Badge, Card, Empty, ErrorNote, Kpi, PageHead } from "../components/ui";

interface ControlRow {
  id: string;
  title: string;
  runtime: string;
  coverage: "covered" | "partial" | "organizational";
  missing: string | null;
  note: string | null;
  status: "events_recorded" | "no_events_in_period" | "outside_audit";
  observed: Record<string, number>;
  total_events: number;
}

interface FrameworkReport {
  framework: string;
  title: string;
  summary: {
    controls_total: number;
    covered: number;
    partial: number;
    organizational: number;
    with_events: number;
    without_events: number;
  };
  controls: ControlRow[];
}

interface ComplianceReport {
  generated_at: string;
  certification: boolean;
  disclaimer: string;
  digest: string;
  scope: {
    source: string | null;
    sources_checked: number;
    verified_sources: number;
    broken_sources: number;
    verified_entries: number;
    open_critical_findings: number;
    open_high_findings: number;
  };
  frameworks: FrameworkReport[];
}

const FRAMEWORKS: { id: string; label: string }[] = [
  { id: "soc2", label: "SOC 2" },
  { id: "eu-ai-act", label: "EU AI Act" },
  { id: "iso42001", label: "ISO/IEC 42001" },
  { id: "nist-ai-rmf", label: "NIST AI RMF" },
  { id: "owasp-agentic", label: "OWASP Agentic" },
];

function coverageTone(c: ControlRow["coverage"]): "ok" | "warn" | "" {
  if (c === "covered") return "ok";
  if (c === "partial") return "warn";
  return "";
}

function statusTone(s: ControlRow["status"]): "ok" | "warn" | "" {
  if (s === "events_recorded") return "ok";
  if (s === "no_events_in_period") return "warn";
  return "";
}

export function Compliance() {
  const [framework, setFramework] = useState("soc2");
  const [exportError, setExportError] = useState<unknown>(null);
  const { data, error } = useQuery({
    queryKey: ["compliance", framework],
    queryFn: () => api<ComplianceReport>(`/api/compliance?framework=${enc(framework)}`),
    refetchInterval: 30_000,
  });

  const active = data?.frameworks[0];

  const exportReport = (format: "markdown" | "json") => {
    setExportError(null);
    const ext = format === "markdown" ? "md" : "json";
    download(`/api/compliance/report?framework=${enc(framework)}&format=${format}`, `contextos-compliance-${framework}.${ext}`).catch(
      setExportError,
    );
  };

  return (
    <div className="stack">
      <PageHead
        title="Compliance readiness"
        sub="Live control index derived from every runtime's verified audit chains and Tower's governance findings. Counts show verified events recorded, never certification or control effectiveness."
        actions={
          <>
            <button onClick={() => exportReport("markdown")} disabled={!data}>
              Export Markdown
            </button>
            <button className="primary" onClick={() => exportReport("json")} disabled={!data}>
              Export JSON
            </button>
          </>
        }
      />
      <ErrorNote error={error ?? exportError} />

      <div className="row wrap">
        <div className="seg" role="tablist" aria-label="Compliance frameworks">
          {FRAMEWORKS.map((fw) => (
            <button key={fw.id} className={framework === fw.id ? "on" : ""} onClick={() => setFramework(fw.id)}>
              {fw.label}
            </button>
          ))}
        </div>
        {data && (
          <span className="small faint">
            Snapshot {time(data.generated_at)} · digest <code>{data.digest.slice(0, 19)}…</code>
          </span>
        )}
      </div>

      {data && active && (
        <>
          <div className="grid four">
            <Kpi
              label="Controls with verified events"
              value={`${n(active.summary.with_events)} / ${n(active.summary.controls_total - active.summary.organizational)}`}
            />
            <Kpi
              label="Runtime coverage"
              value={`${n(active.summary.covered)} covered · ${n(active.summary.partial)} partial`}
            />
            <Kpi
              label="Verified audit chains"
              value={`${n(data.scope.verified_sources)} / ${n(data.scope.sources_checked)}`}
              alert={data.scope.broken_sources > 0}
            />
            <Kpi
              label="Open critical / high findings"
              value={`${n(data.scope.open_critical_findings)} / ${n(data.scope.open_high_findings)}`}
              alert={data.scope.open_critical_findings > 0}
            />
          </div>

          <Card title={active.title} flush>
            {active.controls.length === 0 ? (
              <Empty title="No controls listed for this framework" />
            ) : (
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>Control</th>
                      <th>Coverage</th>
                      <th>Status</th>
                      <th>Verified events</th>
                      <th>Notes &amp; gaps</th>
                    </tr>
                  </thead>
                  <tbody>
                    {active.controls.map((c) => {
                      const entries = Object.entries(c.observed);
                      return (
                        <tr key={c.id}>
                          <td>
                            <strong>{c.id}</strong> {c.title}
                            <div className="small faint">{c.runtime}</div>
                          </td>
                          <td>
                            <Badge tone={coverageTone(c.coverage)}>{c.coverage}</Badge>
                          </td>
                          <td>
                            <Badge tone={statusTone(c.status)}>{c.status.replace(/_/g, " ")}</Badge>
                          </td>
                          <td className="small">
                            {entries.length === 0
                              ? "—"
                              : entries.map(([kind, count]) => (
                                  <div key={kind}>
                                    <code>{kind}</code>: {n(count)}
                                  </div>
                                ))}
                          </td>
                          <td className="small faint">{c.missing ?? c.note ?? "Runtime-covered control."}</td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </Card>

          <p className="small faint">{data.disclaimer}</p>
        </>
      )}
    </div>
  );
}
