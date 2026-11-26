import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api, can, enc, session, useMe } from "../lib/api";
import { ago } from "../lib/format";
import { openAction } from "../components/actions";
import { Badge, Card, Empty, ErrorNote, PageHead } from "../components/ui";

const STATUSES = ["open", "investigating", "contained", "resolved", "closed"] as const;

interface CaseRow {
  id: string;
  title: string;
  severity: string;
  status: string;
  owner: string;
  opened_at: string;
  summary: string;
  links: { kind: string; ref: string; source?: string }[];
  timeline?: { at: string; by: string; kind: string; text: string }[];
}

async function exportMarkdown(id: string) {
  const token = session.token();
  const response = await fetch(`/api/cases/${enc(id)}/report?format=md`, {
    headers: token ? { authorization: `Bearer ${token}` } : {},
    credentials: "omit",
    cache: "no-store",
    referrerPolicy: "no-referrer",
  });
  if (!response.ok) throw new Error(`export failed (${response.status})`);
  const url = URL.createObjectURL(await response.blob());
  const a = document.createElement("a");
  a.href = url;
  a.download = `incident-${id}.md`;
  a.click();
  URL.revokeObjectURL(url);
}

export function Cases() {
  const { data: me } = useMe();
  const [status, setStatus] = useState<string>("open");
  const [selected, setSelected] = useState<string | null>(null);
  const [exportError, setExportError] = useState<unknown>(null);
  const list = useQuery({ queryKey: ["cases", status], queryFn: () => api<{ cases: CaseRow[] }>(`/api/cases?status=${status}`) });
  const one = useQuery({ queryKey: ["case", selected], queryFn: () => api<CaseRow>(`/api/cases/${enc(selected ?? "")}`), enabled: Boolean(selected) });
  const acting = can(me, "operator") || can(me, "risk");
  const invalidate = [["cases"], ["case", selected]];
  const c = one.data;

  return (
    <div className="stack">
      <PageHead
        title="Incident cases"
        sub="From a finding, a refusal, a held effect or an anomaly to a case with an owner, a status, linked evidence and a timeline. Every change is in Tower's signed journal; an exported report's digest is too."
        actions={
          <button
            className="primary"
            disabled={!acting}
            onClick={() =>
              openAction({
                title: "Open a case",
                role: "operator",
                submit: "Open",
                fields: [
                  { name: "title", label: "Title", required: true },
                  { name: "severity", label: "Severity", kind: "select", options: ["critical", "high", "medium", "low"].map((s): [string, string] => [s, s]), initial: "high" },
                  { name: "summary", label: "Summary", kind: "textarea" },
                  { name: "finding", label: "Finding id (optional)", placeholder: "unresolved_effects:tenant/agent" },
                ],
                run: (v) =>
                  api("/api/cases", {
                    body: { title: v.title, severity: v.severity, summary: v.summary ?? "", links: v.finding ? [{ kind: "finding", ref: v.finding }] : [] },
                  }),
                invalidate,
              })
            }
          >
            Open a case
          </button>
        }
      />
      <ErrorNote error={list.error ?? one.error ?? exportError} />
      <div className="seg">
        {STATUSES.map((s) => (
          <button key={s} className={status === s ? "on" : ""} onClick={() => setStatus(s)}>
            {s}
          </button>
        ))}
      </div>
      <div className="grid two">
        <Card title="Cases" flush>
          {(list.data?.cases ?? []).length === 0 ? (
            <Empty title={`No ${status} cases`} />
          ) : (
            <table>
              <tbody>
                {list.data?.cases.map((r) => (
                  <tr key={r.id} className="link" onClick={() => setSelected(r.id)}>
                    <td>
                      <Badge tone={r.severity === "critical" || r.severity === "high" ? "bad" : "warn"}>{r.severity}</Badge>
                    </td>
                    <td>{r.title}</td>
                    <td className="small faint">
                      {r.owner} · {ago(r.opened_at)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Card>
        <Card
          title={c ? c.title : "Select a case"}
          actions={
            c && (
              <span className="row">
                <button onClick={() => exportMarkdown(c.id).catch(setExportError)}>Export report</button>
                <button
                  disabled={!acting || c.status === "closed"}
                  onClick={() =>
                    openAction({
                      title: "Add a note",
                      role: "operator",
                      submit: "Add",
                      fields: [{ name: "text", label: "Note", kind: "textarea", required: true }],
                      run: (v) => api(`/api/cases/${enc(c.id)}/notes`, { body: { text: v.text } }),
                      invalidate,
                    })
                  }
                >
                  Note
                </button>
                <button
                  disabled={!acting || c.status === "closed"}
                  onClick={() =>
                    openAction({
                      title: "Link evidence",
                      role: "operator",
                      submit: "Link",
                      fields: [
                        { name: "kind", label: "Kind", kind: "select", options: ["finding", "run", "audit_entry", "agent", "anomaly"].map((k): [string, string] => [k, k]), initial: "run" },
                        { name: "ref", label: "Reference (run id, audit sequence, finding id…)", required: true },
                        { name: "source", label: "Source runtime" },
                      ],
                      run: (v) => api(`/api/cases/${enc(c.id)}/links`, { body: { kind: v.kind, ref: v.ref, ...(v.source ? { source: v.source } : {}) } }),
                      invalidate,
                    })
                  }
                >
                  Link
                </button>
                <button
                  disabled={!acting || c.status === "closed"}
                  onClick={() =>
                    openAction({
                      title: "Change status",
                      role: "operator",
                      submit: "Change",
                      fields: [
                        { name: "status", label: "Status", kind: "select", options: STATUSES.map((s): [string, string] => [s, s]), initial: c.status },
                        { name: "owner", label: "Owner", initial: c.owner },
                        { name: "reason", label: "Why", kind: "textarea", required: true },
                      ],
                      run: (v) => api(`/api/cases/${enc(c.id)}/status`, { body: { status: v.status, owner: v.owner || undefined, reason: v.reason } }),
                      invalidate,
                    })
                  }
                >
                  Status
                </button>
              </span>
            )
          }
        >
          {!c ? (
            <Empty title="Pick a case on the left" />
          ) : (
            <div className="stack tight">
              <span className="small">
                <Badge>{c.status}</Badge> owner {c.owner}
              </span>
              {c.summary && <p className="small">{c.summary}</p>}
              <strong className="small">Evidence</strong>
              <ul className="small mono">
                {c.links.map((l, i) => (
                  <li key={i}>
                    {l.kind} {l.ref} {l.source ? `@ ${l.source}` : ""}
                  </li>
                ))}
              </ul>
              <strong className="small">Timeline</strong>
              <ul className="small">
                {(c.timeline ?? []).map((e, i) => (
                  <li key={i}>
                    {ago(e.at)} · {e.kind} · {e.by}: {e.text}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </Card>
      </div>
    </div>
  );
}
