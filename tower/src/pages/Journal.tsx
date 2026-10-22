import { useQuery } from "@tanstack/react-query";
import { api } from "../lib/api";
import { ago } from "../lib/format";
import { Card, Digest, Empty, ErrorNote, JsonView, PageHead } from "../components/ui";

interface Entry {
  sequence: number;
  kind: string;
  emitted_at: string;
  payload: Record<string, unknown>;
  record_hash: string;
}

function summary(e: Entry): string {
  const p = e.payload;
  const by = (p.by ?? (p.review as Record<string, unknown> | undefined)?.reviewed_by ?? (p.declaration as Record<string, unknown> | undefined)?.declared_by ?? (p.guardrail as Record<string, unknown> | undefined)?.created_by ?? (p.waiver as Record<string, unknown> | undefined)?.requested_by) as string | undefined;
  const subject = (p.agent ?? p.id ?? p.target ?? p.job ?? "") as string;
  return [by, e.kind.replace(/_/g, " "), subject].filter(Boolean).join(" · ");
}

export function Journal() {
  const { data, error } = useQuery({ queryKey: ["journal"], queryFn: () => api<{ entries: Entry[]; head: number }>("/api/journal?limit=200"), refetchInterval: 15_000 });
  const entries = [...(data?.entries ?? [])].reverse();
  return (
    <div className="stack">
      <PageHead
        title="Journal"
        sub="Every governance decision made in Tower (declarations, reviews, guardrails, waivers, fleet kill-switch use, evidence access and every use of AI) in a signed hash chain. Export it and verify it with ctx audit-verify against /api/journal/keys."
      />
      <ErrorNote error={error} />
      <Card flush>
        {entries.length === 0 ? (
          <Empty title="No governance actions yet" />
        ) : (
          <table>
            <tbody>
              {entries.map((e) => (
                <tr key={e.sequence}>
                  <td className="mono small">#{e.sequence}</td>
                  <td className="small muted nowrap">{ago(e.emitted_at)}</td>
                  <td>
                    <div>{summary(e)}</div>
                    <details>
                      <summary className="small faint">payload</summary>
                      <JsonView value={e.payload} />
                    </details>
                  </td>
                  <td>
                    <Digest value={e.record_hash} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
    </div>
  );
}
