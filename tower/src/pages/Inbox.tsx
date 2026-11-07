import { useState } from "react";
import { Link } from "react-router";
import { useMutation, useQuery } from "@tanstack/react-query";
import { api, can, enc, useMe } from "../lib/api";
import { time } from "../lib/format";
import { facets, resolvable, urgency, waited } from "../lib/inbox";
import type { Inbox as InboxData, InboxItem } from "../lib/types";
import { openAction } from "../components/actions";
import { Badge, Card, Empty, ErrorNote, Id, JsonView, Kpi, PageHead } from "../components/ui";

export function useInbox() {
  return useQuery({ queryKey: ["inbox"], queryFn: () => api<InboxData>("/api/inbox"), refetchInterval: 15_000 });
}

const KIND: Record<InboxItem["kind"], string> = {
  policy: "Policy escalation",
  outcome_missed: "Outcome never confirmed",
};

export function Inbox() {
  const me = useMe().data;
  const { data, error } = useInbox();
  const [source, setSource] = useState("");
  const [team, setTeam] = useState("");
  const [shown, setShown] = useState<{ item: InboxItem; evidence: unknown } | null>(null);
  const evidence = useMutation({
    mutationFn: (i: InboxItem) => api<unknown>(`/api/runs/${enc(i.source)}/${enc(i.run_id)}/evidence`),
    onSuccess: (value, item) => setShown({ item, evidence: value }),
  });

  const items = data?.items ?? [];
  const f = facets(items);
  const list = items.filter((i) => (!source || i.source === source) && (!team || (i.team ?? "undeclared") === team));
  const overdue = items.filter((i) => urgency(i.age_seconds) === "bad").length;
  const failing = (data?.sources ?? []).filter((s) => !s.ok);
  const mayResolve = can(me, "risk") || can(me, "operator");

  const resolve = (i: InboxItem, resolution: "handled" | "dismissed") =>
    openAction({
      title: resolution === "handled" ? "Mark escalation handled" : "Dismiss escalation",
      description: (
        <>
          Recorded on <b>{i.source}</b> against run <span className="mono">{i.run_id}</span>, in its audit chain and in Tower's journal. It
          grants nothing: a retried call still goes through policy and approvals.
        </>
      ),
      role: can(me, "risk") ? "risk" : "operator",
      submit: resolution === "handled" ? "Mark handled" : "Dismiss",
      danger: resolution === "dismissed",
      fields: [{ name: "reason", label: "What was done, and why", kind: "textarea", required: true, help: "Up to 900 characters." }],
      run: (v) => api(`/api/inbox/${enc(i.source)}/${enc(i.escalation_id)}/resolve`, { body: { resolution, reason: v.reason } }),
      done: resolution === "handled" ? "Escalation marked handled" : "Escalation dismissed",
      invalidate: [["inbox"]],
    });

  return (
    <div className="stack">
      <PageHead
        title="Inbox"
        sub="Every runtime's hand-offs to a person, oldest first: policy escalations and effects whose outcome never arrived. Resolved by a risk reviewer or operator who neither declared nor owns the agent."
      />
      <ErrorNote error={error} />
      {failing.map((s) => (
        <div key={s.source} className="banner bad">
          <strong>{s.source}</strong>
          <span>Could not be read, so its escalations are missing below: {s.error}</span>
        </div>
      ))}
      {(data?.sources ?? [])
        .filter((s) => s.truncated)
        .map((s) => (
          <div key={`t-${s.source}`} className="banner warn">
            <strong>{s.source}</strong>
            <span>Has more open escalations than one listing holds; the oldest are shown.</span>
          </div>
        ))}
      <div className="grid kpis">
        <Kpi label="Open" value={data?.open ?? "—"} plane="decision" />
        <Kpi label="Waiting over a day" value={overdue} plane="decision" alert={overdue > 0} />
        <Kpi label="Runtimes read" value={data ? `${data.sources.length - failing.length}/${data.sources.length}` : "—"} plane="trust" alert={failing.length > 0} />
      </div>
      {items.length > 0 && (
        <div className="row wrap">
          <select value={source} onChange={(e) => setSource(e.target.value)} aria-label="Runtime">
            <option value="">All runtimes</option>
            {f.sources.map(([s, c]) => (
              <option key={s} value={s}>
                {s} ({c})
              </option>
            ))}
          </select>
          <select value={team} onChange={(e) => setTeam(e.target.value)} aria-label="Team">
            <option value="">All teams</option>
            {f.teams.map(([t, c]) => (
              <option key={t} value={t}>
                {t} ({c})
              </option>
            ))}
          </select>
        </div>
      )}
      {list.length === 0 ? (
        <Card>
          <Empty title={items.length ? "Nothing matches" : "Nothing is waiting on a person"}>
            {items.length ? "Clear the filters to see every open escalation." : "Escalations appear here when policy hands a call to a human."}
          </Empty>
        </Card>
      ) : (
        <Card flush>
          <table>
            <thead>
              <tr>
                <th>Waiting</th>
                <th>Agent</th>
                <th>Owner</th>
                <th>What</th>
                <th>Run</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {list.map((i) => {
                const allowed = mayResolve && resolvable(i, me?.principal_id);
                const why = !i.can_resolve
                  ? "Tower holds no control key for this runtime"
                  : !mayResolve
                    ? "needs the risk or operator role"
                    : !allowed
                      ? "the agent's owner cannot resolve its escalations"
                      : "";
                return (
                  <tr key={`${i.source}/${i.escalation_id}`}>
                    <td className="nowrap">
                      <Badge tone={urgency(i.age_seconds)}>{waited(i.age_seconds)}</Badge>
                      <div className="faint small" title={i.opened_at}>
                        {time(i.opened_at)}
                      </div>
                    </td>
                    <td className="mono small">
                      {i.agent ? <Link to={`/agents/${enc(i.agent)}`}>{i.agent}</Link> : <span className="faint">run outside Tower's window</span>}
                    </td>
                    <td className="small">
                      {i.declared ? (
                        <>
                          {i.owner}
                          <div className="faint">{i.team}</div>
                        </>
                      ) : (
                        <Badge tone="warn">undeclared</Badge>
                      )}
                    </td>
                    <td className="small">
                      {KIND[i.kind] ?? i.kind}
                      {i.reopened > 0 && <Badge tone="warn">recurred {i.reopened}×</Badge>}
                      <div className="mono">{i.capability_id ?? "—"}</div>
                      <div className="faint">{(i.reason_codes ?? []).join(", ")}</div>
                      {i.due_at && <div className="faint">outcome was due {time(i.due_at)}</div>}
                    </td>
                    <td className="small">
                      <Id value={i.run_id} />
                      <div className="faint">{i.source}</div>
                    </td>
                    <td className="nowrap">
                      <button className="small" disabled={evidence.isPending} onClick={() => evidence.mutate(i)} title="Fetched from the runtime; the access is journalled">
                        Evidence
                      </button>{" "}
                      <button className="small primary" disabled={!allowed} title={why} onClick={() => resolve(i, "handled")}>
                        Handled
                      </button>{" "}
                      <button className="small" disabled={!allowed} title={why} onClick={() => resolve(i, "dismissed")}>
                        Dismiss
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </Card>
      )}
      <ErrorNote error={evidence.error} />
      {shown && (
        <Card
          title={`Evidence for ${shown.item.run_id}`}
          actions={
            <button className="small" onClick={() => setShown(null)}>
              Close
            </button>
          }
        >
          <JsonView value={shown.evidence} maxHeight={420} />
        </Card>
      )}
    </div>
  );
}
