// An agent's lifecycle: its stage, the change waiting for a decision, and past changes.
// A change is requested by an owner or risk reviewer and decided by a risk reviewer who
// is not the requester (nor, to approve, the agent's owner). Suspending or retiring
// revokes the agent on every runtime Tower holds a control key for.

import { useQuery } from "@tanstack/react-query";
import { api, can, enc, useMe } from "../lib/api";
import { ago } from "../lib/format";
import { lifecycleState, mayDecide, nextStages, stops, type LifecycleRequest } from "../lib/lifecycle";
import { openAction } from "./actions";
import { Badge, Card, ErrorNote } from "./ui";

export function Lifecycle({ agentKey, stage, owner, declaredBy }: { agentKey: string; stage: string; owner: string; declaredBy: string }) {
  const { data: me } = useMe();
  const { data, error } = useQuery({
    queryKey: ["lifecycle", agentKey],
    queryFn: () => api<{ requests: LifecycleRequest[] }>(`/api/lifecycle-requests?agent=${enc(agentKey)}`),
  });
  const requests = data?.requests ?? [];
  const waiting = requests.find((r) => r.status === "requested");
  const invalidate = [["lifecycle", agentKey], ["agent", agentKey], ["agents"], ["posture"], ["inventory"]];
  const next = nextStages(stage);

  const ask = () =>
    openAction({
      title: "Request a lifecycle change",
      description: "A risk reviewer other than you, and not the agent's owner, approves it. Suspending or retiring revokes the agent on every runtime Tower controls; resuming restores only what the suspension revoked.",
      role: "owner",
      submit: "Request",
      fields: [
        { name: "to", label: "Move to", kind: "select", options: next.map((s): [string, string] => [s, stops(s) ? `${s} (stops the agent)` : s]), initial: next[0] },
        { name: "reason", label: "Why", kind: "textarea", required: true, placeholder: "At least 10 characters; signed into Tower's journal" },
      ],
      run: (v) => api(`/api/agents/${enc(agentKey)}/lifecycle`, { body: { to: v.to, reason: v.reason } }),
      invalidate,
    });

  const decide = (r: LifecycleRequest, verb: "approve" | "reject" | "cancel") => {
    const label = verb.charAt(0).toUpperCase() + verb.slice(1);
    openAction({
      title: `${label} ${r.from} → ${r.to}`,
      description: verb === "approve" && stops(r.to) ? "Approving revokes the agent on every runtime Tower holds a control key for." : r.reason,
      role: verb === "cancel" ? "owner" : "risk",
      danger: verb === "approve" && stops(r.to),
      confirm: verb === "approve" && stops(r.to) ? agentKey : undefined,
      submit: label,
      run: () => api(`/api/lifecycle-requests/${enc(r.id)}/${verb}`, { method: "POST" }),
      invalidate,
    });
  };

  return (
    <Card
      title="Lifecycle"
      actions={
        next.length > 0 && !waiting ? (
          <button disabled={!can(me, "owner")} title={can(me, "owner") ? "" : "needs the owner or risk role"} onClick={ask}>
            Request change
          </button>
        ) : undefined
      }
    >
      <ErrorNote error={error} />
      <div className="row wrap">
        <Badge tone={stops(stage) ? "bad" : stage === "production" ? "primary" : ""}>{stage}</Badge>
        <span className="small muted">state: {lifecycleState(stage)}</span>
        {next.length === 0 && <span className="small faint">retired agents stay retired</span>}
      </div>
      {waiting && (
        <div className="banner warn">
          {waiting.requested_by} asks to move it from {waiting.from} to <b>{waiting.to}</b> ({ago(waiting.requested_at)}): {waiting.reason}
          <span className="row" style={{ marginTop: 8 }}>
            <button className="primary" disabled={!mayDecide(waiting, me, owner, declaredBy, true)} onClick={() => decide(waiting, "approve")}>
              Approve
            </button>
            <button disabled={!mayDecide(waiting, me, owner, declaredBy, false)} onClick={() => decide(waiting, "reject")}>
              Reject
            </button>
            {waiting.requested_by === me?.principal_id && <button onClick={() => decide(waiting, "cancel")}>Withdraw</button>}
          </span>
        </div>
      )}
      {requests.filter((r) => r !== waiting).length > 0 && (
        <ul className="small">
          {requests
            .filter((r) => r !== waiting)
            .slice(0, 10)
            .map((r) => (
              <li key={r.id}>
                {r.from} → {r.to}: <Badge tone={r.status === "applied" ? "ok" : r.status === "failed" ? "bad" : ""}>{r.status}</Badge> requested by {r.requested_by}
                {r.decided_by ? `, decided by ${r.decided_by}` : ""} · {ago(r.requested_at)}
                {r.results?.some((x) => !x.ok) && <Badge tone="warn">not applied on {r.results.filter((x) => !x.ok).map((x) => x.source ?? "any runtime").join(", ")}</Badge>}
              </li>
            ))}
        </ul>
      )}
    </Card>
  );
}
