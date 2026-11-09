import { Link } from "react-router";
import { useQuery } from "@tanstack/react-query";
import { api, can, enc, useMe } from "../lib/api";
import { ago, n, time } from "../lib/format";
import type { RestoreRequest, RevocationsView } from "../lib/types";
import { actor, approveBlocked, byTarget, pendingFor, provenanceLabel, type RevokedTarget } from "../lib/revocations";
import { openAction } from "../components/actions";
import { Badge, Card, Empty, ErrorNote, Kpi, PageHead } from "../components/ui";

const KINDS: [string, string][] = [
  ["agent", "Agent"],
  ["capability", "Capability"],
  ["adapter", "Adapter"],
  ["pack", "Context Pack"],
  ["principal", "Principal (or any agent on a delegation chain)"],
  ["user", "User (every run acting for them)"],
  ["delegation", "Delegation (one chain, by its digest)"],
];

const INVALIDATE = [["revocations"], ["restore-requests"], ["sources"], ["posture"]];

const requestTone = (s: RestoreRequest["status"]) =>
  s === "restored" ? "ok" : s === "requested" || s === "partially_restored" ? "warn" : s === "failed" ? "bad" : "";

export function Revocations() {
  const me = useMe().data;
  const view = useQuery({ queryKey: ["revocations"], queryFn: () => api<RevocationsView>("/api/revocations"), refetchInterval: 15_000 });
  const reqs = useQuery({
    queryKey: ["restore-requests"],
    queryFn: () => api<{ requests: RestoreRequest[] }>("/api/revocations/restore-requests"),
    refetchInterval: 15_000,
  });
  const data = view.data;
  const requests = reqs.data?.requests ?? [];
  const targets = byTarget(data?.revocations ?? []);
  const twoPerson = data?.two_person_restore ?? me?.two_person_restore ?? true;
  const stopped = new Set(targets.flatMap((t) => t.affected)).size;
  const unread = (data?.sources ?? []).filter((s) => s.live !== "read");

  const revoke = () =>
    openAction({
      title: "Fleet kill switch",
      description: "Revokes the target on every runtime Tower holds a control key for. Each runtime refuses it at the next admission and dispatch, and records the change in its own audit chain.",
      role: "operator",
      danger: true,
      submit: "Revoke everywhere",
      fields: [
        { name: "kind", label: "Kind", kind: "select", options: KINDS, initial: "capability" },
        { name: "target", label: "Target (exact id)", required: true },
        { name: "reason", label: "Reason", kind: "textarea", required: true, placeholder: "INC-123: what is going wrong" },
      ],
      run: (v) => api("/api/fleet/revoke", { body: { kind: v.kind, target: v.target, reason: v.reason } }),
      invalidate: INVALIDATE,
    });

  const restore = (t: RevokedTarget) => {
    const sources = [...new Set(t.rows.map((r) => r.source))];
    openAction({
      title: twoPerson ? "Request a restore" : "Restore across the fleet",
      description: twoPerson ? (
        <>
          Restoring re-grants authority, so it takes two operators. Your request waits a day for <b>another operator</b> to approve it; only the approval acts on the runtimes ({sources.join(", ")}).
        </>
      ) : (
        <>Restores {t.kind} {t.target} on {sources.join(", ")}.</>
      ),
      role: "operator",
      submit: twoPerson ? "Request restore" : "Restore",
      fields: [{ name: "reason", label: "Why is it safe to restore?", kind: "textarea", required: true, placeholder: "INC-123 resolved: fix deployed and verified" }],
      run: (v) =>
        api(twoPerson ? "/api/revocations/restore-requests" : "/api/fleet/restore", {
          body: { kind: t.kind, target: t.target, reason: v.reason, sources },
        }),
      done: twoPerson ? "Restore requested: another operator approves it" : "Restored",
      invalidate: INVALIDATE,
    });
  };

  const approve = (r: RestoreRequest) =>
    openAction({
      title: "Approve restore",
      description: (
        <>
          Restores {r.kind} <span className="mono">{r.target}</span> on {r.sources?.join(", ") ?? "every runtime Tower controls"}, as requested by {r.requested_by}: “{r.reason}”. Recorded in Tower's journal before any runtime is called.
        </>
      ),
      role: "operator",
      confirm: r.target,
      submit: "Approve and restore",
      run: () => api(`/api/revocations/restore-requests/${enc(r.id)}/approve`, { method: "POST" }),
      done: "Restore approved",
      invalidate: INVALIDATE,
    });

  const cancel = (r: RestoreRequest) =>
    openAction({
      title: "Withdraw restore request",
      description: `The ${r.kind} ${r.target} stays revoked.`,
      role: "operator",
      submit: "Withdraw",
      run: () => api(`/api/revocations/restore-requests/${enc(r.id)}/cancel`, { method: "POST" }),
      invalidate: INVALIDATE,
    });

  return (
    <div className="stack">
      <PageHead
        title="Revocations"
        sub="What is switched off right now on every runtime: who did it, when, why, and which agents it stops. Each runtime's live list is checked against the audit chain Tower verified."
        actions={
          <button className="danger" disabled={!can(me, "operator")} onClick={revoke}>
            Kill switch…
          </button>
        }
      />
      <ErrorNote error={view.error ?? reqs.error} />
      <div className="grid kpis">
        <Kpi label="Targets revoked" value={n(targets.length)} plane="action" />
        <Kpi label="Agents stopped" value={n(stopped)} plane="action" />
        <Kpi label="Restores awaiting approval" value={n(data?.pending_requests)} plane="decision" alert={(data?.pending_requests ?? 0) > 0} />
        <Kpi label="Runtime and chain disagree" value={n(data?.mismatches)} plane="trust" alert={(data?.mismatches ?? 0) > 0} />
      </div>
      {(data?.mismatches ?? 0) > 0 && (
        <div className="banner warn">
          A runtime enforces a revocation its verified chain does not show, or the other way round. Briefly after a change this is collector lag; if it persists, check the runtime's store and Tower's chain state on Runtimes.
        </div>
      )}
      {unread.length > 0 && (
        <div className="banner small">
          Shown from the audit chain only for{" "}
          {unread.map((s, i) => (
            <span key={s.id}>
              {i > 0 && ", "}
              <span className="mono">{s.id}</span> ({s.live === "no_control_key" ? "Tower holds no control key" : s.live === "paused" ? "paused" : s.error ?? "unreachable"})
            </span>
          ))}
          .
        </div>
      )}
      {twoPerson && <div className="banner small">Revoking is one operator's action. Restoring takes two: one requests, another approves.</div>}

      {targets.length === 0 ? (
        <Card>
          <Empty title="Nothing is revoked">Every agent, capability, pack, adapter and principal is in service on every runtime Tower reads.</Empty>
        </Card>
      ) : (
        <Card flush>
          <table>
            <thead>
              <tr>
                <th>Target</th>
                <th>Why, who, when</th>
                <th>Where</th>
                <th>Stops</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {targets.map((t) => {
                const pending = pendingFor(requests, t.kind, t.target);
                const blocked = pending ? approveBlocked(me, pending, can) : null;
                return (
                  <tr key={`${t.kind}:${t.target}`}>
                    <td>
                      <Badge tone="bad">{t.kind}</Badge> <span className="mono">{t.target}</span>
                    </td>
                    <td className="small">
                      {t.latest.reason}
                      <div className="faint">
                        {actor(t.latest)}
                        {t.latest.at && <> · {ago(t.latest.at)}</>}
                        {t.latest.sequence !== null && <> · entry #{t.latest.sequence}</>}
                      </div>
                    </td>
                    <td className="small">
                      <div className="stack tight">
                        {t.rows.map((r) => (
                          <span key={r.source} className="row wrap">
                            <span className="mono">{r.source}</span>
                            <Badge tone={provenanceLabel[r.provenance][1]}>{provenanceLabel[r.provenance][0]}</Badge>
                          </span>
                        ))}
                      </div>
                    </td>
                    <td className="small">
                      {t.affected.length === 0 ? (
                        <span className="faint">no agent seen</span>
                      ) : (
                        <div className="stack tight">
                          {t.affected.slice(0, 5).map((a) => (
                            <Link key={a} className="mono" to={`/agents/${enc(a)}`}>
                              {a}
                            </Link>
                          ))}
                          {t.affected.length > 5 && <span className="faint">and {t.affected.length - 5} more</span>}
                        </div>
                      )}
                      {t.refusals > 0 && <div className="faint">{n(t.refusals)} refused</div>}
                    </td>
                    <td className="nowrap">
                      {pending ? (
                        <div className="stack tight">
                          <span className="small faint">requested by {pending.requested_by}</span>
                          <button className="small primary" disabled={blocked !== null} title={blocked ?? ""} onClick={() => approve(pending)}>
                            Approve restore
                          </button>
                        </div>
                      ) : (
                        <button className="small" disabled={!can(me, "operator")} onClick={() => restore(t)}>
                          {twoPerson ? "Request restore…" : "Restore…"}
                        </button>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </Card>
      )}

      <Card title={<h2>Restore requests</h2>} flush>
        {requests.length === 0 ? (
          <Empty title="No restore requests">An operator requests a restore from a revoked target above.</Empty>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Target</th>
                <th>Reason</th>
                <th>Status</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {requests.map((r) => {
                const blocked = approveBlocked(me, r, can);
                return (
                  <tr key={r.id}>
                    <td>
                      <Badge>{r.kind}</Badge> <span className="mono">{r.target}</span>
                      <div className="faint small">{r.sources?.join(", ") ?? "every controlled runtime"}</div>
                    </td>
                    <td className="small">
                      {r.reason}
                      <div className="faint">
                        {r.requested_by} {ago(r.requested_at)}
                        {r.status === "requested" && <>, expires {time(r.expires_at)}</>}
                      </div>
                    </td>
                    <td className="small">
                      <Badge tone={requestTone(r.status)}>{r.status.replace("_", " ")}</Badge>
                      {r.approved_by && <div className="faint">approved by {r.approved_by}</div>}
                      {r.results
                        ?.filter((x) => !x.ok)
                        .map((x, i) => (
                          <div key={i} className="faint">
                            {x.source ?? "—"}: {x.error}
                          </div>
                        ))}
                    </td>
                    <td className="nowrap">
                      {r.status === "requested" && (
                        <>
                          <button className="small primary" disabled={blocked !== null} title={blocked ?? ""} onClick={() => approve(r)}>
                            Approve
                          </button>{" "}
                          {r.requested_by === me?.principal_id && (
                            <button className="small" onClick={() => cancel(r)}>
                              Withdraw
                            </button>
                          )}
                        </>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </Card>
    </div>
  );
}
