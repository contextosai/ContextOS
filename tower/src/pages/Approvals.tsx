import { useQuery } from "@tanstack/react-query";
import { api } from "../lib/api";
import { n, pct } from "../lib/format";
import { type ApprovalRow, type ApprovalsReport, bucketLabels, medianBucket, rubberStampShare } from "../lib/approvals";
import { Card, Empty, ErrorNote, Kpi, PageHead } from "../components/ui";

export function Approvals() {
  const { data, error } = useQuery({
    queryKey: ["approvals"],
    queryFn: () => api<ApprovalsReport>("/api/approvals"),
    refetchInterval: 30_000,
  });
  const labels = bucketLabels(data?.buckets_seconds ?? []);
  const sum = (key: keyof ApprovalRow) =>
    (data?.capabilities ?? []).reduce((a, r) => a + (typeof r[key] === "number" ? (r[key] as number) : 0), 0);
  const total: ApprovalRow = {
    requested: sum("requested"), redeemed: sum("redeemed"), untimed: sum("untimed"),
    refused_too_fast: sum("refused_too_fast"), refused_step_up: sum("refused_step_up"),
    timed_out: sum("timed_out"),
    within_ten_seconds: sum("within_ten_seconds"),
    decision_seconds: labels.map((_, i) => (data?.capabilities ?? []).reduce((a, r) => a + (r.decision_seconds[i] ?? 0), 0)),
  };
  const stamped = rubberStampShare(total);

  return (
    <div className="stack">
      <PageHead
        title="Approvals"
        sub="How approvals are decided, from the runtimes' approval events: requests, redemptions and their decision times (from the gateway's own request time), decisions refused as faster than the review floor or without a required step-up, and requests nobody decided before the approval timeout. Approvals decided within ten seconds are worth a look: oversight people click through looks the same as oversight that works."
      />
      {error ? <ErrorNote error={error} /> : null}
      <div className="grid kpis">
        <Kpi label="Requested" value={n(total.requested)} hint={`${n(total.timed_out)} timed out undecided`} plane="decision" alert={total.timed_out > 0} />
        <Kpi label="Redeemed" value={n(total.redeemed)} hint={`${pct(total.requested ? total.redeemed / total.requested : undefined)} of requested`} plane="decision" />
        <Kpi label="Within 10 seconds" value={pct(stamped)} hint="of timed redemptions" plane="decision" alert={(stamped ?? 0) > 0.5} />
        <Kpi label="Refused" value={n(total.refused_too_fast + total.refused_step_up)} hint={`${n(total.refused_too_fast)} too fast · ${n(total.refused_step_up)} without step-up`} plane="decision" />
      </div>
      <Table title="By capability" rows={data?.capabilities ?? []} name={(r) => r.capability_id ?? ""} labels={labels} requests />
      <Table title="By approver" rows={data?.approvers ?? []} name={(r) => r.approver ?? ""} labels={labels} />
    </div>
  );
}

function Table({ title, rows, name, labels, requests }: {
  title: string; rows: ApprovalRow[]; name: (r: ApprovalRow) => string; labels: string[]; requests?: boolean;
}) {
  return (
    <Card title={title} flush>
      {rows.length === 0 ? (
        <Empty title="No approvals yet">Approval events appear once a gateway asks for an approval.</Empty>
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>{requests ? "Capability" : "Approver"}</th>
                {requests && <th className="num">Requested</th>}
                <th className="num">Redeemed</th>
                <th className="num">Median decision</th>
                <th className="num">Within 10s</th>
                {labels.map((l) => <th key={l} className="num small">{l}</th>)}
                {requests && <th className="num">Too fast</th>}
                {requests && <th className="num">No step-up</th>}
                {requests && <th className="num">Timed out</th>}
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr key={name(r)}>
                  <td className="mono">{name(r)}</td>
                  {requests && <td className="num">{n(r.requested)}</td>}
                  <td className="num">{n(r.redeemed)}</td>
                  <td className="num">{medianBucket(r, labels) ?? "—"}</td>
                  <td className="num">{pct(rubberStampShare(r))}</td>
                  {r.decision_seconds.map((c, i) => <td key={i} className="num small">{n(c)}</td>)}
                  {requests && <td className="num">{n(r.refused_too_fast)}</td>}
                  {requests && <td className="num">{n(r.refused_step_up)}</td>}
                  {requests && <td className="num">{n(r.timed_out)}</td>}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  );
}
