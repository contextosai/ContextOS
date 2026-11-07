import { Link } from "react-router";
import { useQuery } from "@tanstack/react-query";
import { api, ApiError } from "../lib/api";
import { n } from "../lib/format";
import { metering, money, tokens } from "../lib/spend";
import type { AgentSpendReport } from "../lib/types";
import { Badge, Card, ErrorNote, HBars, Kv, Spark, type Tone } from "./ui";

const METERING_TONE: Record<ReturnType<typeof metering>, Tone> = { measured: "ok", mixed: "info", "self-reported": "warn", none: "" };

export function MeteringBadge({ usage }: { usage: Parameters<typeof metering>[0] }) {
  const m = metering(usage);
  return m === "none" ? null : (
    <Badge tone={METERING_TONE[m]} title="Measured: settled by a metering gateway from the provider's usage. Self-reported: charged as reserved.">
      {m}
    </Badge>
  );
}

/** One agent's model spend over the last 7 days, on its page. */
export function AgentSpend({ agentKey }: { agentKey: string }) {
  const { data, error } = useQuery({
    queryKey: ["agent-spend", agentKey],
    queryFn: () => api<AgentSpendReport>(`/api/agents/${encodeURIComponent(agentKey)}/spend?hours=168`),
    refetchInterval: 30_000,
  });
  // An agent only declared, never seen running, has no spend to show.
  if (error) return error instanceof ApiError && error.status === 404 ? null : <ErrorNote error={error} />;
  if (!data || (data.usage.calls === 0 && data.usage.refused === 0 && data.since_start.calls === 0)) return null;
  const u = data.usage;
  return (
    <div className="grid three">
      <Card title="Model spend, last 7 days" actions={<Link to="/spend" className="small">all spend</Link>}>
        <Spark values={data.series.map((p) => p.cost_units)} plane="action" />
        <Kv
          rows={[
            ["Spend", <span key="s">{money(u.cost_units)} <MeteringBadge usage={u} /></span>],
            ["Tokens", `${tokens(u.tokens)} (${tokens(u.verified_tokens)} measured)`],
            ["Model calls", n(u.calls)],
            ["Uncovered by budget", u.uncovered_tokens || u.uncovered_cost_units ? `${tokens(u.uncovered_tokens)} tokens, ${money(u.uncovered_cost_units)}` : "none"],
            ["Awaiting settlement", n(u.unsettled_claims)],
          ]}
        />
      </Card>
      <Card title="By model">
        <HBars rows={data.models.map((m) => [m.key, m.usage.tokens])} plane="intelligence" empty="No model calls settled." />
      </Card>
      <Card title="Budget refusals">
        <HBars rows={Object.entries(data.refusals).sort((x, y) => y[1] - x[1])} plane="decision" empty="None refused." />
      </Card>
    </div>
  );
}
