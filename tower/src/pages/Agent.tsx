import { useState } from "react";
import { Link, useParams } from "react-router";
import { useMutation, useQuery } from "@tanstack/react-query";
import { api, can, enc, useMe } from "../lib/api";
import { ago, n, time } from "../lib/format";
import type { AgentDetail, Capability, Finding, RunSummary } from "../lib/types";
import { openAction } from "../components/actions";
import { Badge, Card, Empty, ErrorNote, HBars, JsonView, Kv, PageHead, ProfileBadge, SeverityBadge, Spark, Tabs } from "../components/ui";

type Tab = "authority" | "findings" | "activity" | "review";

const RISKY: Record<string, string[]> = {
  effect: ["external_state", "physical_world"],
  reversibility: ["irreversible", "compensatable"],
  data_scope: ["CONFIDENTIAL", "RESTRICTED"],
  interaction: ["browser", "computer"],
};

function Dim({ name, value }: { name: string; value: string }) {
  const risky = RISKY[name]?.includes(value);
  const severe = (name === "effect" && value === "physical_world") || (name === "reversibility" && value === "irreversible") || value === "RESTRICTED";
  return <span className={`badge ${severe ? "bad" : risky ? "warn" : ""}`}>{value.replace(/_/g, " ")}</span>;
}

export function Agent() {
  const { key = "" } = useParams();
  const me = useMe().data;
  const [tab, setTab] = useState<Tab>("authority");
  const { data: d, error } = useQuery({ queryKey: ["agent", key], queryFn: () => api<AgentDetail>(`/api/agents/${enc(key)}`), refetchInterval: 15_000 });
  if (!d) return <ErrorNote error={error} />;
  const decl = d.facts.declaration as Record<string, string | string[]> | null;
  const open = d.findings.filter((f) => !f.waiver);

  return (
    <div className="stack" style={{ gap: 16 }}>
      <PageHead
        crumbs={<Link to="/agents">Agents</Link>}
        title={
          <span className="row wrap">
            <span className="mono">{key}</span>
            <Badge tone={d.row.lifecycle === "production" ? "primary" : d.row.lifecycle === "undeclared" ? "warn" : ""}>{d.row.lifecycle}</Badge>
            {d.row.reviewed ? <Badge tone="ok">reviewed</Badge> : <Badge tone="warn">not reviewed</Badge>}
          </span>
        }
        sub={decl ? `${decl.purpose} — owned by ${decl.owner} (${decl.team})` : "Nobody has declared this agent: no owner, purpose or lifecycle."}
        actions={<AgentActions d={d} agentKey={key} />}
      />

      <div className="grid three">
        <Card>
          <div className="stack tight">
            <span className="small muted">Controls its authority requires</span>
            <ProfileBadge profile={d.requirement.profile} />
            <span className="small">{d.requirement.reasons.join("; ")}</span>
          </div>
        </Card>
        <Card>
          <Kv
            rows={[
              ["Open findings", open.length ? `${open.length} (${open.filter((f) => f.severity === "critical").length} critical)` : "none"],
              ["Runs", `${n(d.row.runs)}${d.row.runs ? `, last ${ago(d.row.last_seen)}` : ""}`],
              ["Runtimes", d.row.sources.join(", ") || "—"],
            ]}
          />
        </Card>
        <Card>
          <Kv
            rows={[
              ["Models", d.facts.agent.models.join(", ") || <span className="faint">not pinned</span>],
              ["Evaluators", d.facts.agent.evaluators.join(", ") || <span className="faint">none</span>],
              ["Packs", d.facts.agent.packs.join(", ") || "—"],
            ]}
          />
        </Card>
      </div>

      <Tabs<Tab>
        value={tab}
        onChange={setTab}
        tabs={[
          ["authority", `What it can do (${d.graph.length})`],
          ["findings", `Findings (${open.length})`],
          ["activity", "Activity"],
          ["review", "Review"],
        ]}
      />
      {tab === "authority" && <Authority d={d} />}
      {tab === "findings" && <Findings findings={d.findings} agentKey={key} />}
      {tab === "activity" && <Activity d={d} />}
      {tab === "review" && <Review d={d} agentKey={key} canAssess={Boolean(me?.intelligence) && (can(me, "owner") || can(me, "risk"))} />}
    </div>
  );
}

function AgentActions({ d, agentKey }: { d: AgentDetail; agentKey: string }) {
  const me = useMe().data;
  const decl = d.facts.declaration as Record<string, string | string[]> | null;
  const lists = (v: unknown) => (Array.isArray(v) ? v.join(", ") : "");
  return (
    <>
      <button
        disabled={!can(me, "owner")}
        title={can(me, "owner") ? "" : "needs the owner role"}
        onClick={() =>
          openAction({
            title: decl ? "Update declaration" : "Declare this agent",
            description: "What the owner states about the agent. Tower uses it for accountability and review; it never replaces what the agent can actually do.",
            role: "owner",
            submit: "Save declaration",
            wide: true,
            fields: [
              { name: "owner", label: "Accountable owner", required: true, initial: String(decl?.owner ?? me?.principal_id ?? "") },
              { name: "team", label: "Team", required: true, initial: String(decl?.team ?? me?.teams[0] ?? "") },
              { name: "business_unit", label: "Business unit", initial: String(decl?.business_unit ?? "") },
              { name: "purpose", label: "Purpose", kind: "textarea", required: true, initial: String(decl?.purpose ?? ""), placeholder: "What it does, for whom, and what it must never do" },
              { name: "users_served", label: "Who it serves", kind: "select", options: [["internal", "Internal staff"], ["customers", "Customers"], ["public", "The public"]], initial: String(decl?.users_served ?? "internal") },
              { name: "lifecycle", label: "Lifecycle stage", kind: "select", options: ["proposed", "pilot", "production", "deprecated", "retired"].map((l) => [l, l]), initial: String(decl?.lifecycle ?? "proposed") },
              { name: "data_categories", label: "Data categories (comma-separated)", initial: lists(decl?.data_categories), placeholder: "orders, payments, customer contact" },
              { name: "regulatory_contexts", label: "Regulatory contexts (comma-separated)", initial: lists(decl?.regulatory_contexts), help: "finance, clinical, legal, employment, critical_infrastructure, eu_ai_act_high_risk raise the required profile" },
            ],
            run: (v) => {
              const split = (x: unknown) => String(x ?? "").split(",").map((s) => s.trim()).filter(Boolean);
              return api(`/api/agents/${enc(agentKey)}/declaration`, {
                method: "PUT",
                body: { ...v, business_unit: v.business_unit || null, data_categories: split(v.data_categories), regulatory_contexts: split(v.regulatory_contexts) },
              });
            },
            invalidate: [["agent", agentKey], ["agents"], ["posture"]],
          })
        }
      >
        {decl ? "Edit declaration" : "Declare"}
      </button>
      <button
        className="primary"
        disabled={!can(me, "risk")}
        title={can(me, "risk") ? "" : "needs the risk role"}
        onClick={() =>
          openAction({
            title: "Record risk review",
            description: (
              <>
                Approves (or not) the agent's <strong>current</strong> authority: {d.graph.length} capabilities, requiring {d.requirement.profile}. Any capability added later shows as drift until reviewed again. The agent's owner cannot review it.
              </>
            ),
            role: "risk",
            submit: "Record review",
            wide: true,
            fields: [
              { name: "decision", label: "Decision", kind: "select", options: [["approved", "Approved"], ["changes_requested", "Changes requested"], ["rejected", "Rejected"]], initial: "approved" },
              { name: "notes", label: "Reasoning", kind: "textarea", required: true },
              { name: "conditions", label: "Conditions (one per line)", kind: "textarea" },
              { name: "valid_days", label: "Valid for (days)", kind: "number", initial: 180, min: 1, max: 730 },
            ],
            run: (v) =>
              api(`/api/agents/${enc(agentKey)}/review`, {
                body: { decision: v.decision, notes: v.notes, conditions: String(v.conditions ?? "").split("\n").map((s) => s.trim()).filter(Boolean), valid_days: v.valid_days },
              }),
            invalidate: [["agent", agentKey], ["agents"], ["posture"]],
          })
        }
      >
        Review
      </button>
      <button
        className="danger"
        disabled={!can(me, "operator") || !d.can_revoke}
        title={!d.can_revoke ? "No runtime has a control key configured" : can(me, "operator") ? "" : "needs the operator role"}
        onClick={() =>
          openAction({
            title: "Stop this agent everywhere",
            description: `Revokes agent ${d.row.agent_id} on every runtime Tower controls. The next admission and dispatch are refused; effects already applied stand. Restorable from Runtimes.`,
            role: "operator",
            danger: true,
            confirm: d.row.agent_id,
            submit: "Revoke everywhere",
            fields: [{ name: "reason", label: "Reason (recorded on every runtime)", kind: "textarea", required: true, placeholder: "INC-…" }],
            run: (v) => api("/api/fleet/revoke", { body: { kind: "agent", target: d.row.agent_id, reason: v.reason } }),
            invalidate: [["sources"], ["posture"]],
          })
        }
      >
        Stop everywhere
      </button>
    </>
  );
}

function Authority({ d }: { d: AgentDetail }) {
  const missing = Object.entries(d.facts.controls.missing);
  const sorted = [...d.graph].sort((a, b) => Number(b.effect !== "none") - Number(a.effect !== "none") || a.id.localeCompare(b.id));
  return (
    <div className="stack">
      {d.facts.drift.length > 0 && (
        <div className="banner warn">
          <strong>Drift:</strong> {d.facts.drift.join(", ")} added since the last approved review.
        </div>
      )}
      <Card title="Capabilities and their risk" actions={<span className="small faint">each dimension is assessed separately; risk is never collapsed into a score</span>} flush>
        {sorted.length === 0 ? (
          <Empty title="No capabilities known">Tower learns them from the packs the agent runs under.</Empty>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Capability</th>
                  <th>Effect</th>
                  <th>Reversibility</th>
                  <th>Authority</th>
                  <th>Data</th>
                  <th>Interaction</th>
                  <th>Seen</th>
                </tr>
              </thead>
              <tbody>
                {sorted.map((c: Capability) => (
                  <tr key={c.id}>
                    <td className="mono">
                      {c.id}
                      {c.packs.length === 0 && (
                        <Badge tone="bad" title="Not pinned in any known pack: risk unknown, treated as most consequential">
                          unknown risk
                        </Badge>
                      )}
                    </td>
                    <td>
                      <Dim name="effect" value={c.effect} />
                    </td>
                    <td>
                      <Dim name="reversibility" value={c.reversibility} />
                    </td>
                    <td>
                      <Dim name="authority" value={c.authority} />
                    </td>
                    <td>
                      <Dim name="data_scope" value={c.data_scope} />
                    </td>
                    <td>
                      <Dim name="interaction" value={c.interaction} />
                    </td>
                    <td className="small">{c.used ? <Badge tone="info">used</Badge> : c.surfaced ? <Badge>offered</Badge> : <span className="faint">pinned only</span>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
      <div className="grid two">
        <Card title={`Required controls (${d.requirement.controls.length})`}>
          <div className="stack tight">
            <div className="row wrap">
              {d.requirement.controls.map((c) => (
                <span key={c} className={`chip ${missing.some(([, m]) => m.includes(c)) ? "missing" : ""}`}>
                  {c}
                </span>
              ))}
            </div>
            <p className="small faint">From the standard profile registry: {d.requirement.profile}, plus controls for its features ({d.requirement.features.join(", ") || "none"}).</p>
          </div>
        </Card>
        <Card title="Where controls are missing">
          {missing.length === 0 ? (
            <p className="small muted">Every runtime it runs on declares the controls it needs.</p>
          ) : (
            <div className="stack tight">
              {missing.map(([src, list]) => (
                <div key={src}>
                  <div className="mono small">{src}</div>
                  <div className="row wrap">
                    {list.map((c) => (
                      <span key={c} className="chip missing">
                        {c}
                      </span>
                    ))}
                  </div>
                </div>
              ))}
              <p className="small faint">Admitted under: {d.facts.controls.admitted_profiles.join(", ") || "—"}.</p>
            </div>
          )}
        </Card>
      </div>
    </div>
  );
}

export function Findings({ findings, agentKey }: { findings: Finding[]; agentKey?: string }) {
  const me = useMe().data;
  if (!findings.length) return <Empty title="No findings">This agent meets the governance model and every active guardrail.</Empty>;
  return (
    <div className="stack">
      {findings.map((f) => (
        <Card
          key={f.id}
          title={
            <span className="row wrap">
              <SeverityBadge severity={f.severity} />
              <h2>{f.title}</h2>
              {f.waiver && <Badge tone="info">waived until {time(f.waiver.expires_at)}</Badge>}
            </span>
          }
          actions={
            !f.waiver &&
            (f.agent ?? agentKey) && (
              <button
                className="small"
                disabled={!can(me, "owner")}
                onClick={() =>
                  openAction({
                    title: "Request a waiver",
                    description: "A time-boxed exception for this finding on this agent, decided by a risk reviewer other than you. It expires on its own.",
                    role: "owner",
                    submit: "Request waiver",
                    fields: [
                      { name: "reason", label: "Why the risk is acceptable for now, and what will fix it", kind: "textarea", required: true },
                      { name: "days", label: "Days", kind: "number", initial: 30, min: 1, max: 180 },
                    ],
                    run: (v) => api("/api/waivers", { body: { rule: f.rule, agent: f.agent ?? agentKey, reason: v.reason, days: v.days } }),
                    invalidate: [["waivers"]],
                  })
                }
              >
                Request waiver
              </button>
            )
          }
        >
          <div className="stack tight">
            <p>{f.detail}</p>
            <p className="small">
              <strong>Fix:</strong> {f.remediation}
            </p>
            <details>
              <summary className="small faint">Evidence and rule</summary>
              <div className="small mono faint">{f.rule}</div>
              <JsonView value={f.evidence} />
            </details>
          </div>
        </Card>
      ))}
    </div>
  );
}

function Activity({ d }: { d: AgentDetail }) {
  const me = useMe().data;
  const [explained, setExplained] = useState<{ run: RunSummary; text: string } | null>(null);
  const explain = useMutation({
    mutationFn: (r: RunSummary) => api<{ explanation: string }>(`/api/runs/${enc(r.source)}/${enc(r.run_id)}/explain`, { method: "POST" }),
    onSuccess: (out, r) => setExplained({ run: r, text: out.explanation }),
  });
  const a = d.facts.activity;
  const refusals = Object.entries(a.refusals).sort((x, y) => y[1] - x[1]);
  return (
    <div className="stack">
      <div className="grid three">
        <Card title="Runs, last 7 days">
          <Spark values={d.series.map((s) => s.runs)} plane="intelligence" />
        </Card>
        <Card title="Refusals, last 7 days">
          <Spark values={d.series.map((s) => s.refused)} plane="decision" />
        </Card>
        <Card title="Human oversight">
          <Kv
            rows={[
              ["Approvals asked", n(Number(a.approvals_required))],
              ["Approvals redeemed", n(Number(a.approvals_redeemed))],
              ["Escalations", n(Number(a.escalations))],
              ["Decisions / scored", `${n(Number(a.decisions))} / ${n(Number(a.scores))}`],
            ]}
          />
        </Card>
      </div>
      {d.anomalies.length > 0 && (
        <div className="banner warn">
          {d.anomalies.map((x) => x.title).join(" · ")} — <Link to="/activity">brief</Link>
        </div>
      )}
      <div className="grid two">
        <Card title="Why it was refused">
          <HBars rows={refusals} plane="decision" empty="Nothing refused." />
        </Card>
        <Card title="Unresolved effects">
          <p className="small">{Number(a.unresolved_effects) ? `${a.unresolved_effects} effect(s) with unknown outcome. Reconcile them on the runtime before anything retries.` : "None: every effect's outcome is known."}</p>
        </Card>
      </div>
      <Card title="Recent runs" flush>
        {d.runs.length === 0 ? (
          <Empty title="No runs in Tower's recent window" />
        ) : (
          <table>
            <thead>
              <tr>
                <th>Run</th>
                <th>Status</th>
                <th>Capabilities</th>
                <th>Outcome</th>
                <th>When</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {d.runs.map((r) => (
                <tr key={r.source + r.run_id}>
                  <td className="mono small">
                    {r.run_id}
                    <div className="faint">{r.source}</div>
                  </td>
                  <td>
                    <Badge tone={r.status === "completed" ? "ok" : r.status === "failed" ? "bad" : "info"}>{r.status}</Badge>
                  </td>
                  <td className="small">{r.capabilities.join(", ") || "—"}</td>
                  <td className="small">
                    {r.refused > 0 && <span style={{ color: "var(--bad)" }}>{r.refused} refused ({r.refusal_reasons.join(", ")}) </span>}
                    {r.unknown > 0 && <span style={{ color: "var(--bad)" }}>{r.unknown} unknown </span>}
                    {!r.refused && !r.unknown && <span className="faint">{r.effects} effect(s)</span>}
                  </td>
                  <td className="small muted nowrap">{ago(r.last_at)}</td>
                  <td>
                    {me?.intelligence && (
                      <button className="small" disabled={explain.isPending} onClick={() => explain.mutate(r)}>
                        {explain.isPending && explain.variables === r ? "Explaining…" : "Explain"}
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
      <ErrorNote error={explain.error} />
      {explained && (
        <Card title={`What happened in ${explained.run.run_id}`} actions={<Badge tone="primary">AI explanation</Badge>}>
          <div className="prose-out">{explained.text}</div>
        </Card>
      )}
    </div>
  );
}

interface DraftReview {
  summary: string;
  capabilities: { capability: string; what_it_does: string; consequence_if_misused: string }[];
  required_profile_agrees: boolean;
  required_profile_note: string;
  gaps: string[];
  questions_for_owner: string[];
  regulatory_notes: string[];
  recommendation: string;
  conditions: string[];
}

function Review({ d, agentKey, canAssess }: { d: AgentDetail; agentKey: string; canAssess: boolean }) {
  const review = d.facts.review as Record<string, unknown> | null;
  const assess = useMutation({ mutationFn: () => api<{ review: DraftReview; model: string }>(`/api/agents/${enc(agentKey)}/assess`, { method: "POST" }) });
  const draft = assess.data?.review;
  return (
    <div className="grid two" style={{ alignItems: "start" }}>
      <Card title="Current review">
        {review ? (
          <Kv
            rows={[
              ["Decision", d.facts.review_expired
                ? <Badge key="d" tone="warn">approved, expired</Badge>
                : <Badge key="d" tone={review.decision === "approved" ? "ok" : "warn"}>{String(review.decision)}</Badge>],
              ["By", `${String(review.reviewed_by)}, ${time(String(review.reviewed_at))}`],
              ["Expires", time(String(review.expires_at))],
              ["Profile at review", String(review.required_profile)],
              ["Reasoning", String(review.notes)],
              ["Conditions", (review.conditions as string[]).join("; ") || "none"],
              ["Capabilities approved", (review.capabilities as string[]).join(", ")],
            ]}
          />
        ) : (
          <Empty title="Never reviewed">A risk reviewer approves the agent's authority before production.</Empty>
        )}
      </Card>
      <Card
        title="Draft a review with AI"
        actions={
          <button className="primary" disabled={!canAssess || assess.isPending} title={canAssess ? "" : "needs intelligence enabled and the owner or risk role"} onClick={() => assess.mutate()}>
            {assess.isPending ? "Drafting…" : draft ? "Draft again" : "Draft"}
          </button>
        }
      >
        <ErrorNote error={assess.error} />
        {!draft && !assess.isPending && (
          <p className="small muted">Claude drafts an intake review from the agent's facts and findings: what each capability does and could do if misused, gaps, and questions for the owner. Tower's required profile and findings stay authoritative; the reviewer decides.</p>
        )}
        {draft && (
          <div className="stack">
            <div className="row">
              <Badge tone="primary">AI draft · {assess.data?.model}</Badge>
              <Badge tone={draft.recommendation === "approve" ? "ok" : draft.recommendation === "do_not_approve" ? "bad" : "warn"}>{draft.recommendation.replace(/_/g, " ")}</Badge>
            </div>
            <p>{draft.summary}</p>
            {!draft.required_profile_agrees && <div className="banner warn">Disagrees with the required profile: {draft.required_profile_note}</div>}
            <h3>Capabilities</h3>
            <ul className="tight-list">
              {draft.capabilities.map((c) => (
                <li key={c.capability}>
                  <span className="mono">{c.capability}</span>: {c.what_it_does} <span className="muted">If misused: {c.consequence_if_misused}</span>
                </li>
              ))}
            </ul>
            {[
              ["Gaps", draft.gaps],
              ["Questions for the owner", draft.questions_for_owner],
              ["Conditions to approve", draft.conditions],
              ["Regulatory notes (informative)", draft.regulatory_notes],
            ].map(([title, items]) =>
              (items as string[]).length ? (
                <div key={title as string}>
                  <h3>{title as string}</h3>
                  <ul className="tight-list">
                    {(items as string[]).map((i) => (
                      <li key={i}>{i}</li>
                    ))}
                  </ul>
                </div>
              ) : null,
            )}
          </div>
        )}
      </Card>
    </div>
  );
}
