import { useState } from "react";
import { Link } from "react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, can, useMe } from "../lib/api";
import { ago } from "../lib/format";
import type { Guardrail, Severity } from "../lib/types";
import { openAction, toast } from "../components/actions";
import { Badge, Card, Empty, ErrorNote, JsonView, PageHead, SeverityBadge } from "../components/ui";

interface Draft {
  draft: { title: string; description: string; severity: Severity; rule: unknown; remediation: string; rationale: string };
  valid: boolean;
  checks: { check: string; ok: boolean; note?: string }[];
  impact?: { evaluated: number; violating: string[]; errors: unknown[] };
  model: string;
}

const EXAMPLES = [
  "No agent may take irreversible external actions without a human approval gate.",
  "Customer-facing agents in production must have passed a risk review.",
  "Agents that handle restricted data must pin the model they use.",
  "No agent should be in production without an owner from the business unit it serves.",
];

export function Guardrails() {
  const me = useMe().data;
  const client = useQueryClient();
  const [intent, setIntent] = useState("");
  const { data, error } = useQuery({ queryKey: ["guardrails"], queryFn: () => api<{ guardrails: Guardrail[] }>("/api/guardrails") });
  const draft = useMutation({ mutationFn: (text: string) => api<Draft>("/api/guardrails/draft", { body: { intent: text } }) });
  const save = useMutation({
    mutationFn: (d: Draft) =>
      api<Guardrail>("/api/guardrails", { body: { title: d.draft.title, description: d.draft.description, severity: d.draft.severity, rule: d.draft.rule, remediation: d.draft.remediation, origin: "ai_draft", intent } }),
    onSuccess: async () => {
      toast("ok", "Saved as a draft guardrail", "Another risk reviewer activates it");
      draft.reset();
      setIntent("");
      await client.invalidateQueries({ queryKey: ["guardrails"] });
    },
  });
  const list = data?.guardrails ?? [];
  const status = (g: Guardrail, to: "activate" | "retire") =>
    openAction({
      title: to === "activate" ? `Activate “${g.title}”` : `Retire “${g.title}”`,
      description:
        to === "activate"
          ? `It will be evaluated against every agent, now flagging ${g.impact?.violating.length ?? 0}. A guardrail is activated by someone other than its author (${g.created_by}).`
          : "It stops producing findings. The journal keeps its history.",
      role: "risk",
      submit: to === "activate" ? "Activate" : "Retire",
      danger: to === "retire",
      run: () => api(`/api/guardrails/${g.id}/${to}`, { method: "POST" }),
      invalidate: [["guardrails"], ["posture"], ["findings"]],
    });

  return (
    <div className="stack" style={{ gap: 18 }}>
      <PageHead
        title="Guardrails"
        sub="Organisation-wide rules every agent is checked against, written over the facts Tower knows about each agent. Write one in plain language: Claude drafts it, Tower checks it against the real inventory, and a second reviewer activates it."
        actions={
          <button
            disabled={!can(me, "risk")}
            onClick={() =>
              openAction({
                title: "Write a guardrail by hand",
                description: "A JsonLogic rule over agent facts that is true when an agent violates it. It is evaluated by the same bounded evaluator the runtime uses.",
                role: "risk",
                wide: true,
                submit: "Save draft",
                fields: [
                  { name: "title", label: "Title", required: true },
                  { name: "severity", label: "Severity", kind: "select", options: ["critical", "high", "medium", "low"].map((s) => [s, s]), initial: "high" },
                  { name: "description", label: "Description", kind: "textarea" },
                  { name: "rule", label: "Rule (JsonLogic; true = violation)", kind: "json", required: true, initial: '{"and": [{"var": "exposure.irreversible_external"}, {"==": [{"var": "exposure.approval_gates"}, 0]}]}' },
                  { name: "remediation", label: "How to fix", kind: "textarea" },
                ],
                run: (v) => api("/api/guardrails", { body: { ...v, origin: "manual" } }),
                invalidate: [["guardrails"]],
              })
            }
          >
            Write by hand
          </button>
        }
      />
      <ErrorNote error={error} />

      <Card title="Draft from intent" actions={<Badge tone="primary">AI</Badge>}>
        <div className="stack">
          <textarea className="prose" value={intent} onChange={(e) => setIntent(e.target.value)} placeholder="What should be true of every agent? e.g. No agent may move money without a human approval." />
          <div className="row wrap">
            {EXAMPLES.map((e) => (
              <button key={e} className="small ghost" onClick={() => setIntent(e)}>
                {e.slice(0, 48)}…
              </button>
            ))}
            <button className="primary right" disabled={!me?.intelligence || !can(me, "risk") || intent.trim().length < 10 || draft.isPending} title={!me?.intelligence ? "Intelligence is off" : can(me, "risk") ? "" : "needs the risk role"} onClick={() => draft.mutate(intent)}>
              {draft.isPending ? "Drafting…" : "Draft"}
            </button>
          </div>
          <ErrorNote error={draft.error ?? save.error} />
          {draft.data && (
            <div className="stack">
              <div className="row wrap">
                <SeverityBadge severity={draft.data.draft.severity} />
                <h2>{draft.data.draft.title}</h2>
                <Badge tone={draft.data.valid ? "ok" : "bad"}>{draft.data.valid ? "checks pass" : "checks fail"}</Badge>
              </div>
              <p>{draft.data.draft.description}</p>
              <p className="small muted">{draft.data.draft.rationale}</p>
              <div className="grid two">
                <div className="stack tight">
                  <h3>Checks</h3>
                  {draft.data.checks.map((c) => (
                    <div key={c.check} className="row small">
                      <Badge tone={c.ok ? "ok" : "warn"}>{c.ok ? "✓" : "!"}</Badge>
                      <span>
                        <strong>{c.check.replace(/_/g, " ")}</strong> {c.note}
                      </span>
                    </div>
                  ))}
                  <h3>Would flag today</h3>
                  {draft.data.impact?.violating.length ? (
                    <div className="row wrap">
                      {draft.data.impact.violating.map((k) => (
                        <Link key={k} to={`/agents/${encodeURIComponent(k)}`} className="chip">
                          {k}
                        </Link>
                      ))}
                    </div>
                  ) : (
                    <p className="small muted">No current agent.</p>
                  )}
                </div>
                <div>
                  <h3>Rule</h3>
                  <JsonView value={draft.data.draft.rule} />
                </div>
              </div>
              <div className="row">
                <span className="small faint">Saved as a draft; it has no effect until a different risk reviewer activates it.</span>
                <button className="primary right" disabled={!draft.data.valid || save.isPending} onClick={() => save.mutate(draft.data!)}>
                  Save as draft
                </button>
              </div>
            </div>
          )}
        </div>
      </Card>

      {list.length === 0 ? (
        <Card>
          <Empty title="No guardrails yet">Tower's built-in governance checks always run; guardrails add your organisation's own rules.</Empty>
        </Card>
      ) : (
        list.map((g) => (
          <Card
            key={g.id}
            title={
              <span className="row wrap">
                <SeverityBadge severity={g.severity} />
                <h2>{g.title}</h2>
                <Badge tone={g.status === "active" ? "ok" : g.status === "draft" ? "warn" : ""}>{g.status}</Badge>
                {g.origin === "ai_draft" && <Badge tone="primary">AI-drafted</Badge>}
              </span>
            }
            actions={
              <>
                {g.status === "draft" && (
                  <button className="small primary" disabled={!can(me, "risk") || g.created_by === me?.principal_id} title={g.created_by === me?.principal_id ? "Activated by someone other than its author" : ""} onClick={() => status(g, "activate")}>
                    Activate
                  </button>
                )}
                {g.status !== "retired" && (
                  <button className="small" disabled={!can(me, "risk")} onClick={() => status(g, "retire")}>
                    Retire
                  </button>
                )}
              </>
            }
          >
            <div className="stack tight">
              {g.description && <p>{g.description}</p>}
              {g.intent && <p className="small muted">Intent: “{g.intent}”</p>}
              <p className="small">
                Flags <strong>{g.impact?.violating.length ?? 0}</strong> of {g.impact?.evaluated ?? 0} agents
                {g.impact?.violating.length ? `: ${g.impact.violating.slice(0, 6).join(", ")}${g.impact.violating.length > 6 ? "…" : ""}` : ""}.
              </p>
              <p className="small faint">
                Drafted by {g.created_by} {ago(g.created_at)}
                {g.activated_by && `, activated by ${g.activated_by}`}.
              </p>
              <details>
                <summary className="small faint">Rule</summary>
                <JsonView value={g.rule} />
              </details>
            </div>
          </Card>
        ))
      )}
    </div>
  );
}
