// Runtime sources: collector health for everyone, and for admins adding, pausing,
// re-verifying, re-keying and removing them. Every action names a reason and is
// journalled by towerd; keys are referenced, never typed here.

import { useEffect, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { api, can, enc, useMe } from "../lib/api";
import { ago, n } from "../lib/format";
import {
  actionsFor,
  attentionOrder,
  definition,
  EMPTY_FORM,
  keyText,
  stateBadge,
  syncText,
  type ProbeResult,
  type SourceForm,
  type SourceHealth,
  type SourceHealthRow,
} from "../lib/sources";
import { errorText, openAction, toast } from "./actions";
import { Badge, Card, ErrorNote, Kv } from "./ui";

export const HEALTH_KEY = ["sources", "health"];

export function useSourceHealth() {
  return useQuery({ queryKey: HEALTH_KEY, queryFn: () => api<SourceHealth>("/api/sources/health"), refetchInterval: 10_000 });
}

const ACTIONS = {
  pause: { label: "Pause", title: "Pause collecting", submit: "Pause", text: "Stops reading this runtime's audit chain on every Tower replica. What Tower has verified so far stays; findings and activity for its agents stop updating until it is resumed." },
  resume: { label: "Resume", title: "Resume collecting", submit: "Resume", text: "Reads the chain again from the last entry Tower verified." },
  retry: { label: "Retry verification", title: "Retry chain verification", submit: "Retry", text: "Clears the broken mark and verifies the chain again from the last entry Tower verified. Do this only once you know why verification failed (for example a signing key rotation the runtime published late); an entry that still fails marks the source broken again." },
  reload: { label: "Reload keys", title: "Reload keys", submit: "Reload", text: "Reads this source's keys again from their environment variables or secret files, on every Tower replica, and restarts its collector with them." },
  remove: { label: "Remove…", title: "Remove runtime", submit: "Remove", text: "Stops governing this runtime from the console. What Tower verified stays in its history; adding the source back continues from there." },
} as const;

function act(row: SourceHealthRow, action: keyof typeof ACTIONS) {
  const a = ACTIONS[action];
  openAction({
    title: `${a.title}: ${row.id}`,
    description: a.text,
    role: "admin",
    danger: action === "remove",
    confirm: action === "remove" ? row.id : undefined,
    submit: a.submit,
    fields: [{ name: "reason", label: "Reason", kind: "textarea", required: true }],
    run: (v) => api(`/api/sources/${enc(row.id)}/${action}`, { body: { reason: v.reason } }),
    invalidate: [HEALTH_KEY, ["sources"]],
  });
}

export function SourceHealthCard() {
  const me = useMe().data;
  const admin = can(me, "admin");
  const { data, error } = useSourceHealth();
  const rows = attentionOrder(data?.sources ?? []);
  return (
    <Card
      flush
      title={
        <span className="row wrap">
          <h2>Collectors</h2>
          <span className="muted small">
            {data?.reconciled_at ? `converged ${ago(data.reconciled_at)}` : "not converged yet"} · stale after {data?.stale_after_seconds ?? 60}s without a sync
          </span>
        </span>
      }
      actions={admin ? <AddRuntime /> : undefined}
    >
      <ErrorNote error={error} />
      {data?.reconcile_error && <div className="banner warn small">{data.reconcile_error}</div>}
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Runtime</th>
              <th>State</th>
              <th>Tenant</th>
              <th>Verified</th>
              <th>Last sync</th>
              <th>Kill switch</th>
              {admin && <th>Keys</th>}
              {admin && <th />}
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => {
              const [tone, text] = stateBadge(r.state);
              return (
                <tr key={r.id}>
                  <td>
                    <div className="mono">{r.id}</div>
                    <div className="faint small">
                      {r.origin === "config" ? "towerd.toml" : `console${r.added_by ? `, added by ${r.added_by}` : ""}`}
                    </div>
                  </td>
                  <td>
                    <Badge tone={tone}>{text}</Badge>
                    {r.broken && <div className="small">Entry #{r.broken.sequence}: {r.broken.reason}</div>}
                    {!r.broken && r.last_error && <div className="small muted">{r.last_error}</div>}
                    {r.last_change?.reason && (
                      <div className="faint small" title={r.last_change.at ?? undefined}>
                        {r.last_change.by}: {r.last_change.reason}
                      </div>
                    )}
                  </td>
                  <td className="mono small">{r.tenant_id ?? "—"}</td>
                  <td className="small">
                    #{n(r.verified_to)} of {n(r.head)}
                    {r.lag > 0 && <div className="muted">{n(r.lag)} behind</div>}
                    {r.unattributed > 0 && <div className="faint">{n(r.unattributed)} unattributed</div>}
                  </td>
                  <td className="small">{syncText(r)}</td>
                  <td className="small">{r.can_revoke ? "control key" : "read-only"}</td>
                  {admin && (
                    <td className="small mono">
                      <div>{keyText(r.keys, false)}</div>
                      {(r.keys?.control_token_env || r.keys?.control_token_file) && <div className="faint">{keyText(r.keys, true)}</div>}
                    </td>
                  )}
                  {admin && (
                    <td>
                      <div className="row wrap">
                        {actionsFor(r).map((action) => (
                          <button key={action} className={`small ${action === "remove" ? "danger" : ""}`} onClick={() => act(r, action)}>
                            {ACTIONS[action].label}
                          </button>
                        ))}
                      </div>
                    </td>
                  )}
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </Card>
  );
}

function AddRuntime() {
  const [open, setOpen] = useState(false);
  return (
    <>
      <button className="primary small" onClick={() => setOpen(true)}>
        Add runtime…
      </button>
      {open && <AddRuntimeDialog close={() => setOpen(false)} />}
    </>
  );
}

function AddRuntimeDialog({ close }: { close: () => void }) {
  const client = useQueryClient();
  const me = useMe().data;
  const [form, setForm] = useState<SourceForm>(EMPTY_FORM);
  const [probe, setProbe] = useState<ProbeResult | null>(null);
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const built = definition(form);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && !busy && close();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [busy, close]);

  const set = (k: keyof SourceForm) => (v: string) => {
    setForm((f) => ({ ...f, [k]: v }));
    setProbe(null); // a changed definition must be checked again
  };

  async function run(step: "probe" | "add") {
    if (!built.ok) return;
    setBusy(true);
    setError(null);
    try {
      if (step === "probe") {
        setProbe(await api<ProbeResult>("/api/sources/probe", { body: built.value }));
      } else {
        await api("/api/sources", { body: { source: built.value, reason } });
        toast("ok", `Runtime ${built.value.id} added`, "Tower is reading its audit chain.");
        await client.invalidateQueries({ queryKey: ["sources"] });
        close();
      }
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  }

  const text = (k: keyof SourceForm, label: string, help?: string, placeholder?: string) => (
    <label className="field">
      <span>{label}</span>
      <input value={form[k]} placeholder={placeholder} onChange={(e) => set(k)(e.target.value)} autoComplete="off" spellCheck={false} />
      {help && <span className="help">{help}</span>}
    </label>
  );
  const ref = (kind: "readKind" | "controlKind", value: "read" | "control", label: string, optional: boolean) => (
    <div className="stack tight">
      <label className="field">
        <span>{label}</span>
        <select value={form[kind]} onChange={(e) => set(kind)(e.target.value)}>
          {optional && <option value="none">None (read-only: the kill switch skips it)</option>}
          <option value="file">Secret file on the Tower host</option>
          <option value="env">Environment variable on the Tower host</option>
        </select>
      </label>
      {form[kind] !== "none" &&
        text(value, form[kind] === "env" ? "Variable name" : "File path", undefined, form[kind] === "env" ? "TOWER_EU_AUDIT_KEY" : "/run/secrets/eu-audit-key")}
    </div>
  );

  return (
    <div className="backdrop" onMouseDown={(e) => e.target === e.currentTarget && !busy && close()}>
      <div className="dialog wide" role="dialog" aria-modal="true" aria-label="Add runtime">
        <div className="dialog-head">
          <h2>Add runtime</h2>
        </div>
        <form
          className="dialog-body"
          onSubmit={(e) => {
            e.preventDefault();
            if (!busy && built.ok) void run(probe ? "add" : "probe");
          }}
        >
          <div className="muted">
            Tower reads one runtime tenant with an <code>audit:read</code> key, and acts on it only with an optional <code>control</code> key. Name where each key lives
            on every Tower host; the key itself never passes through this console. Tower checks the keys, their scopes and the tenant before anything is saved.
          </div>
          <div className="acting">
            Acting as <strong>{me?.principal_id}</strong> (admin). Tower signs this into its journal.
          </div>
          <div className="grid two">
            {text("id", "Source id", "Unique, e.g. eu-support")}
            {text("url", "Runtime URL", "https, the contextosd base URL", "https://contextos.eu.internal")}
            {ref("readKind", "read", "audit:read key", false)}
            {ref("controlKind", "control", "control key", true)}
            {text("business_unit", "Business unit")}
            {text("region", "Region")}
            {text("environment", "Environment")}
          </div>
          {!built.ok && form.id && <div className="banner info small">{built.error}</div>}
          {probe && (
            <div className="stack tight">
              <h3>Checked</h3>
              <Kv
                rows={[
                  ["Tenant", <span className="mono">{probe.tenant_id}</span>],
                  ["Read key principal", <span className="mono">{probe.principal_id}</span>],
                  ["Scopes", probe.scopes.join(", ")],
                  ["Mode", probe.mode],
                  ["Packs / controls declared", `${probe.packs} / ${probe.supported_controls}`],
                  ["Kill switch", probe.can_revoke ? "control key verified for this tenant" : "read-only"],
                ]}
              />
              {probe.warnings.map((w) => (
                <div key={w} className="banner warn small">
                  {w}
                </div>
              ))}
              <label className="field">
                <span>Reason *</span>
                <textarea className="prose" value={reason} onChange={(e) => setReason(e.target.value)} />
              </label>
            </div>
          )}
          {error !== null && (
            <div className="banner bad">
              <div>
                <div>{errorText(error)[0]}</div>
                {errorText(error)[1] && <div className="mono small muted">{errorText(error)[1]}</div>}
              </div>
            </div>
          )}
          <button type="submit" hidden />
        </form>
        <div className="dialog-foot">
          <button className="ghost" onClick={close} disabled={busy}>
            Cancel
          </button>
          {probe ? (
            <button className="primary" disabled={busy || !reason.trim()} onClick={() => void run("add")}>
              {busy ? "Working…" : `Add ${probe.id}`}
            </button>
          ) : (
            <button className="primary" disabled={busy || !built.ok} onClick={() => void run("probe")}>
              {busy ? "Checking…" : "Check runtime"}
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
