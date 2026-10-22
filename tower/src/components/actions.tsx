// Every change goes through one dialog: it says who is acting with which role, asks for
// the reason Tower signs into its journal, and makes the person type the target for
// wide or irreversible actions. towerd checks the role and separation of duties again.

import { type ReactNode, useEffect, useState, useSyncExternalStore } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { ApiError, can, useMe } from "../lib/api";

// ---- toasts ----
interface Toast {
  id: number;
  tone: "ok" | "bad" | "info";
  title: string;
  detail?: string;
}
let toasts: Toast[] = [];
const toastListeners = new Set<() => void>();
let toastId = 0;
export function toast(tone: Toast["tone"], title: string, detail?: string) {
  const t = { id: ++toastId, tone, title, detail };
  toasts = [...toasts, t];
  toastListeners.forEach((f) => f());
  setTimeout(() => {
    toasts = toasts.filter((x) => x.id !== t.id);
    toastListeners.forEach((f) => f());
  }, tone === "bad" ? 9000 : 4500);
}
export function Toasts() {
  const list = useSyncExternalStore(
    (f) => {
      toastListeners.add(f);
      return () => toastListeners.delete(f);
    },
    () => toasts,
  );
  return (
    <div id="toasts" role="status" aria-live="polite">
      {list.map((t) => (
        <div key={t.id} className={`toast ${t.tone}`}>
          <div>{t.title}</div>
          {t.detail && <div className="code">{t.detail}</div>}
        </div>
      ))}
    </div>
  );
}

export function errorText(e: unknown): [string, string | undefined] {
  if (e instanceof ApiError) return [e.message, `${e.status} ${e.code}`];
  return [(e as Error)?.message ?? String(e), undefined];
}

// ---- action dialog ----
export interface Field {
  name: string;
  label: string;
  kind?: "text" | "textarea" | "select" | "number" | "checkbox" | "json";
  options?: [string, string][];
  required?: boolean;
  help?: ReactNode;
  initial?: string | number | boolean;
  placeholder?: string;
  min?: number;
  max?: number;
}

export type Values = Record<string, string | number | boolean | unknown>;

export interface ActionSpec {
  title: string;
  description?: ReactNode;
  role: string;
  fields?: Field[];
  confirm?: string;
  danger?: boolean;
  submit: string;
  run: (values: Values) => Promise<unknown>;
  done?: string;
  invalidate?: unknown[][];
  wide?: boolean;
}

let current: ActionSpec | null = null;
const dialogListeners = new Set<() => void>();
export function openAction(spec: ActionSpec) {
  current = spec;
  dialogListeners.forEach((f) => f());
}
function closeAction() {
  current = null;
  dialogListeners.forEach((f) => f());
}

export function ActionHost() {
  const spec = useSyncExternalStore(
    (f) => {
      dialogListeners.add(f);
      return () => dialogListeners.delete(f);
    },
    () => current,
  );
  return spec ? <ActionDialog key={spec.title + spec.submit} spec={spec} /> : null;
}

function ActionDialog({ spec }: { spec: ActionSpec }) {
  const client = useQueryClient();
  const me = useMe().data;
  const [values, setValues] = useState<Values>(() => Object.fromEntries((spec.fields ?? []).map((f) => [f.name, f.initial ?? (f.kind === "checkbox" ? false : "")])));
  const [typed, setTyped] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const allowed = can(me, spec.role);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && !busy && closeAction();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [busy]);

  const missing = (spec.fields ?? []).filter((f) => f.required && (values[f.name] === "" || values[f.name] === undefined));
  const confirmed = !spec.confirm || typed.trim() === spec.confirm;

  async function submit() {
    setBusy(true);
    setError(null);
    try {
      const parsed: Values = { ...values };
      for (const f of spec.fields ?? []) {
        if (f.kind === "json" && typeof parsed[f.name] === "string" && parsed[f.name] !== "") parsed[f.name] = JSON.parse(parsed[f.name] as string);
        if (f.kind === "number" && parsed[f.name] !== "") parsed[f.name] = Number(parsed[f.name]);
      }
      await spec.run(parsed);
      toast("ok", spec.done ?? `${spec.title}: done`);
      for (const key of spec.invalidate ?? []) await client.invalidateQueries({ queryKey: key });
      closeAction();
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="backdrop" onMouseDown={(e) => e.target === e.currentTarget && !busy && closeAction()}>
      <div className={`dialog ${spec.wide ? "wide" : ""}`} role="dialog" aria-modal="true" aria-label={spec.title}>
        <div className="dialog-head">
          <h2>{spec.title}</h2>
        </div>
        <form
          className="dialog-body"
          onSubmit={(e) => {
            e.preventDefault();
            if (!missing.length && confirmed && allowed && !busy) void submit();
          }}
        >
          {spec.description && <div className="muted">{spec.description}</div>}
          {allowed ? (
            <div className="acting">
              Acting as <strong>{me?.principal_id}</strong> ({spec.role}). Tower signs this into its journal.
            </div>
          ) : (
            <div className="banner warn">This needs the {spec.role} role.</div>
          )}
          {(spec.fields ?? []).map((f) => (
            <FieldInput key={f.name} field={f} value={values[f.name]} onChange={(v) => setValues((s) => ({ ...s, [f.name]: v }))} />
          ))}
          {spec.confirm && (
            <label className="field">
              <span>
                Type <code>{spec.confirm}</code> to confirm
              </span>
              <input value={typed} onChange={(e) => setTyped(e.target.value)} autoComplete="off" spellCheck={false} />
            </label>
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
          <button className="ghost" onClick={closeAction} disabled={busy}>
            Cancel
          </button>
          <button className={spec.danger ? "danger" : "primary"} disabled={busy || !allowed || missing.length > 0 || !confirmed} onClick={() => void submit()}>
            {busy ? "Working…" : spec.submit}
          </button>
        </div>
      </div>
    </div>
  );
}

function FieldInput({ field, value, onChange }: { field: Field; value: unknown; onChange: (v: unknown) => void }) {
  const label = (
    <span>
      {field.label}
      {field.required && " *"}
    </span>
  );
  let input: ReactNode;
  switch (field.kind) {
    case "textarea":
    case "json":
      input = <textarea className={field.kind === "textarea" ? "prose" : ""} value={String(value ?? "")} placeholder={field.placeholder} onChange={(e) => onChange(e.target.value)} spellCheck={false} />;
      break;
    case "select":
      input = (
        <select value={String(value ?? "")} onChange={(e) => onChange(e.target.value)}>
          {field.options?.map(([v, l]) => (
            <option key={v} value={v}>
              {l}
            </option>
          ))}
        </select>
      );
      break;
    case "checkbox":
      return (
        <label className="row small">
          <input type="checkbox" checked={Boolean(value)} onChange={(e) => onChange(e.target.checked)} /> {field.label}
          {field.help && <span className="faint"> — {field.help}</span>}
        </label>
      );
    case "number":
      input = <input type="number" min={field.min} max={field.max} value={String(value ?? "")} onChange={(e) => onChange(e.target.value)} />;
      break;
    default:
      input = <input value={String(value ?? "")} placeholder={field.placeholder} onChange={(e) => onChange(e.target.value)} autoComplete="off" spellCheck={false} />;
  }
  return (
    <label className="field">
      {label}
      {input}
      {field.help && <span className="help">{field.help}</span>}
    </label>
  );
}
