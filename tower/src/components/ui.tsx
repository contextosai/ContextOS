import { type ReactNode, useState } from "react";
import { Link } from "react-router";
import { short } from "../lib/format";
import type { Severity } from "../lib/types";

export type Plane = "intelligence" | "context" | "decision" | "action" | "trust";

export function Card({ title, actions, children, flush, className }: { title?: ReactNode; actions?: ReactNode; children: ReactNode; flush?: boolean; className?: string }) {
  return (
    <section className={`card ${className ?? ""}`}>
      {(title || actions) && (
        <div className="card-head">
          {typeof title === "string" ? <h2>{title}</h2> : title}
          <div className="right row">{actions}</div>
        </div>
      )}
      <div className={`card-body${flush ? " flush" : ""}`}>{children}</div>
    </section>
  );
}

export type Tone = "ok" | "warn" | "bad" | "info" | "primary" | "";

export function Badge({ tone = "", children, pulse, title }: { tone?: Tone; children: ReactNode; pulse?: boolean; title?: string }) {
  return (
    <span className={`badge ${tone}`} title={title}>
      {pulse && <span className="pulse" />}
      {children}
    </span>
  );
}

const RUN_TONES: Record<string, Tone> = {
  running: "info",
  completed: "ok",
  failed: "bad",
  cancelled: "",
  cancel_requested: "warn",
  suspended: "warn",
  waiting_approval: "warn",
  waiting_external: "warn",
  expired: "bad",
};

export function RunStatus({ status }: { status: string }) {
  return (
    <Badge tone={RUN_TONES[status] ?? ""} pulse={status === "running"}>
      {status.replace(/_/g, " ")}
    </Badge>
  );
}

const SEVERITY_TONES: Record<Severity, Tone> = { critical: "bad", high: "warn", medium: "info", low: "" };

export function SeverityBadge({ severity }: { severity: Severity }) {
  return <Badge tone={SEVERITY_TONES[severity]}>{severity}</Badge>;
}

const PROFILE_TONES: Record<string, Tone> = {
  "contextos.core": "",
  "contextos.enterprise": "info",
  "contextos.durable-delegated": "warn",
  "contextos.high-assurance": "bad",
};

export function ProfileBadge({ profile }: { profile: string }) {
  return (
    <span className="row" style={{ gap: 4, display: "inline-flex" }}>
      {profile.split("+").map((p) => (
        <Badge key={p} tone={PROFILE_TONES[p] ?? ""} title="Control profile its authority requires">
          {p.replace("contextos.", "").replace("-", " ")}
        </Badge>
      ))}
    </span>
  );
}

export function FindingCounts({ counts }: { counts: Partial<Record<Severity, number>> }) {
  const parts = (["critical", "high", "medium", "low"] as Severity[]).filter((s) => (counts[s] ?? 0) > 0);
  if (!parts.length) return <span className="small faint">none</span>;
  return (
    <span className="row" style={{ gap: 4 }}>
      {parts.map((s) => (
        <Badge key={s} tone={SEVERITY_TONES[s]} title={s}>
          {counts[s]} {s[0]!.toUpperCase()}
        </Badge>
      ))}
    </span>
  );
}

export function PlaneDot({ plane }: { plane: Plane }) {
  return <span className={`dot plane-${plane}`} style={{ width: 8, height: 8, borderRadius: "50%", display: "inline-block", flex: "none" }} title={`${plane} plane`} />;
}

export function Kpi({ label, value, hint, plane, alert, to }: { label: string; value: ReactNode; hint?: ReactNode; plane?: Plane; alert?: boolean; to?: string }) {
  const body = (
    <div className={`card kpi ${plane ? `plane-${plane}` : ""} ${alert ? "alert" : ""}`}>
      <div className="label">{label}</div>
      <div className="value">{value}</div>
      {hint && <div className="hint">{hint}</div>}
    </div>
  );
  return to ? (
    <Link to={to} style={{ color: "inherit", textDecoration: "none" }}>
      {body}
    </Link>
  ) : (
    body
  );
}

export function Empty({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="empty">
      <strong>{title}</strong>
      {children}
    </div>
  );
}

export function Copy({ text, label }: { text: string; label?: ReactNode }) {
  const [done, setDone] = useState(false);
  return (
    <button
      className="ghost small"
      title="Copy"
      onClick={(e) => {
        e.stopPropagation();
        void navigator.clipboard?.writeText(text).then(() => {
          setDone(true);
          setTimeout(() => setDone(false), 1200);
        });
      }}
    >
      {label ?? (done ? "Copied" : "Copy")}
    </button>
  );
}

export function Digest({ value, keep }: { value: string | undefined; keep?: number }) {
  if (!value) return <span className="faint">—</span>;
  return (
    <span className="chip" title={value}>
      {short(value, keep)}
    </span>
  );
}

export function Id({ value }: { value: string | undefined }) {
  return value ? <code title={value}>{value}</code> : <span className="faint">—</span>;
}

function JsonNode({ value, depth, name }: { value: unknown; depth: number; name?: string }) {
  const key = name !== undefined && <span className="k">{JSON.stringify(name)}</span>;
  const sep = name !== undefined && ": ";
  if (value === null) return <span>{key}{sep}<span className="z">null</span></span>;
  if (typeof value === "string")
    return (
      <span>
        {key}
        {sep}
        <span className="s">{JSON.stringify(value)}</span>
      </span>
    );
  if (typeof value === "number") return <span>{key}{sep}<span className="n">{value}</span></span>;
  if (typeof value === "boolean") return <span>{key}{sep}<span className="b">{String(value)}</span></span>;
  const array = Array.isArray(value);
  const items = array ? (value as unknown[]).map((v, i) => [String(i), v] as const) : Object.entries(value as Record<string, unknown>);
  const [open, close] = array ? ["[", "]"] : ["{", "}"];
  if (items.length === 0) return <span>{key}{sep}{open}{close}</span>;
  return (
    <details open={depth < 2}>
      <summary>
        {key}
        {sep}
        {open}
        <span className="z"> {items.length} {array ? "items" : "keys"} </span>
      </summary>
      {items.map(([k, v], i) => (
        <span className="ind" key={k}>
          <JsonNode value={v} depth={depth + 1} name={array ? undefined : k} />
          {i < items.length - 1 && ","}
        </span>
      ))}
      {close}
    </details>
  );
}

export function JsonView({ value, maxHeight }: { value: unknown; maxHeight?: number }) {
  return (
    <div className="json" style={maxHeight ? { maxHeight } : undefined}>
      <JsonNode value={value} depth={0} />
    </div>
  );
}

export function Kv({ rows }: { rows: [ReactNode, ReactNode][] }) {
  return (
    <dl className="kv">
      {rows.map(([k, v], i) => (
        <div key={i} style={{ display: "contents" }}>
          <dt>{k}</dt>
          <dd>{v ?? <span className="faint">—</span>}</dd>
        </div>
      ))}
    </dl>
  );
}

export function Tabs<T extends string>({ tabs, value, onChange }: { tabs: [T, ReactNode][]; value: T; onChange: (t: T) => void }) {
  return (
    <div className="tabs" role="tablist">
      {tabs.map(([id, label]) => (
        <button key={id} role="tab" aria-selected={value === id} className={value === id ? "on" : ""} onClick={() => onChange(id)}>
          {label}
        </button>
      ))}
    </div>
  );
}

export function Meter({ used, reserved = 0, ceiling }: { used: number; reserved?: number; ceiling: number }) {
  const u = ceiling ? Math.min(100, (used / ceiling) * 100) : 0;
  const r = ceiling ? Math.min(100 - u, (reserved / ceiling) * 100) : 0;
  return (
    <div className={`meter ${used > ceiling ? "over" : ""}`} role="meter" aria-valuenow={used} aria-valuemax={ceiling}>
      <span style={{ width: `${u}%` }} />
      <span className="reserved" style={{ width: `${r}%` }} />
    </div>
  );
}

export function Spark({ values, plane }: { values: number[]; plane?: Plane }) {
  const w = 240;
  const h = 44;
  const max = Math.max(1, ...values);
  const step = values.length > 1 ? w / (values.length - 1) : w;
  const pts = values.map((v, i) => `${(i * step).toFixed(1)},${(h - 3 - (v / max) * (h - 6)).toFixed(1)}`);
  const line = pts.length ? `M${pts.join("L")}` : "";
  return (
    <svg className={`spark ${plane ? `plane-${plane}` : ""}`} viewBox={`0 0 ${w} ${h}`} preserveAspectRatio="none" aria-hidden="true">
      {line && <path className="area" d={`${line}L${w},${h}L0,${h}Z`} />}
      {line && <path className="line" d={line} />}
    </svg>
  );
}

export function HBars({ rows, plane, empty }: { rows: [string, number][]; plane?: Plane; empty?: string }) {
  const max = Math.max(1, ...rows.map(([, v]) => v));
  if (!rows.length) return <p className="muted small">{empty ?? "Nothing yet."}</p>;
  return (
    <div className={plane ? `plane-${plane}` : ""}>
      {rows.map(([label, v]) => (
        <div className="hbar" key={label}>
          <span className="ellipsis mono" title={label}>
            {label}
          </span>
          <span>
            <span className="bar" style={{ display: "block", width: `${(v / max) * 100}%` }} />
          </span>
          <span className="v">{v.toLocaleString()}</span>
        </div>
      ))}
    </div>
  );
}

export function PageHead({ title, sub, crumbs, actions }: { title: ReactNode; sub?: ReactNode; crumbs?: ReactNode; actions?: ReactNode }) {
  return (
    <div className="page-head">
      <div className="grow">
        {crumbs && <div className="crumbs">{crumbs}</div>}
        <h1>{title}</h1>
        {sub && <p className="sub">{sub}</p>}
      </div>
      {actions && <div className="row wrap">{actions}</div>}
    </div>
  );
}

export function ErrorNote({ error }: { error: unknown }) {
  if (!error) return null;
  const e = error as { code?: string; message?: string; scope?: string };
  return (
    <div className="banner bad">
      <strong>{e.code ?? "error"}</strong>
      <span>{e.message ?? String(error)}</span>
    </div>
  );
}
