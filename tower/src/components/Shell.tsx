import { useEffect, useMemo, useState } from "react";
import { NavLink, Outlet, useNavigate } from "react-router";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { api, session, useMe } from "../lib/api";
import type { AgentRow, Posture } from "../lib/types";
import { ActionHost, Toasts } from "./actions";
import { Badge, type Plane } from "./ui";

interface NavItem {
  to: string;
  label: string;
  plane: Plane;
  count?: number;
}

export function usePosture() {
  return useQuery({ queryKey: ["posture"], queryFn: () => api<Posture>("/api/posture"), refetchInterval: 15_000 });
}

export function Shell() {
  const me = useMe().data;
  const posture = usePosture().data;
  const waivers = useQuery({ queryKey: ["waivers"], queryFn: () => api<{ waivers: { status: string }[] }>("/api/waivers"), refetchInterval: 30_000 }).data;
  const [palette, setPalette] = useState(false);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setPalette((p) => !p);
      } else if (e.key === "/" && !(e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement)) {
        e.preventDefault();
        setPalette(true);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const critical = posture?.findings.by_severity.critical ?? 0;
  const pendingWaivers = waivers?.waivers.filter((w) => w.status === "requested").length ?? 0;
  const broken = posture?.sources.filter((s) => s.broken).length ?? 0;
  const groups: [string, NavItem[]][] = [
    [
      "Oversee",
      [
        { to: "/", label: "Posture", plane: "trust" },
        { to: "/agents", label: "Agents", plane: "intelligence" },
        { to: "/findings", label: "Findings", plane: "decision", count: critical },
        { to: "/activity", label: "Activity", plane: "action", count: posture?.anomalies },
      ],
    ],
    [
      "Decide",
      [
        { to: "/guardrails", label: "Guardrails", plane: "context" },
        { to: "/waivers", label: "Waivers", plane: "decision", count: pendingWaivers },
        { to: "/ask", label: "Ask Tower", plane: "intelligence" },
      ],
    ],
    [
      "Fleet",
      [
        { to: "/fleet", label: "Runtimes", plane: "action", count: broken },
        { to: "/journal", label: "Journal", plane: "trust" },
      ],
    ],
  ];

  return (
    <div className="shell">
      <header className="topbar">
        <NavLink to="/" className="brand" style={{ textDecoration: "none" }}>
          <img src="/tower/favicon.svg" alt="" />
          Tower <span>ContextOS</span>
        </NavLink>
        <button className="search" onClick={() => setPalette(true)} aria-label="Search">
          <span className="grow" style={{ textAlign: "left" }}>
            Find an agent, owner, team or page…
          </span>
          <kbd>⌘K</kbd>
        </button>
        <div className="right row">
          {broken > 0 && <Badge tone="bad">{broken} chain{broken > 1 ? "s" : ""} broken</Badge>}
          {posture && (
            <Badge tone={posture.intelligence ? "primary" : ""} title={posture.intelligence ? `Intelligence: ${posture.intelligence}` : "Intelligence is off"}>
              {posture.intelligence ? "AI on" : "AI off"}
            </Badge>
          )}
          <Identity />
          <ThemeToggle />
        </div>
      </header>
      <nav className="nav" aria-label="Sections">
        {groups.map(([title, items]) => (
          <div key={title}>
            <h3>{title}</h3>
            {items.map((item) => (
              <NavLink key={item.to} to={item.to} end={item.to === "/"} className={({ isActive }) => (isActive ? "active" : "")}>
                <span className={`dot plane-${item.plane}`} />
                {item.label}
                {item.count !== undefined && item.count > 0 && <span className="count">{item.count}</span>}
              </NavLink>
            ))}
          </div>
        ))}
        {me && (
          <div className="small faint" style={{ padding: "18px 10px 0" }}>
            Signed in as <strong>{me.principal_id}</strong>
            <br />
            {me.roles.join(", ")}
            {me.teams.length > 0 && ` · ${me.teams.join(", ")}`}
          </div>
        )}
      </nav>
      <main className="main" id="main">
        <Outlet />
      </main>
      {palette && <Palette onClose={() => setPalette(false)} />}
      <ActionHost />
      <Toasts />
    </div>
  );
}

function Identity() {
  const me = useMe().data;
  const client = useQueryClient();
  return (
    <button
      className="ghost"
      title="Sign out"
      onClick={() => {
        session.set(null);
        client.clear();
      }}
    >
      {me?.principal_id ?? "…"} · sign out
    </button>
  );
}

function ThemeToggle() {
  const [theme, setTheme] = useState<string>(() => {
    try {
      return localStorage.getItem("contextos.tower.theme") ?? "system";
    } catch {
      return "system";
    }
  });
  useEffect(() => {
    if (theme === "system") document.documentElement.removeAttribute("data-theme");
    else document.documentElement.setAttribute("data-theme", theme);
    try {
      localStorage.setItem("contextos.tower.theme", theme);
    } catch {
      // Not persisted in private mode.
    }
  }, [theme]);
  const next = theme === "system" ? "dark" : theme === "dark" ? "light" : "system";
  return (
    <button className="ghost" title={`Theme: ${theme} (switch to ${next})`} onClick={() => setTheme(next)} aria-label="Toggle theme">
      {theme === "dark" ? "☾" : theme === "light" ? "☀" : "◐"}
    </button>
  );
}

const PAGES: [string, string][] = [
  ["Posture", "/"],
  ["Agents", "/agents"],
  ["Findings", "/findings"],
  ["Activity: anomalies, runs, changes", "/activity"],
  ["Guardrails", "/guardrails"],
  ["Waivers", "/waivers"],
  ["Ask Tower", "/ask"],
  ["Runtimes and kill switch", "/fleet"],
  ["Journal", "/journal"],
];

function Palette({ onClose }: { onClose: () => void }) {
  const navigate = useNavigate();
  const [q, setQ] = useState("");
  const [sel, setSel] = useState(0);
  const agents = useQuery({ queryKey: ["agents", ""], queryFn: () => api<{ agents: AgentRow[] }>("/api/agents") }).data?.agents ?? [];
  const hits = useMemo(() => {
    const needle = q.trim().toLowerCase();
    const pages = PAGES.filter(([l]) => !needle || l.toLowerCase().includes(needle)).map(([label, to]) => ({ label, hint: "", kind: "page", to }));
    const found = agents
      .filter((a) => needle && [a.key, a.owner, a.team, a.purpose, a.business_unit].some((v) => v?.toLowerCase().includes(needle)))
      .map((a) => ({ label: a.key, hint: [a.owner, a.team].filter(Boolean).join(" · "), kind: "agent", to: `/agents/${encodeURIComponent(a.key)}` }));
    return [...found, ...pages].slice(0, 30);
  }, [q, agents]);
  const go = (hit: (typeof hits)[number] | undefined) => {
    if (!hit) return;
    navigate(hit.to);
    onClose();
  };
  return (
    <div className="backdrop" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div className="dialog palette" role="dialog" aria-label="Search">
        <input
          autoFocus
          placeholder="Agent, owner, team, purpose or page"
          value={q}
          onChange={(e) => {
            setQ(e.target.value);
            setSel(0);
          }}
          onKeyDown={(e) => {
            if (e.key === "Escape") onClose();
            if (e.key === "ArrowDown") setSel((s) => Math.min(hits.length - 1, s + 1));
            if (e.key === "ArrowUp") setSel((s) => Math.max(0, s - 1));
            if (e.key === "Enter") go(hits[sel]);
          }}
        />
        <ul>
          {hits.map((h, i) => (
            <li key={h.kind + h.to} className={i === sel ? "sel" : ""} onMouseEnter={() => setSel(i)} onClick={() => go(h)}>
              <span className="ellipsis">{h.label}</span>
              {h.hint && <span className="small faint ellipsis">{h.hint}</span>}
              <span className="kind">{h.kind}</span>
            </li>
          ))}
          {hits.length === 0 && <li className="muted">Nothing matches.</li>}
        </ul>
      </div>
    </div>
  );
}
