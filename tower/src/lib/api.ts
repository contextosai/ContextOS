// towerd client. One signed-in person per tab; their roles come from towerd and every
// action is checked there (the UI only hides what would be refused). The token lives
// in this tab's sessionStorage and is sent only as an Authorization header.

import { useSyncExternalStore } from "react";
import { useQuery } from "@tanstack/react-query";

export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
  ) {
    super(message);
  }
}

const STORAGE = "contextos.tower.token";
let token: string | null = (() => {
  try {
    return sessionStorage.getItem(STORAGE);
  } catch {
    return null;
  }
})();
const listeners = new Set<() => void>();

export const session = {
  token: () => token,
  subscribe(fn: () => void) {
    listeners.add(fn);
    return () => listeners.delete(fn);
  },
  set(next: string | null) {
    token = next;
    try {
      if (next) sessionStorage.setItem(STORAGE, next);
      else sessionStorage.removeItem(STORAGE);
    } catch {
      // Private mode: the session lasts until reload.
    }
    listeners.forEach((fn) => fn());
  },
};

export function useToken() {
  return useSyncExternalStore(session.subscribe, session.token);
}

export async function api<T>(path: string, options: { method?: string; body?: unknown; token?: string } = {}): Promise<T> {
  const headers: Record<string, string> = { accept: "application/json" };
  const bearer = options.token ?? token;
  if (bearer) headers.authorization = `Bearer ${bearer}`;
  if (options.body !== undefined) headers["content-type"] = "application/json";
  const response = await fetch(path, {
    method: options.method ?? (options.body === undefined ? "GET" : "POST"),
    headers,
    body: options.body === undefined ? undefined : JSON.stringify(options.body),
    credentials: "omit",
    cache: "no-store",
    referrerPolicy: "no-referrer",
  });
  const text = await response.text();
  let body: unknown;
  try {
    body = text ? JSON.parse(text) : undefined;
  } catch {
    body = undefined;
  }
  if (!response.ok) {
    const error = (body as { error?: { code?: string; message?: string } } | undefined)?.error;
    if (response.status === 401 && !options.token) session.set(null);
    throw new ApiError(response.status, error?.code ?? `http_${response.status}`, error?.message ?? response.statusText);
  }
  return body as T;
}

export const enc = encodeURIComponent;

export interface Me {
  principal_id: string;
  roles: string[];
  teams: string[];
  intelligence: string | null;
}

export function useMe() {
  const t = useToken();
  return useQuery({ queryKey: ["me", t], queryFn: () => api<Me>("/api/me"), enabled: Boolean(t), staleTime: 60_000 });
}

/** Whether the signed-in person may act as `role`: admin holds all, everyone is a
 *  viewer, and risk reviewers may do what owners do (towerd enforces the same). */
export function can(me: Me | undefined, role: string): boolean {
  if (!me) return false;
  return (
    me.roles.includes(role) ||
    me.roles.includes("admin") ||
    (role === "viewer" && me.roles.length > 0) ||
    (role === "owner" && me.roles.includes("risk"))
  );
}
