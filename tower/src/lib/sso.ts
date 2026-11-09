// Single sign-on: the authorization-code flow with PKCE against the organization's
// identity provider. Tower publishes where to send the browser (`GET /api/sso`) and
// exchanges the returned code itself (`POST /api/sso/token`), so this page talks only
// to Tower. The verifier, state and nonce live in this tab's sessionStorage until the
// browser comes back.

import { api } from "./api";

export interface SsoSettings {
  issuer: string;
  client_id: string;
  scopes: string[];
  redirect_uri: string;
  authorization_endpoint: string | null;
}

interface Pending {
  state: string;
  verifier: string;
  nonce: string;
}

const PENDING = "contextos.tower.sso";

function random(bytes: number): string {
  const data = crypto.getRandomValues(new Uint8Array(bytes));
  return base64url(data);
}

export function base64url(data: Uint8Array): string {
  let text = "";
  data.forEach((b) => (text += String.fromCharCode(b)));
  return btoa(text).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export async function challenge(verifier: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
  return base64url(new Uint8Array(digest));
}

/** The URL that starts a sign-in, remembering what the return must match. */
export async function signInUrl(settings: SsoSettings): Promise<string> {
  if (!settings.authorization_endpoint) throw new Error("The identity provider is not ready yet.");
  const pending: Pending = { state: random(16), verifier: random(48), nonce: random(16) };
  sessionStorage.setItem(PENDING, JSON.stringify(pending));
  const url = new URL(settings.authorization_endpoint);
  url.search = new URLSearchParams({
    response_type: "code",
    client_id: settings.client_id,
    redirect_uri: settings.redirect_uri,
    scope: settings.scopes.join(" "),
    state: pending.state,
    nonce: pending.nonce,
    code_challenge: await challenge(pending.verifier),
    code_challenge_method: "S256",
  }).toString();
  return url.toString();
}

/**
 * Finishes a sign-in when the browser comes back with `code` and `state`: returns the
 * ID token, or null when this load is not a return. The query is cleared either way.
 */
export async function finishSignIn(location: Location, history: History): Promise<string | null> {
  const params = new URLSearchParams(location.search);
  const code = params.get("code");
  const state = params.get("state");
  const error = params.get("error");
  if (!code && !error) return null;
  history.replaceState(null, "", location.pathname);
  const stored = sessionStorage.getItem(PENDING);
  sessionStorage.removeItem(PENDING);
  if (error) throw new Error(params.get("error_description") ?? error);
  const pending = stored ? (JSON.parse(stored) as Pending) : null;
  if (!pending || pending.state !== state) throw new Error("This sign-in was not started here; try again.");
  const done = await api<{ id_token: string }>("/api/sso/token", {
    body: { code, code_verifier: pending.verifier, nonce: pending.nonce },
    token: "",
  });
  return done.id_token;
}
