import { useEffect, useState } from "react";
import { api, session, type Me } from "../lib/api";
import { finishSignIn, signInUrl, type SsoSettings } from "../lib/sso";
import { errorText } from "../components/actions";

export function SignIn() {
  const [token, setToken] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<[string, string | undefined] | null>(null);
  const [sso, setSso] = useState<SsoSettings | null>(null);

  useEffect(() => {
    // Back from the identity provider: finish the sign-in Tower started.
    finishSignIn(window.location, window.history)
      .then(async (idToken) => {
        if (!idToken) return;
        setBusy(true);
        await api<Me>("/api/me", { token: idToken });
        session.set(idToken);
      })
      .catch((err) => setError(errorText(err)))
      .finally(() => setBusy(false));
    api<SsoSettings>("/api/sso", { token: "" })
      .then(setSso)
      .catch(() => setSso(null));
  }, []);

  return (
    <div className="gate">
      <div className="card">
        <div className="hero">
          <img src="/tower/favicon.svg" alt="" />
          <div>
            <h1>ContextOS Tower</h1>
            <p className="muted">Know, control and prove what your organisation's AI agents do.</p>
          </div>
        </div>
        {sso && (
          <div className="card-body stack">
            <button
              className="primary"
              disabled={busy || !sso.authorization_endpoint}
              onClick={async () => {
                setError(null);
                try {
                  window.location.assign(await signInUrl(sso));
                } catch (err) {
                  setError(errorText(err));
                }
              }}
            >
              Sign in with your organization
            </button>
            <span className="help">Your identity provider's groups decide your Tower roles. Or use an access key below.</span>
          </div>
        )}
        <form
          className="card-body stack"
          onSubmit={async (e) => {
            e.preventDefault();
            setBusy(true);
            setError(null);
            try {
              await api<Me>("/api/me", { token: token.trim() });
              session.set(token.trim());
            } catch (err) {
              setError(errorText(err));
            } finally {
              setBusy(false);
            }
          }}
        >
          <label className="field">
            <span>Access key</span>
            <input type="password" autoFocus value={token} onChange={(e) => setToken(e.target.value)} autoComplete="off" placeholder="Paste your Tower key" />
            <span className="help">Your roles (viewer, owner, risk, operator, admin) decide what you can change. The key stays in this tab and is sent only to Tower.</span>
          </label>
          {error && (
            <div className="banner bad">
              <div>
                {error[0]}
                {error[1] && <div className="mono small muted">{error[1]}</div>}
              </div>
            </div>
          )}
          <button className="primary" disabled={!token || busy}>
            {busy ? "Checking…" : "Sign in"}
          </button>
        </form>
      </div>
    </div>
  );
}
