import { useState } from "react";
import { api, session, type Me } from "../lib/api";
import { errorText } from "../components/actions";

export function SignIn() {
  const [token, setToken] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<[string, string | undefined] | null>(null);

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
