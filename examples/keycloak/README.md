# Keycloak: runs bound to the user an agent acts for

Keycloak issues every token here. Alice signs in and consents to the support agent
acting for her; the agent exchanges her token for a delegated one (token exchange
delegation, Keycloak 26.8 preview); contextosd admits a run only for the user that
token acts for, in a role Keycloak says she holds, and the agent dispatches the
quickstart's governed refund with it. Local: Docker and Python, no cloud account.

From the repository or release archive root:

```sh
./examples/keycloak/run.sh
KEYCLOAK_URL=http://localhost:8080 ./examples/keycloak/run.sh   # an existing Keycloak, admin/admin
```

Expected output:

```text
Keycloak realm ready: http://localhost:…/realms/acme
Alice consented; the agent holds a delegated token (sub 17e2ff62…, act support-agent).
Agent's own token: refused, user_not_bound (no_user).
Delegated token, run for usr_771: refused (other_user).
Delegated token, run claiming support_manager: refused (role_not_held).
Alice's own token (audience support-agent): refused, 401.
[payments] refund 120000 for ord_881 (operation refund:ord_881)
Run run_demo_1 admitted for alice; refund dispatched: {"refund_id": "rf_ord_881"}…
run_admitted: user_binding {"bound": true, "mode": "required", "roles_checked": true, "source": "oidc:…/realms/acme#act"}
keycloak delegation bound
```

Files:

- `realm.py` configures realm `acme` through the admin API: organization `acme`,
  agent client `support-agent`, login client `support-console`, user `alice`, the
  ContextOS client scopes and the delegation permission.
- `delegate.py` signs Alice in (login and consent forms), gets the agent's token and
  exchanges Alice's token for the delegated one.
- `pilot.py` starts contextosd with the `[[oidc]]` configuration from
  [docs/integrations/keycloak.md](../../docs/integrations/keycloak.md) and runs the
  checks above.
