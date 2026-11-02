# Keycloak

[Keycloak](https://www.keycloak.org) can be the identity provider for everything that
calls `contextosd`: agent services, executors, evaluators, operators and, through token
exchange delegation, the users agents act for. ContextOS does not run its own identity
provider. It verifies what Keycloak issues and binds each run to it.

Runnable against a real Keycloak (Docker):

```sh
./examples/keycloak/run.sh               # starts quay.io/keycloak/keycloak:26.8.1
KEYCLOAK_URL=http://localhost:8080 ./examples/keycloak/run.sh   # or use yours (admin/admin)
```

## What Keycloak provides, and what ContextOS reads

| Keycloak | Token claim | ContextOS |
|---|---|---|
| Realm | `iss` (`https://kc.example/realms/acme`) | `[[oidc]] issuer`; keys discovered from `<issuer>/.well-known/openid-configuration` |
| Audience mapper (client scope) | `aud` contains `contextosd` | `audience` |
| Client scopes named after ContextOS scopes (`admit`, `dispatch`, `evaluate`, …) | `scope` | caller scopes (only known scopes count) |
| Organization (26+) | `organization`: `["acme"]`, or a map keyed by alias | `tenant_claim = "organization"` + `[oidc.tenant_map]` |
| Confidential client with a service account, one per agent | `azp`, `sub` (service-account user id) | `agent_claim = "azp"` + `[oidc.agents]`; agent binding |
| Token exchange delegation (26.8 preview) | `sub` = the user, `act` = `{sub, client_id}` of the agent | `[oidc.delegation]`: caller = `act.sub`, user = `sub`; user binding |
| Realm roles | `realm_access.roles` | `user_roles_claim`: the roles a run may declare as `user.role` |
| Step-up (`acr`, `amr`, `auth_time` in approvers' ID tokens) | — | `[guards.approval_step_up]`, reported by your approval service |

## Configure the realm

`examples/keycloak/realm.py` does all of this through the admin REST API; it is the
reference for the settings below.

1. **Organizations.** Enable organizations on the realm and create one per ContextOS
   tenant. Clients request the `organization` scope so the claim is issued (it is not
   included for client credentials unless requested).
2. **ContextOS scopes.** Create client scopes named exactly `admit`, `dispatch`,
   `reconcile`, `audit:read`, `evaluate`, `control`, … with *Include in token scope* on,
   and assign each client only the ones it needs as default scopes. An agent gets
   `admit dispatch`; an evaluator only `evaluate`; on-call only `control reconcile`.
   ContextOS refuses scores from a caller that can also admit or dispatch, so keep
   evaluators on separate clients.
3. **Audience.** Add an audience mapper (`included.custom.audience = contextosd`) to
   each client that calls ContextOS. Tokens for other audiences are refused.
4. **One client per agent.** A confidential client with a service account
   (`support-agent`). Its `azp` names the agent: map it with `[oidc.agents]`.
5. **Delegation (users).** Start Keycloak with
   `--features=token-exchange-delegation,parameterized-scopes` (preview in 26.8). On
   the agent client enable *Standard token exchange*. On the client users sign in to
   (`support-console`), turn *Consent required* on and add the optional client scope
   `delegation:client`. Grant the agent the `delegate` permission on Users in
   *Admin Permissions* (fine-grained admin permissions v2); without it Keycloak drops
   the delegation scope silently.

## Configure contextosd

```toml
[[oidc]]
issuer = "https://kc.example/realms/acme"   # jwks_url omitted: discovered
audience = "contextosd"
tenants = ["tenant_acme_prod"]
tenant_claim = "organization"
agent_claim = "azp"
algorithms = ["RS256"]                      # Keycloak's default realm key
[oidc.tenant_map]
acme = "tenant_acme_prod"                   # organization alias → tenant
[oidc.agents]
support-agent = ["agt_support"]             # client id → agent ids
[oidc.delegation]
actor_agent_claim = "client_id"             # the agent of a delegated token: act.client_id
user_roles_claim = "realm_access.roles"

[guards]
agent_binding = "required"
user_binding = "required"                   # every run acts for a signed-in user
```

A token naming no organization, or more than one mapped tenant, is refused: request
`organization:<alias>` when a user belongs to several.

## The delegated flow

1. Alice signs in to `support-console` requesting
   `openid organization delegation:client:support-agent` and consents. Her token gets
   `may_act: {sub: <agent service account>, client_id: support-agent}` and the agent's
   audience, not `contextosd`'s: her own token cannot call ContextOS.
2. The agent gets its own token (client credentials, `scope=organization`).
3. The agent exchanges Alice's token (`grant_type=…:token-exchange`, `subject_token`
   hers, `actor_token` its own). Keycloak 26.8.1 returns:

```json
{
  "iss": "https://kc.example/realms/acme", "aud": ["contextosd", "account"],
  "sub": "18b6271f-…",                        "azp": "support-agent",
  "act": {"sub": "0f37f2cd-…", "client_id": "support-agent"},
  "scope": "dispatch organization admit profile email",
  "organization": ["acme"],
  "realm_access": {"roles": ["support_agent", "default-roles-acme", …]}
}
```

4. The agent admits the run with that token. `run_context.user.user_id` must be Alice's
   Keycloak id (`sub`) and `user.role` one of her realm roles; the caller is the agent's
   service account (`act.sub`, the same `sub` as its client-credentials token), so the
   run's executor can keep dispatching with either token. The agent binding reads
   `act.client_id`.

`examples/keycloak` shows each refusal: the agent's own token (`no_user`), a run for
another user (`other_user`), a role Alice does not hold (`role_not_held`) and Alice's
own token (`401`, wrong audience); then the bound run dispatches the governed refund.

## Rollout

Leave `user_binding` at `observe` first: every run is admitted and
`contextos_user_binding_mismatches_total{reason}` counts the ones `required` would
refuse. `no_user` falls to zero once every agent that acts for users admits with
delegated tokens; then switch to `required`. Agents that never act for users (batch
jobs) need their own deployment or `observe`.

## Limits

- Token exchange delegation is a Keycloak 26.8 preview feature. Without it, ContextOS
  still uses Keycloak for agent, evaluator and operator identity (client credentials),
  tenants and discovery; `run_context.user` then stays caller-asserted (`observe`
  records `no_user`).
- Keycloak's consent for delegation lasts one sign-in session and is never stored.
  Revoking the session does not revoke issued access tokens: keep their lifespan short
  (minutes), because ContextOS verifies tokens offline and does not call introspection.
- Only the immediate actor is read; a nested `act` chain is not recorded.
- The task authorization's `issued_by` is still stated by the caller; user binding
  does not check it.
- Humans signing in to Tower with Keycloak (authorization code flow) is not part of this
  integration.
