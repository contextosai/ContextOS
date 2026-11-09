# Microsoft Entra ID

Microsoft Entra ID can issue the tokens agent services, executors, evaluators and
operators present to `contextosd`. ContextOS verifies Entra's v2.0 access tokens and
binds each run to the tenant and the agent application that called. The configuration
below is the one `crates/contextosd/tests/dispatch/idp_shapes.rs` admits runs with,
using tokens shaped like Entra's.

## What Entra provides, and what ContextOS reads

| Entra | Token claim | ContextOS |
|---|---|---|
| Tenant | `iss` (`https://login.microsoftonline.com/<tenant id>/v2.0`), `tid` | `[[oidc]] issuer`; `tenant_claim = "tid"` + `[oidc.tenant_map]` |
| The API app registration for ContextOS | `aud` (its application id) | `audience` |
| App roles on that registration named after ContextOS scopes (`admit`, `dispatch`, `evaluate`, …), granted to each agent as application permissions | `roles` | `scope_claim = "roles"` (only known scopes count) |
| The agent's own app registration | `azp` (its application id) | `agent_claim = "azp"` + `[oidc.agents]`; agent binding |
| App-only tokens (client credentials) | `idtyp = "app"` (optional claim), `sub` and `oid` = the service principal | the caller (`admitted_by`) |

Claim definitions: Microsoft's
[access token claims reference](https://learn.microsoft.com/en-us/entra/identity-platform/access-token-claims-reference)
and [optional claims](https://learn.microsoft.com/en-us/entra/identity-platform/optional-claims-reference).

## Configure Entra

1. **Register an API for ContextOS.** Set its requested access token version to 2
   (`"requestedAccessTokenVersion": 2` in the manifest). Version 1 tokens have
   `https://sts.windows.net/<tenant id>/` as issuer and `appid` instead of `azp`, and
   the configuration below would refuse them.
2. **Define app roles** on that registration with values exactly `admit`, `dispatch`,
   `reconcile`, `audit:read`, `evaluate`, `control`, …, allowed for applications.
3. **Register each agent as an application**, grant it only the roles it needs as
   application permissions (an agent gets `admit` and `dispatch`; an evaluator only
   `evaluate`), and grant admin consent. The agent requests a token with client
   credentials for `<api application id>/.default`.
4. Optionally add the `idtyp` optional claim to access tokens, so app-only tokens say so.

## Configure contextosd

```toml
[[oidc]]
issuer = "https://login.microsoftonline.com/<tenant id>/v2.0"
audience = "<api application id>"
tenants = ["tenant_acme_prod"]
tenant_claim = "tid"
scope_claim = "roles"
agent_claim = "azp"
# algorithms = ["RS256"]   # the default includes it
[oidc.tenant_map]
"<tenant id>" = "tenant_acme_prod"
[oidc.agents]
"<agent application id>" = ["agt_support"]

[guards]
agent_binding = "required"
```

Keys come from the tenant's OpenID Provider Metadata
(`<issuer>/.well-known/openid-configuration`). A token from another tenant names
another `tid` and is refused; so is a token whose roles do not include the scope a
route needs (`403`).

## Users

ContextOS binds a run to the user an agent acts for through a delegated token that
names the agent in an RFC 8693 actor claim (`act`) and the user in `sub` (see
`[oidc.delegation]` in the GUIDE). Entra's on-behalf-of flow is not RFC 8693 token
exchange: its tokens name the user (`oid`, `sub`) and the calling application (`azp`)
but carry no `act` claim, and agent identities are marked with facet claims
(`xms_act_fct`) instead
([on-behalf-of flow](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-on-behalf-of-flow),
[agent ID token claims](https://learn.microsoft.com/en-us/entra/agent-id/agent-token-claims)).
So `[oidc.delegation]` does not apply to Entra tokens today:

- Keep `[guards] user_binding = "observe"` (the default): runs are admitted, and
  `run_admitted` records `bound: false` with `no_user`.
- Or put a token service that issues RFC 8693 delegated tokens between the agent and
  ContextOS (Keycloak's token exchange, for example, can federate Entra sign-ins) and
  configure that issuer with `[oidc.delegation]`.

Do not map `azp` as an actor on on-behalf-of tokens: an app-only token has `sub` and
`azp` too, and would then read as a user delegation.
