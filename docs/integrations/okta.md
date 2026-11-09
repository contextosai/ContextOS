# Okta

Okta can issue the tokens agent services, executors, evaluators and operators present to
`contextosd`, and, through its token exchange for AI agents, the delegated tokens that
bind a run to the user an agent acts for. The configuration below is the one
`crates/contextosd/tests/dispatch/idp_shapes.rs` admits runs with, using tokens shaped
like Okta's.

## What Okta provides, and what ContextOS reads

| Okta | Token claim | ContextOS |
|---|---|---|
| A custom authorization server for ContextOS | `iss` (`https://<org>.okta.com/oauth2/<server id>`) | `[[oidc]] issuer`; `tenant_claim = "iss"` + `[oidc.tenant_map]`, or a custom `tenant_id` claim |
| Its audience | `aud` (for example `api://contextos`) | `audience` |
| Custom scopes named after ContextOS scopes (`admit`, `dispatch`, `evaluate`, …) | `scp` (an array) | `scope_claim = "scp"` (only known scopes count) |
| An API services app per agent | `cid` (its client id); `sub` = the client for client credentials | `agent_claim = "cid"` + `[oidc.agents]`; agent binding |
| Token exchange for AI agents | `sub` = the user, `act` = `{sub: <agent>, sub_profile: "ai_agent"}`, earlier actors nested | `[oidc.delegation]`: caller = `act.sub`, user = `sub`; user binding |
| Groups claim (`groups` scope and an allowlist) | `groups` | `user_roles_claim = "groups"`: the roles a run may declare as `user.role` |

Claim definitions: Okta's [OAuth 2.0 claims and scopes](https://developer.okta.com/docs/concepts/oauth-claims/),
[token exchange for MCP servers and AI agents](https://developer.okta.com/docs/guides/ai-mcp-server-token-exchange/main/)
and [groups claims](https://developer.okta.com/docs/guides/customize-tokens-static/main/).

## Configure Okta

1. **Create a custom authorization server** for ContextOS (custom scopes and claims
   need one; the org authorization server does not issue them). Set its audience, for
   example `api://contextos`.
2. **Add scopes** named exactly `admit`, `dispatch`, `reconcile`, `audit:read`,
   `evaluate`, `control`, …, and an access policy that grants each client only the ones
   it needs (an agent gets `admit dispatch`; an evaluator only `evaluate`).
3. **Create an API services app per agent** (client credentials). Its client id is the
   `cid` claim, mapped to agent ids below.
4. **For users:** set up token exchange for the agent as Okta's guide describes, so the
   agent exchanges the user's token for one whose `sub` is the user and whose `act`
   names the agent. To check roles, issue a `groups` claim with an allowlist.

The tenant: an authorization server per ContextOS tenant lets `iss` name it, as below.
For several tenants on one server, add a custom claim (for example `tenant_id`) and use
it as `tenant_claim`.

## Configure contextosd

```toml
[[oidc]]
issuer = "https://acme.okta.com/oauth2/<server id>"
audience = "api://contextos"
tenants = ["tenant_acme_prod"]
tenant_claim = "iss"
scope_claim = "scp"
agent_claim = "cid"
[oidc.tenant_map]
"https://acme.okta.com/oauth2/<server id>" = "tenant_acme_prod"
[oidc.agents]
"<agent client id>" = ["agt_support"]
[oidc.delegation]
actor_claim = "act"
# user_roles_claim = "groups"

[guards]
agent_binding = "required"
# user_binding = "required"   # once every admitting credential is a delegated token
```

A token from another authorization server of the same org has another `iss` and is
refused. With `user_binding = "required"`, a run's `user.user_id` must be the token's
`sub`: Okta's default subject for users is their login, so declare that, or change the
authorization server's subject mapping to what your agents declare.
