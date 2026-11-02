"""Configures a Keycloak realm for ContextOS through the admin REST API.

Creates realm `acme` with an organization (the ContextOS tenant), a confidential
agent client `support-agent` (service account, standard token exchange, the
ContextOS scopes `admit` and `dispatch`, audience `contextosd`), a login client
`support-console` whose users may delegate to the agent, a user `alice` with realm
role `support_agent`, and the fine-grained admin permission that lets
`support-agent` act for users. Prints the client secret as JSON.

Usage: python3 realm.py <keycloak base URL> <admin user> <admin password>
"""

import json
import sys
import urllib.error
import urllib.parse
import urllib.request

BASE, ADMIN, PASSWORD = sys.argv[1].rstrip("/"), sys.argv[2], sys.argv[3]
REALM = "acme"


def call(method, path, body=None, token=None, form=None):
    url = BASE + path
    headers = {}
    data = None
    if form is not None:
        data = urllib.parse.urlencode(form).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    elif body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = "Bearer " + token
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request) as response:
            text = response.read().decode()
            location = response.headers.get("Location")
    except urllib.error.HTTPError as error:
        raise SystemExit(f"{method} {path}: {error.code} {error.read().decode()}") from None
    if location and not text:
        return location.rsplit("/", 1)[-1]
    return json.loads(text) if text else None


def admin_token():
    return call("POST", "/realms/master/protocol/openid-connect/token", form={
        "grant_type": "password", "client_id": "admin-cli", "username": ADMIN, "password": PASSWORD,
    })["access_token"]


def main():
    t = admin_token()
    r = f"/admin/realms/{REALM}"
    call("POST", "/admin/realms", {"realm": REALM, "enabled": True, "organizationsEnabled": True,
                                   "adminPermissionsEnabled": True}, t)
    call("POST", f"{r}/roles", {"name": "support_agent"}, t)
    for scope in ("admit", "dispatch"):
        call("POST", f"{r}/client-scopes", {"name": scope, "protocol": "openid-connect",
             "attributes": {"include.in.token.scope": "true", "display.on.consent.screen": "false"}}, t)
    scopes = {s["name"]: s["id"] for s in call("GET", f"{r}/client-scopes", token=t)}

    agent = call("POST", f"{r}/clients", {
        "clientId": "support-agent", "publicClient": False, "serviceAccountsEnabled": True,
        "standardFlowEnabled": False, "directAccessGrantsEnabled": False,
        "attributes": {"standard.token.exchange.enabled": "true"},
        "protocolMappers": [{"name": "contextosd-audience", "protocol": "openid-connect",
                             "protocolMapper": "oidc-audience-mapper",
                             "config": {"included.custom.audience": "contextosd", "access.token.claim": "true"}}],
    }, t)
    for scope in ("admit", "dispatch", "organization"):
        call("PUT", f"{r}/clients/{agent}/default-client-scopes/{scopes[scope]}", token=t)
    console = call("POST", f"{r}/clients", {
        "clientId": "support-console", "publicClient": True, "consentRequired": True,
        "standardFlowEnabled": True, "directAccessGrantsEnabled": True,
        "redirectUris": ["http://localhost/*"],
    }, t)
    for scope in ("organization",):
        call("PUT", f"{r}/clients/{console}/default-client-scopes/{scopes[scope]}", token=t)
    for name, scope_id in scopes.items():
        if name.startswith("delegation:client"):
            call("PUT", f"{r}/clients/{console}/optional-client-scopes/{scope_id}", token=t)

    alice = call("POST", f"{r}/users", {"username": "alice", "enabled": True, "email": "alice@acme.example",
                                        "emailVerified": True, "firstName": "Alice", "lastName": "Acme",
                                        "credentials": [{"type": "password", "value": "alice", "temporary": False}]}, t)
    role = call("GET", f"{r}/roles/support_agent", token=t)
    call("POST", f"{r}/users/{alice}/role-mappings/realm", [role], t)
    org = call("POST", f"{r}/organizations", {"name": "Acme", "alias": "acme",
                                               "domains": [{"name": "acme.example"}]}, t)
    call("POST", f"{r}/organizations/{org}/members", alice, t)
    service_user = call("GET", f"{r}/clients/{agent}/service-account-user", token=t)["id"]
    call("POST", f"{r}/organizations/{org}/members", service_user, t)

    # Fine-grained admin permission: support-agent may act for any user.
    permissions = call("GET", f"{r}/clients?clientId=admin-permissions", token=t)[0]["id"]
    authz = f"{r}/clients/{permissions}/authz/resource-server"
    policy = call("POST", f"{authz}/policy/client", {"name": "support-agent", "clients": [agent]}, t)
    policy = policy["id"] if isinstance(policy, dict) else policy
    call("POST", f"{authz}/permission/scope", {"name": "support-agent delegates for users",
         "resourceType": "Users", "scopes": ["delegate"], "policies": [policy]}, t)

    secret = call("GET", f"{r}/clients/{agent}/client-secret", token=t)["value"]
    print(json.dumps({"issuer": f"{BASE}/realms/{REALM}", "agent_client_secret": secret,
                      "delegation_scopes": [n for n in scopes if n.startswith("delegation:")]}))


main()
