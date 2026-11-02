#!/usr/bin/env python3
"""ContextOS with Keycloak: runs bound to the user an agent acts for.

Keycloak is the identity provider. Realm `acme` has an organization `acme` (the
ContextOS tenant), an agent client `support-agent` and a user `alice` with realm role
`support_agent`. Alice signs in and consents to the agent acting for her; the agent
exchanges her token for a delegated one (`sub` alice, `act` the agent).

contextosd discovers the realm's keys, maps the organization to the tenant, takes the
caller from `act` and, with `[guards] user_binding = "required"`, admits a run only for
the user the token acts for and a role Keycloak says she holds. The agent then
dispatches a governed refund with the same token.
"""
import hashlib
import importlib.util
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import URLError
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "bindings/python"))
from contextos.client import Client, ContextOSHTTPError  # noqa: E402

BIN = Path(os.environ.get("CONTEXTOS_BIN", ROOT / "target/debug"))
HERE = ROOT / "examples/keycloak"
EXAMPLE = ROOT / "examples/support-refund"
KEYCLOAK = os.environ["KEYCLOAK_URL"].rstrip("/")
AUDIT_KEY = "dev-audit-reader-0123456789abcdef012345"


def serve(handler):
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            try:
                request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                payload = json.dumps(handler(request)).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def script(name, *args):
    out = subprocess.run([sys.executable, "-I", str(HERE / name), *args], check=True, capture_output=True, text=True)
    return json.loads(out.stdout)


def claims(token):
    import base64
    part = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))


def refusal(client, body):
    try:
        client.admit(body)
    except ContextOSHTTPError as error:
        return error.status, error.code, error.detail
    raise AssertionError("expected a refusal")


def runtime_config(port, services, issuer):
    config = (EXAMPLE / "contextosd.toml").read_text()
    config = config.replace("127.0.0.1:8080", f"127.0.0.1:{port}")
    for old, service in zip(range(7701, 7705), services):
        config = config.replace(f"127.0.0.1:{old}", f"127.0.0.1:{service.server_port}")
    # The quickstart key keeps reading the audit; only Keycloak tokens admit runs.
    config = config.replace('key_sha256 = "sha256:REPLACED_BY_RUN_SH"',
                            f'key_sha256 = "sha256:{hashlib.sha256(AUDIT_KEY.encode()).hexdigest()}"')
    config = config.replace('scopes = ["compile", "admit", "dispatch", "audit:read"]', 'scopes = ["audit:read"]')
    config = config.replace("[support]", '[guards]\nuser_binding = "required"\nagent_binding = "required"\n\n[support]')
    return config + f"""
# Keycloak realm acme. Keys are discovered from the realm's metadata.
[[oidc]]
issuer = "{issuer}"
audience = "contextosd"
tenants = ["tenant_acme_prod"]
tenant_claim = "organization"
agent_claim = "azp"
[oidc.tenant_map]
acme = "tenant_acme_prod"
[oidc.agents]
support-agent = ["agt_support"]
[oidc.delegation]
actor_agent_claim = "client_id"
user_roles_claim = "realm_access.roles"
"""


def main():
    realm = script("realm.py", KEYCLOAK, "admin", "admin")
    issuer = realm["issuer"]
    print(f"Keycloak realm ready: {issuer}")
    tokens = script("delegate.py", issuer, "support-agent", realm["agent_client_secret"], "support-console",
                    "alice", "alice")
    delegated = claims(tokens["delegated_token"])
    alice = delegated["sub"]
    assert delegated["act"]["client_id"] == "support-agent", delegated
    print(f"Alice consented; the agent holds a delegated token (sub {alice[:8]}…, act support-agent).")

    spec = importlib.util.spec_from_file_location("development_facts", EXAMPLE / "dev_services.py")
    facts = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(facts)
    services = [serve(h) for h in [facts.authority, facts.constraints, facts.approvals, facts.payments]]
    process = None
    try:
        with tempfile.TemporaryDirectory(prefix="contextos-keycloak-") as tmp:
            tmp = Path(tmp)
            with socket.socket() as listener:
                listener.bind(("127.0.0.1", 0))
                port = listener.getsockname()[1]
            (tmp / "runtime.toml").write_text(runtime_config(port, services, issuer))
            base = f"http://127.0.0.1:{port}"
            with (tmp / "server.log").open("w") as log:
                process = subprocess.Popen(
                    [str(BIN / "contextosd"), "--config", str(tmp / "runtime.toml")], cwd=ROOT, stdout=log,
                    stderr=log, env={**os.environ, "CONTEXTOS_AUDIT_SEED": "11" * 32, "RUST_LOG": "warn"})
                for _ in range(150):
                    if process.poll() is not None:
                        raise RuntimeError((tmp / "server.log").read_text())
                    try:
                        urlopen(base + "/readyz", timeout=1)
                        break
                    except (URLError, OSError):
                        time.sleep(0.1)
                else:
                    raise RuntimeError("Local runtime did not become ready: " + (tmp / "server.log").read_text())

                body = json.loads((EXAMPLE / "requests/run.json").read_text())
                as_agent = Client(base, token=tokens["agent_token"])
                assert refusal(as_agent, body) == (403, "user_not_bound", "no_user")
                print("Agent's own token: refused, user_not_bound (no_user).")

                agent = Client(base, token=tokens["delegated_token"])
                assert refusal(agent, body) == (403, "user_not_bound", "other_user")
                print(f"Delegated token, run for {body['run_context']['user']['user_id']}: refused (other_user).")

                body["run_context"]["user"]["user_id"] = alice
                body["run_context"]["user"]["role"] = "support_manager"
                assert refusal(agent, body) == (403, "user_not_bound", "role_not_held")
                print("Delegated token, run claiming support_manager: refused (role_not_held).")

                try:
                    Client(base, token=tokens["user_token"]).admit(body)
                    raise AssertionError("alice's own token must not authenticate")
                except ContextOSHTTPError as error:
                    assert error.status == 401, error
                print("Alice's own token (audience support-agent): refused, 401.")

                body["run_context"]["user"]["role"] = "support_agent"
                run = agent.admit(body)
                call = json.loads((EXAMPLE / "requests/tool_call.json").read_text())
                result = run.call_tool(call["capability_id"], call["args"], approval_mode="destructive",
                                       idempotency_key=call["idempotency_key"],
                                       evidence_refs=call["evidence_refs"], tool_call_id="tc_refund")
                print(f"Run {run.run_id} admitted for alice; refund dispatched: {json.dumps(result)[:80]}…")

                audit = Client(base, token=AUDIT_KEY)
                entries = audit.request("GET", "/v1/audit/entries", query={"from": 1, "limit": 1000})["entries"]
                admitted = next(e["payload"] for e in entries
                                if e["kind"] == "run_admitted" and e["payload"]["run_id"] == run.run_id)
                assert admitted["user_binding"]["bound"] is True, admitted["user_binding"]
                assert admitted["agent_binding"]["bound"] is True, admitted["agent_binding"]
                assert admitted["admitted_by"] == delegated["act"]["sub"], admitted["admitted_by"]
                assert alice not in json.dumps(admitted)
                print("run_admitted: user_binding", json.dumps(admitted["user_binding"], sort_keys=True))
                print("keycloak delegation bound")
    finally:
        if process is not None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        for service in services:
            service.shutdown()
            service.server_close()


if __name__ == "__main__":
    main()
