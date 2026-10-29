"""Separate contextosd processes sharing one PostgreSQL store and audit log, and the
HTTP calls the drill makes against them."""
import copy
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[2]
BIN = Path(os.environ.get("CONTEXTOS_BIN", ROOT / "target/release"))
KEY = "dev-key-0123456789abcdef0123456789abcdef"
LIMIT = 100_000  # INR 1,000 per order, in minor units
TEMPLATE = json.loads((ROOT / "examples/support-refund/requests/run.json").read_text())
TOOL = json.loads((ROOT / "examples/support-refund/requests/tool_call.json").read_text())


def digest(value):
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return "sha256:" + hashlib.sha256(raw.encode()).hexdigest()


def free_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def config_text(port, services, guarantee_id, url_env):
    config = (ROOT / "examples/support-refund/contextosd.toml").read_text()
    config = config.replace("127.0.0.1:8080", f"127.0.0.1:{port}")
    config = config.replace('[store]\nkind = "memory"',
                            f'[store]\nkind = "postgres"\nurl_env = "{url_env}"\nmax_connections = 16')
    config = config.replace("sha256:REPLACED_BY_RUN_SH",
                            "sha256:" + hashlib.sha256(KEY.encode()).hexdigest())
    config = config.replace('"dispatch", "audit:read"', '"dispatch", "reconcile", "audit:read"')
    for old, service in zip(range(7701, 7705), services):
        config = config.replace(f"127.0.0.1:{old}", f"127.0.0.1:{service.server_port}")
    assert 'kind = "postgres"' in config, "the example configuration changed; update the drill"
    return config + f'''
[[guarantees]]
id = "{guarantee_id}"
capability_ids = ["adp_payments.issue_refund"]
resource_pointer = "/order_id"
amount_pointer = "/amount_minor"
limit = {LIMIT}
unit = "INR_minor"
'''


def call(base, path, body=None, generation=None, timeout=30):
    """(HTTP status, JSON body or text). Connection failures are status 0."""
    headers = {"Authorization": f"Bearer {KEY}", "Content-Type": "application/json"}
    if generation is not None:
        headers["contextos-executor-generation"] = str(generation)
    req = Request(base + path, headers=headers,
                  data=None if body is None else json.dumps(body).encode())
    try:
        with urlopen(req, timeout=timeout) as response:
            status, payload, kind = response.status, response.read(), response.headers.get_content_type()
    except HTTPError as error:
        status, payload, kind = error.code, error.read(), error.headers.get_content_type()
    except (URLError, ConnectionError, TimeoutError, OSError) as error:
        return 0, str(error)
    return status, json.loads(payload) if kind == "application/json" and payload else payload.decode()


def ok(base, path, body=None, generation=None):
    status, payload = call(base, path, body, generation)
    if status not in (200, 201):
        raise RuntimeError(f"{status} {path}: {payload}")
    return payload


class Replica:
    def __init__(self, index, workdir, services, guarantee_id, url_env):
        self.index, self.port = index, free_port()
        self.base = f"http://127.0.0.1:{self.port}"
        self.config = workdir / f"replica-{index}.toml"
        self.config.write_text(config_text(self.port, services, guarantee_id, url_env))
        self.log = workdir / f"replica-{index}.log"
        self.process = None
        self.restarts = 0

    def start(self):
        if self.process is not None:
            self.restarts += 1
        with self.log.open("a") as log:
            self.process = subprocess.Popen(
                [str(BIN / "contextosd"), "--config", str(self.config)], cwd=ROOT,
                stdout=log, stderr=log,
                env={**os.environ, "CONTEXTOS_AUDIT_SEED": "11" * 32, "RUST_LOG": "warn"})
        self.wait_ready()

    def wait_ready(self, seconds=30):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise RuntimeError(f"replica {self.index} exited:\n{self.log.read_text()[-2000:]}")
            if call(self.base, "/readyz", timeout=2)[0] == 200:
                return
            time.sleep(0.1)
        raise RuntimeError(f"replica {self.index} did not become ready")

    def kill(self):
        """SIGKILL: no shutdown hooks, no flushing, as in a node or OOM kill."""
        self.process.send_signal(signal.SIGKILL)
        self.process.wait()

    def alive(self):
        return self.process.poll() is None

    def stop(self):
        if self.process is not None and self.alive():
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()


def admit(base, run, agent, amount):
    body = copy.deepcopy(TEMPLATE)
    body["run_context"]["run_id"] = run
    body["contract"]["run_id"] = run
    body["contract"]["contract_id"] = f"contract_{run}"
    body["request"]["request_id"] = f"req_{run}"
    body["request"]["input"]["context"]["refund_amount"] = amount // 100
    for context in [body["request"], body["run_context"]]:
        context["agent"]["agent_id"] = agent
        context["agent"]["workload_identity"] = f"spiffe://contextos/agents/{agent}"
    return ok(base, "/v1/runs", body)["executor_generation"]


def refund(base, run, agent, order, amount, generation, timeout=30):
    """(HTTP status, body, seconds). The idempotency key is per run, so two runs
    asking for the same refund are two operations: the ledger, not the key, holds
    them to the limit."""
    body = copy.deepcopy(TOOL)
    body["run_id"] = run
    body["tool_call_id"] = f"call_{run}"
    body["idempotency_key"] = f"refund_{run}"
    body["args"]["order_id"] = order
    body["args"]["amount_minor"] = amount
    body["principal_chain"] = [{"kind": "agent", "id": agent}]
    started = time.perf_counter()
    status, payload = call(base, f"/v1/runs/{run}/tool-calls", body, generation, timeout)
    return status, payload, time.perf_counter() - started


def outcome(status, payload):
    """A short label for one tool call's result."""
    if status == 0:
        return "connection_lost"
    if status != 200 or not isinstance(payload, dict):
        return f"http_{status}:{payload.get('error', {}).get('code', '') if isinstance(payload, dict) else ''}"
    result = payload.get("result", {})
    if result.get("status") == "completed":
        return "completed"
    codes = payload.get("report", {}).get("reason_codes", [])
    return f"{result.get('status')}:{','.join(codes) or result.get('error', '')}"


def current_generation(base, run):
    return ok(base, f"/v1/runs/{run}")["executor_generation"]


def evidence(entries):
    export = json.dumps({"provider": "synthetic_payments", "entries": entries}, sort_keys=True)
    return {"artifact_type": "provider_ledger", "artifact_id": "synthetic_payments_export",
            "version": "1", "sha256": "sha256:" + hashlib.sha256(export.encode()).hexdigest()}


def reconcile(base, run, operation, result, entries, generation):
    return call(base, f"/v1/runs/{run}/operations/{operation}/reconcile",
                {"source": "operator", "outcome": result, "evidence_ref": evidence(entries)}, generation)


def balance(base, guarantee_id, order):
    status, view = call(base, f"/v1/guarantees/{guarantee_id}/resources/{digest(order)}")
    if status == 404:
        return {"committed": 0, "held": 0, "available": LIMIT}
    if status != 200:
        raise RuntimeError(f"{status} balance {order}: {view}")
    return view


def holds(base, guarantee_id):
    """Every open hold under the guarantee, through the inspection API."""
    found, after = [], None
    while True:
        query = f"?after={after}" if after else ""
        page = ok(base, f"/v1/guarantees/{guarantee_id}/holds{query}")
        for resource in page["resources"]:
            detail = ok(base, f"/v1/guarantees/{guarantee_id}/resources/{resource['resource_digest']}/holds")
            found.extend(dict(hold, resource_digest=resource["resource_digest"]) for hold in detail["holds"])
        after = page["next"]
        if not after:
            return found


def export_audit(base):
    entries, start = [], 1
    while True:
        page = ok(base, f"/v1/audit/entries?from={start}&limit=1000")
        entries.extend(page["entries"])
        if not page.get("next"):
            return entries, ok(base, "/v1/audit/keys")
        start = page["next"]
