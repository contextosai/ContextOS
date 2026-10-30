#!/usr/bin/env python3
"""Why not a database transaction? The same faults, against a row lock and against ContextOS.

Synthetic and local: no model key, cloud account or payment service. One synthetic
provider applies refunds and store credit and can lose a response after applying the
effect, as a timed-out payment call does. Part 1 drives the refund service from
refund_service.py; part 2 drives the same provider through the ContextOS gateway.
"""
import concurrent.futures
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import URLError
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "bindings/python"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from contextos.client import Client, ToolOutcome, ToolPaused  # noqa: E402
from refund_service import LockAroundCall, ReserveThenCall, StoreCreditService  # noqa: E402

# Set by run.sh: a release archive's bin/ or a fresh cargo build.
BIN = Path(os.environ.get("CONTEXTOS_BIN", ROOT / "target/debug"))
EXAMPLE = ROOT / "examples/support-refund"
KEY = "dev-key-0123456789abcdef0123456789abcdef"
# On call: reconciles, and as a principal that admitted no run may record an effect absent.
OPS_KEY = "dev-ops-0123456789abcdef0123456789abcdef"
CEILING = 100_000  # INR 1,000 in minor units, per order
TIMEOUT_MS = 500


def inr(minor):
    return f"INR {minor // 100:,}"


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


class Provider:
    """The provider's own ledger: what actually happened to the customer's money.

    A tool in `lose` applies its effect and answers too late; a tool in `stall` answers
    too late and never applies it. The caller sees the same timeout either way.
    """

    def __init__(self):
        self.applied, self.lose, self.stall, self.lock = [], set(), set(), threading.Lock()

    def __call__(self, request):
        tool, args = request["params"]["name"], request["params"]["arguments"]
        with self.lock:
            stalled = tool in self.stall
            lost = tool in self.lose
            self.stall.discard(tool)
            self.lose.discard(tool)
            if not stalled:
                self.applied.append((tool, args["order_id"], args["amount_minor"]))
        if lost or stalled:
            time.sleep(TIMEOUT_MS / 1000 * 2)
        return {"jsonrpc": "2.0", "id": request["id"], "result": {"structuredContent": {"status": "done", **args}}}

    def total(self, order_id):
        with self.lock:
            return sum(amount for _, order, amount in self.applied if order == order_id)


def baseline(provider, endpoint, tmp):
    print("Part 1: a refund service with a row lock (refund_service.py), ceiling INR 1,000 per order")

    def row(case, outcome):
        print(f"  {case:<50} {outcome}")

    service = LockAroundCall(str(tmp / "race.db"), endpoint, CEILING)
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: service.refund("ord_race", 80_000), range(2)))
    assert sorted(results) == ["exceeded", "refunded"], results
    assert provider.total("ord_race") == 80_000
    row("race: two agents, INR 800 each", "1 applied, 1 refused. Correct.")

    for name, service in [
            ("lock held across the call", LockAroundCall(str(tmp / "around.db"), endpoint, CEILING)),
            ("reserve, call, release on failure", ReserveThenCall(str(tmp / "release.db"), endpoint, CEILING))]:
        order = "ord_" + name.split()[0]
        provider.lose.add("issue_refund")
        assert service.refund(order, 80_000) == "failed"  # applied; the answer was lost
        assert service.refund(order, 80_000) == "refunded"  # the next agent, or a retry
        assert service.used(order) == 80_000 and provider.total(order) == 160_000
        row(f"lost response, {name}", f"ledger {inr(service.used(order))}, "
            f"provider refunded {inr(provider.total(order))}. Over the limit.")

    service = ReserveThenCall(str(tmp / "keep.db"), endpoint, CEILING, release_on_failure=False)
    provider.stall.add("issue_refund")
    assert service.refund("ord_keep", 80_000) == "failed"  # never applied
    assert service.refund("ord_keep", 80_000) == "exceeded"
    assert service.used("ord_keep") == 80_000 and provider.total("ord_keep") == 0
    row("stalled call, reserve and keep on failure", f"ledger {inr(80_000)}, provider refunded INR 0. "
        "Owed refunds refused until someone edits the row.")

    refunds = ReserveThenCall(str(tmp / "split_refunds.db"), endpoint, CEILING)
    credit = StoreCreditService(str(tmp / "split_credit.db"), endpoint, CEILING)
    assert refunds.refund("ord_split", 80_000) == "refunded"
    assert credit.refund("ord_split", 80_000) == "refunded"
    assert provider.total("ord_split") == 160_000
    row("refund + store credit, two databases", f"each within its own ceiling; customer paid "
        f"{inr(provider.total('ord_split'))}. Over the limit.")
    print("  Every lock held. The order's limit did not, because the money moves outside the database.\n")


def capability(name, adapter):
    """A manifest in the shape of the quickstart's refund, with a short timeout."""
    manifest = json.loads((EXAMPLE / "capabilities/issue_refund.json").read_text())
    manifest.update({
        "capability_id": f"{adapter}.{name}", "adapter_id": adapter, "protocol_tool": name,
        "desired_effect": name, "description": name.replace("_", " ").capitalize() + ".",
        "timeout_ms": TIMEOUT_MS, "capability_ref": {**manifest["capability_ref"], "artifact_id": name},
    })
    return manifest


def configure(tmp, port, services):
    manifests = [capability("issue_refund", "adp_payments"), capability("grant_store_credit", "adp_loyalty")]
    paths = []
    for manifest in manifests:
        path = tmp / f"{manifest['capability_id']}.json"
        path.write_text(json.dumps(manifest))
        paths.append(str(path))

    # The pack surfaces the loyalty system's tool beside the payment provider's.
    pack = json.loads((EXAMPLE / "pack.json").read_text())
    pack["pack_meta"]["pack_version"] = "5.2.1"
    tooling = pack["tooling_layer"]
    payments = next(a for a in tooling["adapter_registry"] if a["adapter_id"] == "adp_payments")
    tooling["adapter_registry"].append({
        **copy.deepcopy(payments), "adapter_id": "adp_loyalty", "endpoint_ref": "internal://loyalty",
        "capabilities": ["grant_store_credit"],
        "capability_risks": {"grant_store_credit": payments["capability_risks"]["issue_refund"]}})
    tooling["permissions"].append({"permission_id": "p_store_credit", "adapter_id": "adp_loyalty",
                                   "capability": "grant_store_credit", "allow": True})
    (tmp / "pack.json").write_text(json.dumps(pack))

    config = (EXAMPLE / "contextosd.toml").read_text()
    config = config.replace('packs = ["examples/support-refund/pack.json"]', f'packs = ["{tmp / "pack.json"}"]')
    config = config.replace(
        'capabilities = ["examples/support-refund/capabilities/issue_refund.json", '
        '"examples/support-refund/capabilities/lookup_order.json"]',
        "capabilities = " + json.dumps(paths + [str(EXAMPLE / "capabilities/lookup_order.json")]))
    config = config.replace("127.0.0.1:8080", f"127.0.0.1:{port}")
    config = config.replace("sha256:REPLACED_BY_RUN_SH", "sha256:" + hashlib.sha256(KEY.encode()).hexdigest())
    config = config.replace('"dispatch", "audit:read"', '"dispatch", "reconcile", "audit:read"')
    for old, service in zip(range(7701, 7705), services):
        config = config.replace(f"127.0.0.1:{old}", f"127.0.0.1:{service.server_port}")
    config = config.replace('[[adapters]]\nid = "adp_orders"',
                            f'[[adapters]]\nid = "adp_loyalty"\nkind = "mcp"\n'
                            f'endpoint = "http://127.0.0.1:{services[3].server_port}/mcp"\n\n'
                            '[[adapters]]\nid = "adp_orders"')
    # One business limit across two systems: everything paid back on an order.
    config += f'''
[[guarantees]]
id = "compensation-per-order"
capability_ids = ["adp_payments.issue_refund", "adp_loyalty.grant_store_credit"]
resource_pointer = "/order_id"
amount_pointer = "/amount_minor"
limit = {CEILING}
unit = "INR_minor"
'''
    (tmp / "runtime.toml").write_text(config)


def governed(provider, client, tmp):
    print("Part 2: the same faults through ContextOS, one guarantee over both tools")
    template = json.loads((EXAMPLE / "requests/run.json").read_text())
    template["pack_ref"] = "ctxpack.support@5.2.1"
    template["request"]["input"]["context"]["refund_amount"] = 800

    def admit(run_id, agent):
        body = copy.deepcopy(template)
        for part in ("run_context", "contract"):
            body[part]["run_id"] = run_id
        body["contract"]["contract_id"] = f"contract_{run_id}"
        body["request"]["request_id"] = f"req_{run_id}"
        for context in (body["request"], body["run_context"]):
            context["agent"]["agent_id"] = agent
            context["agent"]["workload_identity"] = f"spiffe://contextos/agents/{agent}"
        return client.admit(body)

    def call(run, capability_id, amount, key, order="ord_881"):
        args = {"order_id": order, "customer_id": "cus_77", "amount_minor": amount}
        return run.call_tool(capability_id, args, approval_mode="destructive", idempotency_key=key)

    def refused(run, capability_id, amount, key):
        try:
            call(run, capability_id, amount, key)
        except ToolOutcome as outcome:
            assert outcome.reason_codes == ["shared_guarantee_exceeded"], outcome.reason_codes
            return
        raise AssertionError(f"{capability_id} {amount} must be withheld")

    def balance(order="ord_881"):
        resource = "sha256:" + hashlib.sha256(json.dumps(order).encode()).hexdigest()
        view = client.request("GET", f"/v1/guarantees/compensation-per-order/resources/{resource}")
        return view["committed"], view["held"], view["available"]

    email = admit("run_email", "support_email")
    provider.lose.add("issue_refund")
    try:
        call(email, "adp_payments.issue_refund", 80_000, "refund:email")
        raise AssertionError("a lost response must not complete")
    except ToolPaused as paused:
        assert paused.kind == "unknown_outcome", (paused.kind, paused.reason_codes)
        operation = paused.operation_id
    assert balance() == (0, 80_000, 20_000), balance()
    print(f"  {'lost response, ord_881':<50} unknown: {inr(80_000)} held, {inr(20_000)} available")

    chat = admit("run_chat", "support_chat")
    refused(chat, "adp_payments.issue_refund", 80_000, "refund:chat")
    loyalty = admit("run_loyalty", "loyalty_agent")
    refused(loyalty, "adp_loyalty.grant_store_credit", 80_000, "credit:loyalty")
    assert provider.total("ord_881") == 80_000, provider.applied
    print(f"  {'second agent, refund INR 800':<50} withheld before dispatch (shared_guarantee_exceeded)")
    print(f"  {'third agent, store credit INR 800':<50} withheld before dispatch: another system, one limit")

    evidence = {"artifact_type": "provider_ledger", "artifact_id": "psp-settlement-2026-10-28", "version": "1",
                "sha256": "sha256:" + hashlib.sha256(b"refund ord_881 INR 800 applied").hexdigest()}
    resolved = email.reconcile(operation, outcome="confirmed", evidence_ref=evidence)
    assert resolved["status"] == "resolved", resolved
    assert balance() == (80_000, 0, 20_000), balance()
    print(f"  {'reconciled from the provider ledger':<50} confirmed: {inr(80_000)} committed")

    # A stalled call that never applied: held until evidence says so, then released once.
    stalled = admit("run_stalled", "support_email")
    provider.stall.add("issue_refund")
    try:
        call(stalled, "adp_payments.issue_refund", 50_000, "refund:stalled", order="ord_882")
        raise AssertionError("a stalled call must not complete")
    except ToolPaused as paused:
        assert paused.kind == "unknown_outcome", (paused.kind, paused.reason_codes)
        operation = paused.operation_id
    assert balance("ord_882") == (0, 50_000, 50_000), balance("ord_882")
    absent = {**evidence, "artifact_id": "psp-settlement-2026-10-28-b",
              "sha256": "sha256:" + hashlib.sha256(b"no refund for ord_882").hexdigest()}
    oncall = Client(client.base_url, token=OPS_KEY)
    oncall.reconcile(stalled.run_id, operation, outcome="not_applied", evidence_ref=absent)
    assert balance("ord_882") == (0, 0, CEILING), balance("ord_882")
    retry = admit("run_stalled_retry", "support_email")
    call(retry, "adp_payments.issue_refund", 50_000, "refund:stalled:retry", order="ord_882")
    assert provider.total("ord_882") == 50_000, provider.applied
    print(f"  {'stalled call, ord_882':<50} held; reconciled not applied, released; retry refunds {inr(50_000)}")

    call(loyalty, "adp_loyalty.grant_store_credit", 20_000, "credit:loyalty:remaining")
    assert balance() == (100_000, 0, 0), balance()
    assert provider.total("ord_881") == CEILING, provider.applied
    print(f"  {'store credit INR 200':<50} applied; customer paid {inr(provider.total('ord_881'))}"
          f" of {inr(CEILING)}")

    entries = client.request("GET", "/v1/audit/entries", query={"from": 1, "limit": 1000})
    keys = client.request("GET", "/v1/audit/keys")
    (tmp / "entries.json").write_text(json.dumps(entries))
    (tmp / "keys.json").write_text(json.dumps(keys))
    verified = subprocess.run([str(BIN / "ctx"), "audit-verify", "--entries", str(tmp / "entries.json"),
                               "--keys", str(tmp / "keys.json")], check=True, capture_output=True, text=True)
    proof = json.loads(verified.stdout)
    assert proof["verified"] is True, proof
    print("  Offline audit verification:", json.dumps(proof, sort_keys=True))


def main():
    spec = importlib.util.spec_from_file_location("development_facts", EXAMPLE / "dev_services.py")
    facts = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(facts)
    provider = Provider()
    services = [serve(handler) for handler in [facts.authority, facts.constraints, facts.approvals, provider]]
    endpoint = f"http://127.0.0.1:{services[3].server_port}/mcp"
    process = None
    try:
        with tempfile.TemporaryDirectory(prefix="contextos-row-lock-") as tmp:
            tmp = Path(tmp)
            baseline(provider, endpoint, tmp)

            with socket.socket() as listener:
                listener.bind(("127.0.0.1", 0))
                port = listener.getsockname()[1]
            configure(tmp, port, services)
            base = f"http://127.0.0.1:{port}"
            with (tmp / "server.log").open("w") as log:
                process = subprocess.Popen(
                    [str(BIN / "contextosd"), "--config", str(tmp / "runtime.toml")],
                    cwd=ROOT, stdout=log, stderr=log,
                    env={**os.environ, "CONTEXTOS_AUDIT_SEED": "11" * 32, "RUST_LOG": "warn"})
                for _ in range(100):
                    if process.poll() is not None:
                        raise RuntimeError((tmp / "server.log").read_text())
                    try:
                        urlopen(base + "/readyz", timeout=1)
                        break
                    except (URLError, OSError):
                        time.sleep(0.1)
                else:
                    raise RuntimeError("Local runtime did not become ready")
                governed(provider, Client(base, token=KEY), tmp)
                print("row lock comparison complete")
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
