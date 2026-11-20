"""One scenario of the Agent Failure Lab against one real gateway: sends each step and
records the request, the gateway's answer, every world's money and the new audit entries."""
import copy
import hashlib
import json
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "bindings/python"))
from contextos.client import operation_key  # noqa: E402

from scenarios import AGENT, CUSTOMER, REFUND  # noqa: E402
from worlds import view  # noqa: E402

OPS_KEY = "dev-ops-0123456789abcdef0123456789abcdef"
SUPPORT = ROOT / "examples/support-refund"


def digest(value):
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return "sha256:" + hashlib.sha256(raw.encode()).hexdigest()


def summarize(response):
    """What the caller's code sees, in the gateway's own fields."""
    result, report, error = response.get("result") or {}, response.get("report") or {}, response.get("error")
    if isinstance(error, dict):  # a refused request, such as a run that is not admitted
        return {"status": "refused", "error": error.get("message"), "reason_codes": error.get("detail") or [error.get("code")]}
    return {k: v for k, v in {
        "status": response.get("status") or result.get("status"),
        "error": result.get("error"),
        "reason_codes": report.get("reason_codes") or response.get("reason_codes"),
        "obligations": report.get("obligations") or response.get("obligations"),
        "outcome": response.get("outcome"),
        "output": result.get("output"),
    }.items() if v not in (None, [], {})}


class Session:
    def __init__(self, scenario, base, key, services, provider, baselines, money):
        self.scenario, self.base, self.key, self.services = scenario, base, key, services
        self.provider, self.baselines, self.money = provider, baselines, money
        self.steps, self.audit_seen, self.generations = [], 0, {}
        self.approved, self.responses, self.actor_resource = set(), {}, None
        self.template = json.loads((SUPPORT / "requests/run.json").read_text())
        self.tool = json.loads((SUPPORT / "requests/tool_call.json").read_text())

    def http(self, url, body=None, *, key=None, generation=None):
        headers = {"Authorization": f"Bearer {key or self.key}", "Content-Type": "application/json"}
        if generation is not None:
            headers["contextos-executor-generation"] = str(generation)
        request = Request(url, headers=headers, data=None if body is None else json.dumps(body).encode())
        try:
            with urlopen(request, timeout=15) as response:
                return response.status, json.loads(response.read())
        except HTTPError as error:
            return error.code, json.loads(error.read() or b"{}")

    def api(self, path, body=None, **kwargs):
        return self.http(self.base + path, body, **kwargs)

    # Requests

    def task_authorization(self, run_id, task):
        """What the customer asked for, fixed by the application before the agent acts."""
        return {"issued_by": {"principal_id": "usr_771", "principal_type": "person",
                              "trust_domain": "contextos.dev", "tenant_id": "tenant_acme_prod"},
                "scopes": [{"root_run_id": run_id, "purpose_ids": ["support.refund"], "capability_ids": [REFUND],
                            "resource_ids": [task["order"]], "destination_ids": [CUSTOMER],
                            "classification_labels": ["CONFIDENTIAL"], "argument_constraints": [],
                            "amount_ceiling": {"minor_units": task["amount"], "currency": "INR"}}]}

    def run_request(self, run_id, order, amount):
        """The admission request for a run: the ticket states one refund on one order."""
        spec = self.scenario.get("runs", {}).get(run_id, {})
        order, amount = spec.get("order", order), spec.get("stated", amount)
        body = copy.deepcopy(self.template)
        body["run_context"]["run_id"] = body["contract"]["run_id"] = run_id
        body["contract"]["contract_id"] = f"contract_{run_id}"
        body["request"]["request_id"] = f"req_{run_id}"
        body["request"]["input"]["message"] = f"Refund order {order} for INR {amount // 100}."
        body["request"]["input"]["context"].update(refund_amount=amount // 100, order_id=order)
        for context in (body["request"], body["run_context"]):
            context["agent"]["agent_id"] = AGENT
        if "task" in spec:
            body["task_authorization"] = self.task_authorization(run_id, spec["task"])
        return body

    def refund_call(self, step):
        args = {"order_id": step["order"], "customer_id": CUSTOMER, "amount_minor": step["amount"]}
        body = copy.deepcopy(self.tool)
        body.update(run_id=step["run"], tool_call_id=step["call"], args=args,
                    principal_chain=[{"kind": "agent", "id": AGENT}],
                    idempotency_key=operation_key(REFUND, args))
        return body

    # What gets recorded

    def audit(self):
        status, page = self.api(f"/v1/audit/entries?from={self.audit_seen + 1}&limit=1000")
        assert status == 200, page
        entries = page["entries"]
        if entries:
            self.audit_seen = entries[-1]["sequence"]
        for entry in entries:  # the per-agent guarantee names its resource only by digest
            binding = (entry.get("payload") or {}).get("binding") or {}
            if binding.get("resource_digest"):
                self.actor_resource = binding["resource_digest"]
        return entries

    def balance(self):
        spec = self.scenario.get("balance")
        if not spec:
            return None
        resource = self.actor_resource if spec["resource"] == "actor" else digest(spec["resource"])
        if resource is None:
            return None
        status, view_ = self.api(f"/v1/guarantees/{spec['guarantee']}/resources/{resource}")
        if status == 404:
            return None
        assert status == 200, view_
        return {k: view_[k] for k in ("limit", "committed", "held", "available")}

    def record(self, step, actor, request, status, response, attempts, outcome=None):
        """`outcome` names what a service that answers without a status did."""
        entries = self.audit()
        gated = view(self.provider.ledger, self.provider.calls, self.money["gated"], self.approved)
        balance = self.balance()
        if balance is not None:
            gated["balance"] = balance
        worlds = {"gated": gated}
        for name, world in self.baselines.items():
            worlds[name] = {**view(world.provider.ledger, world.provider.calls, self.money[name], self.approved),
                            "attempt": attempts.get(name)}
        self.responses[step["step"]] = response
        self.steps.append({
            "step": step["step"], "kind": step["kind"], "actor": actor, "request": request,
            "response": {"http_status": status, "body": response},
            "summary": {"status": outcome} if outcome else summarize(response),
            "worlds": worlds, "audit": [e["sequence"] for e in entries],
        })

    # Steps

    def admit(self, run_id, order, amount):
        body = self.run_request(run_id, order, amount)
        status, admitted = self.api("/v1/runs", body)
        if 200 <= status < 300:
            self.generations[run_id] = admitted["executor_generation"]
        return body, status, admitted

    def attempts(self, step):
        return {name: world.refund(step, self.approved) for name, world in self.baselines.items()}

    def step_refund(self, step):
        """The agent sends one refund; each baseline gets the same attempt."""
        run_id = step["run"]
        if run_id not in self.generations:
            _, status, admitted = self.admit(run_id, step["order"], step["amount"])
            assert 200 <= status < 300, (status, admitted)
            self.audit()  # admission entries are not part of any step
        body, path = self.refund_call(step), f"/v1/runs/{run_id}/tool-calls"
        self.provider.mode = step["mode"]
        status, response = self.api(path, body, generation=self.generations[run_id])
        self.provider.mode = "answer"
        self.record(step, "agent", {"method": "POST", "path": path, "body": body}, status, response,
                    self.attempts(step))

    def step_admit(self, step):
        """The application starts a new run for the agent's next refund. Without a
        gateway there is no admission: the refund is simply sent."""
        body, status, response = self.admit(step["run"], step["order"], step["amount"])
        self.record(step, "application", {"method": "POST", "path": "/v1/runs", "body": body}, status, response,
                    self.attempts(step))

    def step_reconcile(self, step):
        """On-call settles a refund in doubt, citing the provider's ledger export."""
        export = self.provider.export(step["order"])
        raw = json.dumps(export, indent=2, sort_keys=True)
        body = {"source": "operator", "outcome": step["outcome"], "evidence_ref": {
            "artifact_type": "provider_ledger", "artifact_id": f"synthetic_payments_{step['order']}", "version": "1",
            "sha256": "sha256:" + hashlib.sha256(raw.encode()).hexdigest()}}
        args = {"order_id": step["order"], "customer_id": CUSTOMER, "amount_minor": step["amount"]}
        path = f"/v1/runs/{step['run']}/operations/{operation_key(REFUND, args)}/reconcile"
        status, response = self.api(path, body, key=OPS_KEY, generation=self.generations[step["run"]])
        self.record(step, "operator", {"method": "POST", "path": path, "body": body, "evidence": export},
                    status, response, {})

    def step_approve(self, step):
        """A finance lead approves one exact request in the development approval
        service, which approves whatever it is asked to; a real one authenticates the
        reviewer and shows them the action."""
        request_id = self.responses[step["of"]]["report"]["approval_request_id"]
        body = {"op": "approve", "approval_request_id": request_id}
        status, response = self.http(self.services["approvals"], body)
        self.approved.add((step["order"], step["amount"]))
        self.record(step, "reviewer", {"method": "POST", "path": "/", "service": "development approval service",
                                       "body": body}, status, response, {}, "approved")

    def step_restore(self, step):
        """On-call restores the agent the circuit breaker revoked."""
        body = {"kind": "agent", "target": AGENT, "reason": step["reason"]}
        status, response = self.api("/v1/revocations/restore", body, key=OPS_KEY)
        self.record(step, "operator", {"method": "POST", "path": "/v1/revocations/restore", "body": body},
                    status, response, {}, "restored")

    def receipt(self):
        status, entries = self.api("/v1/audit/entries?from=1&limit=1000")
        assert status == 200, entries
        status, keys = self.api("/v1/audit/keys")
        assert status == 200, keys
        return {"entries": entries, "keys": keys}
