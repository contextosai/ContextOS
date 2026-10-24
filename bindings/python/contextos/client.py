"""HTTP client for ``contextosd``: govern an agent's tool calls from Python.

Standard library only. Typical use::

    from contextos.client import Client, governed_tool

    client = Client("https://contextos.internal", token=os.environ["CONTEXTOS_TOKEN"])
    run = client.admit(admission_body)          # holds the executor generation
    result = run.call_tool("adp_payments.issue_refund",
                           {"order_id": "ord_881", "amount_minor": 1200},
                           idempotency_key="refund:ord_881",
                           approval_mode="destructive",
                           evidence_refs=["kg:order:ord_881#snapshot"])

    @governed_tool(run, "adp_orders.lookup", approval_mode="read_only")
    def lookup_order(order_id: str): ...     # body never runs; the gateway dispatches

Results that are not plain success raise typed exceptions, so agent code cannot
mistake a pause, a refusal or an unknown outcome for a result:

- ``ToolPaused``: approval pending, input required, or the outcome is unknown and
  must be reconciled (never retry it blindly);
- ``ToolBlocked``: authority, policy, constraints or budget refused it;
- ``ToolRejected``: malformed, unsurfaced or incompatible reuse;
- ``ToolFailed``: the provider definitively did not apply the effect.

A model-call reservation the run cannot afford raises ``BudgetExhausted``. For asyncio
agents, ``contextos.aio`` has the same client as coroutines.

The client retries only requests the server did not process (``429``, ``503``),
honouring ``Retry-After``. It never retries a tool call after a lost response on
its own: the gateway's operation ledger makes a retry with the same idempotency key
safe, but deciding to retry is the caller's.
"""

import contextlib
import functools
import inspect
import json
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from typing import Any, Callable, Dict, Iterator, List, Optional, Tuple

GENERATION_HEADER = "ContextOS-Executor-Generation"
# On a model request, these tell a metering LLM gateway which reservation to settle
# with the usage it measures (see examples/metering-proxy).
RUN_HEADER = "ContextOS-Run-Id"
RESERVATION_HEADER = "ContextOS-Usage-Reservation"


class ContextOSHTTPError(Exception):
    """The server refused the request (4xx/5xx other than a governed tool result)."""

    def __init__(self, status: int, code: str, message: str, detail: Any = None):
        super().__init__(f"{status} {code}: {message}")
        self.status = status
        self.code = code
        self.detail = detail


class BudgetExhausted(ContextOSHTTPError):
    """The run's budget cannot fit a model-call or replan reservation (``reasons``
    says which limit). Stop the loop: retrying the same reservation cannot succeed."""

    @property
    def reasons(self) -> List[str]:
        return self.detail if isinstance(self.detail, list) else []


_HTTP_ERRORS = {"budget_exhausted": BudgetExhausted}


class ToolOutcome(Exception):
    """A governed tool call that did not simply succeed."""

    def __init__(self, result: dict, report: dict):
        self.result = result
        self.report = report
        self.status = result.get("status")
        self.reason_codes: List[str] = report.get("reason_codes", [])
        self.obligations: List[str] = report.get("obligations", [])
        self.operation_id: Optional[str] = report.get("operation_id")
        super().__init__(f"{self.status}: {', '.join(self.reason_codes) or result.get('error') or ''}")


class ToolPaused(ToolOutcome):
    """Approval pending, input required, or an unknown outcome awaiting reconciliation."""

    @property
    def kind(self) -> str:
        """What the pause waits on: ``approval`` (redeem by re-sending the same call once
        approved), ``input`` (answer with ``provide_input``), ``unknown_outcome`` (the
        effect may have happened: reconcile), ``duplicate`` (this operation was already
        requested and is not repeated) or ``other``."""
        return _pause_kind(self.obligations, self.reason_codes)

    @property
    def input_requests(self) -> Optional[dict]:
        return (self.result.get("output") or {}).get("result", {}).get("inputRequests")


class ToolBlocked(ToolOutcome):
    """Authority, policy, constraints or budget refused the call."""


class ToolRejected(ToolOutcome):
    """The call was malformed, not surfaced to this run, or reused an operation key."""


class ToolFailed(ToolOutcome):
    """The provider definitively did not apply the effect."""


def _pause_kind(obligations: List[str], reason_codes: List[str]) -> str:
    if "await_approval" in obligations:
        return "approval"
    if "provide_requested_input" in obligations:
        return "input"
    if "reconcile_effect_before_retry" in obligations:
        return "unknown_outcome"
    if "retry_unsafe" in reason_codes or "reconcile_existing_operation" in obligations:
        return "duplicate"
    return "other"


def task_scope(root_run_id: str, purpose_id: str, capability_id: str, *, resources: List[str] = (),
               destinations: List[str] = (), classification: str = "CONFIDENTIAL",
               amount: Optional[tuple] = None, argument_constraints: List[dict] = ()) -> dict:
    """One `AuthorityGrant` scope for a task authorization: this capability, on these
    resources, to these destinations, up to ``amount`` = ``(minor_units, currency)``."""
    scope: Dict[str, Any] = {
        "root_run_id": root_run_id, "purpose_ids": [purpose_id], "capability_ids": [capability_id],
        "resource_ids": list(resources), "destination_ids": list(destinations),
        "classification_labels": [classification], "argument_constraints": list(argument_constraints)}
    if amount is not None:
        scope["amount_ceiling"] = {"minor_units": amount[0], "currency": amount[1]}
    return scope


def task_authorization(issued_by: dict, scopes: List[dict], *, out_of_scope: str = "deny",
                       read_only: str = "allow", confirmation_ref: Optional[dict] = None,
                       max_effects: Optional[int] = None, amount_total: Optional[Tuple[int, str]] = None) -> dict:
    """What the principal authorized for a run, for ``admit(body)`` as
    ``body["task_authorization"]``. Effects outside every scope are refused
    (``out_of_scope="deny"``) or wait for an exact approval (``"ask"``, raised as
    ``ToolPaused`` with ``kind == "approval"``). ``max_effects`` and ``amount_total``
    (``(minor_units, currency)``) bound the task as a whole, across all its effects."""
    task: Dict[str, Any] = {"issued_by": issued_by, "scopes": scopes, "out_of_scope": out_of_scope,
                            "read_only": read_only}
    if confirmation_ref is not None:
        task["confirmation_ref"] = confirmation_ref
    limits: Dict[str, Any] = {}
    if max_effects is not None:
        limits["max_effects"] = max_effects
    if amount_total is not None:
        limits["amount_total"] = {"minor_units": amount_total[0], "currency": amount_total[1]}
    if limits:
        task["limits"] = limits
    return task


_OUTCOMES = {"paused": ToolPaused, "blocked": ToolBlocked, "rejected": ToolRejected, "failed": ToolFailed}


class Client:
    """A connection to one ``contextosd`` deployment, authenticated as one caller."""

    def __init__(self, base_url: str, token: str, timeout: float = 30.0, max_retries: int = 3):
        self.base_url = base_url.rstrip("/")
        self._token = token
        self.timeout = timeout
        self.max_retries = max_retries

    def __repr__(self) -> str:  # never print the token
        return f"Client({self.base_url!r})"

    def request(self, method: str, path: str, body: Any = None, generation: Optional[int] = None,
                query: Optional[Dict[str, Any]] = None) -> Any:
        url = self.base_url + path
        if query:
            url += "?" + urllib.parse.urlencode(query)
        data = None if body is None else json.dumps(body, allow_nan=False).encode()
        headers = {"Authorization": f"Bearer {self._token}", "Accept": "application/json"}
        if data is not None:
            headers["Content-Type"] = "application/json"
        if generation is not None:
            headers[GENERATION_HEADER] = str(generation)
        for attempt in range(self.max_retries + 1):
            request = urllib.request.Request(url, data=data, method=method, headers=headers)
            try:
                with urllib.request.urlopen(request, timeout=self.timeout) as response:
                    payload = response.read()
                    return json.loads(payload) if payload else None
            except urllib.error.HTTPError as error:
                payload = error.read()
                try:
                    decoded = json.loads(payload) if payload else {}
                except ValueError:
                    decoded = {}
                # Not processed: safe to retry after the server's hint.
                if error.code in (429, 503) and attempt < self.max_retries:
                    time.sleep(_retry_after(error.headers.get("Retry-After"), attempt))
                    continue
                failure = decoded.get("error") if isinstance(decoded, dict) else None
                if isinstance(failure, dict):
                    code = failure.get("code", "error")
                    raise _HTTP_ERRORS.get(code, ContextOSHTTPError)(error.code, code, failure.get("message", ""),
                                                                     failure.get("detail")) from None
                # Lifecycle refusals return their outcome body with 409.
                raise ContextOSHTTPError(error.code, "refused", json.dumps(decoded), decoded) from None
        raise AssertionError("unreachable")

    def admit(self, body: dict, principal_chain: Optional[List[dict]] = None) -> "Run":
        """Admits a run (``POST /v1/runs``) and returns a handle that owns it."""
        admitted = self.request("POST", "/v1/runs", body)
        context = body.get("run_context", {})
        agent = (context.get("agent") or {}).get("agent_id")
        chain = principal_chain or ([{"kind": "agent", "id": agent}] if agent else [])
        return Run(self, admitted["run_id"], context.get("trace_id", ""), admitted["executor_generation"], chain,
                   admitted)

    def attach(self, run_id: str, trace_id: str, principal_chain: List[dict]) -> "Run":
        """A handle on an existing run, at its current generation (no takeover)."""
        status = self.request("GET", f"/v1/runs/{_quote(run_id)}")
        return Run(self, run_id, trace_id, status["executor_generation"], principal_chain, status)

    def amend_task_authorization(self, run_id: str, expected_revision: int, task: dict) -> dict:
        """Corrects what a run's principal authorized. Narrowing is open to the executor;
        widening needs an ``authorize`` token that does not run tasks, the principal's
        ``confirmation_ref`` and the same ``issued_by``. Returns the new revision."""
        return self.request("PUT", f"/v1/runs/{_quote(run_id)}/task-authorization",
                            {"expected_revision": expected_revision, "task_authorization": task})

    def score(self, run_id: str, record_id: str, evaluator_ref: str, *, policy: float, utility: float,
              safety: float) -> dict:
        """Scores a recorded decision as an independent evaluator (a client whose token
        has only the `evaluate` scope). The runtime adds the measured cost and latency."""
        return self.request("POST", f"/v1/runs/{_quote(run_id)}/decisions/{_quote(record_id)}/scores",
                            {"evaluator_ref": evaluator_ref, "policy": policy, "utility": utility, "safety": safety})

    def file_feedback(self, run_id: str, kind: str, target_surface: str, summary: str, *,
                      decision_record_id: Optional[str] = None, expected_outcome: Optional[str] = None) -> dict:
        """Files an operator correction or override against a run as an independent
        reviewer (`evaluate` scope); the run's replay case becomes its replay obligation."""
        body: Dict[str, Any] = {"kind": kind, "target_surface": target_surface, "summary": summary}
        if decision_record_id is not None:
            body["decision_record_id"] = decision_record_id
        if expected_outcome is not None:
            body["expected_outcome"] = expected_outcome
        return self.request("POST", f"/v1/runs/{_quote(run_id)}/feedback", body)

    def open_escalations(self, limit: int = 500) -> dict:
        """The tenant's open policy escalations, oldest first (`audit:read`)."""
        return self.request("GET", "/v1/escalations", query={"limit": limit})

    def resolve_escalation(self, escalation_id: str, resolution: str, reason: str) -> dict:
        """Records how a human resolved an escalation, `handled` or `dismissed` (`control`).
        Grants nothing: an action the human approves is retried through policy."""
        return self.request("POST", f"/v1/escalations/{_quote(escalation_id)}/resolve",
                            {"resolution": resolution, "reason": reason})

    def open_feedback(self, limit: int = 500) -> dict:
        """The tenant's open feedback, oldest first: the replay corpus a change must pass."""
        return self.request("GET", "/v1/feedback", query={"limit": limit})

    def close_feedback(self, feedback_id: str, status: str, *, artifact_type: str, artifact_id: str,
                       sha256: str) -> dict:
        """Closes feedback as fixed, still_failing, invalid or superseded, with a reference
        to the evidence (`control` scope)."""
        return self.request("POST", f"/v1/feedback/{_quote(feedback_id)}/close", {
            "status": status,
            "evidence_ref": {"artifact_type": artifact_type, "artifact_id": artifact_id, "sha256": sha256}})

    def revoke(self, kind: str, target: str, reason: str) -> dict:
        """Kill switch (a client whose token has the `control` scope): revokes a `tenant`,
        `pack`, `agent`, `adapter` or `capability` from the next dispatch and admission."""
        return self.request("POST", "/v1/revocations", {"kind": kind, "target": target, "reason": reason})

    def restore(self, kind: str, target: str, reason: str) -> dict:
        """Restores a revoked target."""
        return self.request("POST", "/v1/revocations/restore", {"kind": kind, "target": target, "reason": reason})

    def revocations(self) -> dict:
        """The tenant's revoked targets."""
        return self.request("GET", "/v1/revocations")

    def audit_entries(self, start: int = 1, page: int = 500):
        """Yields the tenant's signed audit entries in order."""
        cursor: Optional[int] = start
        while cursor is not None:
            batch = self.request("GET", "/v1/audit/entries", query={"from": cursor, "limit": page})
            yield from batch["entries"]
            cursor = batch.get("next")


class Run:
    """One admitted run, held by this executor at ``executor_generation``."""

    def __init__(self, client: Client, run_id: str, trace_id: str, executor_generation: int,
                 principal_chain: List[dict], admitted: Optional[dict] = None):
        self.client = client
        self.run_id = run_id
        self.trace_id = trace_id
        self.executor_generation = executor_generation
        self.principal_chain = principal_chain
        self.admitted = admitted or {}

    def __repr__(self) -> str:
        return f"Run({self.run_id!r}, generation={self.executor_generation})"

    def _path(self, suffix: str = "") -> str:
        return f"/v1/runs/{_quote(self.run_id)}{suffix}"

    def _post(self, suffix: str, body: Any = None) -> Any:
        return self.client.request("POST", self._path(suffix), body if body is not None else {},
                                   generation=self.executor_generation)

    def envelope(self, capability_id: str, args: dict, *, approval_mode: str, idempotency_key: Optional[str] = None,
                 evidence_refs: Optional[List[str]] = None, tool_call_id: Optional[str] = None) -> dict:
        """The ``contextos.tool_call.v1`` envelope for a call."""
        return {
            "envelope_version": "contextos.tool_call.v1",
            "tool_call_id": tool_call_id or f"tc_{uuid.uuid4().hex}",
            "run_id": self.run_id, "trace_id": self.trace_id, "capability_id": capability_id, "args": args,
            "principal_chain": self.principal_chain, "approval_mode_requested": approval_mode,
            "approval_mode_effective": approval_mode, "approval_mode_highest": approval_mode,
            "evidence_refs": evidence_refs or [], "idempotency_key": idempotency_key,
        }

    def call_tool(self, capability_id: str, args: dict, *, approval_mode: str = "read_only",
                  idempotency_key: Optional[str] = None, evidence_refs: Optional[List[str]] = None,
                  tool_call_id: Optional[str] = None) -> dict:
        """Governs and dispatches one tool call; returns its output or raises a ``ToolOutcome``."""
        envelope = self.envelope(capability_id, args, approval_mode=approval_mode, idempotency_key=idempotency_key,
                                 evidence_refs=evidence_refs, tool_call_id=tool_call_id)
        return _outcome(self._post("/tool-calls", envelope))

    def provide_input(self, paused: ToolPaused, envelope: dict, responses: dict) -> dict:
        """Answers a tool's input requests and continues the same operation."""
        body = {"tool_call": envelope, "input_responses": responses}
        return _outcome(self._post(f"/operations/{_quote(paused.operation_id or '')}/input", body))

    def reconcile(self, operation_id: str, *, outcome: Optional[str] = None,
                  evidence_ref: Optional[dict] = None) -> dict:
        """Resolves an unknown effect: by provider query, or by asserting ``outcome`` with evidence."""
        body = {"source": "provider"} if outcome is None else \
            {"source": "operator", "outcome": outcome, "evidence_ref": evidence_ref}
        return self._post(f"/operations/{_quote(operation_id)}/reconcile", body)

    def record_decision(self, decision_key: str, status: str, *, decision_version: str = "1",
                        outcome: Optional[str] = None, tool_calls: Optional[List[dict]] = None, **fields: Any) -> dict:
        """Records a DecisionRecord; returns ``{"record", "replay_packet"}``."""
        body = {"decision_key": decision_key, "decision_version": decision_version, "status": status,
                "tool_calls": tool_calls or [], **fields}
        if outcome is not None:
            body["outcome"] = outcome
        return self._post("/decisions", body)

    def delegate(self, child_admission: dict, envelope: dict) -> "Run":
        """Admits a child run in a narrowed lane (``AgentDelegationEnvelope``). Its
        budget is reserved from this run; this run must hold the current generation."""
        body = dict(child_admission, delegation=envelope)
        admitted = self.client.request("POST", "/v1/runs", body, generation=self.executor_generation)
        context = child_admission.get("run_context", {})
        return Run(self.client, admitted["run_id"], context.get("trace_id", self.trace_id), admitted["executor_generation"],
                   self.principal_chain, admitted)

    def close_child(self, child: "Run", decision: str = "accept") -> dict:
        """Closes a delegated child, settling its spend into this run."""
        return self.client.request("POST", f"/v1/runs/{_quote(child.run_id)}/close", {"decision": decision},
                                   generation=self.executor_generation)

    def checkpoint(self, state: Any, expected_revision: int) -> dict:
        """Saves the orchestrator's state as the next checkpoint revision."""
        return self._post("/checkpoint", {"expected_revision": expected_revision, "state": state})

    def latest_checkpoint(self) -> dict:
        """The latest checkpoint (`state`, `revision`), e.g. after taking the run over."""
        return self.client.request("GET", self._path("/checkpoint"), generation=self.executor_generation)

    def reserve_usage(self, kind: str, *, tokens: int = 0, cost_cents: int = 0) -> str:
        """Reserves budget for a `model_call` or a `replan`; returns the reservation id."""
        return self._post("/usage/reserve", {"kind": kind, "tokens": tokens, "cost_cents": cost_cents})["reservation_id"]

    def settle_usage(self, reservation_id: str) -> dict:
        """Settles a reservation as the executor: the whole reservation is charged. Pass
        the reservation id to your metering gateway instead to settle measured usage."""
        return self._post("/usage/settle", {"reservation_id": reservation_id})

    def metering_headers(self, reservation_id: str) -> Dict[str, str]:
        """Headers for a model request that a metering LLM gateway settles with the
        usage it measures (``budgeted_model_call(..., metered=True)``)."""
        return {RUN_HEADER: self.run_id, RESERVATION_HEADER: reservation_id}

    @contextlib.contextmanager
    def budgeted_model_call(self, *, tokens: int, cost_cents: int = 0, metered: bool = False) -> Iterator[str]:
        """Reserves budget for one model call and settles it afterwards, even if the call
        raises. Raises ``BudgetExhausted`` before the call when the run cannot afford it.

        ``metered=True`` leaves settlement to a metering LLM gateway (send
        ``metering_headers(reservation)`` with the model request), which charges what it
        measured. If the call raises, a reservation the gateway did not settle is settled
        here, charging all of it: unknown usage is never free."""
        reservation = self.reserve_usage("model_call", tokens=tokens, cost_cents=cost_cents)
        try:
            yield reservation
        except BaseException:
            if metered:
                self._settle_open(reservation)
            else:
                self.settle_usage(reservation)
            raise
        if not metered:
            self.settle_usage(reservation)

    def _settle_open(self, reservation_id: str) -> None:
        try:
            self.settle_usage(reservation_id)
        except ContextOSHTTPError as error:
            if error.status != 404:  # 404: already settled by the gateway
                raise

    def status(self) -> dict:
        return self.client.request("GET", self._path())

    def take_over(self) -> "Run":
        """Takes the run over from whichever executor held it; the old one becomes stale."""
        current = self.status()["executor_generation"]
        taken = self.client.request("POST", self._path("/takeover"), {"expected_generation": current})
        self.executor_generation = taken["executor_generation"]
        return self

    def complete(self) -> dict:
        return self._post("/complete")

    def fail(self) -> dict:
        return self._post("/fail")

    def cancel(self) -> dict:
        return self.client.request("POST", self._path("/cancel"), {})

    def evidence(self) -> dict:
        return self.client.request("GET", self._path("/evidence"))


def governed_tool(run: Run, capability_id: str, *, approval_mode: str = "read_only",
                  idempotency_key: Optional[Callable[..., str]] = None,
                  evidence_refs: Optional[List[str]] = None,
                  tool_call_id: Optional[Callable[..., str]] = None) -> Callable[[Callable[..., Any]], Callable[..., dict]]:
    """Turns a tool's signature into a governed call: arguments are bound by name and
    sent through the gateway; the decorated body never runs locally.

    ``idempotency_key`` derives the operation key from the call's arguments, so a
    retried agent step maps to the same operation and cannot apply twice.
    ``tool_call_id`` derives the call's id the same way, so a DecisionRecord can cite it.
    With an ``AsyncRun`` (``contextos.aio``) the governed function is a coroutine.
    """

    def wrap(function: Callable[..., Any]) -> Callable[..., Any]:
        signature = inspect.signature(function)

        def dispatch(args: Any, kwargs: Any) -> Any:
            bound = signature.bind(*args, **kwargs)
            bound.apply_defaults()
            arguments = dict(bound.arguments)
            key = idempotency_key(**arguments) if idempotency_key else None
            call_id = tool_call_id(**arguments) if tool_call_id else None
            return run.call_tool(capability_id, arguments, approval_mode=approval_mode, idempotency_key=key,
                                 evidence_refs=evidence_refs, tool_call_id=call_id)

        if inspect.iscoroutinefunction(run.call_tool):
            @functools.wraps(function)
            async def call_async(*args: Any, **kwargs: Any) -> dict:
                return await dispatch(args, kwargs)

            return call_async

        @functools.wraps(function)
        def call(*args: Any, **kwargs: Any) -> dict:
            return dispatch(args, kwargs)

        return call

    return wrap


def _outcome(response: dict) -> dict:
    result, report = response["result"], response["report"]
    status = result.get("status")
    if status in ("ok", "completed"):
        return result.get("output") or {}
    raise _OUTCOMES.get(status, ToolOutcome)(result, report)


def _retry_after(header: Optional[str], attempt: int) -> float:
    try:
        return min(float(header), 30.0) if header else min(0.2 * 2 ** attempt, 5.0)
    except ValueError:
        return min(0.2 * 2 ** attempt, 5.0)


def _quote(segment: str) -> str:
    if segment in ("", ".", ".."):
        raise ValueError(f"invalid path segment {segment!r}")
    return urllib.parse.quote(segment, safe="")
