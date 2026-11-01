"""What the ``contextosd`` client raises: refused requests, governed tool outcomes that
are not plain success, and an incompatible server. Import them from
``contextos.client``, which re-exports every name here."""
from typing import Any, List, Optional


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


class IncompatibleServer(Exception):
    """The server speaks a different HTTP API generation than this client."""


class VersionMismatchWarning(UserWarning):
    """The server is a different ContextOS release than this client. Releases before
    1.0 may change the API, so use the same release on both sides."""


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


_OUTCOMES = {"paused": ToolPaused, "blocked": ToolBlocked, "rejected": ToolRejected, "failed": ToolFailed}
