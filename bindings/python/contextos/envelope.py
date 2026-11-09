"""Request bodies the client builds: task authorizations, and the operation key a
call gets when the caller names none. Import them from ``contextos.client``, which
re-exports every name here."""
import hashlib
import json
from typing import Any, Dict, List, Optional, Tuple


def operation_key(capability_id: str, args: Any) -> str:
    """The operation key of a call that changes something and names no key: a digest of
    the capability and its canonical arguments, so the same call re-sent (a retried
    step, a LangGraph node re-run on resume, a call re-sent once its approval is
    granted) is the same operation and cannot apply twice. Identical calls that are
    distinct effects (two equal top-ups) need keys of their own."""
    canonical = json.dumps({"capability": capability_id, "arguments": args}, sort_keys=True,
                           separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    return "call:" + hashlib.sha256(canonical.encode()).hexdigest()[:32]


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
