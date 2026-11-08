"""Framework adapters for the HTTP client. Each submodule imports its framework, so
import only the one you use:

- ``contextos.integrations.langgraph``: middleware for LangChain ``create_agent``
  (LangGraph) that budgets model calls, reports refusals to the model and turns an
  approval pause into a LangGraph ``interrupt``, safe to resume.
- ``contextos.integrations.openai_agents``: a ``needs_approval`` bridge that raises
  the gateway's own approval as an SDK interruption, and a ``failure_error_function``
  that tells the model what happened.

``describe`` is the framework-neutral part: what to tell a model when the gateway did
not complete a call.
"""
from ..errors import ToolOutcome, ToolPaused

__all__ = ["describe", "stops_the_run"]


def describe(outcome: ToolOutcome) -> str:
    """What a model is told when the gateway did not complete a call: whether anything
    happened, why, and that retrying will not change it."""
    reasons = ", ".join(outcome.reason_codes) or outcome.status
    kind = outcome.kind if isinstance(outcome, ToolPaused) else None
    if kind == "duplicate":
        return f"ALREADY REQUESTED ({reasons}): this exact action was submitted before and was not repeated."
    if kind == "unknown_outcome":
        return f"OUTCOME UNKNOWN ({reasons}): the action may have happened and is being reconciled; do not retry it."
    return f"NOT DONE ({outcome.status}: {reasons}). The action did not take effect; do not retry it."


def stops_the_run(error: Exception) -> bool:
    """Whether a call's failure is for people, not the model: a pause for approval or
    input, an unknown outcome, or a fault that is not a governed outcome. The model
    cannot fix these and must not retry them."""
    if not isinstance(error, ToolOutcome):
        return True
    return isinstance(error, ToolPaused) and error.kind in ("approval", "input", "unknown_outcome")
