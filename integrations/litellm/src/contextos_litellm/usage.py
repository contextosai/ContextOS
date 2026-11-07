"""Reading measured usage and cost from what LiteLLM logged for a call."""
from __future__ import annotations

import math
from typing import Any, Mapping, Optional, Tuple


def _int(value: Any) -> Optional[int]:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value >= 0 else None
    if isinstance(value, float) and value.is_integer() and value >= 0:
        return int(value)
    return None


def _field(container: Any, key: str) -> Any:
    if isinstance(container, Mapping):
        return container.get(key)
    return getattr(container, key, None)


def usage_tokens(usage: Any) -> Optional[Tuple[int, int]]:
    """``(input, output)`` tokens from a usage block, or None if it reports none.

    OpenAI-style usage (``prompt_tokens``, also what LiteLLM normalizes every provider
    to) already counts cached prompt tokens. Native Anthropic usage (``input_tokens``)
    counts prompt-cache writes and reads apart, so they are added.
    """
    if usage is None:
        return None
    prompt = _int(_field(usage, "prompt_tokens"))
    if prompt is None:
        prompt = _int(_field(usage, "input_tokens"))
        if prompt is not None:
            prompt += sum(_int(_field(usage, k)) or 0
                          for k in ("cache_creation_input_tokens", "cache_read_input_tokens"))
    output = _int(_field(usage, "completion_tokens"))
    if output is None:
        output = _int(_field(usage, "output_tokens"))
    if prompt is None and output is None:
        return None
    return prompt or 0, output or 0


def measured_tokens(kwargs: Mapping[str, Any], response: Any) -> Optional[Tuple[int, int]]:
    """The call's ``(input, output)`` tokens: the provider's usage block first, then
    LiteLLM's standard logging payload. None when neither reports any token, since a
    served call that used no tokens means the usage is unknown, not zero."""
    candidates = [_field(response, "usage")]
    standard = kwargs.get("standard_logging_object")
    if isinstance(standard, Mapping):
        candidates.append({"prompt_tokens": standard.get("prompt_tokens"),
                           "completion_tokens": standard.get("completion_tokens")})
    for candidate in candidates:
        tokens = usage_tokens(candidate)
        if tokens is not None and sum(tokens) > 0:
            return tokens
    return None


def response_cost(kwargs: Mapping[str, Any]) -> Optional[float]:
    """LiteLLM's computed cost of the call in USD, or None when it could not price the
    call (its standard payload then reports a cost of 0 and the failure separately)."""
    standard = kwargs.get("standard_logging_object") or {}
    if kwargs.get("response_cost_failure_debug_information") or standard.get("response_cost_failure_debug_info"):
        return None
    value = kwargs["response_cost"] if "response_cost" in kwargs else standard.get("response_cost")
    if isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value) and value >= 0:
        return float(value)
    return None


def cost_cents(usd: float) -> int:
    """Whole cents, rounded up per call (a fraction of a cent is still spent); float
    noise below a millionth of a cent is ignored."""
    return math.ceil(round(usd * 100, 6))
