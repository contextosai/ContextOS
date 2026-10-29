"""ContextOS kernel for Python, in-process.

The kernel is pure and deterministic: no I/O, no clock, no randomness. Verdicts
(deny, rejected, insufficient evidence) are returned as results; ``ContextOSError``
is raised only for unusable input.

    import contextos
    compiled = contextos.compile(pack=pack, request=request, run_context=run_context)
    decision = contextos.evaluate_authorization(authorization_input)
"""

import json
from typing import Any, Optional

try:
    from . import _native
except ImportError:  # the HTTP client (contextos.client) works without the extension
    _native = None

__version__ = getattr(_native, "__version__", "0.1.0-alpha.3")


class ContextOSError(Exception):
    """Raised when the kernel cannot evaluate the input."""

    def __init__(self, code: str, message: str, detail: Any = None):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.detail = detail


def call(operation: str, payload: Any) -> Any:
    """Runs one kernel operation; see the embed facade for the operation list."""
    if _native is None:
        raise ContextOSError("native_unavailable", "the in-process kernel is not built; install the wheel or run maturin develop")
    response = json.loads(_native.call(operation, json.dumps(payload, allow_nan=False)))
    if "error" in response:
        error = response["error"]
        raise ContextOSError(error.get("code", "error"), error.get("message", ""), error.get("detail"))
    return response["ok"]


def compile(pack: dict, request: dict, run_context: dict, deps: Optional[dict] = None) -> dict:
    """Compiles a Context Pack into a CompiledContext."""
    return call("compile", {"pack": pack, "request": request, "run_context": run_context, "deps": deps or {}})


def evaluate_authorization(authorization_input: dict) -> dict:
    """Conjunctive authorization of one action binding."""
    return call("evaluate_authorization", authorization_input)


def digest_action_binding(binding: dict) -> str:
    """RFC 8785 digest of an ActionBinding."""
    return call("digest_action_binding", binding)["action_digest"]


def negotiate(contract: dict, support: dict, features: dict) -> dict:
    """Negotiates an execution contract against the standard profile registry."""
    return call("negotiate", {"contract": contract, "support": support, "features": features})


def validate(schema: str, instance: Any, definition: Optional[str] = None) -> dict:
    """Validates a payload against a published ContextOS schema."""
    return call("validate", {"schema": schema, "def": definition, "instance": instance})


def canonicalize(value: Any) -> dict:
    """RFC 8785 canonical JSON and its sha256 digest."""
    return call("canonicalize", value)


__all__ = [
    "ContextOSError", "call", "compile", "evaluate_authorization", "digest_action_binding",
    "negotiate", "validate", "canonicalize", "__version__",
]
