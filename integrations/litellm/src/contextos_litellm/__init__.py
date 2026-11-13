"""ContextOS metering for the LiteLLM proxy.

In the proxy's config.yaml::

    litellm_settings:
      callbacks: ["contextos_litellm.metering_handler"]

with ``CONTEXTOS_URL`` and ``CONTEXTOS_METER_TOKEN`` (a token with only the ``meter``
scope) in the proxy's environment. ``metering_handler`` is created, and its settings
checked, when LiteLLM first loads it, so a misconfigured proxy fails at startup.
"""
from __future__ import annotations

from typing import Any, Optional

from .client import Claim, ContextOSRefused, ContextOSUnavailable, Settlement
from .config import ConfigError, Settings
from .handler import METADATA_KEY, RESERVATION_HEADER, RUN_HEADER, ContextOSMetering

__version__ = "0.1.0a21"

__all__ = [
    "Claim", "ConfigError", "ContextOSMetering", "ContextOSRefused", "ContextOSUnavailable", "METADATA_KEY",
    "RESERVATION_HEADER", "RUN_HEADER", "Settings", "Settlement", "metering_handler", "__version__",
]

_handler: Optional[ContextOSMetering] = None


def __getattr__(name: str) -> Any:
    global _handler
    if name == "metering_handler":
        if _handler is None:
            _handler = ContextOSMetering(Settings.from_env())
        return _handler
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
