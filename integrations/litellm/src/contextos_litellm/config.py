"""Settings, from the environment of the LiteLLM proxy process."""
from __future__ import annotations

import os
import urllib.parse
from dataclasses import dataclass
from typing import Mapping, Optional

_TRUE = {"1", "true", "yes", "on"}
_FALSE = {"0", "false", "no", "off"}
PRICE_SOURCES = ("litellm", "none")


class ConfigError(ValueError):
    """The plugin is misconfigured; raised at startup so the proxy does not serve
    model calls it cannot govern."""


@dataclass(frozen=True)
class Settings:
    """How the plugin reaches contextosd and governs calls.

    ``url`` and ``meter_token`` are required. The token must carry only the ``meter``
    scope: contextosd treats usage reported by such a principal as measured.
    """

    url: str
    meter_token: str
    # Refuse model calls that carry no reservation (403). Turn off only on a proxy that
    # also serves traffic ContextOS does not govern.
    require_reservation: bool = True
    # Seconds for each contextosd request.
    timeout: float = 5.0
    # "litellm": charge LiteLLM's computed response cost; "none": do not measure cost
    # (the reservation's cost is charged in full).
    price_source: str = "litellm"
    # Lower the request's output-token limit to what the reservation covers.
    cap_output_tokens: bool = True
    # Settlement retries (5xx, 429, network) with exponential backoff and jitter.
    settle_attempts: int = 8
    settle_backoff: float = 0.5
    settle_backoff_max: float = 30.0
    # Settlements waiting to be sent, and the workers sending them.
    queue_size: int = 10_000
    workers: int = 4
    # Seconds a claimed call is remembered while it runs; a call that outlives it is
    # left unsettled (the run's executor then settles the whole reservation).
    claim_ttl: float = 3_600.0
    max_open_claims: int = 100_000

    def __post_init__(self) -> None:
        parsed = urllib.parse.urlparse(self.url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise ConfigError(f"CONTEXTOS_URL must be an http(s) URL, not {self.url!r}")
        if not self.meter_token or any(c.isspace() for c in self.meter_token):
            raise ConfigError("CONTEXTOS_METER_TOKEN (or CONTEXTOS_METER_TOKEN_FILE) must hold the meter token")
        if self.price_source not in PRICE_SOURCES:
            raise ConfigError(f"CONTEXTOS_PRICE_SOURCE must be one of {PRICE_SOURCES}, not {self.price_source!r}")
        for name in ("timeout", "settle_backoff", "settle_backoff_max", "claim_ttl"):
            if not getattr(self, name) > 0:
                raise ConfigError(f"{name} must be positive")
        for name in ("settle_attempts", "queue_size", "workers", "max_open_claims"):
            if getattr(self, name) < 1:
                raise ConfigError(f"{name} must be at least 1")

    @property
    def base_url(self) -> str:
        return self.url.rstrip("/")

    @classmethod
    def from_env(cls, env: Optional[Mapping[str, str]] = None) -> "Settings":
        """Reads ``CONTEXTOS_*`` variables (see the package README)."""
        env = os.environ if env is None else env
        token = env.get("CONTEXTOS_METER_TOKEN", "")
        token_file = env.get("CONTEXTOS_METER_TOKEN_FILE")
        if token_file:
            if token:
                raise ConfigError("set CONTEXTOS_METER_TOKEN or CONTEXTOS_METER_TOKEN_FILE, not both")
            try:
                with open(token_file, encoding="utf-8") as handle:
                    token = handle.read().strip()
            except OSError as error:
                raise ConfigError(f"cannot read CONTEXTOS_METER_TOKEN_FILE: {error}") from error
        if not env.get("CONTEXTOS_URL"):
            raise ConfigError("CONTEXTOS_URL is required")
        return cls(
            url=env["CONTEXTOS_URL"],
            meter_token=token,
            require_reservation=_flag(env, "CONTEXTOS_REQUIRE_RESERVATION", True),
            timeout=_number(env, "CONTEXTOS_TIMEOUT", 5.0),
            price_source=env.get("CONTEXTOS_PRICE_SOURCE", "litellm").strip().lower(),
            cap_output_tokens=_flag(env, "CONTEXTOS_CAP_OUTPUT_TOKENS", True),
            settle_attempts=int(_number(env, "CONTEXTOS_SETTLE_ATTEMPTS", 8)),
            settle_backoff=_number(env, "CONTEXTOS_SETTLE_BACKOFF", 0.5),
            settle_backoff_max=_number(env, "CONTEXTOS_SETTLE_BACKOFF_MAX", 30.0),
            queue_size=int(_number(env, "CONTEXTOS_SETTLE_QUEUE", 10_000)),
            workers=int(_number(env, "CONTEXTOS_SETTLE_WORKERS", 4)),
            claim_ttl=_number(env, "CONTEXTOS_CLAIM_TTL", 3_600.0),
        )


def _flag(env: Mapping[str, str], name: str, default: bool) -> bool:
    value = env.get(name)
    if value is None or value.strip() == "":
        return default
    value = value.strip().lower()
    if value in _TRUE:
        return True
    if value in _FALSE:
        return False
    raise ConfigError(f"{name} must be true or false, not {value!r}")


def _number(env: Mapping[str, str], name: str, default: float) -> float:
    value = env.get(name)
    if value is None or value.strip() == "":
        return default
    try:
        return float(value)
    except ValueError:
        raise ConfigError(f"{name} must be a number, not {value!r}") from None
