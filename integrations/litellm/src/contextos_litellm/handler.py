"""The LiteLLM proxy callback: claim before the call, settle measured usage after.

    agent ──(request + ContextOS-Run-Id, ContextOS-Usage-Reservation)──▶ LiteLLM proxy
      pre-call hook:  POST /v1/runs/{run}/usage/claim  (refused → the call is refused)
    LiteLLM ──▶ provider ──▶ response with usage
      success event:  POST /v1/runs/{run}/usage/settle (measured tokens and cost)
      failure hook:   provider refused the call → settle nothing used

Semantics match contextosd's metering contract: a reservation covers one call; a
provider error settles as nothing used; a served call whose usage is unknown, or one
that fails in a way that may have used tokens (timeouts, dropped streams), is left
unsettled so the run's executor charges the whole reservation.
"""
from __future__ import annotations

import logging
import secrets
import time
from collections import Counter, OrderedDict
from typing import Any, Dict, Mapping, Optional, Tuple

from fastapi import HTTPException
from litellm.integrations.custom_logger import CustomLogger

from .client import Claim, ContextOSClient, ContextOSRefused, ContextOSUnavailable, Settlement, Settler
from .config import Settings
from .usage import cost_cents, measured_tokens, response_cost

log = logging.getLogger("contextos_litellm")

RUN_HEADER = "ContextOS-Run-Id"
RESERVATION_HEADER = "ContextOS-Usage-Reservation"
# Where the pre-call hook leaves the claim's handle for the logging hooks. Its value is
# a random nonce this process issued: a client that puts one in its request metadata
# cannot name a claim it did not make.
METADATA_KEY = "contextos_metering"
_METADATA_FIELDS = ("metadata", "litellm_metadata")
_MAX_HEADER = 256

# The request field that bounds output tokens, by call type.
_OUTPUT_LIMITS = {
    "completion": ("max_completion_tokens", "max_tokens"),
    "acompletion": ("max_completion_tokens", "max_tokens"),
    "text_completion": ("max_tokens",),
    "atext_completion": ("max_tokens",),
    "responses": ("max_output_tokens",),
    "aresponses": ("max_output_tokens",),
    "anthropic_messages": ("max_tokens",),
    "aanthropic_messages": ("max_tokens",),
}
_CHAT = {"completion", "acompletion"}
# Provider statuses that mean the call was not served (nothing used); timeouts may
# have used tokens and are not among them.
_NOT_SERVED = set(range(400, 600)) - {408, 504}

# What the client sees when the plugin refuses a call.
_REFUSALS = {
    "reservation_not_found": (403, "contextos_reservation_unknown",
                              "The ContextOS usage reservation is unknown, settled or not for a model call."),
    "reservation_claimed": (409, "contextos_reservation_reused", "This reservation already covered a model call."),
    "revoked": (403, "contextos_revoked", "This run has been revoked by an operator."),
    "run_not_found": (403, "contextos_run_unknown", "No such ContextOS run."),
}
_MISCONFIGURED = {"unauthenticated", "scope_missing", "meter_not_independent", "request_invalid"}


def _refuse(status: int, code: str, message: str) -> HTTPException:
    return HTTPException(status_code=status, detail={"error": {"type": code, "code": code, "message": message}})


def _request_headers(data: Mapping[str, Any]) -> Dict[str, str]:
    """The client's request headers, lower-cased, as LiteLLM recorded them."""
    sources = [(data.get("proxy_server_request") or {}).get("headers")]
    sources += [(data.get(field) or {}).get("headers") for field in _METADATA_FIELDS
                if isinstance(data.get(field), Mapping)]
    for headers in sources:
        if isinstance(headers, Mapping):
            return {str(k).lower(): str(v) for k, v in headers.items()}
    return {}


def _valid(value: str) -> bool:
    return 0 < len(value) <= _MAX_HEADER and value.isprintable() and value.strip() == value


def _nonce_from(container: Any) -> Optional[str]:
    if isinstance(container, Mapping):
        value = container.get(METADATA_KEY)
        if isinstance(value, str):
            return value
    return None


def _call_nonce(kwargs: Mapping[str, Any]) -> Optional[str]:
    """The nonce in a call's logged metadata, wherever this LiteLLM version keeps it."""
    params = kwargs.get("litellm_params") or {}
    for container in (params.get("metadata"), params.get("litellm_metadata"), kwargs.get("metadata"),
                      kwargs.get("litellm_metadata")):
        nonce = _nonce_from(container)
        if nonce:
            return nonce
    return None


class ContextOSMetering(CustomLogger):
    """Meters every model call the LiteLLM proxy serves against its run's ContextOS
    budget. Register it under ``litellm_settings.callbacks`` as
    ``contextos_litellm.metering_handler`` (configured from ``CONTEXTOS_*``)."""

    def __init__(self, settings: Optional[Settings] = None, *, transport: Any = None):
        super().__init__()
        self.settings = settings or Settings.from_env()
        self.stats: Counter = Counter()
        self.client = ContextOSClient(self.settings, transport)
        self.settler = Settler(self.client, self.settings, self.stats)
        self._claims: "OrderedDict[str, Tuple[float, Claim]]" = OrderedDict()

    # Claims in flight -------------------------------------------------------------

    def _remember(self, claim: Claim) -> str:
        now = time.monotonic()
        while self._claims:
            nonce, (at, old) = next(iter(self._claims.items()))
            if now - at < self.settings.claim_ttl and len(self._claims) < self.settings.max_open_claims:
                break
            del self._claims[nonce]
            self.stats["claims_expired"] += 1
            log.warning("contextos_claim_expired run_id=%s reservation_id=%s; left unsettled", old.run_id,
                        old.reservation_id)
        nonce = secrets.token_urlsafe(18)
        self._claims[nonce] = (now, claim)
        return nonce

    def _take(self, nonce: Optional[str]) -> Optional[Claim]:
        entry = self._claims.pop(nonce, None) if nonce else None
        return entry[1] if entry else None

    @property
    def open_claims(self) -> int:
        return len(self._claims)

    # Proxy hooks -------------------------------------------------------------------

    async def async_pre_call_hook(self, user_api_key_dict: Any, cache: Any, data: dict, call_type: Any) -> dict:
        for field in _METADATA_FIELDS:
            if isinstance(data.get(field), dict):
                data[field].pop(METADATA_KEY, None)  # never trust a client-supplied handle
        headers = _request_headers(data)
        run_id = headers.get(RUN_HEADER.lower())
        reservation = headers.get(RESERVATION_HEADER.lower())
        if run_id is None and reservation is None:
            if self.settings.require_reservation:
                self.stats["refused"] += 1
                raise _refuse(403, "contextos_reservation_required",
                              f"Model calls need the {RUN_HEADER} and {RESERVATION_HEADER} headers.")
            self.stats["ungoverned"] += 1
            return data
        if not (run_id and reservation and _valid(run_id) and _valid(reservation)):
            self.stats["refused"] += 1
            raise _refuse(400, "contextos_reservation_invalid",
                          f"{RUN_HEADER} and {RESERVATION_HEADER} must both be set to valid ids.")
        model = data.get("model") if isinstance(data.get("model"), str) and _valid(data["model"]) else None
        try:
            claim = await self.client.claim(run_id, reservation, model)
        except ContextOSRefused as refusal:
            self.stats["refused"] += 1
            if refusal.code in _MISCONFIGURED or refusal.status == 401:
                # The proxy's own credential is wrong: not the caller's fault.
                log.error("contextos_meter_misconfigured code=%s message=%s", refusal.code, refusal.message)
                raise _refuse(503, "contextos_unavailable",
                              "ContextOS metering is misconfigured on this proxy.") from None
            status, code, message = _REFUSALS.get(
                refusal.code, (403, f"contextos_{refusal.code}", refusal.message))
            log.warning("contextos_claim_refused run_id=%s reservation_id=%s code=%s", run_id, reservation,
                        refusal.code)
            raise _refuse(status, code, message) from None
        except ContextOSUnavailable as error:
            self.stats["refused"] += 1
            log.error("contextos_unavailable run_id=%s reservation_id=%s error=%s", run_id, reservation, error)
            raise _refuse(503, "contextos_unavailable",
                          "ContextOS could not be reached to meter this call; try again.") from None
        self.stats["claimed"] += 1
        nonce = self._remember(claim)
        field = next((f for f in _METADATA_FIELDS if isinstance(data.get(f), dict) and "headers" in data[f]),
                     None) or next((f for f in _METADATA_FIELDS if isinstance(data.get(f), dict)), "metadata")
        data.setdefault(field, {})[METADATA_KEY] = nonce
        kind = str(getattr(call_type, "value", call_type))
        if self.settings.cap_output_tokens:
            _cap_output(data, kind, claim.tokens)
        if kind in _CHAT and data.get("stream") is True:
            # A streamed Chat Completion reports usage only when asked to.
            options = data.get("stream_options")
            options = dict(options) if isinstance(options, dict) else {}
            options["include_usage"] = True
            data["stream_options"] = options
        return data

    async def async_log_success_event(self, kwargs: Any, response_obj: Any, start_time: Any, end_time: Any) -> None:
        claim = self._take(_call_nonce(kwargs or {}))
        if claim is None:
            return
        try:
            tokens = measured_tokens(kwargs, response_obj)
            if tokens is None:
                self.stats["unmetered"] += 1
                log.warning("contextos_usage_unknown run_id=%s reservation_id=%s; left unsettled", claim.run_id,
                            claim.reservation_id)
                return
            cost = response_cost(kwargs) if self.settings.price_source == "litellm" else None
            served = (kwargs.get("standard_logging_object") or {}).get("model") or kwargs.get("model") or claim.model
            self.settler.submit(Settlement(
                run_id=claim.run_id, reservation_id=claim.reservation_id, tokens=tokens[0] + tokens[1],
                # Unknown cost is never free: charge what was reserved. LiteLLM prices a
                # model it has no price for at 0, so a zero cost counts as unknown; an
                # agent calling a free model reserves no cost, and is charged none.
                cost_cents=claim.cost_cents if not cost else cost_cents(cost),
                model=served if isinstance(served, str) and _valid(served) else claim.model))
        except Exception:  # logging hooks must never fail the proxy
            self.stats["settle_failed"] += 1
            log.exception("contextos_settle_failed run_id=%s reservation_id=%s", claim.run_id, claim.reservation_id)

    async def async_post_call_failure_hook(self, request_data: dict, original_exception: Exception,
                                           user_api_key_dict: Any, traceback_str: Optional[str] = None) -> None:
        nonce = None
        for field in _METADATA_FIELDS:
            nonce = nonce or _nonce_from((request_data or {}).get(field))
        claim = self._take(nonce)
        if claim is None:
            return None
        status = getattr(original_exception, "status_code", None)
        if isinstance(status, int) and status in _NOT_SERVED:
            # The provider (or the proxy) refused the call: nothing was used.
            self.settler.submit(Settlement(claim.run_id, claim.reservation_id, 0, 0, claim.model))
        else:
            self.stats["unmetered"] += 1
            log.warning("contextos_usage_unknown run_id=%s reservation_id=%s error=%s; left unsettled",
                        claim.run_id, claim.reservation_id, type(original_exception).__name__)
        return None

    async def aclose(self, timeout: float = 30.0) -> bool:
        """Delivers queued settlements, then closes the HTTP client; True if all were sent."""
        drained = await self.settler.drain(timeout)
        await self.client.aclose()
        return drained


def _cap_output(data: dict, call_type: str, limit: int) -> None:
    """Lowers the output-token limit to what the reservation covers (input tokens
    count against it too, so the call may still exceed it; the excess is charged as
    overage up to the run's remaining budget)."""
    fields = _OUTPUT_LIMITS.get(call_type)
    if not fields or limit <= 0:
        return
    present = [f for f in fields if isinstance(data.get(f), int) and not isinstance(data.get(f), bool)]
    for field in present:
        data[field] = min(data[field], limit)
    if not present:
        data[fields[-1] if call_type in _CHAT else fields[0]] = limit
