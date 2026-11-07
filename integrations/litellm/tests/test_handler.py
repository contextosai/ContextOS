"""The callback's hooks, against a fake contextosd."""
import asyncio
import pathlib
import re

import httpx
import pytest
from fastapi import HTTPException
from litellm.integrations.custom_logger import CustomLogger
from litellm.types.utils import ModelResponse, Usage

import contextos_litellm
from contextos_litellm import METADATA_KEY, ConfigError, ContextOSMetering, Settings
from contextos_litellm.usage import cost_cents, measured_tokens, usage_tokens

from conftest import governed, request_data


def logged(data, response_cost=None, **standard):
    """The kwargs LiteLLM passes a success event for a call made with ``data``."""
    return {"litellm_params": {"metadata": data["metadata"]}, "response_cost": response_cost,
            "standard_logging_object": {"model": "gpt-test-2026", **standard}}


def response(prompt=120, completion=30):
    return ModelResponse(usage=Usage(prompt_tokens=prompt, completion_tokens=completion,
                                     total_tokens=prompt + completion))


async def settle(handler):
    assert await handler.settler.drain(5)


def test_it_is_a_litellm_callback(handler):
    assert isinstance(handler, CustomLogger)


async def test_a_governed_call_is_claimed_and_settled_with_measured_usage(handler, contextos):
    data = await handler.async_pre_call_hook(None, None, request_data(governed()), "acompletion")
    assert contextos.claimed == {"usage:r1"}
    assert contextos.requests[0][0] == "/v1/runs/run_1/usage/claim"
    assert contextos.requests[0][1] == {"reservation_id": "usage:r1", "model": "gpt-test"}
    assert contextos.requests[0][2] == "Bearer meter-token"
    assert data["max_tokens"] == 2000  # capped to what the reservation covers
    nonce = data["metadata"][METADATA_KEY]
    assert handler.open_claims == 1
    await handler.async_log_success_event(logged(data, response_cost=0.00081), response(), None, None)
    await settle(handler)
    assert contextos.settled["usage:r1"] == {"reservation_id": "usage:r1", "tokens": 150, "cost_cents": 1,
                                             "model": "gpt-test-2026"}
    assert handler.open_claims == 0 and handler.stats["settled"] == 1
    # The same success logged again settles nothing more.
    data["metadata"][METADATA_KEY] = nonce
    await handler.async_log_success_event(logged(data), response(), None, None)
    await settle(handler)
    assert len(contextos.requests) == 2


async def test_calls_without_a_reservation_are_refused_unless_allowed(handler, contextos, settings):
    with pytest.raises(HTTPException) as refused:
        await handler.async_pre_call_hook(None, None, request_data(), "acompletion")
    assert refused.value.status_code == 403
    assert refused.value.detail["error"]["code"] == "contextos_reservation_required"
    lenient = ContextOSMetering(Settings(**{**settings.__dict__, "require_reservation": False}),
                                transport=httpx.MockTransport(contextos.handle))
    data = await lenient.async_pre_call_hook(None, None, request_data(), "acompletion")
    assert METADATA_KEY not in data["metadata"] and "max_tokens" not in data
    assert lenient.stats["ungoverned"] == 1 and not contextos.requests
    # One header without the other is never let through.
    with pytest.raises(HTTPException) as refused:
        await lenient.async_pre_call_hook(None, None, request_data({"contextos-run-id": "run_1"}), "acompletion")
    assert refused.value.status_code == 400


@pytest.mark.parametrize("reservation, run, status, code", [
    ("usage:nope", "run_1", 403, "contextos_reservation_unknown"),
    ("usage:r1", "run_other", 403, "contextos_reservation_unknown"),
])
async def test_forged_reservations_are_refused(handler, reservation, run, status, code):
    with pytest.raises(HTTPException) as refused:
        await handler.async_pre_call_hook(None, None, request_data(governed(reservation, run)), "acompletion")
    assert (refused.value.status_code, refused.value.detail["error"]["code"]) == (status, code)


async def test_a_reservation_covers_one_call(handler):
    await handler.async_pre_call_hook(None, None, request_data(governed()), "acompletion")
    with pytest.raises(HTTPException) as refused:
        await handler.async_pre_call_hook(None, None, request_data(governed()), "acompletion")
    assert (refused.value.status_code, refused.value.detail["error"]["code"]) == (409, "contextos_reservation_reused")


async def test_revoked_runs_are_refused(handler, contextos):
    contextos.revoked = True
    with pytest.raises(HTTPException) as refused:
        await handler.async_pre_call_hook(None, None, request_data(governed()), "acompletion")
    assert refused.value.detail["error"]["code"] == "contextos_revoked"


@pytest.mark.parametrize("failure", [503, httpx.ConnectError("refused")])
async def test_it_fails_closed_when_contextos_is_unreachable(handler, contextos, failure):
    contextos.fail = [failure]
    with pytest.raises(HTTPException) as refused:
        await handler.async_pre_call_hook(None, None, request_data(governed()), "acompletion")
    assert (refused.value.status_code, refused.value.detail["error"]["code"]) == (503, "contextos_unavailable")


async def test_a_misconfigured_meter_is_not_the_callers_fault(handler, contextos):
    contextos.fail = [401]
    with pytest.raises(HTTPException) as refused:
        await handler.async_pre_call_hook(None, None, request_data(governed()), "acompletion")
    assert refused.value.status_code == 503


async def test_a_client_cannot_name_a_claim(handler, contextos):
    data = request_data(governed())
    data["metadata"][METADATA_KEY] = "forged"
    data = await handler.async_pre_call_hook(None, None, data, "acompletion")
    assert data["metadata"][METADATA_KEY] != "forged"
    forged = request_data()
    forged["metadata"][METADATA_KEY] = "forged"
    await handler.async_log_success_event(logged(forged), response(), None, None)
    await settle(handler)
    assert contextos.settled == {} and handler.open_claims == 1


@pytest.mark.parametrize("call_type, body, expected", [
    ("acompletion", {"max_tokens": 50_000}, {"max_tokens": 2000}),
    ("acompletion", {"max_completion_tokens": 100}, {"max_completion_tokens": 100}),
    ("aresponses", {}, {"max_output_tokens": 2000}),
    ("anthropic_messages", {"max_tokens": 4096}, {"max_tokens": 2000}),
    ("aembedding", {}, {}),
])
async def test_output_is_capped_to_the_reservation(handler, call_type, body, expected):
    data = await handler.async_pre_call_hook(None, None, request_data(governed(), **body), call_type)
    limits = {k: data[k] for k in ("max_tokens", "max_completion_tokens", "max_output_tokens") if k in data}
    assert limits == expected


async def test_streamed_chat_completions_ask_for_usage(handler):
    data = await handler.async_pre_call_hook(
        None, None, request_data(governed(), stream=True, stream_options={"include_usage": False}), "acompletion")
    assert data["stream_options"] == {"include_usage": True}


async def test_a_refused_provider_call_used_nothing(handler, contextos):
    data = await handler.async_pre_call_hook(None, None, request_data(governed()), "acompletion")
    error = Exception("bad request")
    error.status_code = 400
    await handler.async_post_call_failure_hook(data, error, None)
    await settle(handler)
    assert contextos.settled["usage:r1"]["tokens"] == 0


@pytest.mark.parametrize("status", [None, 408, 504])
async def test_failures_that_may_have_used_tokens_are_left_unsettled(handler, contextos, status):
    data = await handler.async_pre_call_hook(None, None, request_data(governed()), "acompletion")
    error = TimeoutError("timed out")
    if status:
        error.status_code = status
    await handler.async_post_call_failure_hook(data, error, None)
    await settle(handler)
    assert contextos.settled == {} and handler.stats["unmetered"] == 1


async def test_unknown_usage_is_left_unsettled(handler, contextos):
    data = await handler.async_pre_call_hook(None, None, request_data(governed()), "acompletion")
    await handler.async_log_success_event(logged(data), ModelResponse(), None, None)
    await settle(handler)
    assert contextos.settled == {} and handler.stats["unmetered"] == 1


@pytest.mark.parametrize("cost", [None, 0.0])
async def test_unknown_cost_charges_the_reserved_cost(handler, contextos, cost):
    # LiteLLM prices a model it has no price for at zero.
    data = await handler.async_pre_call_hook(None, None, request_data(governed()), "acompletion")
    await handler.async_log_success_event(logged(data, response_cost=cost), response(), None, None)
    await settle(handler)
    assert contextos.settled["usage:r1"]["cost_cents"] == 5


async def test_cost_is_not_measured_when_the_price_source_is_none(contextos, settings):
    handler = ContextOSMetering(Settings(**{**settings.__dict__, "price_source": "none"}),
                                transport=httpx.MockTransport(contextos.handle))
    data = await handler.async_pre_call_hook(None, None, request_data(governed()), "acompletion")
    await handler.async_log_success_event(logged(data, response_cost=0.5), response(), None, None)
    await settle(handler)
    assert contextos.settled["usage:r1"]["cost_cents"] == 5


def test_a_failed_pricing_is_unknown_cost():
    from contextos_litellm.usage import response_cost
    assert response_cost({"response_cost": 0.0, "response_cost_failure_debug_information": {"error_str": "x"}}) is None
    assert response_cost({"standard_logging_object": {"response_cost": 0.2}}) == 0.2


async def test_settlement_is_retried_and_idempotent(handler, contextos):
    data = await handler.async_pre_call_hook(None, None, request_data(governed()), "acompletion")
    contextos.fail = [503, httpx.ReadTimeout("slow")]
    await handler.async_log_success_event(logged(data, response_cost=0.01), response(), None, None)
    await settle(handler)
    assert contextos.settled["usage:r1"]["tokens"] == 150 and handler.stats["settled"] == 1


async def test_a_lost_reply_counts_as_settled(handler, contextos):
    data = await handler.async_pre_call_hook(None, None, request_data(governed()), "acompletion")
    contextos.settled["usage:r1"] = {}  # an earlier attempt landed; its reply was lost
    contextos.fail = [502]
    await handler.async_log_success_event(logged(data, response_cost=0.01), response(), None, None)
    await settle(handler)
    assert handler.stats["settled"] == 1 and handler.stats["settle_refused"] == 0


async def test_settlement_gives_up_without_raising(handler, contextos):
    data = await handler.async_pre_call_hook(None, None, request_data(governed()), "acompletion")
    contextos.fail = [503, 503, 503]
    await handler.async_log_success_event(logged(data, response_cost=0.01), response(), None, None)
    await settle(handler)
    assert contextos.settled == {} and handler.stats["settle_failed"] == 1


async def test_a_full_queue_drops_without_blocking(contextos, settings):
    handler = ContextOSMetering(Settings(**{**settings.__dict__, "queue_size": 1, "workers": 1}),
                                transport=httpx.MockTransport(contextos.handle))
    datas = [await handler.async_pre_call_hook(None, None, request_data(governed(r)), "acompletion")
             for r in ("usage:r1", "usage:r2")]
    for data in datas:
        await handler.async_log_success_event(logged(data, response_cost=0.0), response(), None, None)
    await settle(handler)
    assert handler.stats["settle_dropped"] + handler.stats["settled"] == 2


async def test_expired_claims_are_forgotten(contextos, settings):
    handler = ContextOSMetering(Settings(**{**settings.__dict__, "claim_ttl": 0.01}),
                                transport=httpx.MockTransport(contextos.handle))
    first = await handler.async_pre_call_hook(None, None, request_data(governed("usage:r1")), "acompletion")
    await asyncio.sleep(0.02)
    await handler.async_pre_call_hook(None, None, request_data(governed("usage:r2")), "acompletion")
    assert handler.stats["claims_expired"] == 1 and handler.open_claims == 1
    await handler.async_log_success_event(logged(first), response(), None, None)
    await settle(handler)
    assert "usage:r1" not in contextos.settled


def test_usage_shapes():
    assert usage_tokens({"prompt_tokens": 10, "completion_tokens": 5}) == (10, 5)
    assert usage_tokens({"input_tokens": 200, "cache_read_input_tokens": 50, "cache_creation_input_tokens": 7,
                         "output_tokens": 40}) == (257, 40)
    assert usage_tokens({"input_tokens": 3, "output_tokens": True}) == (3, 0)
    assert usage_tokens({}) is None and usage_tokens(None) is None
    assert measured_tokens({"standard_logging_object": {"prompt_tokens": 7, "completion_tokens": 1}}, None) == (7, 1)
    assert measured_tokens({}, {"usage": {"prompt_tokens": 0, "completion_tokens": 0}}) is None
    assert (cost_cents(0.00081), cost_cents(0.07), cost_cents(0.0)) == (1, 7, 0)


def test_settings_from_env(tmp_path):
    with pytest.raises(ConfigError):
        Settings.from_env({})
    with pytest.raises(ConfigError):
        Settings.from_env({"CONTEXTOS_URL": "contextos:8080", "CONTEXTOS_METER_TOKEN": "t"})
    with pytest.raises(ConfigError):
        Settings.from_env({"CONTEXTOS_URL": "http://c", "CONTEXTOS_METER_TOKEN": "t",
                           "CONTEXTOS_REQUIRE_RESERVATION": "maybe"})
    token = tmp_path / "token"
    token.write_text("from-file\n")
    loaded = Settings.from_env({"CONTEXTOS_URL": "https://c/", "CONTEXTOS_METER_TOKEN_FILE": str(token),
                                "CONTEXTOS_REQUIRE_RESERVATION": "false", "CONTEXTOS_PRICE_SOURCE": "none"})
    assert (loaded.base_url, loaded.meter_token, loaded.require_reservation, loaded.price_source) == (
        "https://c", "from-file", False, "none")


def test_the_module_level_handler_is_configured_from_the_environment(monkeypatch):
    monkeypatch.setattr(contextos_litellm, "_handler", None)
    monkeypatch.delenv("CONTEXTOS_URL", raising=False)
    with pytest.raises(ConfigError):
        contextos_litellm.metering_handler  # noqa: B018
    monkeypatch.setenv("CONTEXTOS_URL", "http://contextos:8080")
    monkeypatch.setenv("CONTEXTOS_METER_TOKEN", "meter")
    assert contextos_litellm.metering_handler is contextos_litellm.metering_handler


def test_the_version_follows_the_workspace():
    cargo = (pathlib.Path(__file__).resolve().parents[3] / "Cargo.toml").read_text()
    version = re.search(r'^version\s*=\s*"([^"]+)"', cargo.split("[workspace.package]", 1)[1], re.M).group(1)
    core, _, pre = version.partition("-")
    kind, _, number = pre.partition(".")
    expected = core + ({"alpha": "a", "beta": "b", "rc": "rc"}[kind] + number if pre else "")
    assert contextos_litellm.__version__ == expected
