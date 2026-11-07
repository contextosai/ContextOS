# contextos-litellm

ContextOS metering for the [LiteLLM proxy](https://docs.litellm.ai/docs/simple_proxy).
Every model call an agent makes through the proxy is charged to its ContextOS run's
budget at the usage the provider reported, not the amount the agent reserved, and a
call the run cannot pay for is refused before it reaches the provider.

```text
agent ──(model request + ContextOS-Run-Id, ContextOS-Usage-Reservation)──▶ LiteLLM proxy
  pre-call:  POST /v1/runs/{run}/usage/claim    refused → the call is refused, provider never called
LiteLLM ──▶ provider ──▶ response with usage
  success:   POST /v1/runs/{run}/usage/settle   measured tokens, LiteLLM's cost, the serving model
  failure:   provider refused the call          settled as nothing used
```

The agent reserves before each call and sends the two headers; it does not settle a
metered call itself:

```python
with run.budgeted_model_call(tokens=4000, cost_cents=5, metered=True) as reservation:
    openai.chat.completions.create(model="gpt-4o", messages=messages,
                                   extra_headers=run.metering_headers(reservation))
```

```ts
await run.budgetedModelCall((reservation) =>
  openai.chat.completions.create({ model: "gpt-4o", messages },
                                 { headers: run.meteringHeaders(reservation) }),
  { tokens: 4000, costCents: 5, metered: true });
```

## Install and configure

```sh
# into the proxy's environment; the package is not on PyPI yet
pip install "contextos-litellm @ git+https://github.com/contextosai/ContextOS@v0.1.0-alpha.17#subdirectory=integrations/litellm"
```

```yaml
# config.yaml
litellm_settings:
  callbacks: ["contextos_litellm.metering_handler"]
```

| Variable | Default | Meaning |
|---|---|---|
| `CONTEXTOS_URL` | required | contextosd base URL |
| `CONTEXTOS_METER_TOKEN` or `CONTEXTOS_METER_TOKEN_FILE` | required | a key or token with **only** the `meter` scope; contextosd treats usage from such a principal as measured |
| `CONTEXTOS_REQUIRE_RESERVATION` | `true` | refuse calls without the ContextOS headers (`403 contextos_reservation_required`); set `false` only on a proxy that also serves traffic ContextOS does not govern |
| `CONTEXTOS_PRICE_SOURCE` | `litellm` | `litellm` charges LiteLLM's computed `response_cost` (rounded up to a cent per call); `none` charges each reservation's cost in full |
| `CONTEXTOS_CAP_OUTPUT_TOKENS` | `true` | lower the request's output-token limit (`max_tokens`, `max_completion_tokens`, `max_output_tokens`) to the tokens the reservation covers |
| `CONTEXTOS_TIMEOUT` | `5` | seconds per contextosd request |
| `CONTEXTOS_SETTLE_ATTEMPTS`, `CONTEXTOS_SETTLE_BACKOFF`, `CONTEXTOS_SETTLE_BACKOFF_MAX` | `8`, `0.5`, `30` | settlement retries on 429, 5xx and network errors, with exponential backoff and jitter |
| `CONTEXTOS_SETTLE_QUEUE`, `CONTEXTOS_SETTLE_WORKERS` | `10000`, `4` | settlements waiting to be sent, and the tasks sending them |
| `CONTEXTOS_CLAIM_TTL` | `3600` | seconds a claimed call is remembered while it runs |

The handler is created, and its settings checked, when LiteLLM loads the callback, so a
misconfigured proxy fails at startup instead of serving calls it cannot meter.

## What it guarantees

- **Fails closed.** A call is forwarded only after contextosd accepted the claim. If
  contextosd cannot be reached, or the proxy's own credential is wrong, the caller gets
  `503 contextos_unavailable`.
- **One call per reservation, across replicas.** The claim is a store document in
  contextosd, so a reused reservation is refused (`409 contextos_reservation_reused`)
  whichever proxy replica or worker sees it. A forged or settled one is refused
  (`403 contextos_reservation_unknown`), as is a revoked run (`403 contextos_revoked`).
- **Only the claiming proxy settles as measured.** contextosd refuses measured
  settlement of a reservation another meter claimed.
- **Unknown usage is never free.** A served call whose response reports no tokens, a
  timeout or dropped stream, a settlement that exhausted its retries or found the queue
  full, and a claim older than `CONTEXTOS_CLAIM_TTL` all leave the reservation reserved:
  it keeps counting against the run's budget in full, and the executor can settle it in
  full (`run.settle_usage(reservation)`; `budgeted_model_call` does so when the call
  raises). A provider error status (4xx or 5xx, except 408 and 504) settles as nothing
  used.
- **Unknown cost is never free.** LiteLLM prices a model it has no price for at zero, so
  a call LiteLLM priced at zero is charged its reservation's cost; an agent that calls a
  free model reserves no cost and is charged none.
- **Refusals are identifiable.** LiteLLM wraps a refusal in its own error body; the
  ContextOS code is in `error.provider_specific_fields.error.code` (and the message).
- **Never on the response path.** Settlement runs in background tasks after the response;
  a contextosd outage delays settlement, it does not fail or slow model calls already
  admitted.
- **Clients cannot steer it.** The ContextOS headers are not forwarded to the provider
  (LiteLLM forwards only `x-` headers), and the handle the logging hooks use is a
  random nonce the pre-call hook issues, so a client that writes one into its request
  metadata names nothing.

Usage is read from the provider's usage block (prompt and completion tokens as LiteLLM
normalizes them, which include prompt-cache reads and writes), falling back to
LiteLLM's standard logging payload. A streamed Chat Completions request is asked to
include usage (`stream_options.include_usage`). If a provider omits usage in a way
LiteLLM fills in by counting tokens itself, that estimate is what is charged.

Every claim and settlement is in contextosd's audit chain (`usage_claimed`,
`usage_settled` with the model, measured and charged usage), which is what Tower
reports model spend from.

## Operating it

- Log lines are `key=value` under the `contextos_litellm` logger: `contextos_settled`,
  `contextos_settle_retry`, `contextos_settle_refused`, `contextos_settle_failed`,
  `contextos_settle_dropped`, `contextos_claim_refused`, `contextos_unavailable`,
  `contextos_usage_unknown`, `contextos_claim_expired`. Alert on the last five.
- `metering_handler.stats` counts `claimed`, `refused`, `ungoverned`, `settled`,
  `settle_refused`, `settle_failed`, `settle_dropped`, `unmetered` and `claims_expired`;
  `metering_handler.settler.pending` and `metering_handler.open_claims` are gauges.
- On shutdown, `await metering_handler.aclose()` delivers queued settlements. Settlements
  lost to a crash leave their reservations reserved (charged in full), never free.
- Run one meter principal per proxy deployment; replicas and workers of one deployment
  share it.

## Tested against

LiteLLM `1.108.2` (`requirements-test.txt`): unit tests against a fake contextosd
(`pytest integrations/litellm/tests`) and an end-to-end run of a real LiteLLM proxy with
a live contextosd and a fake provider in OpenAI and Anthropic shapes, streamed and not
(`integrations/litellm/tests/e2e/run.sh`).
