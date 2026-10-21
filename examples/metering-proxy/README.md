# Metering proxy

A reference LLM gateway that settles each model call's budget reservation with the
usage the provider reported, so a run is charged what its model calls used rather than
what they reserved. It sits between the agent and the model API:

```text
agent ──(request + ContextOS-Run-Id, ContextOS-Usage-Reservation)──▶ proxy ──▶ model API
                                                          proxy ◀── response with usage
proxy ──(POST /v1/runs/{run}/usage/settle, measured tokens and cost; meter scope)──▶ contextosd
```

The executor reserves and sends the two headers; it does not settle a metered call
itself:

```python
with run.budgeted_model_call(tokens=4000, metered=True) as reservation:
    client.chat.completions.create(..., extra_headers=run.metering_headers(reservation))
```

```ts
await run.budgetedModelCall((reservation) =>
  fetch(`${PROXY}/v1/messages`, { method: "POST", headers: { ...run.meteringHeaders(reservation), ... }, body }),
  { tokens: 4000, metered: true });
```

The proxy holds a token with only the `meter` scope, which is what makes contextosd
treat its report as measured. It understands the usage of OpenAI Chat Completions and
Responses and Anthropic Messages (including prompt-cache tokens), streamed or not, and
asks a streamed Chat Completions request to include usage. With `--price
input:output` (cents per million tokens) it charges cost as well, rounded up per call.
With `--upstream-key-env` it adds the provider key itself, so agents never hold it.

It fails closed: a call without a reservation is refused (`403`), a reservation covers
one call (`409` on reuse), a provider error without usage settles as nothing used, and a
successful response without usage leaves the reservation reserved for the executor to
settle in full, because unknown usage is never free.

```sh
CONTEXTOS_METER_TOKEN=… python3 examples/metering-proxy/proxy.py \
  --upstream https://api.anthropic.com --upstream-key-env ANTHROPIC_API_KEY --upstream-auth x-api-key \
  --contextos https://contextos.internal --price 300:1500
```

Standard library only; a reference for the contract, not a hardened gateway. In
production, put the same behavior in the LLM gateway you already run.

`./examples/metering-proxy/run.sh` tests it against a local contextosd and a fake model
API (both providers, streamed and not, reuse, errors, missing usage):

```text
ok: metering proxy (5455 tokens charged, 5 provider calls)
```
