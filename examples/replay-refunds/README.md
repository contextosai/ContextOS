# Replay your refund calls

If your agent issues refunds, you can see what ContextOS would have done with the refunds
it already made: which repeats it would not have sent, which refunds it would have held
because nobody knew whether they were paid, and which ones it would have blocked that it
should not have. Everything runs on your machine. Each call is answered with the outcome
you recorded, so no payment system is called.

```sh
./examples/replay-refunds/run.sh                      # the bundled sample
./examples/replay-refunds/run.sh my-calls.jsonl \
    --refund-tool refund_payment --order /order --amount /amount --amount-unit major --currency USD
```

From a source checkout this builds the gateway (Rust toolchain from
[rust-toolchain.toml](../../rust-toolchain.toml), Python 3.9+, Bash). A
[release archive](https://github.com/contextosai/ContextOS/releases) carries the binaries,
so it needs only Python and Bash. No model key, account or network access is needed.

## 1. Export your calls

One tool call per line, JSON Lines. Most agent logs already have these fields under one
of the names listed; add `outcome` if yours does not.

| Field | Also accepted | What it is |
|---|---|---|
| `ts` | | ISO 8601 time of the call. Optional: file order is used without it. |
| `run_id` | `session_id`, `conversation_id`, `trace_id` | The agent run the call belongs to. |
| `tool` | `name`, `tool_name` | The tool's name. |
| `args` | `arguments`, `input` | The arguments, as an object or a JSON string. |
| `outcome` | | `ok` the provider applied it, `error` it refused, `timeout` no answer arrived. |
| `output` | | Optional: what the tool returned. |
| `agent` | | Optional: which agent made the call. |

```json
{"ts": "2026-11-03T09:14:05Z", "run_id": "conv_8812", "tool": "refund_payment", "args": {"order": "A-1042", "amount": 25.0}, "outcome": "ok", "output": {"refund_id": "re_9a1"}}
```

Mark a call `timeout` when your code gave up waiting or the connection dropped: that is
the case where the refund may or may not have happened. Calls to other tools are counted
and skipped. [sample.jsonl](sample.jsonl) is a day of a support agent's calls with a retry
that paid twice, a ticket redelivered into a new run, a timeout followed by a retry, two
partial refunds of one order and a repeat three days later.

## 2. Say where the refund is

| Option | Default | |
|---|---|---|
| `--refund-tool` | the only tool with `refund` in its name | The tool that issues refunds. |
| `--order`, `--amount` | `/order_id`, `/amount` | JSON Pointers into its arguments. |
| `--customer` | none | JSON Pointer to the customer, if the arguments have one. |
| `--amount-unit` | `minor` | `minor` for cents or paise (`2500`), `major` for `25.00`. |
| `--currency` | `USD` | Three-letter code used in the report. |
| `--order-limit` | none | Cap all refunds of one order at this amount (major units). |
| `--approval-above` | none | Ask a person to approve runs whose first refund is above this. |
| `--out` | `receipts/replay-refunds/report` | Writes `.md` and `.json`. |

## 3. Read the report

The report opens with one sentence and a table in money: what your recording paid, what
ContextOS would have sent and paid, what it would have held, the repeats it would not
have sent, and amounts over the order's ceiling or waiting for approval. A table per
order and every refund call follow.

Two lists need your judgement:

- **Possible false blocks**: refunds your recording shows as successful that the gateway
  refused for a reason other than a repeat, a ceiling or an approval. Each names the
  reason. Fix the mapping or the configuration, or tell us the rule is wrong.
- **Repeats to review**: the gateway treats the same amount on the same order as the same
  refund for 24 hours, across runs. The replay runs in minutes, so a refund your recording
  made more than a day after an identical one is refused here and listed for you to check.

## How it decides

The replay runs `contextosd` with the support-refund example's configuration, an
in-memory store and development fact services, then sends each refund through it in time
order with [`contextos.replay`](../../bindings/python/contextos/replay.py). The refund
capability is configured as a production refund workflow would be:

- One refund is one order and one amount: a second send of it in the same run, or from
  another run within 24 hours (`intent.key_pointers`), is refused.
- A refund with no answer is held. It is never retried blind; once an operator records it
  as not applied, it may be sent once more (`recovery.max_attempts = 2`).
- With `--order-limit`, all refunds of one order share one ceiling (a shared guarantee).

What it does not tell you:

- **Authority.** The development services vouch for every caller, so the replay says
  nothing about who may refund what.
- **Concurrency.** Calls go one at a time, so races between agents are not measured; the
  [shared guarantees demo](../shared-guarantees) shows them.
- **Identical refunds inside one run.** Two refunds of the same amount on the same order
  in one run are one refund here. If your agent does that on purpose, they show as repeats.
- **One ceiling for every order.** `--order-limit` is a single number; real orders differ.
- **Reconciliation.** Held refunds stay held. In production the provider is queried or an
  operator records the outcome; the [Agent Failure Lab](../failure-lab) shows that step.

See the generic [replay kit](../replay) to replay other workflows with your own packs and
manifests.
