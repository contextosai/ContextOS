# Replay recorded tool calls

Before you put ContextOS in front of a workflow, you can measure what it would have done
with traffic you already have. `python -m contextos.replay` sends recorded tool calls, in
time order, through a gateway configured like your deployment. Every effect goes to the
replay's own tool server, which answers with the recorded outcome, so nothing real is
called.

```sh
./examples/replay/run.sh
```

The local run replays [traffic.jsonl](traffic.jsonl), six calls from a support desk
without ContextOS:

| Line | What the agents did | What the gateway does |
|---|---|---|
| 1 | Look up order `ord_881` | allowed (read only) |
| 2 | Refund INR 600 on `ord_881` | allowed |
| 3 | Send the same refund again after a client timeout | refused: `effect_repeated` |
| 4 | A second channel refunds `ord_881` in its own run | refused: `shared_guarantee_exceeded` (INR 1,000 per order) |
| 5 | Refund on `ord_990`; the response never arrived | held: the effect may have happened |
| 6 | Refund INR 4,500, above the INR 3,000 threshold | paused for approval |

It writes `receipts/replay/replay-report.md` and `.json`: calls allowed, duplicates refused,
limits held, approvals required, outcomes left in doubt, and refusals of calls that really
succeeded, listed as possible false blocks to review.

## Your own traffic

1. Export one workflow's tool calls as JSON Lines, one call per line. The fields are
   documented in [`contextos/replay.py`](../../bindings/python/contextos/replay.py):
   `ts`, `run_id`, `capability_id`, `args` and `outcome` (`ok`, `error` or `timeout`),
   plus optional `agent`, `approval_mode`, `output`, `idempotency_key`, `evidence_refs`
   and `vars`.
2. Write an admission template: one run's admission body with `$RUN_ID`, `$AGENT` and
   any `$NAME` from a record's `vars` where values differ per run
   ([admission.json](admission.json) is the one used here).
3. Run a gateway with your packs, manifests and guards on an in-memory store, and your
   fact services or development stand-ins for them. Then:

   ```sh
   CONTEXTOS_TOKEN=... python -m contextos.replay traffic.jsonl \
     --url http://127.0.0.1:8080 --admission admission.json --wait --out my-week
   ```

   `--wait` prints the replay tool server's address. Point every adapter's `endpoint` at
   it (`kind = "mcp"`), start the gateway, then press Enter.

The replay sends calls one at a time, so it measures what the rules decide, not how
they behave under concurrency. The [design-partner kit](../../docs/research/design-partner-kit.md)
explains how the report feeds a partner scorecard.
