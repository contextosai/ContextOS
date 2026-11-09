# A staging gateway with the starter guards

What the guards in [`deploy/profiles/consequential-tools.toml`](../../deploy/profiles/consequential-tools.toml)
do with real traffic, replayed. [traffic.jsonl](traffic.jsonl) is a staging support
agent's morning without ContextOS. Its credential also reached production, a second run
repeated a refund, and it refunded more in a day than anyone meant it to:

```sh
./examples/consequential-tools/run.sh
```

| Line | What the agent did | What the gateway does |
|---|---|---|
| 1 | Look up test order `test_ord_1` | allowed (read only) |
| 2 | Refund INR 600 on `test_ord_1` | allowed |
| 3 | Refund INR 500 on the live order `ord_881` | refused: `environment_mismatch` |
| 4 | A new run refunds `test_ord_1` again | refused: `effect_repeated_across_runs` |
| 5 | Refund INR 700 on `test_ord_2` | allowed (INR 1,300 today) |
| 6 | Refund INR 400 on `test_ord_3` | refused: `shared_guarantee_exceeded` (INR 1,500 per agent per day) |

The gateway is configured in [demo.py](demo.py):

- `[guards.environments]` says it serves `staging` and places a refund by its order id:
  `test_ord_` orders are staging, `ord_` orders production.
- A spend cap, a shared guarantee with `resource_from = "actor"` and
  `window_seconds = 86400`, limits what each agent refunds per day across all its runs.
- [issue_refund.json](issue_refund.json) is the support example's refund manifest with
  an intent key on `/order_id`: one refund per order, whichever run sends it.

Line 3 also appears under "Possible false blocks". The recording shows that refund
succeeding, and a replay cannot know it should not have happened. A person reviews it;
here the review confirms the refusal. The report is written to
`receipts/consequential-tools/`.

The same recording format and tool works on your own traffic; see
[examples/replay](../replay/README.md).
