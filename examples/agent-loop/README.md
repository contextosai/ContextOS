# A governed agent loop

`agent.py` is a complete agent loop on the Python client, against `contextosd` with
the quickstart's development services:

1. **Plan** the goal into steps (a deterministic stand-in for a model call). Every
   model call first reserves tokens from the run's budget, the same ledger tool calls
   spend; the plan is checkpointed so another executor could resume it.
2. **Delegate** research to a child run in a `read_only` lane with its own sub-budget
   reserved from the parent. The lane reads the order through a governed read-only
   tool; when it tries to issue a refund, the gateway refuses (the effectful tool is
   not in its lane). Closing the lane settles its spend into the parent.
3. **Critique** the step against the evidence (another stand-in for a model), then
   checkpoint the verdict.
4. **Act**: the refund runs through the full governed pipeline, keyed so it can never
   apply twice.
5. **Decide**: a DecisionRecord whose tool lineage the gateway verifies against its own
   ledgers, signed into the audit chain with a replay packet.
6. **Complete** the run and read its evidence.

```sh
./examples/agent-loop/run.sh
```

```text
admitted run_agent_… (executor generation 2)
planned 2 steps; checkpoint revision 1
research lane …_research found: {'amount_minor': 120000, … 'refundable': True, 'status': 'delivered_damaged'}
research lane cannot act: ['capability_not_surfaced']
closed research lane; usage settled into the parent: tool_calls=1
critic: accept (damaged delivery, refund within order amount); checkpoint revision 2
refund issued: {'refund_id': 'rf_ord_881'}
decision decision_… signed at audit hash sha256:…
run completed
evidence: 1 decision(s), budget used {… 'tokens': 2000, 'tool_calls': 2}, 17 signed audit entries
```

To use a real model, replace `plan()` and `critic()`; keep tool execution on
`run.call_tool` (or register `governed_tool` functions with your framework). The
script holds no authority of its own: everything it is allowed to do is decided by the
gateway, the kernel and the services you operate.
