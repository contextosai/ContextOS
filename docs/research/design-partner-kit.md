# Design-partner kit

Written 2026-11-08 after the [enterprise problems research](2026-11-08-enterprise-agent-problems.md).
That research found strong public evidence for ungated consequential actions and weak
evidence for the shared-limit problem ContextOS leads with, and the repository records no
user research. This kit is how ContextOS earns evidence before building further: an
interview, a data request, an offline replay of the partner's own traffic, and a scorecard.

## Who to talk to

Five to eight teams that already run agents against tools with real effects:

- **Platform engineer** who wires agents to tools (the user). Job: put agents on
  consequential tools without becoming the approval queue.
- **Operations owner** of the workflow (support, payments or finance operations lead).
  Job: no refund, credit or change goes out that the business would not stand behind.
- **Security reviewer** who signs off on the deployment. Job: approve the agent in days,
  and answer "which person did this act for, under which rule".

Prefer teams with refunds, credits, account changes or cloud provisioning in production
or in a pilot that is about to go live. Coding assistants with shell access are a poor
fit: the gateway protects only calls routed through it.

## Interview (45 minutes)

Ask for stories, not opinions. Write down the words they use.

1. Walk me through the last time an agent did something it should not have, or nearly
   did. What happened, who noticed, how long until it was fixed, what did it cost?
2. Which tools can your agents call that change something outside your systems: money,
   customer records, infrastructure, messages? Which one worries you most?
3. When a tool call times out, what does your agent do? Has a retry ever applied
   something twice? How would you find out?
4. Can two agents, channels or runs act on the same order, account or budget? Is there
   a limit they share (a refund ceiling, a credit allowance, a daily spend)? Where is it
   enforced today?
5. Where do people approve agent actions today? How many approvals per person per day?
   How often is the answer "no"? How long does an approval take?
6. What did security ask for at the last agent review? What blocked or delayed it?
7. Which identity does the agent use to call tools: a service account, the user's
   token, something else? Could you say which person an agent acted for last Tuesday?
8. If you could stop one class of agent action tomorrow, which would it be?

## Data request

One week of tool-call records from one workflow, as JSON Lines, one call per line:

```json
{"ts": "2026-11-01T09:00:05Z", "run_id": "conv_1931", "agent": "support-bot",
 "capability_id": "payments.issue_refund", "args": {"order_id": "o_1", "amount_minor": 60000},
 "approval_mode": "destructive", "outcome": "ok", "output": {"refund_id": "rf_1"}}
```

- `run_id` is whatever groups one task: a conversation, a job, a workflow execution.
- `outcome` is `ok` (applied), `error` (the tool refused) or `timeout` (no answer).
- Redact before sending: replace customer identifiers with stable pseudonyms (the same
  customer gets the same token everywhere), keep amounts and timestamps. The replay needs
  equality, not the real values.
- Traces exported as OpenTelemetry GenAI spans can be mapped to this format; the
  `gen_ai.tool.name` and tool-call arguments attributes carry most of it.

## Replay

`python -m contextos.replay` sends the recorded calls, in time order, through a gateway
configured like the partner's deployment. Every effect goes to the replay's own tool
server, which answers with the recorded outcome, so no real system is touched. See
[examples/replay](../../examples/replay/README.md) for a complete local run.

```sh
pip install contextos-client
CONTEXTOS_TOKEN=... python -m contextos.replay traffic.jsonl \
  --url http://127.0.0.1:8080 --admission admission.json --wait --out partner-week
```

`--wait` prints the replay tool server's address; point the gateway's adapters at it,
then press Enter. The report counts calls allowed, duplicates refused, limits held,
approvals required and outcomes left in doubt, and lists refusals of calls that really
succeeded as possible false blocks to review with the partner.

## Scorecard

Fill one per partner after the interview and the replay.

| Question | Answer | Evidence |
|---|---|---|
| Most recent real incident, and its class (duplicate, spend, destructive, approval, identity) | | interview |
| Do two runs or channels share a numeric limit today? | | interview, replay `limits_held` |
| Duplicates the replay refused per 1,000 effects | | replay |
| Approvals required per day, and today's approval rate | | replay, interview |
| Outcomes left in doubt per 1,000 effects | | replay `held_unknown` |
| Possible false blocks per 1,000 calls, after review | | replay |
| Share of consequential calls that would route through the gateway | | architecture review |
| What security demanded at the last review | | interview |
| Would they run the gateway in front of this workflow? What is missing? | | interview |

## When to stop or change direction

From the [value proposition](2026-10-22-value-proposition.md): stop or change direction if
resource-level APIs already solve the problem cheaply, if buyers need identity and
inventory first, or if stable resource binding cannot be established. Treat shared limits
at payment scale as unconfirmed until at least two partners show a shared limit and a
replay that holds it.
