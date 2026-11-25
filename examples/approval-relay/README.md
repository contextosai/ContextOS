# Approval relay: Slack, Teams and e-mail approvals

A reference approval service for `[providers.approvals]`. The gateway asks it for an
approval of one exact action; it delivers the request to people on Slack, Microsoft
Teams or e-mail, takes their decision back through a **signed callback**, checks **who
they are** and whether they may decide, and hands the gateway decision material the
kernel verifies again (eligible approver, no self-approval, the exact action digest).

| Feature | How |
|---|---|
| Signed callbacks | Slack `X-Slack-Signature` (five-minute window), Teams `Authorization: HMAC …`, e-mail links signed by the relay that name one request, one decision and one approver and expire after a day. Anything else: 401 |
| Approver identity | `directory` maps `slack:U…`, `teams:<aad id>` and `email:<address>` to a principal and roles; unknown identities are refused; a requester never decides their own request |
| Escalation | `tiers`: tier one is asked at once, each later tier `after_seconds` after the request while it is undecided; every tier reached stays eligible |
| Delegation | `delegations`: an approver on leave hands decisions to another person `until` a time; the delegate decides on their behalf, never for their own request |
| Delivery | Slack and Teams incoming webhooks and SMTP when configured; a JSON-lines file otherwise |

Secrets (`slack_signing_secret`, `teams_secret`, `email_link_secret`, webhook URLs) are
read from the environment variables the configuration names. `observer` and
`trusted_observers` must be the observers the deployment's authority service vouches
with: the kernel accepts approval facts only from the observers it trusts for every
other fact.

```sh
python3 examples/approval-relay/relay.py --config relay.json --port 7703
./examples/approval-relay/run.sh   # unit tests, then a real gateway approving and denying from Slack
```

This is a reference, not a product: state is in memory (a restart forgets open
requests), and it trusts the clock of the host it runs on. Approval quality (decision
times, denials, overrides) is measured on the gateway's side, in Tower's Approvals page.
