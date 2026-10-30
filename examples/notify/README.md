# Escalation notification relay

`relay.py` receives contextosd's escalation webhooks (`[[notifications]]`, see the
GUIDE section on policy escalations). It verifies the signature and drops duplicate
event ids. It then posts a short message with the decision's link to a Slack incoming
webhook (`SLACK_WEBHOOK_URL`) and/or PagerDuty Events v2 (`PAGERDUTY_ROUTING_KEY`).
PagerDuty incidents are keyed by escalation, so a resolved escalation resolves its
incident.

It is an example: it remembers seen ids in memory only and listens on loopback. Run
it behind your ingress and keep its secret in your secret store.
