# Make contextosd the only path to your systems

A shared guarantee, an approval or a budget binds only the effects that go through
`contextosd`. An agent that holds a payments token, or can open a connection to the
payments API, can refund around all of them, and no dashboard will show it. Coverage is
established by construction instead: the agent has no credential for the systems it
acts on and no network path to them, so its only way to act is a governed call.

Three things make that true. The chart does the network part.

| Layer | What to do | Where |
|---|---|---|
| Credentials | Provider tokens, OAuth client secrets and adapter keys live only in `contextosd`'s Secret (`secretName`). Agents get a ContextOS API key or an OIDC identity with `dispatch`, nothing else. | Your secret store |
| Agent egress | Agents' pods may reach `contextosd`, DNS and your model gateway, nothing else. | `agentEgress` (below) |
| contextosd egress | Optionally, `contextosd` itself reaches only the store, its providers and tool endpoints. | `networkPolicy.egressTo` |

Exposure created before onboarding, or later through a system that does not go through
`contextosd` (a legacy back office), still counts: import it into the guarantee's
ledgers ([SHARED_GUARANTEES.md](../SHARED_GUARANTEES.md), `POST
/v1/guarantees/{id}/imports`).

## Confine the agents

Run agents in their own namespace, with a label every agent workload carries:

```yaml
agentEgress:
  enabled: true
  namespace: agents                          # defaults to the release's namespace
  podSelector:
    matchLabels: { app.kubernetes.io/component: agent }
  allowTo:                                   # NetworkPolicyEgressRule list
    - to:                                    # your model gateway
        - namespaceSelector: { matchLabels: { kubernetes.io/metadata.name: llm-gateway } }
      ports: [{ port: 443, protocol: TCP }]
```

The chart then renders, in the agents' namespace, a NetworkPolicy that lets the
selected pods reach DNS, `contextosd`'s pods on port 8080 and the `allowTo` rules, and
adds the agents as an allowed peer to `contextosd`'s own policy. Everything else they
try is dropped: the payments API, the order service, the internet. The chart refuses an
empty `podSelector`, which would select every pod in the namespace, `contextosd`'s
included when they share one.

Things to get right:

- **Every agent is selected.** A pod the selector misses is not confined. Prefer a
  namespace that holds only agents, and enforce the label at admission (Kyverno,
  Gatekeeper or a `ValidatingAdmissionPolicy`) so a new workload cannot run without it.
- **Model calls go through a gateway you run.** NetworkPolicy allows by pod, namespace
  or CIDR, not by host name, and model providers' addresses change. Point agents at an
  in-cluster LLM gateway and allow that; the gateway reaches the provider. A metering
  gateway also charges model calls to the run's budget
  ([examples/metering-proxy](../../examples/metering-proxy)).
- **Your CNI enforces NetworkPolicy.** Calico, Cilium, and kind's kindnet (kind 0.24
  and later) do. A cluster without an enforcing CNI accepts the policy and ignores it,
  so check it (below).
- **Host-name allow-lists for `contextosd`.** `networkPolicy.egressTo` takes CIDRs and
  selectors. To allow `payments.example.com` by name, use your mesh's or CNI's egress
  gateway (Istio egress gateway, Cilium FQDN policies); the chart does not.

## Check it

From the agents' namespace, a pod with the agents' label should reach `contextosd` and
not a provider, and one without it should reach the provider:

```sh
probe() {   # probe NAME LABELS
  kubectl -n agents run "$1" --restart=Never --image=python:3.12-slim --labels="$2" --command -- \
    python3 -c 'import sys, urllib.request
for url in sys.argv[1:]:
    try: urllib.request.urlopen(url, timeout=5); print(url, "reached")
    except urllib.error.HTTPError: print(url, "reached")
    except Exception: print(url, "unreachable")' \
    http://contextosd.contextos.svc:8080/readyz https://payments.internal.example/
  kubectl -n agents wait --for=jsonpath='{.status.phase}'=Succeeded "pod/$1" --timeout=120s
  kubectl -n agents logs "$1"; kubectl -n agents delete pod "$1"
}
probe agent-check app.kubernetes.io/component=agent   # contextosd reached, payments unreachable
probe control-check app=control                       # payments reached
```

If the control cannot reach the provider either, the check proves nothing: pick a
target the cluster can reach. If the agent reaches the provider, the CNI is not
enforcing the policy. CI runs this check on a kind cluster in `deploy/kind/e2e.sh`.

## What this does not cover

- Agents outside the cluster, or with credentials obtained some other way. Rotate any
  provider credential an agent held before onboarding.
- People and systems acting on the provider directly. Import that exposure, and
  reconcile holds against the provider's records.
- Data an agent can read from the model gateway or `contextosd`'s responses. This
  recipe governs effects, not what the agent learns.
