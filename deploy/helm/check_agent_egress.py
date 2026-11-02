#!/usr/bin/env python3
"""Checks the chart's agent egress policy, rendered with agentEgress enabled for the
agents namespace and component=agent pods, and allowTo one CIDR.

Usage: yq ea -o=json '[.]' rendered.yaml | python3 deploy/helm/check_agent_egress.py
"""
import json
import sys

docs = [d for d in json.load(sys.stdin) if d]
policies = {d["metadata"]["name"]: d for d in docs if d.get("kind") == "NetworkPolicy"}
agents = policies["t-contextosd-agent-egress"]
server = policies["t-contextosd"]
agent_pods = {"matchLabels": {"app.kubernetes.io/component": "agent"}}
contextosd = {"matchLabels": {"app.kubernetes.io/name": "contextosd", "app.kubernetes.io/instance": "t"}}

# The agents' pods, in their own namespace, are confined for egress only.
assert agents["metadata"]["namespace"] == "agents", agents["metadata"]
assert agents["spec"]["podSelector"] == agent_pods, agents["spec"]["podSelector"]
assert agents["spec"]["policyTypes"] == ["Egress"], agents["spec"]["policyTypes"]

# Exactly three rules: DNS, contextosd's pods on 8080, and allowTo.
dns, server_rule, allowed = agents["spec"]["egress"]
assert "to" not in dns and {p["port"] for p in dns["ports"]} == {53}, dns
assert server_rule["ports"] == [{"port": 8080, "protocol": "TCP"}], server_rule
(peer,) = server_rule["to"]
assert peer["podSelector"] == contextosd, peer
assert peer["namespaceSelector"] == {"matchLabels": {"kubernetes.io/metadata.name": "default"}}, peer
assert allowed == {"to": [{"ipBlock": {"cidr": "10.20.0.0/16"}}], "ports": [{"port": 443}]}, allowed

# contextosd admits them from their namespace.
peers = server["spec"]["ingress"][0]["from"]
admitted = {"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "agents"}}, "podSelector": agent_pods}
assert admitted in peers, peers
print("agent egress policy: ok")
