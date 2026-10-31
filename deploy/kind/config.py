"""Writes the kind e2e's contextosd.toml from the quickstart's configuration: production
mode, PostgreSQL, providers over HTTPS on loopback (a sidecar, behind a CA the test
generates), and the operator's own keys, since production refuses the published ones.

    python3 deploy/kind/config.py <executor key> <operator key> > contextosd.toml

Production defaults the quickstart's files cannot meet are opted out of explicitly,
as the guide's refusal table shows: recalled memory without a memory service, and a
completion contract for the demo provider, which reports no state.
"""
import hashlib
import sys

executor, operator = sys.argv[1], sys.argv[2]


def digest(key: str) -> str:
    return "sha256:" + hashlib.sha256(key.encode()).hexdigest()


text = open("examples/support-refund/contextosd.toml").read()
for old, new in [
    ('packs = ["examples/support-refund/pack.json"]', 'packs = ["/etc/contextos/packs/support.json"]'),
    ('"examples/support-refund/capabilities/', '"/etc/contextos/capabilities/'),
    ('listen = "127.0.0.1:8080"', 'listen = "0.0.0.0:8080"'),
    ('mode = "development"', 'mode = "production"'),
    ('kind = "memory"', 'kind = "postgres"\nurl_env = "CONTEXTOS_DATABASE_URL"'),
    ("http://127.0.0.1:", "https://127.0.0.1:"),
    ("sha256:REPLACED_BY_RUN_SH", digest(executor)),
]:
    assert old in text, old
    text = text.replace(old, new)
# Only the executor's key and an operator key: the development keys are published.
text = text[: text.index("# Development evaluator")]
text += f"""
[[api_keys]]
key_sha256 = "{digest(operator)}"
tenant_id = "tenant_acme_prod"
principal_id = "svc_oncall"
scopes = ["control", "reconcile"]

[guards]
trust_supplied_memory = true
require_completion_contracts = false
"""
sys.stdout.write(text)
