# contextosd Helm chart

```sh
kubectl create secret generic contextosd \
  --from-literal=CONTEXTOS_DATABASE_URL='postgres://…' \
  --from-literal=CONTEXTOS_AUDIT_SEED="$(your-kms-fetch)"
helm install contextosd deploy/helm/contextosd -f my-values.yaml
```

Defaults are hardened: non-root (65532), read-only root filesystem, all capabilities
dropped, `RuntimeDefault` seccomp, no service-account token, zero-unavailable rolling
updates, a PodDisruptionBudget and a NetworkPolicy. Readiness waits for the store and
every OIDC issuer's keys.

The default `config` starts a server nobody can call: it has no API keys or OIDC
issuer, no packs and no providers. A values file for a first deployment:

```yaml
config: |
  packs = ["/etc/contextos/packs/support.json"]
  capabilities = ["/etc/contextos/capabilities/issue_refund.json"]
  [server]
  listen = "0.0.0.0:8080"
  [store]
  kind = "postgres"
  url_env = "CONTEXTOS_DATABASE_URL"
  [audit]
  key_id = "audit-2026-11"
  [audit.kms]                     # keep the signing key out of the pod
  kind = "vault_transit"
  url = "https://vault.internal:8200"
  key_name = "contextos-audit"
  token_env = "VAULT_TOKEN"
  key_version = 1
  public_key = "<base64url Ed25519 public key of that version>"
  [support]
  implementation_id = "contextos-rs"
  implementation_version = "0.1.0-alpha.10"
  profiles = ["contextos.core"]
  controls = ["identity.authenticated", "authority.scoped", "policy.fail_visible", "context.integrity", "audit.correlated"]
  [[api_keys]]                    # your executor service
  key_sha256 = "sha256:…"         # from `ctx hash-key`
  tenant_id = "tenant_acme_prod"
  principal_id = "svc_orchestrator"
  scopes = ["compile", "admit", "dispatch", "audit:read"]
  [[api_keys]]                    # on-call operators (docs/INCIDENT.md)
  key_sha256 = "sha256:…"
  tenant_id = "tenant_acme_prod"
  principal_id = "oncall"
  scopes = ["control", "reconcile", "audit:read"]
  # [providers.*] and [[adapters]]: see deploy/contextosd.example.toml
packs:
  support.json: { … }             # your Context Pack, as JSON
capabilities:
  issue_refund.json: { … }        # a reviewed capability manifest
```

Validate it before installing: render the `config` value to a file and run
`contextosd --check-config` on it with the same environment variables set.

**Database schema.** The server creates or upgrades its schema on start only if its
database role may; a least-privilege runtime role (docs/GUIDE.md section 12, *Store*)
cannot. Let the chart migrate as the schema's owner before every install and upgrade:

```sh
kubectl create secret generic contextosd-owner \
  --from-literal=CONTEXTOS_DATABASE_URL='postgres://contextos_owner:…@db/contextos'
helm install contextosd deploy/helm/contextosd -f my-values.yaml \
  --set migration.enabled=true --set migration.secretName=contextosd-owner
```

The pre-install and pre-upgrade hook runs `contextosd --migrate` as a Job and the
release waits for it. The runtime role then needs only data rights (`USAGE` on the
schema; `SELECT, INSERT, UPDATE` on `contextos_documents`, `SELECT, INSERT` on
`contextos_audit_log`, `SELECT` on `contextos_schema_version`); grant them after the
first migration, or in advance with `ALTER DEFAULT PRIVILEGES FOR ROLE <owner>`. The
Secret named by `secretName` must exist before install; pods wait in
`CreateContainerConfigError` until it does. CI installs the chart this way on a kind
cluster (`deploy/kind/e2e.sh`).

**Private CAs.** Providers, adapters, the KMS and OIDC issuers behind your own CA are
trusted once the server can read that CA:

```yaml
extraVolumes:
  - name: corp-ca
    configMap: { name: corp-ca }        # kubectl create configmap corp-ca --from-file=ca.pem
extraVolumeMounts:
  - { name: corp-ca, mountPath: /etc/contextos/ca, readOnly: true }
extraEnv:
  - { name: CONTEXTOS_CA_BUNDLE, value: /etc/contextos/ca/ca.pem }
```

Sidecars go in `extraContainers` (with `extraVolumes`): they share the pod's network,
so contextosd reaches them on loopback, for example a database proxy or a secrets
agent.

Put `contextosd.toml` in `config`; reference packs and capability manifests at
`/etc/contextos/packs/<name>` and `/etc/contextos/capabilities/<name>` after listing
them under `packs` / `capabilities`. Secrets come only from `secretName`. Pin the image
by `image.digest` in production.

Monitoring: `serviceMonitor.enabled` scrapes `/metrics`. The default NetworkPolicy
admits only pods in the release's namespace, so a Prometheus elsewhere needs a peer in
`networkPolicy.ingressFrom` (for example a `namespaceSelector` for its namespace); `prometheusRule.enabled`
installs the alerting rules in `files/contextos-rules.yaml` (also usable as a plain
Prometheus rules file). Each alert links to its runbook in
[docs/INCIDENT.md](../../../docs/INCIDENT.md#alerts). The rules' unit tests are in
`deploy/alerts/` (`promtool test rules deploy/alerts/contextos-rules.test.yaml`). Import
`deploy/grafana/contextos-governance.json` into Grafana for the matching dashboard; it
uses the rules' recording rules.
