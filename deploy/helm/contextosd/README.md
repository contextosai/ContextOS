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
  implementation_version = "0.1.0-alpha.9"
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
cannot. Run the migration with an owner role before installing or upgrading, for
example as a one-off pod from the same image:

```sh
kubectl run contextosd-migrate --rm -i --restart=Never --image=<image> \
  --env CONTEXTOS_DATABASE_URL='postgres://owner@…' -- --migrate /etc/contextos/contextosd.toml
```

(mount the same config, or pass one that names the store). The Secret named by
`secretName` must exist before install; pods wait in `CreateContainerConfigError`
until it does.

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
