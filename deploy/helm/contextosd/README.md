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

Put `contextosd.toml` in `config`; reference packs and capability manifests at
`/etc/contextos/packs/<name>` and `/etc/contextos/capabilities/<name>` after listing
them under `packs` / `capabilities`. Secrets come only from `secretName`. Pin the image
by `image.digest` in production.
