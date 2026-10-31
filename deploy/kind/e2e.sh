#!/usr/bin/env bash
# Installs the Helm chart into the current Kubernetes context (a kind cluster in CI)
# the way the docs describe a production install, and checks that it works:
#
# - PostgreSQL with a schema-owner role and a least-privilege runtime role;
# - the chart's migration hook creates the schema as the owner;
# - the server starts as the runtime role (no DDL), serves, signs and verifies audit;
# - the data survives a rolling restart, and `helm upgrade` re-runs the hook.
#
# Needs kubectl, helm, curl and python3, and the image already loaded into the
# cluster as $IMAGE (default contextosd:e2e). Run from the repo root.
set -euo pipefail
IMAGE="${IMAGE:-contextosd:e2e}"
NS="${NS:-contextos-e2e}"
WORK="$(mktemp -d)"
PF=""
dump() {
  echo "::group::cluster state" >&2
  kubectl -n "$NS" get all,jobs,configmaps,secrets >&2 || true
  kubectl -n "$NS" describe pods >&2 || true
  for pod in $(kubectl -n "$NS" get pods -o name 2>/dev/null); do
    echo "--- logs $pod" >&2; kubectl -n "$NS" logs "$pod" --all-containers --tail=80 >&2 || true
  done
  echo "::endgroup::" >&2
}
cleanup() { [ -n "$PF" ] && kill "$PF" 2>/dev/null; rm -rf "$WORK"; }
trap 'status=$?; [ $status -ne 0 ] && dump; cleanup; exit $status' EXIT

kubectl create namespace "$NS" --dry-run=client -o yaml | kubectl apply -f - >/dev/null

echo "== PostgreSQL"
kubectl -n "$NS" apply -f - >/dev/null <<YAML
apiVersion: apps/v1
kind: Deployment
metadata: { name: postgres }
spec:
  selector: { matchLabels: { app: postgres } }
  template:
    metadata: { labels: { app: postgres } }
    spec:
      containers:
        - name: postgres
          image: postgres:17
          env:
            - { name: POSTGRES_USER, value: contextos_owner }
            - { name: POSTGRES_PASSWORD, value: owner-pw }
            - { name: POSTGRES_DB, value: contextos }
          ports: [{ containerPort: 5432 }]
          readinessProbe:
            exec: { command: ["pg_isready", "-U", "contextos_owner", "-d", "contextos"] }
            periodSeconds: 2
---
apiVersion: v1
kind: Service
metadata: { name: postgres }
spec:
  selector: { app: postgres }
  ports: [{ port: 5432 }]
YAML
kubectl -n "$NS" rollout status deployment/postgres --timeout=180s
psql() { kubectl -n "$NS" exec deploy/postgres -- psql -v ON_ERROR_STOP=1 -U contextos_owner -d contextos -tAc "$1"; }
# The runtime role gets the documented data rights on tables the owner creates later,
# and no right to create anything.
psql "CREATE ROLE contextos_runtime LOGIN PASSWORD 'runtime-pw'" >/dev/null
psql "REVOKE CREATE ON SCHEMA public FROM PUBLIC; GRANT USAGE ON SCHEMA public TO contextos_runtime" >/dev/null
psql "ALTER DEFAULT PRIVILEGES FOR ROLE contextos_owner IN SCHEMA public GRANT SELECT, INSERT, UPDATE ON TABLES TO contextos_runtime" >/dev/null

echo "== Secrets and values"
KEY="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
HASH="sha256:$(printf %s "$KEY" | python3 -c 'import hashlib,sys; print(hashlib.sha256(sys.stdin.buffer.read()).hexdigest())')"
SEED="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
kubectl -n "$NS" create secret generic contextosd \
  --from-literal=CONTEXTOS_DATABASE_URL="postgres://contextos_runtime:runtime-pw@postgres:5432/contextos" \
  --from-literal=CONTEXTOS_AUDIT_SEED="$SEED" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl -n "$NS" create secret generic contextosd-owner \
  --from-literal=CONTEXTOS_DATABASE_URL="postgres://contextos_owner:owner-pw@postgres:5432/contextos" \
  --dry-run=client -o yaml | kubectl apply -f - >/dev/null
cat > "$WORK/values.yaml" <<VALUES
image: { repository: "${IMAGE%:*}", tag: "${IMAGE##*:}", pullPolicy: Never }
replicaCount: 2
migration: { enabled: true, secretName: contextosd-owner }
config: |
  packs = ["/etc/contextos/packs/support.json"]
  capabilities = []
  [server]
  listen = "0.0.0.0:8080"
  [store]
  kind = "postgres"
  url_env = "CONTEXTOS_DATABASE_URL"
  [audit]
  key_id = "audit-e2e"
  signing_seed_env = "CONTEXTOS_AUDIT_SEED"
  [support]
  implementation_id = "contextos-rs"
  implementation_version = "e2e"
  profiles = ["contextos.core"]
  controls = []
  [[api_keys]]
  key_sha256 = "$HASH"
  tenant_id = "tenant_acme_prod"
  principal_id = "oncall"
  scopes = ["control", "audit:read"]
VALUES

echo "== helm install (the migration hook runs first)"
helm install contextosd deploy/helm/contextosd -n "$NS" -f "$WORK/values.yaml" \
  --set-file 'packs.support\.json=examples/support-refund/pack.json' --wait --timeout 5m
owner="$(psql "SELECT tableowner FROM pg_tables WHERE tablename = 'contextos_documents'")"
[ "$owner" = contextos_owner ] || { echo "schema owned by $owner, expected contextos_owner" >&2; exit 1; }
[ "$(psql "SELECT version FROM contextos_schema_version")" -ge 4 ]

forward() {
  [ -n "$PF" ] && kill "$PF" 2>/dev/null || true
  kubectl -n "$NS" port-forward svc/contextosd 18080:8080 >/dev/null 2>&1 & PF=$!
  for _ in $(seq 50); do curl -sf http://127.0.0.1:18080/readyz >/dev/null && return; sleep 0.2; done
  echo "the service did not answer" >&2; exit 1
}
api() { curl -sf -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' "$@"; }
verified() { api http://127.0.0.1:18080/v1/audit/verify | python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["verified"], d; print(len(d["entries"]) if isinstance(d["entries"], list) else d["entries"])'; }

echo "== Serving as the runtime role"
forward
api -X POST http://127.0.0.1:18080/v1/revocations \
  -d '{"kind": "capability", "target": "adp_payments.issue_refund", "reason": "E2E-1"}' >/dev/null
before="$(verified)"
echo "audit verifies ($before)"

echo "== Rolling restart: state persists, no DDL needed"
kubectl -n "$NS" rollout restart deployment/contextosd >/dev/null
kubectl -n "$NS" rollout status deployment/contextosd --timeout=180s
forward
api http://127.0.0.1:18080/v1/revocations | grep -q 'E2E-1'
[ "$(verified)" = "$before" ]

echo "== helm upgrade re-runs the migration hook"
helm upgrade contextosd deploy/helm/contextosd -n "$NS" -f "$WORK/values.yaml" \
  --set-file 'packs.support\.json=examples/support-refund/pack.json' --set logLevel=debug --wait --timeout 5m
forward
api http://127.0.0.1:18080/v1/revocations | grep -q 'E2E-1'
echo "kubernetes e2e passed"
