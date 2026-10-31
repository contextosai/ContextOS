#!/usr/bin/env bash
# Installs the Helm chart into the current Kubernetes context (a kind cluster in CI)
# the way the docs describe a production install, and checks that it works:
#
# - PostgreSQL with a schema-owner role and a least-privilege runtime role;
# - the chart's migration hook creates the schema as the owner;
# - the server starts in production mode as the runtime role (no DDL), with its own
#   keys, and reaches its providers over HTTPS behind a private CA it trusts through
#   CONTEXTOS_CA_BUNDLE: it admits a run, dispatches a refund, signs and verifies audit;
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
            # Over TCP: the image's init phase runs a socket-only server, then restarts.
            exec: { command: ["pg_isready", "-h", "127.0.0.1", "-U", "contextos_owner", "-d", "contextos"] }
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
psql() { kubectl -n "$NS" exec deploy/postgres -- psql -v ON_ERROR_STOP=1 -h 127.0.0.1 -U contextos_owner -d contextos -tAc "$1"; }
for _ in $(seq 30); do psql "SELECT 1" >/dev/null 2>&1 && break; sleep 2; done
# The runtime role gets the documented data rights on tables the owner creates later,
# and no right to create anything.
psql "CREATE ROLE contextos_runtime LOGIN PASSWORD 'runtime-pw'" >/dev/null
psql "REVOKE CREATE ON SCHEMA public FROM PUBLIC; GRANT USAGE ON SCHEMA public TO contextos_runtime" >/dev/null
psql "ALTER DEFAULT PRIVILEGES FOR ROLE contextos_owner IN SCHEMA public GRANT SELECT, INSERT, UPDATE ON TABLES TO contextos_runtime" >/dev/null

echo "== Secrets and values"
# Production mode, as the docs describe it: the operator's own keys (production refuses
# the published development ones), providers over HTTPS behind a private CA the test
# generates and the server trusts through CONTEXTOS_CA_BUNDLE. The quickstart's
# synthetic providers run as a sidecar, serving TLS on loopback.
KEY="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
OPS="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
SEED="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
(cd "$WORK" \
  && openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.pem -days 2 -subj "/CN=ContextOS e2e CA" \
  && openssl req -newkey rsa:2048 -nodes -keyout tls.key -out tls.csr -subj "/CN=127.0.0.1" \
  && printf 'subjectAltName=IP:127.0.0.1\n' > san.ext \
  && openssl x509 -req -in tls.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out tls.pem -days 2 -extfile san.ext) \
  >/dev/null 2>&1
kubectl -n "$NS" create secret generic contextosd \
  --from-literal=CONTEXTOS_DATABASE_URL="postgres://contextos_runtime:runtime-pw@postgres:5432/contextos" \
  --from-literal=CONTEXTOS_AUDIT_SEED="$SEED" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl -n "$NS" create secret generic contextosd-owner \
  --from-literal=CONTEXTOS_DATABASE_URL="postgres://contextos_owner:owner-pw@postgres:5432/contextos" \
  --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl -n "$NS" create configmap dev-services --from-file=examples/support-refund/dev_services.py \
  --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl -n "$NS" create secret generic provider-tls --from-file="$WORK/tls.pem" --from-file="$WORK/tls.key" \
  --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl -n "$NS" create configmap provider-ca --from-file="$WORK/ca.pem" \
  --dry-run=client -o yaml | kubectl apply -f - >/dev/null
python3 deploy/kind/config.py "$KEY" "$OPS" > "$WORK/contextosd.toml"
python3 - "$WORK/contextosd.toml" "$IMAGE" > "$WORK/values.yaml" <<'PY'
import json, sys
config, image = open(sys.argv[1]).read(), sys.argv[2]
repo, tag = image.rsplit(":", 1)
print(json.dumps({
    "image": {"repository": repo, "tag": tag, "pullPolicy": "Never"},
    "replicaCount": 2,
    "migration": {"enabled": True, "secretName": "contextosd-owner"},
    "config": config,
    "extraEnv": [{"name": "CONTEXTOS_CA_BUNDLE", "value": "/etc/contextos/ca/ca.pem"}],
    "extraVolumeMounts": [{"name": "provider-ca", "mountPath": "/etc/contextos/ca", "readOnly": True}],
    "extraContainers": [{
        "name": "dev-services", "image": "python:3.12-slim",
        "command": ["python3", "/dev-services/dev_services.py"],
        "env": [{"name": "CONTEXTOS_DEV_TLS_CERT", "value": "/tls/tls.pem"},
                {"name": "CONTEXTOS_DEV_TLS_KEY", "value": "/tls/tls.key"}],
        "volumeMounts": [{"name": "dev-services", "mountPath": "/dev-services", "readOnly": True},
                         {"name": "provider-tls", "mountPath": "/tls", "readOnly": True}],
        "securityContext": {"allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"]}},
    }],
    "extraVolumes": [{"name": "dev-services", "configMap": {"name": "dev-services"}},
                     {"name": "provider-tls", "secret": {"secretName": "provider-tls", "defaultMode": 0o444}},
                     {"name": "provider-ca", "configMap": {"name": "provider-ca"}}],
}))
PY
files=(--set-file 'packs.support\.json=examples/support-refund/pack.json'
       --set-file 'capabilities.issue_refund\.json=examples/support-refund/capabilities/issue_refund.json'
       --set-file 'capabilities.lookup_order\.json=examples/support-refund/capabilities/lookup_order.json')

echo "== helm install (the migration hook runs first)"
helm install contextosd deploy/helm/contextosd -n "$NS" -f "$WORK/values.yaml" "${files[@]}" --wait --timeout 5m
owner="$(psql "SELECT tableowner FROM pg_tables WHERE tablename = 'contextos_documents'")"
[ "$owner" = contextos_owner ] || { echo "schema owned by $owner, expected contextos_owner" >&2; exit 1; }
[ "$(psql "SELECT version FROM contextos_schema_version")" -ge 4 ]

URL=http://127.0.0.1:18080
forward() {
  [ -n "$PF" ] && kill "$PF" 2>/dev/null || true
  kubectl -n "$NS" port-forward svc/contextosd 18080:8080 >/dev/null 2>&1 & PF=$!
  for _ in $(seq 50); do curl -sf "$URL/readyz" >/dev/null && return; sleep 0.2; done
  echo "the service did not answer" >&2; exit 1
}
api() { local key="$1"; shift; curl -sS --fail-with-body -H "Authorization: Bearer $key" -H 'Content-Type: application/json' "$@"; }
verified() { api "$KEY" "$URL/v1/audit/verify" | python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["verified"], d; e=d["entries"]; print(len(e) if isinstance(e, list) else e)'; }

echo "== Serving in production mode as the runtime role: admit, dispatch over TLS, kill switch, audit"
forward
RUN="$(python3 -c '
import json
run = json.load(open("examples/support-refund/requests/run.json"))
# Production requires the model and evaluator releases to be pinned.
art = lambda t, i: {"artifact_type": t, "artifact_id": i, "version": "1", "sha256": "sha256:" + "0" * 64}
run["contract"]["release_refs"] += [art("model_profile", "e2e-model"), art("evaluator_suite", "e2e-evals")]
run["task_authorization"] = {
    "issued_by": {"principal_id": "usr_771", "principal_type": "person", "trust_domain": "contextos.dev",
                  "tenant_id": "tenant_acme_prod"},
    "scopes": [{"root_run_id": "run_demo_1", "purpose_ids": ["support.refund"],
                "capability_ids": ["adp_payments.issue_refund"], "resource_ids": ["ord_881"],
                "destination_ids": ["cus_77"], "classification_labels": ["CONFIDENTIAL"], "argument_constraints": [],
                "amount_ceiling": {"minor_units": 120000, "currency": "INR"}}]}
print(json.dumps(run))')"
ADMITTED=""
for _ in $(seq 20); do ADMITTED="$(api "$KEY" -X POST "$URL/v1/runs" --data "$RUN" 2>/dev/null)" && break; sleep 1; done
[ -n "$ADMITTED" ] || api "$KEY" -X POST "$URL/v1/runs" --data "$RUN"
GENERATION="$(echo "$ADMITTED" | python3 -c 'import json,sys; print(json.load(sys.stdin)["executor_generation"])')"
status="$(api "$KEY" -H "contextos-executor-generation: $GENERATION" -X POST "$URL/v1/runs/run_demo_1/tool-calls" \
  --data @examples/support-refund/requests/tool_call.json | python3 -c 'import json,sys; print(json.load(sys.stdin)["result"]["status"])')"
[ "$status" = completed ] || { echo "refund dispatch: $status" >&2; exit 1; }
api "$OPS" -X POST "$URL/v1/revocations" \
  -d '{"kind": "capability", "target": "adp_orders.lookup", "reason": "E2E-1"}' >/dev/null
before="$(verified)"
kubectl -n "$NS" logs deploy/contextosd -c contextosd | grep -q 'trusting private CAs from CONTEXTOS_CA_BUNDLE'
echo "admitted, refunded over TLS behind a private CA, revoked; audit verifies ($before entries)"

echo "== Rolling restart: state persists, no DDL needed"
kubectl -n "$NS" rollout restart deployment/contextosd >/dev/null
kubectl -n "$NS" rollout status deployment/contextosd --timeout=180s
forward
api "$KEY" "$URL/v1/runs/run_demo_1" >/dev/null
api "$OPS" "$URL/v1/revocations" | grep -q 'E2E-1'
# The same operation again is not sent twice, by any replica.
again="$(api "$KEY" -H "contextos-executor-generation: $GENERATION" -X POST "$URL/v1/runs/run_demo_1/tool-calls" \
  --data @examples/support-refund/requests/tool_call.json | python3 -c 'import json,sys; r=json.load(sys.stdin); print(r["result"]["status"], r["report"]["reason_codes"])')"
echo "replayed after restart: $again"
case "$again" in completed*\[\]) echo "the refund was dispatched again" >&2; exit 1;; esac
[ "$(verified)" -ge "$before" ]

echo "== helm upgrade re-runs the migration hook"
helm upgrade contextosd deploy/helm/contextosd -n "$NS" -f "$WORK/values.yaml" "${files[@]}" \
  --set logLevel=debug --wait --timeout 5m
forward
api "$OPS" "$URL/v1/revocations" | grep -q 'E2E-1'
verified >/dev/null
echo "kubernetes e2e passed"
