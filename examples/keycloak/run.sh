#!/usr/bin/env bash
# Runs ContextOS with Keycloak as its identity provider: an agent acts for a signed-in
# user through Keycloak token exchange delegation, and admission binds each run to that
# user. Starts Keycloak in Docker unless KEYCLOAK_URL names one (admin/admin).
set -euo pipefail
cd "$(dirname "$0")/../.."
source examples/binaries.sh
contextos_binaries debug contextosd
if [ -z "${KEYCLOAK_URL:-}" ]; then
  image="${KEYCLOAK_IMAGE:-quay.io/keycloak/keycloak:26.8.1}"
  name="contextos-keycloak-$$"
  port=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')
  trap 'docker rm -f "$name" >/dev/null 2>&1 || true' EXIT
  docker run -d --name "$name" -p "127.0.0.1:$port:8080" \
    -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
    "$image" start-dev --features=token-exchange-delegation,parameterized-scopes >/dev/null
  KEYCLOAK_URL="http://localhost:$port"
  for _ in $(seq 1 90); do
    curl -sf "$KEYCLOAK_URL/realms/master/.well-known/openid-configuration" >/dev/null && break
    sleep 2
  done
fi
export KEYCLOAK_URL
python3 examples/keycloak/pilot.py
