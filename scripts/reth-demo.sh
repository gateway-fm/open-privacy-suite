#!/usr/bin/env bash
# Isolated, development-only OPS + signed-approval Reth stack. No host toolchain.
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# Match privacy-dev-up.sh's Docker CLI invocation so Compose receives Docker's
# selected context. Keep the legacy fallback for installations without a plugin.
command -v docker >/dev/null 2>&1 || { echo 'Docker is required.' >&2; exit 1; }
if docker compose version >/dev/null 2>&1; then
  COMPOSE_CMD=(docker compose)
elif command -v docker-compose >/dev/null 2>&1; then
  COMPOSE_CMD=(docker-compose)
else
  echo 'Docker Compose is required.' >&2
  exit 1
fi
export RETH_DEMO_PROJECT="${RETH_DEMO_PROJECT:-ops-reth-demo-$(printf '%s' "$REPO_ROOT" | cksum | awk '{print $1}')}"
case "$RETH_DEMO_PROJECT" in
  *[!a-z0-9_-]*|[!a-z0-9]*|'') echo 'RETH_DEMO_PROJECT must start with a lowercase letter or digit and contain only lowercase letters, digits, _ or -.' >&2; exit 2 ;;
esac
COMPOSE_ARGS=(--env-file /dev/null -p "$RETH_DEMO_PROJECT" -f docker-compose.reth-demo.yml)
compose() { "${COMPOSE_CMD[@]}" "${COMPOSE_ARGS[@]}" "$@"; }

print_urls() {
  local frontend backend rpc
  frontend="$(compose port proxy-frontend 5173)"
  backend="$(compose port proxy-backend 8080)"
  rpc="$(compose port reth 8545)"
  echo "Reth demo Compose project: $RETH_DEMO_PROJECT"
  echo "Frontend: http://$frontend"
  echo "OPS:      http://$backend"
  echo "Reth RPC: http://$rpc"
  echo 'Development identity: did:test:reth-demo-alice'
  echo 'Local development admin token: ops-reth-local-demo-only'
  echo 'Commands: make demo-reth-status | demo-reth-logs | demo-reth-down | demo-reth-reset'
}

start() {
  compose up -d --build postgres redis reth proxy-backend proxy-frontend
  compose run --rm demo seed
}

case "${1:-up}" in
  up)
    start
    compose up -d block-driver
    print_urls ;;
  check|walkthrough)
    # These scenarios intentionally require a new chain and policy database.
    # Only this checkout's demo project is reset; the developer's other stacks
    # and their volumes are never selected.
    echo "Starting fresh $RETH_DEMO_PROJECT fixtures for ${1}."
    compose --profile driver --profile tools down --volumes --remove-orphans
    start
    print_urls
    compose run --rm demo "$1"
    mkdir -p .tmp/reth-demo-evidence
    compose run --rm --no-deps --entrypoint cat demo /demo/evidence/demo.json > .tmp/reth-demo-evidence/demo.json
    compose run --rm --no-deps --entrypoint cat demo /demo/evidence/direct-canary.json > .tmp/reth-demo-evidence/direct-canary.json
    compose up -d block-driver
    echo 'All scenarios passed. Stack remains running; evidence: .tmp/reth-demo-evidence/' ;;
  down)
    compose --profile driver --profile tools down --remove-orphans ;;
  reset)
    compose --profile driver --profile tools down --volumes --remove-orphans ;;
  logs)
    compose --profile driver logs -f ;;
  status)
    compose --profile driver --profile tools ps -a ;;
  *) echo 'Usage: reth-demo.sh [up|check|walkthrough|down|reset|logs|status]' >&2; exit 2 ;;
esac
