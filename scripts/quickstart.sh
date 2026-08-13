#!/usr/bin/env bash
# One-command demo stack for first contact with the Open Privacy Suite:
#
#   make quickstart
#
# Brings up the self-contained dev stack (docker-compose.yml +
# docker-compose.quickstart.yml — built from this checkout, mock auth
# enabled, nothing external required beyond public base images), then
# seeds a two-bank demo scenario (scripts/quickstart-seed.sh) and prints
# ready-to-use tokens, URLs and example requests.
#
# Requirements: docker (with compose v2), curl, jq, openssl.
#
# Flags:
#   --down          stop the stack (keeps data volumes)
#   --reset         stop the stack and DELETE data volumes, then exit
#   --no-explorer   skip the chain-indexer (explorer API stays empty);
#                   also the automatic fallback when the published
#                   gatewayfm/chain-indexer image cannot be pulled
#   --seed-only     re-run scenario seeding against an already-running stack

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

COMPOSE_ARGS=(-f docker-compose.yml -f docker-compose.quickstart.yml)
ENV_FILE=".env.quickstart"

color() { printf '\033[%sm%s\033[0m' "$1" "$2"; }
bold()  { color "1"    "$1"; }
green() { color "0;32" "$1"; }
yellow(){ color "0;33" "$1"; }
red()   { color "0;31" "$1"; }

WITH_EXPLORER=1
SEED_ONLY=0
case "${1:-}" in
  --down)
    docker compose "${COMPOSE_ARGS[@]}" --profile explorer down --remove-orphans
    exit 0 ;;
  --reset)
    docker compose "${COMPOSE_ARGS[@]}" --profile explorer down --remove-orphans -v
    rm -f .quickstart-demo.json
    echo "$(green 'Stack stopped and data volumes removed.')"
    exit 0 ;;
  --no-explorer) WITH_EXPLORER=0 ;;
  --seed-only)   SEED_ONLY=1 ;;
  "") ;;
  *) echo "usage: $0 [--down|--reset|--no-explorer|--seed-only]" >&2; exit 2 ;;
esac

for cmd in docker curl jq openssl; do
  command -v "$cmd" >/dev/null 2>&1 || { echo "$(red "ERROR: '$cmd' is required")" >&2; exit 1; }
done

# --- Admin token -------------------------------------------------------------
# The base compose interpolates ${ADMIN_API_TOKEN} with no default (fail-open
# would be worse). Generate one once and persist it in .env.quickstart; if a
# .env already provides one (e.g. the privacy dev stack's symlinked secrets),
# reuse it so both stacks agree.
resolve_admin_token() {
  if [[ -n "${ADMIN_API_TOKEN:-}" ]]; then return; fi
  for f in .env "$ENV_FILE"; do
    if [[ -e "$f" ]] && grep -qE '^ADMIN_API_TOKEN=.+' "$f"; then
      ADMIN_API_TOKEN="$(grep -E '^ADMIN_API_TOKEN=' "$f" | tail -1 | cut -d= -f2-)"
      return
    fi
  done
  umask 077
  ADMIN_API_TOKEN="$(openssl rand -hex 32)"
  printf 'ADMIN_API_TOKEN=%s\n' "$ADMIN_API_TOKEN" >>"$ENV_FILE"
  umask 022
  echo "$(bold '==>') $(green "Generated ADMIN_API_TOKEN (persisted in $ENV_FILE)")"
}
resolve_admin_token
export ADMIN_API_TOKEN

# Let a bare `docker compose up` (or Docker Desktop's start button) resolve the
# token too. Same rules as privacy-dev-up.sh: a symlink (or absent .env) is
# ours to manage; a real .env is someone's hand-rolled config — never clobber.
if [[ -f "$ENV_FILE" ]]; then
  if [[ -L ".env" || ! -e ".env" ]]; then
    ln -sf "$ENV_FILE" .env
  fi
fi

PROXY_URL="http://localhost:${HOST_PORT_PROXY:-8080}"

if [[ "$SEED_ONLY" -eq 1 ]]; then
  # Restore the explorer state persisted by the last full run: the seed's
  # explorer check must not run against a stack that was deliberately brought
  # up without one (--no-explorer or the chain-indexer pull fallback).
  # An explicit QUICKSTART_WITH_EXPLORER in the environment still wins.
  if [[ -z "${QUICKSTART_WITH_EXPLORER:-}" && -f "$ENV_FILE" ]] \
     && grep -qE '^QUICKSTART_WITH_EXPLORER=' "$ENV_FILE"; then
    QUICKSTART_WITH_EXPLORER="$(grep -E '^QUICKSTART_WITH_EXPLORER=' "$ENV_FILE" | tail -1 | cut -d= -f2-)"
  fi
  export QUICKSTART_WITH_EXPLORER="${QUICKSTART_WITH_EXPLORER:-1}"
  exec "$REPO_ROOT/scripts/quickstart-seed.sh"
fi

# --- Explorer profile --------------------------------------------------------
# chain-indexer is a published image (its source lives in a separate repo).
# If the pull fails (no Docker Hub access to it), fall back to a stack
# without the explorer — everything else in the demo still works.
PROFILE_ARGS=()
if [[ "$WITH_EXPLORER" -eq 1 ]]; then
  echo "$(bold '==>') Checking chain-indexer image (explorer data source)…"
  if docker compose "${COMPOSE_ARGS[@]}" --profile explorer pull chain-indexer >/dev/null 2>&1 \
     || docker image inspect "gatewayfm/chain-indexer:${INDEXER_VERSION:-0.3.0}" >/dev/null 2>&1; then
    PROFILE_ARGS=(--profile explorer)
    echo "    $(green 'chain-indexer available — explorer API will be live.')"
  else
    WITH_EXPLORER=0
    echo "    $(yellow 'gatewayfm/chain-indexer image not accessible — starting without the explorer.')"
    echo "    The RPC + admin + privacy demo works fully; explorer endpoints will just be empty."
  fi
fi
if [[ "$WITH_EXPLORER" -eq 0 ]]; then
  # Empty on purpose: ${VAR-default} in the overlay keeps the empty value,
  # which disables the explorer backends instead of dangling hostnames.
  export QUICKSTART_INDEXER_URL=""
  export QUICKSTART_EXPLORER_DATABASE_URL=""
fi
export QUICKSTART_WITH_EXPLORER="$WITH_EXPLORER"
# Persist the resolved explorer state so --seed-only re-runs verify the
# stack that actually exists (see the restore above).
if [[ -f "$ENV_FILE" ]] && grep -qE '^QUICKSTART_WITH_EXPLORER=' "$ENV_FILE"; then
  env_tmp="$(mktemp)"
  grep -vE '^QUICKSTART_WITH_EXPLORER=' "$ENV_FILE" >"$env_tmp" || true
  printf 'QUICKSTART_WITH_EXPLORER=%s\n' "$WITH_EXPLORER" >>"$env_tmp"
  cat "$env_tmp" >"$ENV_FILE"
  rm -f "$env_tmp"
else
  printf 'QUICKSTART_WITH_EXPLORER=%s\n' "$WITH_EXPLORER" >>"$ENV_FILE"
fi

# Build identity (RD-1023) — same resolution as privacy-dev-up.sh.
export VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"
export GIT_COMMIT="${GIT_COMMIT:-$(git rev-parse --short HEAD 2>/dev/null || echo none)}"
export BUILD_TIME="${BUILD_TIME:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"

echo "$(bold '==>') $(green 'Building and starting the quickstart stack') (first build takes a few minutes)"
docker compose "${COMPOSE_ARGS[@]}" "${PROFILE_ARGS[@]}" up -d --build

# --- Audit DB on pre-existing volumes ---------------------------------------
# The init hook only runs when the postgres volume is first created. If this
# checkout previously ran the base compose (volume exists, no audit DB), the
# backend would crash-loop on a missing privacy_proxy_audit. The hook is
# idempotent — run it explicitly once postgres is up.
echo "$(bold '==>') Ensuring the audit database exists…"
for _ in $(seq 1 30); do
  if docker compose "${COMPOSE_ARGS[@]}" exec -T postgres pg_isready -U postgres -d privacy_proxy >/dev/null 2>&1; then
    break
  fi
  sleep 2
done
docker compose "${COMPOSE_ARGS[@]}" exec -T \
  -e AUDIT_APP_PASSWORD="${QUICKSTART_AUDIT_APP_PASSWORD:-quickstart-audit-dev-only}" \
  postgres sh /docker-entrypoint-initdb.d/10-init-audit-db.sh >/dev/null

# --- Wait for the backend ----------------------------------------------------
echo "$(bold '==>') Waiting for proxy-backend to become healthy…"
healthy=0
for _ in $(seq 1 90); do
  status="$(docker inspect --format='{{.State.Health.Status}}' \
    "$(docker compose "${COMPOSE_ARGS[@]}" ps -q proxy-backend)" 2>/dev/null || echo starting)"
  if [[ "$status" == "healthy" ]]; then healthy=1; break; fi
  sleep 2
done
if [[ "$healthy" -ne 1 ]]; then
  echo "$(red 'Backend did not become healthy in 180s.') Check:" >&2
  echo "  docker compose ${COMPOSE_ARGS[*]} logs proxy-backend" >&2
  exit 1
fi
echo "    $(green 'Backend healthy.')"

# --- Seed the demo scenario --------------------------------------------------
"$REPO_ROOT/scripts/quickstart-seed.sh"

cat <<EOF

$(bold 'Stack management:')
  make quickstart          re-run (idempotent; re-seeds and re-prints tokens)
  make quickstart-down     stop the stack
  make quickstart-reset    stop and wipe all data
EOF
