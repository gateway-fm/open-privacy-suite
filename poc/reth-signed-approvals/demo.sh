#!/usr/bin/env bash
set -euo pipefail
DEMO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEMO_ROOT="$(cd "$DEMO_DIR/../.." && pwd)"
cd "$DEMO_ROOT"

# Prefer the shared cache of the earlier PoC on this workstation; portable
# setup.py builds use .tmp/approval-target. An explicit binary always wins.
if [[ -z "${OPS_RETH_BINARY:-}" ]]; then
  for candidate in "$DEMO_ROOT/.tmp/approval-target/release/ops-reth-approvals-poc" \
    "$DEMO_ROOT/../../reth-policy-poc/target/release/ops-reth-approvals-poc"; do
    if [[ -x "$candidate" ]]; then export OPS_RETH_BINARY="$candidate"; break; fi
  done
fi
if [[ -z "${OPS_RETH_BINARY:-}" || ! -x "$OPS_RETH_BINARY" || ! -x "$DEMO_ROOT/.tmp/ops-server" ]]; then
  echo 'Build first: python3 poc/reth-signed-approvals/setup.py' >&2
  exit 1
fi
export OPS_EVIDENCE_DIR="${OPS_EVIDENCE_DIR:-$DEMO_DIR/evidence/demo-replay}"
export OPS_FINGERPRINT_MODE=direct
export OPS_PROFILE=0
exec python3 "$DEMO_DIR/demo.py" "$@"
