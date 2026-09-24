#!/usr/bin/env bash
set -euo pipefail
POC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_ROOT="$(cd "$POC_DIR/../.." && pwd)"
COMMON_GIT_DIR="$(git -C "$POC_ROOT" rev-parse --path-format=absolute --git-common-dir)"
LOADGEN_UPSTREAM="${GASSTORM_LOADGEN_SOURCE:-$(dirname "$(dirname "$COMMON_GIT_DIR")")/loadgenerator}"
GASSTORM_UPSTREAM="${GASSTORM_SOURCE:-$(dirname "$(dirname "$COMMON_GIT_DIR")")/gasstorm}"
export GASSTORM_LOADGEN_SOURCE
GASSTORM_LOADGEN_SOURCE="$(python3 "$POC_DIR/prepare_gasstorm.py" loadgenerator "$LOADGEN_UPSTREAM")"
GASSTORM_SOURCE="$(python3 "$POC_DIR/prepare_gasstorm.py" gasstorm "$GASSTORM_UPSTREAM")"
export OPS_FINGERPRINT_MODE=direct OPS_PROFILE=0
if [[ -z "${OPS_RETH_BINARY:-}" ]]; then
  for candidate in "$POC_ROOT/.tmp/approval-target/release/ops-reth-approvals-poc" \
    "$POC_ROOT/../../reth-policy-poc/target/release/ops-reth-approvals-poc"; do
    if [[ -x "$candidate" ]]; then export OPS_RETH_BINARY="$candidate"; break; fi
  done
fi
if [[ -z "${OPS_RETH_BINARY:-}" || ! -x "$OPS_RETH_BINARY" ]]; then
  echo 'Build the PoC first: python3 poc/reth-signed-approvals/setup.py' >&2
  exit 1
fi
cd "$POC_ROOT"
mkdir -p .tmp
(cd "$GASSTORM_LOADGEN_SOURCE" && go build -o "$POC_ROOT/.tmp/gasstorm-loadgen" ./cmd/loadgen)
go build -tags mockauth -o .tmp/ops-server ./cmd/server
go build -o .tmp/approval-client ./poc/reth-signed-approvals/client
OUTPUT_ROOT="${OPS_EVIDENCE_DIR:-$POC_DIR/evidence/gasstorm-replay-$(date -u +%Y%m%dT%H%M%SZ)}"
mkdir -p "$OUTPUT_ROOT"
OUTPUT_ROOT="$(cd "$OUTPUT_ROOT" && pwd)"
if [[ "${1:-all}" == ui ]]; then
  shift
  export GASSTORM_DASHBOARD_IMAGE="${GASSTORM_DASHBOARD_IMAGE:-ops-reth-gasstorm-dashboard:local}"
  echo 'Building Gasstorm dashboard (cached after the first start)...'
  if ! docker build -t "$GASSTORM_DASHBOARD_IMAGE" "$GASSTORM_SOURCE/dashboard" > "$OUTPUT_ROOT/dashboard-build.log" 2>&1; then
    tail -n 40 "$OUTPUT_ROOT/dashboard-build.log"
    exit 1
  fi
  export OPS_EVIDENCE_DIR="$OUTPUT_ROOT"
  exec python3 "$POC_DIR/gasstorm_ui.py" "$@"
fi
run_case() {
  local case_name="$1"; shift
  OPS_EVIDENCE_DIR="$OUTPUT_ROOT/$case_name" python3 "$POC_DIR/gasstorm_compare.py" "$@" 2>&1 | tee "$OUTPUT_ROOT/$case_name.log"
}
if [[ "${1:-all}" == all ]]; then
  run_case eth-final compare --workload eth-transfer --rates 100,500,1000 --duration 20 --pairs 2 --resume
  run_case contract-final compare --workload erc20-approve --rates 100,500 --duration 20 --pairs 2 --resume
  run_case contention pilot --workload storage-write
  run_case safety-final safety
  python3 "$POC_DIR/analyze_gasstorm.py" "$OUTPUT_ROOT"
else
  OPS_EVIDENCE_DIR="$OUTPUT_ROOT" python3 "$POC_DIR/gasstorm_compare.py" "$@"
fi
echo "Results: $OUTPUT_ROOT"
