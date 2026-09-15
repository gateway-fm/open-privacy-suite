#!/usr/bin/env bash
# One Adaptive session end to end: start the stack, drive the dashboard, capture evidence, stop.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CASE="${1:?case name}"; shift
DURATION="${OPS_UI_DURATION:-60}"
LOG="$HERE/../../.tmp/ui-$CASE.log"
rm -f "$LOG"
(cd "$HERE" && timeout 1800 python3 gasstorm_ui.py --port 18000 "$@" >| "$LOG" 2>&1 &)
for _ in $(seq 1 240); do grep -q READY "$LOG" 2>/dev/null && break; sleep 2; done
grep -q READY "$LOG" || { tail -20 "$LOG"; exit 1; }
export OPS_PLAYWRIGHT_ROOT="${OPS_PLAYWRIGHT_ROOT:?set it to a directory containing node_modules/playwright}"
export OPS_UI_TEST_EVIDENCE="$HERE/evidence/gasstorm/browser-$CASE"
case " $* " in *" --direct "*) export OPS_UI_MODE=Direct;; esac
export OPS_UI_CAPTURE_PEAK=1 OPS_UI_CAPACITY=1 OPS_UI_TEST_WORKLOADS="${OPS_UI_WORKLOADS:-eth-transfer}" OPS_UI_DURATION="$DURATION"
# Tear the session down however this exits: a failed assertion used to leave the stack — and
# port 18000 — behind, which then broke the next run with "Address already in use".
cleanup() {
  pkill -f "gasstorm_ui.py" || true
  sleep 3
  docker ps --filter label=ops-besu-demo=true -q | xargs -r docker stop -t 3 >/dev/null || true
  pkill -f "besu-dist/besu-26.8.1/bin" || true; pkill -f ".tmp/ops-server" || true; pkill -f gasstorm-loadgen || true
}
trap cleanup EXIT
( cd "$HERE" && node ui_browser_test.mjs )
