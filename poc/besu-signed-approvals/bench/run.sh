#!/usr/bin/env bash
# Delivery transport matrix: raw TCP (today), one gRPC stream, one gRPC unary call per batch; each gRPC
# shape plain and mTLS. Same signed frames, same host. Each run appends to results/summary.{jsonl,log}.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
RATE="${RATE:-500}"; COUNT="${COUNT:-10000}"; OUT="$HERE/results"; mkdir -p "$OUT"
TRANSPORTS="${TRANSPORTS:-tcp grpc grpc-mtls grpc-unary grpc-unary-mtls}"
RECV="$HERE/receiver/build/install/ops-approvals-bench-receiver/bin/ops-approvals-bench-receiver"
# Throwaway mTLS material for localhost (CA, server, client), 30 days, never committed.
if [ ! -f "$HERE/certs/ca.crt" ]; then
  mkdir -p "$HERE/certs" && cd "$HERE/certs"
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout ca.key -out ca.crt -days 30 -subj "/CN=ops-bench-ca" >/dev/null 2>&1
  for n in server client; do
    openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout $n.key -out $n.csr -subj "/CN=$n" >/dev/null 2>&1
    printf "subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth,clientAuth\n" > $n.ext
    openssl x509 -req -in $n.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out $n.crt -days 30 -extfile $n.ext >/dev/null 2>&1
  done
  cd "$HERE"
fi
# Before the build: Gradle must run on JDK 25 to find the receiver's toolchain; the shell may carry an older JAVA_HOME.
export JAVA_HOME="$ROOT/.tmp/jdk25/jdk-25.0.4.1+1/Contents/Home"
export PATH="$JAVA_HOME/bin:$PATH"
# Always rebuild (both are incremental): binaries left from before a transport was added would reject it.
(cd "$HERE/receiver" && gradle --no-daemon -q installDist)
(cd "$ROOT" && go build -o .tmp/bench-sender ./poc/besu-signed-approvals/bench/sender)
trap '[ -n "${RPID:-}" ] && kill "$RPID" 2>/dev/null; true' EXIT  # a failed sender must not orphan the receiver JVM
for T in $TRANSPORTS; do
  PORT=$((19000 + RANDOM % 1000))
  "$RECV" "$T" "$PORT" "$OUT/$T-receiver.jsonl" "$HERE/certs" > "$OUT/$T-receiver.log" 2>&1 &
  RPID=$!
  for _ in $(seq 1 100); do grep -q READY "$OUT/$T-receiver.log" 2>/dev/null && break; sleep 0.2; done
  grep -q READY "$OUT/$T-receiver.log" || { echo "receiver $T did not start"; cat "$OUT/$T-receiver.log"; kill $RPID; exit 1; }
  sleep 1
  "$ROOT/.tmp/bench-sender" -transport "$T" -addr "127.0.0.1:$PORT" -rate "$RATE" -count "$COUNT" -out "$OUT/$T-sender.jsonl" -certs "$HERE/certs" | tee -a "$OUT/summary.log"
  sleep 1; kill $RPID; wait $RPID 2>/dev/null || true; RPID=; sleep 0.5
  python3 "$HERE/report.py" "$T" "$OUT/$T-sender.jsonl" "$OUT/$T-receiver.jsonl" | tee -a "$OUT/summary.jsonl"
done
echo DONE
