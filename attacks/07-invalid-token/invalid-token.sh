#!/bin/bash
# 07 - Invalid-token burst against our own payment API only.
# Sends clearly invalid Bearer tokens (not forgeries) to trip the SOC rule
# InvalidTokenFlood (>20 auth_failure/min from one IP on payment-api).
# This is a DETECTION drill: the payment service must stay up and no container
# may be restarted. Compromise attempt, not availability.
# Usage: TARGET=172.16.147.10 ./invalid-token.sh
#   Env: TARGET, PORT, COUNT (default 40), DELAY (default 0.2s)
set -euo pipefail
source "$(dirname "$0")/../_lib/guard.sh"

TARGET="${TARGET:-172.16.147.10}"
PORT="${PORT:-8080}"
COUNT="${COUNT:-40}"
DELAY="${DELAY:-0.2}"
BASE="http://$TARGET:$PORT"
ra_require_scope "$TARGET"

if [ "$COUNT" -gt 200 ]; then
  echo "[-] Refusing: COUNT=$COUNT > 200. This is a drill, not a flood."
  exit 1
fi

OUTDIR="$(ra_logdir invalid-token)"
exec > >(tee -a "$OUTDIR/invalid-token.log") 2>&1
echo "[*] Target: $BASE   Started: $(ra_now)   Logs: $OUTDIR"

echo "[*] Baseline health (must be 200 before the drill)..."
code=$(curl -sk -m 8 -o "$OUTDIR/health-before.json" -w '%{http_code}' "$BASE/api/payments/health" || echo 000)
echo "    /api/payments/health -> HTTP $code"
if [ "$code" != "200" ]; then
  echo "[-] Service is not healthy. Fix the baseline first; do not run the drill."
  exit 1
fi

echo "[*] Sending $COUNT invalid tokens (${DELAY}s apart) to /api/payments/accounts/me ..."
unauthorized=0; other=0
for i in $(seq 1 "$COUNT"); do
  code=$(curl -sk -m 5 -o /dev/null -w '%{http_code}' \
    -H "Authorization: Bearer ra-invalid-token-$i-not-a-jwt" \
    "$BASE/api/payments/accounts/me" || echo 000)
  case "$code" in
    401) unauthorized=$((unauthorized+1)) ;;
    000) other=$((other+1)) ;;
    *)   other=$((other+1)) ;;
  esac
  printf '%s\n' "$code" >> "$OUTDIR/codes.txt"
  sleep "$DELAY"
done

echo "[*] Health after the drill (payment must still work)..."
code=$(curl -sk -m 8 -o "$OUTDIR/health-after.json" -w '%{http_code}' "$BASE/api/payments/health" || echo 000)
echo "    /api/payments/health -> HTTP $code"

echo ""
echo "[+] 401: $unauthorized   other: $other   (expected: all 401)"
echo "[+] Evidence: $OUTDIR"
echo "[*] Host-side oracle to confirm (Prometheus/Alertmanager on 127.0.0.1):"
echo "      curl -s http://127.0.0.1:9090/api/v1/alerts | grep -o '\"alertname\":\"[^\"]*\"' | sort -u"
echo "    Expect: InvalidTokenFlood (Loki) within ~1 min, and NO ServiceDown."
echo "[!] Correct response: keep the SOC alert, do NOT restart the payment service."
echo "[*] Ended: $(ra_now)"
