#!/bin/bash
# 03 - SQL injection probe against our own payment API only. Level 1 / Risk 1.
# No --risk 3, no --level 5, no --os-shell, no table dump (--dbs at most).
# Expected detection: WAF 403 (OWASP CRS), ModSecurity audit log, WafAttackBlocked.
# Expected response: WAF block - NOT an availability restart. This is a
#   compromise-attempt scenario; do not confuse it with the DoS recovery.
# Usage: TARGET=192.168.137.1 ./sqli.sh "http://192.168.137.1:8080/api/payments/accounts?id=1"
set -euo pipefail
source "$(dirname "$0")/../_lib/guard.sh"

URL="${1:-${URL:-http://192.168.137.1:8080/api/payments/accounts?id=1}}"
ra_require_scope "$URL"

command -v sqlmap >/dev/null 2>&1 || { echo "[-] sqlmap not installed (git clone or pipx install sqlmap)"; exit 1; }

OUTDIR="$(ra_logdir sqli)"
exec > >(tee -a "$OUTDIR/sqli.log") 2>&1

echo "[*] URL: $URL"
echo "[*] Started: $(ra_now)   Logs: $OUTDIR"

timeout 120 sqlmap -u "$URL" \
  --batch --level 1 --risk 1 \
  --timeout 10 --retries 1 \
  --output-dir "$OUTDIR" \
  --banner --dbs || true

echo "[*] Ended: $(ra_now)"
echo "[+] Blue check: WAF 403 + ModSecurity audit JSON, WafAttackBlocked alert."
echo "    Report only - do NOT dump tables beyond --dbs (availability != compromise, see subject)."
