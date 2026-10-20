#!/bin/bash
# clip-chrono.sh - Clip Chrono orchestrator (single continuous take, <=60s window).
# Proves the Axe-1 chain end to end, hands-off:
#   before (smoke_test OK) -> attack (L7 DoS) -> ML detects + remediation heals,
#   NO human action -> after (smoke_test OK = service truly usable again).
# The recovery proof is the team's own witness transaction, tests/smoke_test.py
# (exit 0 = SI de paiement rétabli). A restarted container is NOT proof.
#
# Optional Act II (INTEGRITY_ACT=1, Hôte only): corrupt the ledger -> integrity
# detection fires -> restore -> integrity green. Data-compromise recovery is a
# restore, not a restart. Needs docker + the postgres container (so run it on
# the Hôte); skipped with a warning when the DB is not reachable locally.
# Usage: TARGET=172.16.147.10 ./clip-chrono.sh
#   Env: TARGET, PORT, DURATION (<=60 attack window), RECOVER_WAIT (max s),
#        INTEGRITY_ACT=1, ADMIN_TOKEN (optional, to poll /admin/integrity)
set -euo pipefail
source "$(dirname "$0")/../_lib/guard.sh"

TARGET="${TARGET:-172.16.147.10}"
PORT="${PORT:-8080}"
DURATION="${DURATION:-30}"
RECOVER_WAIT="${RECOVER_WAIT:-90}"
INTEGRITY_ACT="${INTEGRITY_ACT:-0}"
ADMIN_TOKEN="${ADMIN_TOKEN:-}"
ra_require_scope "$TARGET"

BASE="http://$TARGET:$PORT"
SMOKE="$RA_REPO_DIR/tests/smoke_test.py"
PY="$(command -v python3 || command -v python)"

OUTDIR="$(ra_logdir demo)"
exec > >(tee -a "$OUTDIR/demo.log") 2>&1

witness() {  # $1 = label ; returns smoke_test exit code
  echo "[*] Witness transaction (smoke_test) [$1] ..."
  "$PY" "$SMOKE" "$BASE" > "$OUTDIR/smoke-$1.txt" 2>&1
}

banner() { echo ""; echo "=== $1 === $(ra_now)"; }

# admin_integrity_code : HTTP code of /api/payments/admin/integrity (200 ok, 409 broken),
# or "n/a" when no ADMIN_TOKEN is set to reach the admin route.
admin_integrity_code() {
  [ -n "$ADMIN_TOKEN" ] || { echo "n/a"; return; }
  curl -s -o /dev/null -w '%{http_code}' -m 5 -H "Authorization: Bearer $ADMIN_TOKEN" \
    "$BASE/api/payments/admin/integrity" || echo 000
}

integrity_act() {
  local CORRUPT="$(dirname "$0")/04-integrity-violation/corrupt-ledger.sh"
  banner "ACT II - 1/4  INTEGRITY PRE-CHECK"
  if ! command -v docker >/dev/null 2>&1 || [ -z "$(docker ps --filter name=postgres -q 2>/dev/null | head -1)" ]; then
    echo "[!] No local postgres container - the DB is not reachable from here."
    echo "    Run clip-chrono.sh with INTEGRITY_ACT=1 ON THE HÔTE. Skipping Act II."
    return 0
  fi
  echo "[*] admin/integrity -> HTTP $(admin_integrity_code) (expect 200)"
  "$CORRUPT" check

  banner "ACT II - 2/4  CORRUPT LEDGER (backup-first)"
  CONFIRM=1 "$CORRUPT" corrupt

  banner "ACT II - 3/4  AWAIT INTEGRITY DETECTION (watcher ~15s)"
  local broken=0 c
  for ((t=0; t<60; t+=5)); do
    c=$(admin_integrity_code)
    echo "    t+${t}s  admin/integrity -> HTTP $c   (Grafana: payment_ledger_integrity_ok, LedgerIntegrityBroken)"
    if [ "$c" = "409" ]; then broken=1; break; fi
    # Without a token, fall back to the DB truth and give the watcher its window.
    if [ "$c" = "n/a" ] && [ "$t" -ge 20 ]; then broken=1; break; fi
    sleep 5
  done
  [ "$broken" = 1 ] && echo "[+] Integrity violation detected - alert should be firing now." \
                    || echo "[!] Did not observe a 409 - check the dashboard before restoring."

  banner "ACT II - 4/4  RESTORE + PROOF"
  "$CORRUPT" restore
  echo "[*] admin/integrity -> HTTP $(admin_integrity_code) (expect 200 within ~15s)"
  if witness after-integrity; then
    echo "[+] RESTORED: ledger consistent again AND a witness transaction succeeds."
  else
    echo "[-] Witness transaction still failing after restore - investigate."
  fi
}

[ -f "$SMOKE" ] || { echo "[-] Not found: $SMOKE (run from the cloned repo)."; exit 1; }

banner "0/4  PRE-FLIGHT  $BASE"
if witness before; then
  echo "[+] Baseline OK: SI de paiement sain (smoke_test exit 0)."
else
  echo "[-] Baseline smoke_test failed. Fix the SI before demoing. See $OUTDIR/smoke-before.txt"
  exit 1
fi

banner "1/4  ATTACK  (${DURATION}s L7)"
echo "[*] Launching 01-dos-applicatif/dos.sh - watch Grafana for p95/5xx/probe spike."
DURATION="$DURATION" "$(dirname "$0")/01-dos-applicatif/dos.sh" "$TARGET" "$PORT" "$DURATION" || true

banner "2/4  DETECTION"
echo "[*] ML should flag the anomaly; alertmanager -> remediation-engine should act now."

banner "3/4  AWAIT AUTONOMOUS RECOVERY (max ${RECOVER_WAIT}s, NO manual action)"
recovered=0
for ((t=0; t<RECOVER_WAIT; t+=5)); do
  # "/health" renvoie le SPA : il vaut 200 même quand auth est HS. On exige les
  # deux vraies sondes API avant de considérer le service revenu.
  ca=$(curl -s -o /dev/null -w '%{http_code}' -m 5 "$BASE/api/auth/health" || echo 000)
  cp=$(curl -s -o /dev/null -w '%{http_code}' -m 5 "$BASE/api/payments/health" || echo 000)
  echo "    t+${t}s  auth=$ca payments=$cp"
  if [ "$ca" = "200" ] && [ "$cp" = "200" ]; then recovered=1; break; fi
  sleep 5
done

banner "4/4  PROOF OF RECOVERY"
if [ "$recovered" != 1 ]; then
  echo "[-] Service did not return to healthy within ${RECOVER_WAIT}s."
  echo "    Do NOT fix by hand on camera: manual intervention = 0/5 on remediation."
  exit 2
fi
if witness after; then
  echo "[+] RECOVERED: auth + payments health 200 AND smoke_test passes - a new fictive transaction succeeds."
  echo "[+] This is the Axe-1 proof. Evidence in $OUTDIR"
else
  echo "[-] API health probes are 200 but smoke_test failed - service not truly usable (restart != recovery)."
  exit 3
fi

[ "$INTEGRITY_ACT" = 1 ] && integrity_act

echo ""
echo "[*] Demo window complete: $(ra_now)"
