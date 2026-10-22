#!/bin/bash
# 08 - Stale integrity watcher (chaos injection). Hote only, needs docker.
# Pauses the payment-api container long enough for its periodic integrity check
# to stop updating payment_ledger_integrity_last_check_timestamp, which trips
# LedgerIntegrityCheckStale. This is NOT scenario 04: the data is not wrong,
# the checker is stopped. A restart is the correct response here.
#
# Side effect: while paused, the API is unavailable. That is expected and
# bounded by PAUSE_SECONDS. Keep it under 120s, and unpause on exit.
#
# Usage (on the Hote, stack up):
#   ./stale-watcher.sh check
#   CONFIRM=1 ./stale-watcher.sh inject        # default 100s pause
#   CONFIRM=1 PAUSE_SECONDS=110 ./stale-watcher.sh inject
set -euo pipefail
source "$(dirname "$0")/../_lib/guard.sh"

CMD="${1:-check}"
PAUSE_SECONDS="${PAUSE_SECONDS:-100}"
cid="$(docker ps --filter name=payment-api -q | head -1)"
[ -n "$cid" ] || { echo "[-] No running 'payment-api' container. Run this on the Hote."; exit 1; }

metric() {
  # Le conteneur est en read-only sans curl : on lit les metriques via python.
  docker exec "$cid" python -c 'import urllib.request;print(urllib.request.urlopen("http://localhost:8000/metrics",timeout=3).read().decode())' 2>/dev/null \
    | grep -E '^payment_ledger_integrity_(ok|last_check_timestamp)' || true
}

case "$CMD" in
  check)
    echo "[*] payment-api container: $cid"
    metric
    echo "[*] Attendu au repos : payment_ledger_integrity_ok 1"
    ;;

  inject)
    [ "${CONFIRM:-0}" = "1" ] || { echo "[!] DRY RUN. Re-run with CONFIRM=1 to pause payment-api for ${PAUSE_SECONDS}s."; exit 0; }
    if [ "$PAUSE_SECONDS" -lt 95 ]; then
      echo "[!] PAUSE_SECONDS=$PAUSE_SECONDS : l'alerte (seuil 60s + for 30s) risque de ne pas se declencher."
    fi
    OUTDIR="$(ra_logdir integrity-stale)"
    exec > >(tee -a "$OUTDIR/stale.log") 2>&1
    echo "[*] Before: $(ra_now)"; metric
    trap 'docker unpause "$cid" >/dev/null 2>&1 || true; echo "[*] payment-api unpaused (trap)"' EXIT
    echo "[*] Pausing payment-api for ${PAUSE_SECONDS}s ..."
    docker pause "$cid"
    sleep "$PAUSE_SECONDS"
    docker unpause "$cid"; trap - EXIT
    echo "[*] After: $(ra_now)"; sleep 3; metric
    echo "[+] Preuve attendue : LedgerIntegrityCheckStale a cree ~$((${PAUSE_SECONDS}+30-60))s apres la pause,"
    echo "    puis s'est resolue apres le unpause (le timestamp repart)."
    echo "[*] Logs: $OUTDIR"
    ;;

  *)
    echo "Usage: ./stale-watcher.sh [check | inject]   (inject needs CONFIRM=1)"
    exit 1
    ;;
esac
