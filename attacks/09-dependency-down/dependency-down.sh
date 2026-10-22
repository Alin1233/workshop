#!/bin/bash
# 09 - Dependency outage drill (chaos injection). Hote only, needs docker.
# Pauses PostgreSQL briefly so the services return 503 with
# event_type=dependency_failure, which trips DependencyFailures.
# The data is intact; this is an availability-of-dependency drill.
#
# Usage (on the Hote, stack up):
#   ./dependency-down.sh check
#   CONFIRM=1 ./dependency-down.sh inject
#   CONFIRM=1 PAUSE_SECONDS=25 ./dependency-down.sh inject
set -euo pipefail
source "$(dirname "$0")/../_lib/guard.sh"

CMD="${1:-check}"
PAUSE_SECONDS="${PAUSE_SECONDS:-25}"
cid="$(docker ps --filter name=postgres -q | head -1)"
[ -n "$cid" ] || { echo "[-] No running 'postgres' container. Run this on the Hote."; exit 1; }

health() {
  curl -sk -m 8 -o /tmp/ra-dep-health -w '%{http_code}' "http://127.0.0.1:8080/api/payments/health" 2>/dev/null || echo 000
}

case "$CMD" in
  check)
    echo "[*] postgres container: $cid"
    echo "    pg_isready: $(docker exec "$cid" pg_isready -U postgres -d postgres 2>&1 || true)"
    echo "    /api/payments/health -> HTTP $(health)"
    ;;

  inject)
    [ "${CONFIRM:-0}" = "1" ] || { echo "[!] DRY RUN. Re-run with CONFIRM=1 to pause postgres for ${PAUSE_SECONDS}s."; exit 0; }
    if [ "$PAUSE_SECONDS" -gt 40 ]; then
      echo "[-] Refusing: PAUSE_SECONDS > 40. Docker healthcheck (10 x 5s) would mark postgres unhealthy."
      exit 1
    fi
    OUTDIR="$(ra_logdir dependency-down)"
    exec > >(tee -a "$OUTDIR/dependency-down.log") 2>&1
    echo "[*] Baseline before $(ra_now): /api/payments/health -> HTTP $(health)"
    trap 'docker unpause "$cid" >/dev/null 2>&1 || true; echo "[*] postgres unpaused (trap)"' EXIT
    echo "[*] Pausing postgres for ${PAUSE_SECONDS}s ..."
    docker pause "$cid"
    # 6 requetes en parallele : chaque pool attend ~5s puis repond 503 database_unavailable.
    seq 1 6 | xargs -P 6 -I{} sh -c 'curl -sk -m 8 -o /dev/null -w "%{http_code}\n" http://127.0.0.1:8080/api/payments/health' \
      | sort | uniq -c | tee "$OUTDIR/codes.txt"
    sleep "$PAUSE_SECONDS"
    docker unpause "$cid"; trap - EXIT
    sleep 3
    echo "[*] After unpause $(ra_now): /api/payments/health -> HTTP $(health)"
    echo "    body: $(cat /tmp/ra-dep-health 2>/dev/null | head -c 200)"
    echo "[+] Preuve attendue : DependencyFailures (>3 dependency_failure en 1 min), puis retour a 200."
    echo "[*] Logs: $OUTDIR"
    ;;

  *)
    echo "Usage: ./dependency-down.sh [check | inject]   (inject needs CONFIRM=1)"
    exit 1
    ;;
esac
