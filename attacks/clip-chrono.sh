#!/bin/bash
# clip-chrono.sh - Clip Chrono orchestrator (single continuous take, <=60s window).
# Proves the Axe-1 chain end to end, hands-off:
#   before (smoke_test OK) -> attack (L7 DoS) -> ML detects + remediation heals,
#   NO human action -> after (smoke_test OK = service truly usable again).
# The recovery proof is the team's own witness transaction, tests/smoke_test.py
# (exit 0 = SI de paiement rétabli). A restarted container is NOT proof.
# Usage: TARGET=172.16.147.10 ./clip-chrono.sh
#   Env: TARGET, PORT, DURATION (<=60 attack window), RECOVER_WAIT (max s)
set -euo pipefail
source "$(dirname "$0")/../_lib/guard.sh"

TARGET="${TARGET:-172.16.147.10}"
PORT="${PORT:-8080}"
DURATION="${DURATION:-30}"
RECOVER_WAIT="${RECOVER_WAIT:-90}"
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
  c=$(curl -s -o /dev/null -w '%{http_code}' -m 5 "$BASE/health" || echo 000)
  echo "    t+${t}s  /health -> HTTP $c"
  if [ "$c" = "200" ]; then recovered=1; break; fi
  sleep 5
done

banner "4/4  PROOF OF RECOVERY"
if [ "$recovered" != 1 ]; then
  echo "[-] Service did not return to healthy within ${RECOVER_WAIT}s."
  echo "    Do NOT fix by hand on camera: manual intervention = 0/5 on remediation."
  exit 2
fi
if witness after; then
  echo "[+] RECOVERED: /health 200 AND smoke_test passes - a new fictive transaction succeeds."
  echo "[+] This is the Axe-1 proof. Evidence in $OUTDIR"
else
  echo "[-] /health is 200 but smoke_test failed - service not truly usable (restart != recovery)."
  exit 3
fi

echo ""
echo "[*] Demo window complete: $(ra_now)"
