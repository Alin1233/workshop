#!/bin/bash
# 00b - Software Composition Analysis: find known CVEs in the versions the SI
# actually runs. Grey-box, run on the Hôte (needs image/container access).
#
# Why not just read requirements.txt: the Python deps are version RANGES
# (fastapi>=0.115,<1), so the exploitable version is whatever pip resolved into
# the image. This reads versions as BUILT/RUNNING, then matches them to CVEs
# with their fixed-in version (actionable for hardening and for exploit triage).
#
# Usage: ./vuln-scan.sh [IMAGE ...]   (default: project + infra images from compose)
# Tools: trivy (preferred) or grype; docker; npm (frontend audit). Install:
#   sudo dnf install -y trivy        # or: grype
set -euo pipefail
source "$(dirname "$0")/../_lib/guard.sh"

OUTDIR="$(ra_logdir vulnscan)"
COMPOSE="$RA_REPO_DIR/docker-compose.yml"
echo "[*] SCA started: $(ra_now)   Logs: $OUTDIR"

# Build the image list: explicit args, else every image: in the compose file
# plus the locally built service images.
if [ "$#" -gt 0 ]; then
  IMAGES=("$@")
else
  mapfile -t IMAGES < <(grep -hE '^\s*image:' "$COMPOSE" | sed -E 's/.*image:\s*//' | tr -d '"' | sort -u)
fi
printf '%s\n' "${IMAGES[@]}" > "$OUTDIR/images.txt"
echo "[*] ${#IMAGES[@]} images to scan (see images.txt)"

SCANNER=""
command -v trivy >/dev/null 2>&1 && SCANNER=trivy
[ -z "$SCANNER" ] && command -v grype >/dev/null 2>&1 && SCANNER=grype
if [ -z "$SCANNER" ]; then
  echo "[-] No scanner. Install one: sudo dnf install -y trivy   (or grype)"; exit 1
fi
echo "[*] Scanner: $SCANNER"

SUMMARY="$OUTDIR/findings-HIGH-CRITICAL.txt"
: > "$SUMMARY"

for img in "${IMAGES[@]}"; do
  [ -z "$img" ] && continue
  safe="${img//[^a-zA-Z0-9._-]/_}"
  echo "[*] Scanning $img ..."
  case "$SCANNER" in
    trivy)
      trivy image --quiet --scanners vuln --severity HIGH,CRITICAL --ignore-unfixed \
        -f json -o "$OUTDIR/trivy-$safe.json" "$img" || { echo "    [!] scan failed: $img"; continue; }
      # one line per HIGH/CRITICAL fixable CVE: pkg installed -> fixed, id, severity
      python3 - "$OUTDIR/trivy-$safe.json" "$img" >> "$SUMMARY" <<'PY' || true
import json,sys
data=json.load(open(sys.argv[1])); img=sys.argv[2]
for res in data.get("Results") or []:
    for v in res.get("Vulnerabilities") or []:
        print(f"{img}\t{v.get('Severity'):8}\t{v.get('VulnerabilityID')}\t{v.get('PkgName')} {v.get('InstalledVersion')} -> {v.get('FixedVersion','?')}\t{(v.get('Title') or '')[:80]}")
PY
      ;;
    grype)
      grype "$img" -o json > "$OUTDIR/grype-$safe.json" 2>/dev/null || { echo "    [!] scan failed: $img"; continue; }
      python3 - "$OUTDIR/grype-$safe.json" "$img" >> "$SUMMARY" <<'PY' || true
import json,sys
data=json.load(open(sys.argv[1])); img=sys.argv[2]
for m in data.get("matches") or []:
    vu=m.get("vulnerability",{}); a=m.get("artifact",{})
    sev=vu.get("severity","")
    if sev not in ("High","Critical"): continue
    fix=",".join((vu.get("fix") or {}).get("versions") or []) or "?"
    print(f"{img}\t{sev:8}\t{vu.get('id')}\t{a.get('name')} {a.get('version')} -> {fix}\t{(vu.get('description') or '')[:80]}")
PY
      ;;
  esac
done

# Resolve the real Python versions from the running containers (ranges -> exact).
if command -v docker >/dev/null 2>&1; then
  for svc in auth-service payment-api; do
    cid=$(docker ps --filter "name=$svc" -q | head -1)
    [ -n "$cid" ] && { echo "[*] pip freeze @ $svc"; docker exec "$cid" pip freeze > "$OUTDIR/pipfreeze-$svc.txt" 2>/dev/null || true; }
  done
fi

# Frontend: audit the lockfile directly (static assets, built at image time).
if command -v npm >/dev/null 2>&1 && [ -f "$RA_REPO_DIR/services/frontend/package-lock.json" ]; then
  echo "[*] npm audit (frontend)"
  (cd "$RA_REPO_DIR/services/frontend" && npm audit --omit=dev --json > "$OUTDIR/npm-audit.json" 2>/dev/null) || true
fi

n=$(grep -c . "$SUMMARY" 2>/dev/null || echo 0)
echo ""
echo "[+] Done: $(ra_now)"
echo "[+] $n HIGH/CRITICAL fixable finding(s). Triaged list: $SUMMARY"
echo "    Next (skill /redteam, CVE path): triage -> reachable here? public PoC? -> scoped exploit."
sort -u "$SUMMARY" | sed -n '1,25p'
