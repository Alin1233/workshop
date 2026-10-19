#!/bin/bash
# 00 - Reconnaissance (non-intrusive) against our own SI only.
# Baseline inventory before any attack. No auto-response expected.
# Usage: ./recon.sh [TARGET_IP] [PORT]
set -euo pipefail
source "$(dirname "$0")/../_lib/guard.sh"

TARGET="${1:-${TARGET:-192.168.137.1}}"
PORT="${2:-${PORT:-8080}}"
ra_require_scope "$TARGET"

OUTDIR="$(ra_logdir recon)"
echo "[*] Target: $TARGET:$PORT   Started: $(ra_now)   Logs: $OUTDIR"

echo "[*] ping check..."
ping -c 3 -W 2 "$TARGET" | tee "$OUTDIR/ping.txt" || true

echo "[*] nmap service scan (ports 1-100 + API port)..."
# -p overrides --top-ports, so list the range + API port explicitly.
nmap -sV -T4 -p "1-100,$PORT" "$TARGET" -oN "$OUTDIR/nmap.txt"

echo "[*] http headers / health (through the WAF)..."
curl -sk -m 10 -D "$OUTDIR/headers.txt" -o "$OUTDIR/index.html" "http://$TARGET:$PORT/" || true
curl -sk -m 10 "http://$TARGET:$PORT/health" -o "$OUTDIR/health.json" || true
cat "$OUTDIR/headers.txt" 2>/dev/null || true

if command -v ffuf >/dev/null 2>&1; then
  WORDLIST="${WORDLIST:-/usr/share/wordlists/dirb/common.txt}"
  if [ -f "$WORDLIST" ]; then
    echo "[*] ffuf discovery (60s cap)..."
    timeout 60 ffuf -u "http://$TARGET:$PORT/FUZZ" -w "$WORDLIST" -mc 200,301,302,401,403 -t 20 -o "$OUTDIR/ffuf.json" || true
  else
    echo "[!] ffuf wordlist not found: $WORDLIST, skipping."
  fi
else
  echo "[!] ffuf not installed, skipping."
fi

echo "[*] Done: $(ra_now)   Results in $OUTDIR"
