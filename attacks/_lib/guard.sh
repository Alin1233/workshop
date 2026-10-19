#!/bin/bash
# guard.sh - shared helpers for Red Team scripts. Source, don't execute.
#   source "$(dirname "$0")/../_lib/guard.sh"
#
# Enforces the subject's scope (own SI only) and gives every scenario a
# timestamped log dir under attacks/logs/ for the dossier (before/during/after).

# Authorized lab networks (own SI only): the subject's hotspot plus the team's
# current deployment subnet. Override/extend with RA_ALLOWED_NETS (space-separated
# address prefixes) when the deployment moves again - keep the guard, don't disable it.
RA_ALLOWED_NETS="${RA_ALLOWED_NETS:-192.168.137. 172.16.147.}"
RA_ATTACKS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RA_REPO_DIR="$(cd "$RA_ATTACKS_DIR/.." && pwd)"

# ra_require_scope <host-or-url> : refuse anything outside the authorized nets.
ra_require_scope() {
  local h="$1" p
  case "$h" in
    *://*) h="$(printf '%s' "$h" | sed -E 's#^[a-zA-Z]+://([^/:?]+).*#\1#')" ;;
  esac
  h="${h%%:*}"  # strip :port
  for p in $RA_ALLOWED_NETS; do
    [[ "$h" == "$p"* ]] && return 0
  done
  if [[ "${ALLOW_UNSAFE:-0}" != "1" ]]; then
    echo "[-] Refusing: host '$h' not in authorized nets ($RA_ALLOWED_NETS). Set ALLOW_UNSAFE=1 to override (not recommended)."
    exit 1
  fi
}

# ra_logdir <name> : create and echo attacks/logs/<name>-<ts>.
ra_logdir() {
  local d="$RA_ATTACKS_DIR/logs/$1-$(date +%Y%m%d-%H%M%S)"
  mkdir -p "$d"
  printf '%s' "$d"
}

ra_now() { date -u +%FT%TZ; }
