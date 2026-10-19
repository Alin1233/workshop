#!/bin/bash
# 05 - Business-logic / BOLA abuse against our own payment API.
# Registers real users, logs in, and TRIES to: inflate its own balance, move
# money it doesn't own, read another user's data, and reach admin routes.
# Each attempt is scored BLOCKED (expected) or >>> POTENTIAL ISSUE (worked).
# App-level only (no flooding); safe to run from the attacker PC.
# Usage: TARGET=172.16.147.10 ./abuse.sh
set -euo pipefail
source "$(dirname "$0")/../_lib/guard.sh"

TARGET="${TARGET:-172.16.147.10}"
PORT="${PORT:-8080}"
ra_require_scope "$TARGET"
BASE="http://$TARGET:$PORT"
PW="RedTeam2026!xyz"            # >=10 chars
TS="$(date +%s)"

OUTDIR="$(ra_logdir bizlogic)"
exec > >(tee -a "$OUTDIR/abuse.log") 2>&1
echo "[*] Target: $BASE   Started: $(ra_now)   Logs: $OUTDIR"

body="$OUTDIR/.body"
req() {  # METHOD PATH [data] [auth] [extra-header...] -> echoes HTTP code, body in $body
  local method="$1" path="$2" data="${3:-}" auth="${4:-}"; shift || true; shift || true; shift || true; shift || true
  local args=(-s -o "$body" -w '%{http_code}' -m 15 -X "$method" "$BASE$path")
  [ -n "$data" ] && args+=(-H 'Content-Type: application/json' -d "$data")
  [ -n "$auth" ] && args+=(-H "Authorization: Bearer $auth")
  while [ "$#" -gt 0 ]; do args+=(-H "$1"); shift; done
  curl "${args[@]}" || echo 000
}

register() { req POST /api/auth/register "{\"email\":\"$1\",\"full_name\":\"$2\",\"password\":\"$PW\"}" >/dev/null; }
login() { req POST /api/auth/login "{\"email\":\"$1\",\"password\":\"$PW\"}" >/dev/null; jq -r '.access_token // empty' "$body"; }
balance() { req GET /api/payments/accounts/me "" "$1" >/dev/null; jq -r '.balance_cents // empty' "$body"; }
acctnum() { req GET /api/payments/accounts/me "" "$1" >/dev/null; jq -r '.account_number // empty' "$body"; }

PASS=0; FLAG=0
score() {  # NAME  EXPECTED-BLOCKED-REGEX  ACTUAL-CODE  [note]
  local name="$1" exp="$2" code="$3" note="${4:-}"
  if [[ "$code" =~ $exp ]]; then echo "  [BLOCKED ] $name -> HTTP $code  $note"; PASS=$((PASS+1))
  else echo "  >>> POTENTIAL ISSUE: $name -> HTTP $code (expected $exp)  $note"; FLAG=$((FLAG+1)); fi
}

echo "[*] Provisioning 3 users (attacker A, parties B & C)..."
A="rt-a-$TS@pay.local"; B="rt-b-$TS@pay.local"; C="rt-c-$TS@pay.local"
register "$A" "Red A"; register "$B" "Vic B"; register "$C" "Vic C"
TA="$(login "$A")"; TB="$(login "$B")"; TC="$(login "$C")"
[ -n "$TA" ] && [ -n "$TB" ] && [ -n "$TC" ] || { echo "[-] Could not obtain tokens (registration/login blocked?). Body:"; cat "$body"; exit 1; }
NA="$(acctnum "$TA")"; NB="$(acctnum "$TB")"; NC="$(acctnum "$TC")"
BAL_A0="$(balance "$TA")"
echo "    A=$NA (bal $BAL_A0)  B=$NB  C=$NC"

echo ""; echo "== Self-enrichment: can A increase its own balance illegitimately? =="
code=$(req POST /api/payments/transfers "{\"to_account_number\":\"$NB\",\"amount_cents\":-100000,\"label\":\"neg\"}" "$TA" "Idempotency-Key: k-neg-$TS"); score "negative amount (reverse flow)" '^(422|400)$' "$code"
code=$(req POST /api/payments/transfers "{\"to_account_number\":\"$NB\",\"amount_cents\":100000000,\"label\":\"ovf\"}" "$TA" "Idempotency-Key: k-ovf-$TS"); score "amount over 10 000 EUR cap" '^(422|400)$' "$code"
code=$(req POST /api/payments/transfers "{\"to_account_number\":\"$NA\",\"amount_cents\":5000,\"label\":\"self\"}" "$TA" "Idempotency-Key: k-self-$TS"); score "transfer to self" '^(422|400)$' "$code"
code=$(req POST /api/payments/transfers "{\"to_account_number\":\"$NB\",\"amount_cents\":99999999,\"label\":\"over\"}" "$TA" "Idempotency-Key: k-over-$TS"); score "overdraw beyond balance" '^(422|400)$' "$code"
# Mass-assignment: smuggle balance/role/from fields hoping the API honors them.
code=$(req POST /api/payments/transfers "{\"to_account_number\":\"$NB\",\"amount_cents\":100,\"label\":\"ma\",\"balance_cents\":999999999,\"from_account_number\":\"$NC\",\"role\":\"admin\"}" "$TA" "Idempotency-Key: k-ma-$TS")
echo "  [info    ] mass-assignment transfer -> HTTP $code (extra fields should be ignored)"
BAL_A1="$(balance "$TA")"
if [ -n "$BAL_A0" ] && [ -n "$BAL_A1" ]; then
  # A legit 100c debit may have happened; A's balance must only ever DROP, never be minted up.
  if [ "$BAL_A1" -le "$BAL_A0" ]; then echo "  [BLOCKED ] no self-minting: balance $BAL_A0 -> $BAL_A1 (not inflated)"; PASS=$((PASS+1));
  else echo "  >>> POTENTIAL ISSUE: balance INFLATED $BAL_A0 -> $BAL_A1"; FLAG=$((FLAG+1)); fi
fi

echo ""; echo "== BOLA/IDOR: can A reach another user's data or funds? =="
# B pays C so there is a transfer A is not party to.
req POST /api/payments/transfers "{\"to_account_number\":\"$NC\",\"amount_cents\":100,\"label\":\"bc\"}" "$TB" "Idempotency-Key: k-bc-$TS" >/dev/null
TID="$(jq -r '.id // empty' "$body")"
if [ -n "$TID" ]; then
  code=$(req GET "/api/payments/transfers/$TID" "" "$TA"); score "read B->C transfer as outsider A" '^(404|403)$' "$code"
else echo "  [info    ] could not seed a B->C transfer to test IDOR (code above)"; fi
code=$(req GET "/api/payments/transfers/00000000-0000-0000-0000-000000000000" "" "$TA"); score "read random transfer id" '^(404|403|422)$' "$code"
code=$(req GET /api/payments/admin/integrity "" "$TA"); score "non-admin reaches /admin/integrity" '^(403|401)$' "$code"
code=$(req GET /api/payments/internal/integrity "" "$TA"); score "reach internal-only /internal/integrity via WAF" '^(403|404)$' "$code"

echo ""; echo "== Token forgery =="
# alg=none forgery of A's token.
NONE_TOK="$(python3 - "$TA" <<'PY'
import sys,base64,json
def b64(d): return base64.urlsafe_b64encode(d).rstrip(b'=')
try:
    p=sys.argv[1].split('.')[1]; p+='='*(-len(p)%4)
    claims=json.loads(base64.urlsafe_b64decode(p)); claims['role']='admin'
    h=b64(json.dumps({"alg":"none","typ":"JWT"}).encode()); c=b64(json.dumps(claims).encode())
    print((h+b'.'+c+b'.').decode())
except Exception: print("")
PY
)"
if [ -n "$NONE_TOK" ]; then
  code=$(req GET /api/payments/admin/integrity "" "$NONE_TOK"); score "alg=none + role=admin forgery" '^(401|403)$' "$code"
fi

echo ""; echo "== Idempotency / double-spend =="
req POST /api/payments/transfers "{\"to_account_number\":\"$NB\",\"amount_cents\":200,\"label\":\"idem\"}" "$TA" "Idempotency-Key: k-dup-$TS" >/dev/null
BAL_B0="$(balance "$TB")"
req POST /api/payments/transfers "{\"to_account_number\":\"$NB\",\"amount_cents\":200,\"label\":\"idem\"}" "$TA" "Idempotency-Key: k-dup-$TS" >/dev/null
BAL_B1="$(balance "$TB")"
if [ -n "$BAL_B0" ] && [ "$BAL_B0" = "$BAL_B1" ]; then echo "  [BLOCKED ] idempotency replay not double-credited (B stayed $BAL_B1)"; PASS=$((PASS+1));
else echo "  >>> POTENTIAL ISSUE: idempotent replay changed B $BAL_B0 -> $BAL_B1"; FLAG=$((FLAG+1)); fi
code=$(req POST /api/payments/transfers "{\"to_account_number\":\"$NB\",\"amount_cents\":999,\"label\":\"reuse\"}" "$TA" "Idempotency-Key: k-dup-$TS"); score "reuse idempotency key, different amount" '^(422|409)$' "$code"

echo ""; echo "=== SUMMARY: $PASS blocked (good), $FLAG potential issue(s) ==="
[ "$FLAG" -gt 0 ] && echo "    Review the >>> lines above and $OUTDIR" || echo "    Business logic held: no self-minting, no cross-user access, no forgery."
echo "[*] Ended: $(ra_now)"
rm -f "$body"
