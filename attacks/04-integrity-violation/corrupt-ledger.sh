#!/bin/bash
# 04 - Ledger integrity violation (chaos injection). DESTRUCTIVE, lab only.
# Runs ON THE HÔTE (the DB is only reachable there, via Docker). Not a remote
# exploit: the API is parameterized and the DB is not exposed — this is a
# controlled fault injection to demonstrate the integrity DETECTION + restore.
#
# What it does: flips one non-system account's balance so it no longer matches
# its ledger entries. The payment-api integrity watcher (every ~15s) then sets
# payment_ledger_integrity_ok=0, logs event_type=integrity_violation, and the
# alert LedgerIntegrityBroken fires. GET /api/payments/admin/integrity -> 409.
#
# Safety: backs up paydb FIRST, records an exact reverse-delta, and refuses to
# corrupt without CONFIRM=1. Restore with:  ./corrupt-ledger.sh restore
#
# Usage (on the Hôte):
#   ./corrupt-ledger.sh check                 # show current integrity
#   CONFIRM=1 ./corrupt-ledger.sh corrupt     # back up + inject the violation
#   ./corrupt-ledger.sh restore               # reverse the injection
#   ./corrupt-ledger.sh restore <backup.sql>  # full restore from a pg_dump
set -euo pipefail
source "$(dirname "$0")/../_lib/guard.sh"

CMD="${1:-check}"
DB="${PGDATABASE:-paydb}"
DELTA_CENTS="${DELTA_CENTS:-100000}"   # +1000.00 € injected onto one account
STATE_DIR="$RA_ATTACKS_DIR/04-integrity-violation/.state"
mkdir -p "$STATE_DIR"

cid="$(docker ps --filter name=postgres -q | head -1)"
[ -n "$cid" ] || { echo "[-] No running 'postgres' container found. Run this on the Hôte with the stack up."; exit 1; }
PGUSER="${PGUSER:-$(docker exec "$cid" printenv POSTGRES_USER 2>/dev/null || echo postgres)}"
psql() { docker exec -i "$cid" psql -U "$PGUSER" -d "$DB" -v ON_ERROR_STOP=1 "$@"; }

integrity_report() {
  psql -t -A -F$'\t' -c "
    SELECT 'global_sum', COALESCE(SUM(amount_cents),0) FROM ledger_entries
    UNION ALL SELECT 'mismatched_accounts', COUNT(*) FROM accounts a
      LEFT JOIN (SELECT account_id, SUM(amount_cents) t FROM ledger_entries GROUP BY account_id) e
      ON e.account_id=a.id WHERE a.balance_cents <> COALESCE(e.t,0)
    UNION ALL SELECT 'negative_balances', COUNT(*) FROM accounts WHERE NOT is_system AND balance_cents<0;"
}

case "$CMD" in
  check)
    echo "[*] Integrity snapshot ($DB @ $cid):"; integrity_report
    ;;

  corrupt)
    OUTDIR="$(ra_logdir integrity)"
    echo "[*] Target DB: $DB @ container $cid (user $PGUSER)"
    echo "[*] Backing up paydb FIRST -> $OUTDIR/paydb-backup.sql"
    docker exec "$cid" pg_dump -U "$PGUSER" --clean --if-exists "$DB" > "$OUTDIR/paydb-backup.sql"
    echo "    backup size: $(wc -c < "$OUTDIR/paydb-backup.sql") bytes"

    # Pick a victim account and record the exact reverse-delta before touching it.
    acct="$(psql -t -A -c "SELECT id FROM accounts WHERE NOT is_system ORDER BY created_at LIMIT 1;")"
    [ -n "$acct" ] || { echo "[-] No non-system account to corrupt (seed a transaction first)."; exit 1; }
    before="$(psql -t -A -c "SELECT balance_cents FROM accounts WHERE id='$acct';")"
    printf 'UPDATE accounts SET balance_cents = %s WHERE id = %s;\n' "$before" "'$acct'" > "$STATE_DIR/reverse.sql"
    cp "$STATE_DIR/reverse.sql" "$OUTDIR/reverse.sql"
    echo "[*] Victim account $acct : balance $before -> $((before + DELTA_CENTS)) (reverse-delta saved)"

    if [ "${CONFIRM:-0}" != "1" ]; then
      echo "[!] DRY RUN. This WILL break ledger integrity. Re-run with CONFIRM=1 to inject."
      exit 0
    fi
    echo "[*] Injecting violation ($(ra_now))..."
    psql -c "UPDATE accounts SET balance_cents = balance_cents + $DELTA_CENTS WHERE id = '$acct';"
    echo "[+] Done. Within ~15s expect on the Hôte dashboards:"
    echo "      payment_ledger_integrity_ok -> 0, LedgerIntegrityBroken firing, Loki event_type=integrity_violation"
    echo "      curl -s http://127.0.0.1:8080/api/payments/admin/integrity  (admin JWT) -> HTTP 409"
    echo "[*] Post-injection snapshot:"; integrity_report
    echo "[i] Restore when the team has seen the alert:  ./corrupt-ledger.sh restore"
    echo "[i] Evidence: $OUTDIR"
    ;;

  restore)
    backup="${2:-}"
    if [ -n "$backup" ]; then
      [ -f "$backup" ] || { echo "[-] Backup file not found: $backup"; exit 1; }
      echo "[*] Full restore from $backup ($(ra_now))..."
      docker exec -i "$cid" psql -U "$PGUSER" -d "$DB" -v ON_ERROR_STOP=1 < "$backup"
    else
      [ -f "$STATE_DIR/reverse.sql" ] || { echo "[-] No reverse-delta recorded. Restore from a pg_dump: ./corrupt-ledger.sh restore <backup.sql>"; exit 1; }
      echo "[*] Reversing the injection ($(ra_now))..."
      docker exec -i "$cid" psql -U "$PGUSER" -d "$DB" -v ON_ERROR_STOP=1 < "$STATE_DIR/reverse.sql"
      rm -f "$STATE_DIR/reverse.sql"
    fi
    echo "[+] Restored. Integrity should return to OK within ~15s."
    echo "[*] Snapshot:"; integrity_report
    ;;

  *)
    echo "Usage: ./corrupt-ledger.sh [check | corrupt | restore [backup.sql]]   (corrupt needs CONFIRM=1)"
    exit 1
    ;;
esac
