"""Règles métier du registre : ouverture de compte, virement atomique, contrôle d'intégrité."""

import secrets
import uuid
from datetime import datetime, timezone

from psycopg import Connection, errors

TREASURY_ID = uuid.UUID("00000000-0000-0000-0000-000000000001")
WELCOME_CREDIT_CENTS = 100_000  # 1 000,00 € fictifs


class LedgerError(Exception):
    def __init__(self, status_code: int, code: str, message: str):
        # Cette méthode permet de porter une erreur métier avec son code HTTP et un code stable pour le front.
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message


def _new_account_number() -> str:
    # Cette méthode permet de générer un numéro de compte fictif (aucun format bancaire réel).
    return "RA" + "".join(secrets.choice("0123456789") for _ in range(10))


def _insert_transfer(conn: Connection, from_id, to_id, amount_cents: int, label: str, initiated_by, idempotency_key) -> dict:
    # Cette méthode permet d'écrire un virement et ses deux écritures, puis de mettre à jour les soldes ;
    # elle doit être appelée dans une transaction où les deux comptes sont déjà verrouillés.
    transfer = conn.execute(
        """INSERT INTO transfers (id, from_account_id, to_account_id, amount_cents, label, initiated_by, idempotency_key)
           VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING *""",
        (uuid.uuid4(), from_id, to_id, amount_cents, label, initiated_by, idempotency_key),
    ).fetchone()
    conn.execute(
        "INSERT INTO ledger_entries (transfer_id, account_id, amount_cents) VALUES (%s, %s, %s), (%s, %s, %s)",
        (transfer["id"], from_id, -amount_cents, transfer["id"], to_id, amount_cents),
    )
    conn.execute("UPDATE accounts SET balance_cents = balance_cents - %s WHERE id = %s", (amount_cents, from_id))
    conn.execute("UPDATE accounts SET balance_cents = balance_cents + %s WHERE id = %s", (amount_cents, to_id))
    return transfer


def get_or_open_account(conn: Connection, claims: dict) -> tuple[dict, bool]:
    # Cette méthode permet de récupérer le compte de l'utilisateur, ou de l'ouvrir avec un crédit de bienvenue
    # lors de sa première visite (retourne le compte et un booléen « créé »).
    owner_id = uuid.UUID(claims["sub"])
    account = conn.execute("SELECT * FROM accounts WHERE owner_id = %s", (owner_id,)).fetchone()
    if account:
        return account, False
    with conn.transaction():
        account = conn.execute(
            """INSERT INTO accounts (id, account_number, owner_id, owner_name, owner_email)
               VALUES (%s, %s, %s, %s, %s)
               ON CONFLICT (owner_id) DO NOTHING RETURNING *""",
            (uuid.uuid4(), _new_account_number(), owner_id, claims.get("name", ""), claims.get("email")),
        ).fetchone()
        if account is None:  # ouverture concurrente par une autre requête
            return conn.execute("SELECT * FROM accounts WHERE owner_id = %s", (owner_id,)).fetchone(), False
        conn.execute("SELECT id FROM accounts WHERE id = ANY(%s) ORDER BY id FOR UPDATE", ([TREASURY_ID, account["id"]],))
        _insert_transfer(conn, TREASURY_ID, account["id"], WELCOME_CREDIT_CENTS, "Crédit de bienvenue", None, None)
    return conn.execute("SELECT * FROM accounts WHERE id = %s", (account["id"],)).fetchone(), True


def execute_transfer(conn: Connection, sender: dict, to_account_number: str, amount_cents: int, label: str,
                     initiated_by: uuid.UUID, idempotency_key: str) -> tuple[dict, bool]:
    # Cette méthode permet d'exécuter un virement de façon atomique et idempotente : une même clé rejouée renvoie
    # le virement initial (booléen « rejoué » à True) au lieu de débiter une seconde fois.
    existing = _find_by_idempotency(conn, initiated_by, idempotency_key)
    if existing:
        return _check_replay(existing, sender, to_account_number, amount_cents), True

    recipient = conn.execute(
        "SELECT * FROM accounts WHERE account_number = %s AND NOT is_system", (to_account_number,)
    ).fetchone()
    if recipient is None:
        raise LedgerError(404, "recipient_not_found", "Compte bénéficiaire introuvable")
    if recipient["id"] == sender["id"]:
        raise LedgerError(422, "same_account", "Impossible de virer vers son propre compte")

    try:
        with conn.transaction():
            # Verrouillage dans un ordre déterministe pour éviter les interblocages entre virements croisés.
            locked = conn.execute(
                "SELECT id, balance_cents FROM accounts WHERE id = ANY(%s) ORDER BY id FOR UPDATE",
                ([sender["id"], recipient["id"]],),
            ).fetchall()
            balance = next(row["balance_cents"] for row in locked if row["id"] == sender["id"])
            if balance < amount_cents:
                raise LedgerError(422, "insufficient_funds", "Solde insuffisant")
            transfer = _insert_transfer(conn, sender["id"], recipient["id"], amount_cents, label, initiated_by, idempotency_key)
    except errors.UniqueViolation:
        # Deux requêtes simultanées avec la même clé : la seconde renvoie le résultat de la première.
        existing = _find_by_idempotency(conn, initiated_by, idempotency_key)
        return _check_replay(existing, sender, to_account_number, amount_cents), True
    return transfer_view(conn, transfer["id"], sender["id"]), False


def _find_by_idempotency(conn: Connection, initiated_by, idempotency_key: str) -> dict | None:
    # Cette méthode permet de retrouver un virement déjà enregistré pour ce couple (utilisateur, clé d'idempotence).
    row = conn.execute(
        "SELECT id, from_account_id FROM transfers WHERE initiated_by = %s AND idempotency_key = %s",
        (initiated_by, idempotency_key),
    ).fetchone()
    return transfer_view(conn, row["id"], row["from_account_id"]) if row else None


def _check_replay(existing: dict, sender: dict, to_account_number: str, amount_cents: int) -> dict:
    # Cette méthode permet de refuser la réutilisation d'une clé d'idempotence pour un virement différent.
    if existing["amount_cents"] != amount_cents or existing["counterparty_account_number"] != to_account_number:
        raise LedgerError(422, "idempotency_key_reused", "Clé d'idempotence déjà utilisée pour un autre virement")
    return existing


_TRANSFER_VIEW_SQL = """
    SELECT t.id, t.amount_cents, t.label, t.status, t.created_at,
           CASE WHEN t.from_account_id = %(acc)s THEN 'debit' ELSE 'credit' END AS direction,
           CASE WHEN t.from_account_id = %(acc)s THEN dst.account_number ELSE src.account_number END AS counterparty_account_number,
           CASE WHEN t.from_account_id = %(acc)s THEN dst.owner_name ELSE src.owner_name END AS counterparty_name
    FROM transfers t
    JOIN accounts src ON src.id = t.from_account_id
    JOIN accounts dst ON dst.id = t.to_account_id
"""


def transfer_view(conn: Connection, transfer_id, account_id) -> dict:
    # Cette méthode permet de présenter un virement du point de vue d'un compte (sens, contrepartie).
    return conn.execute(_TRANSFER_VIEW_SQL + " WHERE t.id = %(id)s", {"acc": account_id, "id": transfer_id}).fetchone()


def list_transfers(conn: Connection, account_id, limit: int) -> list[dict]:
    # Cette méthode permet de lister les derniers virements émis ou reçus par un compte.
    return conn.execute(
        _TRANSFER_VIEW_SQL + " WHERE t.from_account_id = %(acc)s OR t.to_account_id = %(acc)s ORDER BY t.created_at DESC LIMIT %(limit)s",
        {"acc": account_id, "limit": limit},
    ).fetchall()


def check_integrity(conn: Connection) -> dict:
    # Cette méthode permet de vérifier la cohérence comptable (somme nulle, soldes = écritures, virements équilibrés) ;
    # elle sert de preuve que les données sont saines après une remédiation, au-delà du simple redémarrage.
    with conn.transaction():
        # Instantané unique : évite les faux positifs pendant qu'un virement est en cours d'écriture.
        conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        return _run_integrity_checks(conn)


def _run_integrity_checks(conn: Connection) -> dict:
    # Cette méthode permet d'exécuter les requêtes de contrôle comptable dans la transaction ouverte par l'appelant.
    global_sum =conn.execute("SELECT COALESCE(SUM(amount_cents), 0) AS s FROM ledger_entries").fetchone()["s"]
    mismatched = conn.execute(
        """SELECT a.account_number, a.balance_cents, COALESCE(e.total, 0) AS ledger_cents
           FROM accounts a
           LEFT JOIN (SELECT account_id, SUM(amount_cents) AS total FROM ledger_entries GROUP BY account_id) e
             ON e.account_id = a.id
           WHERE a.balance_cents <> COALESCE(e.total, 0)"""
    ).fetchall()
    unbalanced = conn.execute(
        """SELECT t.id FROM transfers t LEFT JOIN ledger_entries e ON e.transfer_id = t.id
           GROUP BY t.id, t.amount_cents
           HAVING COUNT(e.id) <> 2 OR COALESCE(SUM(e.amount_cents), 0) <> 0
              OR COALESCE(MAX(e.amount_cents), 0) <> t.amount_cents"""
    ).fetchall()
    negative = conn.execute(
        "SELECT account_number, balance_cents FROM accounts WHERE NOT is_system AND balance_cents < 0"
    ).fetchall()
    stats = conn.execute(
        "SELECT (SELECT COUNT(*) FROM accounts WHERE NOT is_system) AS accounts, (SELECT COUNT(*) FROM transfers) AS transfers"
    ).fetchone()
    checks = {
        "ledger_sum_is_zero": global_sum == 0,
        "balances_match_ledger": not mismatched,
        "transfers_balanced": not unbalanced,
        "no_negative_balance": not negative,
    }
    return {
        "ok": all(checks.values()),
        "checks": checks,
        "details": {
            "ledger_sum_cents": int(global_sum),
            "mismatched_accounts": mismatched,
            "unbalanced_transfers": [str(row["id"]) for row in unbalanced],
            "negative_accounts": negative,
        },
        "stats": stats,
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }
