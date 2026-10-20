"""Règles métier du registre : ouverture de compte, virement atomique, contrôle d'intégrité."""

import secrets
import uuid
from datetime import datetime, timezone
from psycopg.conninfo import conninfo_to_dict
from sqlalchemy import URL, case, create_engine, func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, aliased, sessionmaker

from resilience_common.settings import database_url

from .models.account import Account
from .models.ledger_entries import LedgerEntry
from .models.transfer import Transfer

TREASURY_ID = uuid.UUID("00000000-0000-0000-0000-000000000001")
WELCOME_CREDIT_CENTS = 100_000  # 1 000,00 € fictifs

_session_factory: sessionmaker | None = None
_session_dsn: str | None = None


def _session() -> Session:
    global _session_dsn, _session_factory
    dsn = database_url()
    if _session_factory is None or _session_dsn != dsn:
        parameters = conninfo_to_dict(dsn)
        engine_url = URL.create(
            "postgresql+psycopg",
            username=parameters.pop("user", None),
            password=parameters.pop("password", None),
            host=parameters.pop("host", None),
            port=parameters.pop("port", None),
            database=parameters.pop("dbname", None),
            query=parameters,
        )
        _session_factory = sessionmaker(bind=create_engine(engine_url, pool_pre_ping=True), expire_on_commit=False)
        _session_dsn = dsn
    return _session_factory()


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


def _insert_transfer(session: Session, from_id, to_id, amount_cents: int, label: str, initiated_by, idempotency_key) -> dict:
    # Cette méthode permet d'écrire un virement et ses deux écritures, puis de mettre à jour les soldes ;
    # elle doit être appelée dans une transaction où les deux comptes sont déjà verrouillés.
    transfer = Transfer(
        id=uuid.uuid4(),
        from_account_id=from_id,
        to_account_id=to_id,
        amount_cents=amount_cents,
        label=label,
        status="completed",
        initiated_by=initiated_by,
        idempotency_key=idempotency_key,
    )
    session.add(transfer)
    session.add_all([
        LedgerEntry(transfer=transfer, account_id=from_id, amount_cents=-amount_cents),
        LedgerEntry(transfer=transfer, account_id=to_id, amount_cents=amount_cents),
    ])
    session.execute(update(Account).where(Account.id == from_id).values(balance_cents=Account.balance_cents - amount_cents))
    session.execute(update(Account).where(Account.id == to_id).values(balance_cents=Account.balance_cents + amount_cents))
    session.flush()
    return _transfer_dict(transfer)


def _transfer_dict(transfer: Transfer) -> dict:
    return {column.name: getattr(transfer, column.name) for column in Transfer.__table__.columns}


def _account_dict(account: Account) -> dict:
    return {column.name: getattr(account, column.name) for column in Account.__table__.columns}


def get_or_open_account(_conn, claims: dict) -> tuple[dict, bool]:
    # Cette méthode permet de récupérer le compte de l'utilisateur, ou de l'ouvrir avec un crédit de bienvenue
    # lors de sa première visite (retourne le compte et un booléen « créé »).
    owner_id = uuid.UUID(claims["sub"])
    session = _session()
    try:
        account = session.scalar(select(Account).where(Account.owner_id == owner_id))
        if account:
            return _account_dict(account), False
        account = Account(
            id=uuid.uuid4(), account_number=_new_account_number(), owner_id=owner_id,
            owner_name=claims.get("name", ""), owner_email=claims.get("email"),
        )
        session.add(account)
        session.flush()
        session.execute(
            select(Account.id).where(Account.id.in_([TREASURY_ID, account.id])).order_by(Account.id).with_for_update()
        ).all()
        _insert_transfer(session, TREASURY_ID, account.id, WELCOME_CREDIT_CENTS, "Crédit de bienvenue", None, None)
        session.commit()
        return _account_dict(account), True
    except IntegrityError:
        session.rollback()
        account = session.scalar(select(Account).where(Account.owner_id == owner_id))
        return _account_dict(account), False
    finally:
        session.close()


def execute_transfer(_conn, sender: dict, to_account_number: str, amount_cents: int, label: str,
                     initiated_by: uuid.UUID, idempotency_key: str) -> tuple[dict, bool]:
    # Cette méthode permet d'exécuter un virement de façon atomique et idempotente : une même clé rejouée renvoie
    # le virement initial (booléen « rejoué » à True) au lieu de débiter une seconde fois.
    existing = _find_by_idempotency(None, initiated_by, idempotency_key)
    if existing:
        return _check_replay(existing, sender, to_account_number, amount_cents), True

    session = _session()
    recipient = session.scalar(select(Account).where(Account.account_number == to_account_number, ~Account.is_system))
    if recipient is None:
        session.close()
        raise LedgerError(404, "recipient_not_found", "Compte bénéficiaire introuvable")
    if recipient.id == sender["id"]:
        session.close()
        raise LedgerError(422, "same_account", "Impossible de virer vers son propre compte")

    try:
        locked = session.scalars(
            select(Account).where(Account.id.in_([sender["id"], recipient.id])).order_by(Account.id).with_for_update()
        ).all()
        balance = next(account.balance_cents for account in locked if account.id == sender["id"])
        if balance < amount_cents:
            raise LedgerError(422, "insufficient_funds", "Solde insuffisant")
        transfer = _insert_transfer(session, sender["id"], recipient.id, amount_cents, label, initiated_by, idempotency_key)
        session.commit()
    except IntegrityError:
        session.rollback()
        existing = _find_by_idempotency(None, initiated_by, idempotency_key)
        return _check_replay(existing, sender, to_account_number, amount_cents), True
    finally:
        session.close()
    return transfer_view(None, transfer["id"], sender["id"]), False


def _find_by_idempotency(_conn, initiated_by, idempotency_key: str) -> dict | None:
    # Cette méthode permet de retrouver un virement déjà enregistré pour ce couple (utilisateur, clé d'idempotence).
    session = _session()
    try:
        transfer = session.scalar(select(Transfer).where(
            Transfer.initiated_by == initiated_by, Transfer.idempotency_key == idempotency_key
        ))
        return transfer_view(session, transfer.id, transfer.from_account_id) if transfer else None
    finally:
        session.close()


def _check_replay(existing: dict, _sender: dict, to_account_number: str, amount_cents: int) -> dict:
    # Cette méthode permet de refuser la réutilisation d'une clé d'idempotence pour un virement différent.
    if existing["amount_cents"] != amount_cents or existing["counterparty_account_number"] != to_account_number:
        raise LedgerError(422, "idempotency_key_reused", "Clé d'idempotence déjà utilisée pour un autre virement")
    return existing


def transfer_view(_conn, transfer_id, account_id) -> dict:
    # Cette méthode permet de présenter un virement du point de vue d'un compte (sens, contrepartie).
    session = _session()
    try:
        source = aliased(Account)
        destination = aliased(Account)
        statement = select(
            Transfer.id, Transfer.amount_cents, Transfer.label, Transfer.status, Transfer.created_at,
            case((Transfer.from_account_id == account_id, "debit"), else_="credit").label("direction"),
            case((Transfer.from_account_id == account_id, destination.account_number), else_=source.account_number).label("counterparty_account_number"),
            case((Transfer.from_account_id == account_id, destination.owner_name), else_=source.owner_name).label("counterparty_name"),
        ).join(source, source.id == Transfer.from_account_id).join(destination, destination.id == Transfer.to_account_id).where(Transfer.id == transfer_id)
        row = session.execute(statement).mappings().first()
        return dict(row) if row else None
    finally:
        session.close()


def list_transfers(_conn, account_id, limit: int) -> list[dict]:
    # Cette méthode permet de lister les derniers virements émis ou reçus par un compte.
    session = _session()
    try:
        source = aliased(Account)
        destination = aliased(Account)
        statement = select(
            Transfer.id, Transfer.amount_cents, Transfer.label, Transfer.status, Transfer.created_at,
            case((Transfer.from_account_id == account_id, "debit"), else_="credit").label("direction"),
            case((Transfer.from_account_id == account_id, destination.account_number), else_=source.account_number).label("counterparty_account_number"),
            case((Transfer.from_account_id == account_id, destination.owner_name), else_=source.owner_name).label("counterparty_name"),
        ).join(source, source.id == Transfer.from_account_id).join(destination, destination.id == Transfer.to_account_id).where(
            (Transfer.from_account_id == account_id) | (Transfer.to_account_id == account_id)
        ).order_by(Transfer.created_at.desc()).limit(limit)
        return [dict(row) for row in session.execute(statement).mappings().all()]
    finally:
        session.close()


def check_integrity(_conn) -> dict:
    # Cette méthode permet de vérifier la cohérence comptable (somme nulle, soldes = écritures, virements équilibrés) ;
    # elle sert de preuve que les données sont saines après une remédiation, au-delà du simple redémarrage.
    session = _session()
    try:
        return _run_integrity_checks(session)
    finally:
        session.close()


def _run_integrity_checks(session: Session) -> dict:
    # Cette méthode permet d'exécuter les requêtes de contrôle comptable dans la transaction ouverte par l'appelant.
    global_sum = session.scalar(select(func.coalesce(func.sum(LedgerEntry.amount_cents), 0)))
    ledger_totals = select(
        LedgerEntry.account_id, func.sum(LedgerEntry.amount_cents).label("total")
    ).group_by(LedgerEntry.account_id).subquery()
    mismatched = session.execute(
        select(Account.account_number, Account.balance_cents, func.coalesce(ledger_totals.c.total, 0).label("ledger_cents"))
        .outerjoin(ledger_totals, ledger_totals.c.account_id == Account.id)
        .where(Account.balance_cents != func.coalesce(ledger_totals.c.total, 0))
    ).mappings().all()
    # SUM(bigint) renvoie un numeric (Decimal côté Python) : converti en entier pour rester sérialisable en JSON.
    mismatched = [{**row, "ledger_cents": int(row["ledger_cents"])} for row in mismatched]
    unbalanced = session.execute(
        select(Transfer.id).outerjoin(LedgerEntry, LedgerEntry.transfer_id == Transfer.id)
        .group_by(Transfer.id, Transfer.amount_cents)
        .having(
            (func.count(LedgerEntry.id) != 2)
            | (func.coalesce(func.sum(LedgerEntry.amount_cents), 0) != 0)
            | (func.coalesce(func.max(LedgerEntry.amount_cents), 0) != Transfer.amount_cents)
        )
    ).all()
    negative = session.execute(
        select(Account.account_number, Account.balance_cents).where(~Account.is_system, Account.balance_cents < 0)
    ).mappings().all()
    stats = {
        "accounts": session.scalar(select(func.count(Account.id)).where(~Account.is_system)),
        "transfers": session.scalar(select(func.count(Transfer.id))),
    }
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
            "unbalanced_transfers": [str(row[0]) for row in unbalanced],
            "negative_accounts": negative,
        },
        "stats": stats,
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }
