"""Règles métier du registre : ouverture de compte, virement atomique, contrôle d'intégrité.

Accès à la base par l'ORM SQLAlchemy, sur le moteur unique du service (créé au démarrage, voir main.py). Chaque
fonction reçoit la session de la requête, ouverte et fermée par l'appelant (`with sessions() as session:`) : la
connexion revient au pool sur tous les chemins, erreurs comprises. Une écriture se termine par un commit, ou par un
rollback qui libère aussitôt les verrous ; les résultats sont des dictionnaires construits avant la fermeture.
"""

import secrets
import uuid
from datetime import datetime, timezone

from sqlalchemy import Engine, case, func, or_, select, text, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, aliased, sessionmaker

from .models import IDEMPOTENCY_UNIQUE, OWNER_UNIQUE, Account, LedgerEntry, Transfer

TREASURY_ID = uuid.UUID("00000000-0000-0000-0000-000000000001")
WELCOME_CREDIT_CENTS = 100_000  # 1 000,00 € fictifs


def session_factory(engine: Engine) -> sessionmaker[Session]:
    # Cette méthode permet de fabriquer les sessions du registre sur le moteur du service. Avec expire_on_commit=False,
    # un commit n'expire pas les objets chargés : les valeurs écrites par la base elle-même (solde après crédit,
    # horodatage) sont relues explicitement par refresh() là où elles sont rendues.
    return sessionmaker(bind=engine, expire_on_commit=False)


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


def _violated_constraint(exc: IntegrityError) -> str | None:
    # Cette méthode permet de lire le nom de la contrainte violée, tel que PostgreSQL le rapporte au pilote psycopg.
    return getattr(getattr(exc.orig, "diag", None), "constraint_name", None)


def _insert_transfer(session: Session, from_id, to_id, amount_cents: int, label: str, initiated_by, idempotency_key) -> uuid.UUID:
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
    # Mise à jour relative (solde = solde ± montant) calculée par la base, sur des lignes verrouillées.
    session.execute(update(Account).where(Account.id == from_id).values(balance_cents=Account.balance_cents - amount_cents))
    session.execute(update(Account).where(Account.id == to_id).values(balance_cents=Account.balance_cents + amount_cents))
    session.flush()
    return transfer.id


def _account_dict(account: Account) -> dict:
    # Cette méthode permet de rendre un compte sous la forme des colonnes de la table accounts.
    return {column.key: getattr(account, column.key) for column in Account.__table__.columns}


def _lock_accounts(session: Session, *account_ids) -> dict:
    # Cette méthode permet de verrouiller des comptes (SELECT … FOR UPDATE) dans un ordre déterministe, pour éviter
    # les interblocages entre virements croisés, et de rendre leurs soldes lus sous verrou. On lit des colonnes et non
    # des objets : l'ORM ne remplace pas un objet déjà chargé dans la session, dont le solde pourrait être périmé.
    rows = session.execute(
        select(Account.id, Account.balance_cents).where(Account.id.in_(account_ids)).order_by(Account.id).with_for_update()
    ).all()
    return {row.id: row.balance_cents for row in rows}


def get_or_open_account(session: Session, claims: dict) -> tuple[dict, bool]:
    # Cette méthode permet de récupérer le compte de l'utilisateur, ou de l'ouvrir avec un crédit de bienvenue
    # lors de sa première visite (retourne le compte et un booléen « créé »).
    owner_id = uuid.UUID(claims["sub"])
    account = session.scalar(select(Account).where(Account.owner_id == owner_id))
    if account:
        return _account_dict(account), False
    account = Account(
        id=uuid.uuid4(), account_number=_new_account_number(), owner_id=owner_id,
        owner_name=claims.get("name", ""), owner_email=claims.get("email"),
    )
    try:
        session.add(account)
        session.flush()
        _lock_accounts(session, TREASURY_ID, account.id)
        _insert_transfer(session, TREASURY_ID, account.id, WELCOME_CREDIT_CENTS, "Crédit de bienvenue", None, None)
        session.commit()
    except IntegrityError as exc:
        session.rollback()
        if _violated_constraint(exc) != OWNER_UNIQUE:
            raise
        # Ouverture concurrente par une autre requête : son compte, déjà crédité, est relu (crédit unique).
        account = session.scalar(select(Account).where(Account.owner_id == owner_id))
        return _account_dict(account), False
    except Exception:
        session.rollback()
        raise
    session.refresh(account)  # solde après crédit et horodatage, tels qu'enregistrés
    return _account_dict(account), True


def execute_transfer(session: Session, sender: dict, to_account_number: str, amount_cents: int, label: str,
                     initiated_by: uuid.UUID, idempotency_key: str) -> tuple[dict, bool]:
    # Cette méthode permet d'exécuter un virement de façon atomique et idempotente : une même clé rejouée renvoie
    # le virement initial (booléen « rejoué » à True) au lieu de débiter une seconde fois.
    existing = _find_by_idempotency(session, initiated_by, idempotency_key)
    if existing:
        return _check_replay(existing, to_account_number, amount_cents), True

    recipient = session.scalar(select(Account).where(Account.account_number == to_account_number, ~Account.is_system))
    if recipient is None:
        raise LedgerError(404, "recipient_not_found", "Compte bénéficiaire introuvable")
    if recipient.id == sender["id"]:
        raise LedgerError(422, "same_account", "Impossible de virer vers son propre compte")

    try:
        balances = _lock_accounts(session, sender["id"], recipient.id)
        if balances[sender["id"]] < amount_cents:
            raise LedgerError(422, "insufficient_funds", "Solde insuffisant")
        transfer_id = _insert_transfer(session, sender["id"], recipient.id, amount_cents, label, initiated_by, idempotency_key)
        session.commit()
    except IntegrityError as exc:
        session.rollback()
        if _violated_constraint(exc) != IDEMPOTENCY_UNIQUE:
            raise
        # Deux requêtes simultanées avec la même clé : la seconde renvoie le résultat de la première.
        existing = _find_by_idempotency(session, initiated_by, idempotency_key)
        return _check_replay(existing, to_account_number, amount_cents), True
    except Exception:
        session.rollback()
        raise
    return transfer_view(session, transfer_id, sender["id"]), False


def _find_by_idempotency(session: Session, initiated_by, idempotency_key: str) -> dict | None:
    # Cette méthode permet de retrouver un virement déjà enregistré pour ce couple (utilisateur, clé d'idempotence).
    transfer = session.scalar(select(Transfer).where(
        Transfer.initiated_by == initiated_by, Transfer.idempotency_key == idempotency_key
    ))
    return transfer_view(session, transfer.id, transfer.from_account_id) if transfer else None


def _check_replay(existing: dict, to_account_number: str, amount_cents: int) -> dict:
    # Cette méthode permet de refuser la réutilisation d'une clé d'idempotence pour un virement différent.
    if existing["amount_cents"] != amount_cents or existing["counterparty_account_number"] != to_account_number:
        raise LedgerError(422, "idempotency_key_reused", "Clé d'idempotence déjà utilisée pour un autre virement")
    return existing


def _transfer_view_query(account_id):
    # Cette méthode permet de construire la requête des virements vus depuis un compte (sens, contrepartie),
    # limitée à ceux dont ce compte est l'émetteur ou le bénéficiaire.
    source = aliased(Account)
    destination = aliased(Account)
    sent = Transfer.from_account_id == account_id
    return select(
        Transfer.id, Transfer.amount_cents, Transfer.label, Transfer.status, Transfer.created_at,
        case((sent, "debit"), else_="credit").label("direction"),
        case((sent, destination.account_number), else_=source.account_number).label("counterparty_account_number"),
        case((sent, destination.owner_name), else_=source.owner_name).label("counterparty_name"),
    ).join(source, source.id == Transfer.from_account_id).join(destination, destination.id == Transfer.to_account_id).where(
        or_(sent, Transfer.to_account_id == account_id)
    )


def transfer_view(session: Session, transfer_id, account_id) -> dict | None:
    # Cette méthode permet de présenter un virement du point de vue d'un compte (sens, contrepartie) ;
    # None si le virement n'existe pas ou si ce compte n'en est ni l'émetteur ni le bénéficiaire.
    row = session.execute(_transfer_view_query(account_id).where(Transfer.id == transfer_id)).mappings().first()
    return dict(row) if row else None


def list_transfers(session: Session, account_id, limit: int) -> list[dict]:
    # Cette méthode permet de lister les derniers virements émis ou reçus par un compte.
    statement = _transfer_view_query(account_id).order_by(Transfer.created_at.desc()).limit(limit)
    return [dict(row) for row in session.execute(statement).mappings().all()]


def check_integrity(session: Session) -> dict:
    # Cette méthode permet de vérifier la cohérence comptable (somme nulle, soldes = écritures, virements équilibrés) ;
    # elle sert de preuve que les données sont saines après une remédiation, au-delà du simple redémarrage.
    # Elle ouvre sa propre transaction : la session ne doit pas en avoir une en cours.
    with session.begin():
        # Instantané unique : évite les faux positifs pendant qu'un virement est en cours d'écriture.
        session.execute(text("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY"))
        return _run_integrity_checks(session)


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
    # Lignes converties en dictionnaires : le rapport est sérialisé tel quel par json.dumps (réponse 409, journal).
    negative = [dict(row) for row in session.execute(
        select(Account.account_number, Account.balance_cents).where(~Account.is_system, Account.balance_cents < 0)
    ).mappings().all()]
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
            "unbalanced_transfers": [str(row.id) for row in unbalanced],
            "negative_accounts": negative,
        },
        "stats": stats,
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }
