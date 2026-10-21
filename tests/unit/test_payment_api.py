"""Tests de l'API de paiement : ouverture de compte, virements, idempotence, droits, intégrité, pannes de base."""

import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor

import jwt
import psycopg
import pytest
from sqlalchemy import CheckConstraint, UniqueConstraint, inspect, select
from sqlalchemy.dialects import postgresql
from sqlalchemy.exc import IntegrityError

from service_loader import load_service

WELCOME = 100_000


def open_account(client, user) -> dict:
    # Cette méthode permet d'ouvrir (ou relire) le compte d'un utilisateur et de renvoyer sa représentation.
    res = client.get("/accounts/me", headers=user["headers"])
    assert res.status_code == 200, res.text
    return res.json()


def transfer(client, user, to: str, amount: int, key: str | None = None, label: str = "Test"):
    # Cette méthode permet d'émettre un virement avec une clé d'idempotence (aléatoire si non fournie).
    headers = {**user["headers"], "Idempotency-Key": key or uuid.uuid4().hex}
    return client.post("/transfers", json={"to_account_number": to, "amount_cents": amount, "label": label}, headers=headers)


def account_row(sessions, user) -> dict:
    # Cette méthode permet de relire la ligne SQL du compte d'un utilisateur, attendue par les fonctions du registre.
    ledger = load_service("payment-api", "ledger")
    with sessions() as session:
        return ledger.get_or_open_account(session, {"sub": str(user["id"])})[0]


def tamper(database, sql: str, *params) -> None:
    # Cette méthode permet d'altérer la base par une connexion directe, hors de l'API et de son pool,
    # comme le ferait une attaque ou une restauration ratée.
    with psycopg.connect(**database, autocommit=True) as conn:
        conn.execute(sql, params)


@pytest.fixture
def alice_bob(payment_client, make_user):
    # Cette méthode permet de préparer deux clients avec leur compte ouvert et crédité.
    alice, bob = make_user("Alice Test"), make_user("Bob Test")
    alice["account"], bob["account"] = open_account(payment_client, alice), open_account(payment_client, bob)
    return alice, bob


def test_first_visit_opens_account_with_welcome_credit(payment_client, make_user):
    user = make_user("Alice Test")
    account = open_account(payment_client, user)
    assert account["account_number"].startswith("RA") and len(account["account_number"]) == 12
    assert account["balance_cents"] == WELCOME
    assert account["owner_name"] == "Alice Test" and account["currency"] == "EUR"
    assert open_account(payment_client, user)["account_number"] == account["account_number"]

    history = payment_client.get("/transfers", headers=user["headers"]).json()
    assert [(t["direction"], t["amount_cents"], t["label"]) for t in history] == [("credit", WELCOME, "Crédit de bienvenue")]


def test_transfer_moves_money_and_appears_on_both_sides(payment_client, alice_bob):
    alice, bob = alice_bob
    res = transfer(payment_client, alice, bob["account"]["account_number"], 2_550, label="  Loyer  ")
    assert res.status_code == 201, res.text
    sent = res.json()
    assert sent["direction"] == "debit" and sent["label"] == "Loyer"
    assert sent["counterparty_account_number"] == bob["account"]["account_number"]

    assert open_account(payment_client, alice)["balance_cents"] == WELCOME - 2_550
    assert open_account(payment_client, bob)["balance_cents"] == WELCOME + 2_550
    received = payment_client.get("/transfers", headers=bob["headers"]).json()[0]
    assert received["id"] == sent["id"] and received["direction"] == "credit"
    assert received["counterparty_name"] == "Alice Test"


def test_replayed_idempotency_key_debits_only_once(payment_client, alice_bob):
    alice, bob = alice_bob
    to = bob["account"]["account_number"]
    first = transfer(payment_client, alice, to, 1_000, key="retry-key-0001")
    second = transfer(payment_client, alice, to, 1_000, key="retry-key-0001")
    assert (first.status_code, second.status_code) == (201, 200)
    assert first.json()["id"] == second.json()["id"]
    assert open_account(payment_client, alice)["balance_cents"] == WELCOME - 1_000


def test_idempotency_key_cannot_be_reused_for_another_transfer(payment_client, alice_bob):
    alice, bob = alice_bob
    to = bob["account"]["account_number"]
    assert transfer(payment_client, alice, to, 1_000, key="reused-key-01").status_code == 201
    res = transfer(payment_client, alice, to, 9_999, key="reused-key-01")
    assert res.status_code == 422 and res.json()["code"] == "idempotency_key_reused"


def test_same_key_from_two_users_creates_two_transfers(payment_client, alice_bob):
    alice, bob = alice_bob
    a = transfer(payment_client, alice, bob["account"]["account_number"], 100, key="shared-key-01")
    b = transfer(payment_client, bob, alice["account"]["account_number"], 100, key="shared-key-01")
    assert (a.status_code, b.status_code) == (201, 201) and a.json()["id"] != b.json()["id"]


@pytest.mark.parametrize(
    ("amount", "target", "status", "code"),
    [
        (WELCOME + 1, "bob", 422, "insufficient_funds"),
        (100, "self", 422, "same_account"),
        (100, "RA0000000000", 404, "recipient_not_found"),
        (100, "RA-TREASURY", 422, None),  # compte système : refusé dès la validation du format
    ],
)
def test_business_rules_reject_invalid_transfers(payment_client, alice_bob, amount, target, status, code):
    alice, bob = alice_bob
    to = {"bob": bob["account"]["account_number"], "self": alice["account"]["account_number"]}.get(target, target)
    res = transfer(payment_client, alice, to, amount)
    assert res.status_code == status, res.text
    if code:
        assert res.json()["code"] == code
    assert open_account(payment_client, alice)["balance_cents"] == WELCOME


@pytest.mark.parametrize(
    ("body", "headers"),
    [
        ({"to_account_number": "RA1234567890", "amount_cents": 0}, {"Idempotency-Key": "valid-key-01"}),
        ({"to_account_number": "RA1234567890", "amount_cents": 1_000_001}, {"Idempotency-Key": "valid-key-01"}),
        ({"to_account_number": "FR7612345678", "amount_cents": 100}, {"Idempotency-Key": "valid-key-01"}),
        ({"to_account_number": "RA1234567890", "amount_cents": 100, "label": "x" * 141}, {"Idempotency-Key": "valid-key-01"}),
        ({"to_account_number": "RA1234567890", "amount_cents": 100}, {}),
        ({"to_account_number": "RA1234567890", "amount_cents": 100}, {"Idempotency-Key": "short"}),
    ],
    ids=["zero", "over-limit", "bad-account", "long-label", "no-key", "short-key"],
)
def test_malformed_transfer_requests_are_rejected(payment_client, make_user, body, headers):
    user = make_user()
    res = payment_client.post("/transfers", json=body, headers={**user["headers"], **headers})
    assert res.status_code == 422


def test_requests_without_valid_token_are_refused(payment_client, issuer, rsa_keys, other_rsa_keys):
    claims = {"sub": str(uuid.uuid4()), "role": "client", "iss": "resilience-alpha-auth", "aud": "payment-api",
              "exp": int(time.time()) + 60}
    forged = jwt.encode(claims, other_rsa_keys[0], algorithm="RS256")
    wrong_audience = jwt.encode({**claims, "aud": "other-api"}, rsa_keys[0], algorithm="RS256")
    expired = jwt.encode({**claims, "exp": int(time.time()) - 60}, rsa_keys[0], algorithm="RS256")
    hs256 = jwt.encode(claims, "secret-partage-assez-long-pour-hs256-0123456789", algorithm="HS256")

    assert payment_client.get("/accounts/me").status_code == 401
    for token in (forged, wrong_audience, expired, hs256, "pas-un-jeton"):
        res = payment_client.get("/accounts/me", headers={"Authorization": f"Bearer {token}"})
        assert res.status_code == 401, token


def test_transfer_is_visible_only_to_its_parties(payment_client, alice_bob, make_user):
    alice, bob = alice_bob
    transfer_id = transfer(payment_client, alice, bob["account"]["account_number"], 500).json()["id"]
    assert payment_client.get(f"/transfers/{transfer_id}", headers=bob["headers"]).json()["direction"] == "credit"
    assert payment_client.get(f"/transfers/{transfer_id}", headers=alice["headers"]).json()["direction"] == "debit"
    assert payment_client.get(f"/transfers/{transfer_id}", headers=make_user("Eve Test")["headers"]).status_code == 404
    assert payment_client.get(f"/transfers/{uuid.uuid4()}", headers=alice["headers"]).status_code == 404


def test_history_is_newest_first_and_limited(payment_client, alice_bob):
    alice, bob = alice_bob
    for amount in (101, 102, 103):
        transfer(payment_client, alice, bob["account"]["account_number"], amount)
    history = payment_client.get("/transfers", params={"limit": 2}, headers=alice["headers"]).json()
    assert [t["amount_cents"] for t in history] == [103, 102]
    assert payment_client.get("/transfers", params={"limit": 0}, headers=alice["headers"]).status_code == 422


def test_admin_integrity_requires_admin_role(payment_client, alice_bob, make_user):
    alice, _ = alice_bob
    assert payment_client.get("/admin/integrity", headers=alice["headers"]).status_code == 403
    report = payment_client.get("/admin/integrity", headers=make_user("Admin", role="admin")["headers"]).json()
    assert report["ok"] is True
    assert report["stats"] == {"accounts": 2, "transfers": 2}


def test_integrity_check_detects_tampered_balance(payment_client, alice_bob, database):
    alice, bob = alice_bob
    transfer(payment_client, alice, bob["account"]["account_number"], 700)
    assert payment_client.get("/internal/integrity").status_code == 200

    tamper(database, "UPDATE accounts SET balance_cents = balance_cents + 5000 WHERE account_number = %s",
           bob["account"]["account_number"])
    res = payment_client.get("/internal/integrity")
    report = res.json()
    assert res.status_code == 409 and report["ok"] is False
    assert report["checks"]["balances_match_ledger"] is False and report["checks"]["ledger_sum_is_zero"] is True
    [mismatch] = report["details"]["mismatched_accounts"]
    assert mismatch["account_number"] == bob["account"]["account_number"]
    assert mismatch["ledger_cents"] == WELCOME + 700 and mismatch["balance_cents"] == WELCOME + 5_700


def test_integrity_check_detects_unbalanced_ledger(payment_client, alice_bob, database):
    alice, bob = alice_bob
    transfer_id = transfer(payment_client, alice, bob["account"]["account_number"], 700).json()["id"]
    tamper(database, "DELETE FROM ledger_entries WHERE transfer_id = %s AND amount_cents > 0", transfer_id)
    report = payment_client.get("/internal/integrity").json()
    assert report["checks"]["ledger_sum_is_zero"] is False
    assert transfer_id in report["details"]["unbalanced_transfers"]


def test_concurrent_crossed_transfers_keep_ledger_consistent(payment_client, alice_bob):
    # 40 virements croisés en parallèle : aucun interblocage, masse monétaire conservée, registre cohérent.
    alice, bob = alice_bob
    ledger = load_service("payment-api", "ledger")
    sessions = payment_client.app.state.sessions
    rows = {"alice": account_row(sessions, alice), "bob": account_row(sessions, bob)}

    def run(i: int) -> None:
        # Cette méthode permet d'exécuter un virement dans un fil, alternativement d'Alice vers Bob et inversement.
        sender, recipient = (alice, bob) if i % 2 else (bob, alice)
        sender_row = rows["alice" if sender is alice else "bob"]
        with sessions() as session:
            ledger.execute_transfer(session, sender_row, recipient["account"]["account_number"], 100 + i, "",
                                    sender["id"], f"concurrent-{i:04d}")

    with ThreadPoolExecutor(max_workers=8) as executor:
        list(executor.map(run, range(40)))

    with sessions() as session:
        report = ledger.check_integrity(session)
    assert report["ok"], report
    assert report["stats"]["transfers"] == 42  # 40 virements + 2 crédits de bienvenue
    total = open_account(payment_client, alice)["balance_cents"] + open_account(payment_client, bob)["balance_cents"]
    assert total == 2 * WELCOME


def test_concurrent_replays_of_same_key_debit_once(payment_client, alice_bob):
    alice, bob = alice_bob
    ledger = load_service("payment-api", "ledger")
    sessions = payment_client.app.state.sessions
    sender_row = account_row(sessions, alice)

    def run(_: int) -> str:
        # Cette méthode permet de rejouer le même virement depuis plusieurs fils, comme des doubles clics simultanés.
        with sessions() as session:
            result, _replayed = ledger.execute_transfer(session, sender_row, bob["account"]["account_number"], 1_234, "",
                                                        alice["id"], "double-click-0001")
            return str(result["id"])

    with ThreadPoolExecutor(max_workers=6) as executor:
        ids = set(executor.map(run, range(6)))
    assert len(ids) == 1
    assert open_account(payment_client, alice)["balance_cents"] == WELCOME - 1_234


@pytest.fixture
def cut_database(pg_admin_dsn, database):
    # Cette méthode permet de couper la base du test côté serveur, comme un arrêt de PostgreSQL : connexions du pool
    # terminées, nouvelles connexions refusées ; elle est rétablie en fin de test quoi qu'il arrive.

    def toggle(available: bool) -> None:
        # Cette méthode permet d'ouvrir ou de fermer la base aux connexions.
        with psycopg.connect(pg_admin_dsn, autocommit=True) as conn:
            conn.execute(f'ALTER DATABASE "{database["dbname"]}" ALLOW_CONNECTIONS {str(available).lower()}')
            if not available:
                conn.execute("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = %s", (database["dbname"],))

    yield toggle
    toggle(True)


def server_connections(pg_admin_dsn, database) -> int:
    # Cette méthode permet de compter les connexions ouvertes sur la base du test, vues par PostgreSQL.
    with psycopg.connect(pg_admin_dsn, autocommit=True) as conn:
        return conn.execute("SELECT count(*) FROM pg_stat_activity WHERE datname = %s", (database["dbname"],)).fetchone()[0]


def test_database_outage_returns_503_not_500_then_recovers_alone(payment_client, alice_bob, cut_database):
    alice, bob = alice_bob
    assert payment_client.get("/health").json() == {"service": "payment-api", "status": "ok", "checks": {"database": True}}

    cut_database(False)
    health = payment_client.get("/health")
    assert health.status_code == 503 and health.json()["status"] == "degraded"
    for res in (payment_client.get("/accounts/me", headers=alice["headers"]),
                transfer(payment_client, alice, bob["account"]["account_number"], 100),
                payment_client.get("/transfers", headers=alice["headers"]),
                payment_client.get("/internal/integrity")):
        assert res.status_code == 503 and res.json()["code"] == "database_unavailable", res.text
    assert payment_client.app.state.engine.pool.checkedout() == 0

    # Retour de la base : les connexions sont testées avant usage, le service reprend sans redémarrage.
    cut_database(True)
    assert payment_client.get("/health").status_code == 200
    assert transfer(payment_client, alice, bob["account"]["account_number"], 100).status_code == 201
    assert open_account(payment_client, alice)["balance_cents"] == WELCOME - 100
    assert payment_client.get("/internal/integrity").status_code == 200


def test_failed_requests_give_their_connection_back(payment_client, alice_bob, pg_admin_dsn, database):
    # Erreurs métier levées avant, pendant et après le verrouillage des comptes : aucune session ni connexion perdue,
    # et un seul pool (borné à 10 connexions) côté serveur, même après 40 virements simultanés.
    alice, bob = alice_bob
    to = bob["account"]["account_number"]
    assert transfer(payment_client, alice, to, 100, key="leak-check-0001").status_code == 201
    failures = [
        transfer(payment_client, alice, to, 2 * WELCOME),
        transfer(payment_client, alice, alice["account"]["account_number"], 100),
        transfer(payment_client, alice, "RA0000000000", 100),
        transfer(payment_client, alice, to, 999, key="leak-check-0001"),
        payment_client.get(f"/transfers/{uuid.uuid4()}", headers=alice["headers"]),
    ]
    assert [(res.status_code, res.json().get("code")) for res in failures] == [
        (422, "insufficient_funds"), (422, "same_account"), (404, "recipient_not_found"),
        (422, "idempotency_key_reused"), (404, None),
    ]
    with ThreadPoolExecutor(max_workers=16) as executor:
        codes = list(executor.map(lambda i: transfer(payment_client, bob, alice["account"]["account_number"], 10).status_code,
                                  range(40)))
    assert codes == [201] * 40
    assert payment_client.app.state.engine.pool.checkedout() == 0
    assert server_connections(pg_admin_dsn, database) <= 10
    assert open_account(payment_client, bob)["balance_cents"] == WELCOME + 100 - 400


def test_concurrent_first_visits_open_one_account_credited_once(payment_client, make_user, monkeypatch):
    # Huit premières visites simultanées : toutes lisent « aucun compte » avant d'en ouvrir un (barrière), une seule
    # l'ouvre ; les autres reconnaissent la violation d'unicité du propriétaire et relisent ce compte.
    ledger = load_service("payment-api", "ledger")
    sessions = payment_client.app.state.sessions
    user = make_user("Carol Test")
    claims = {"sub": str(user["id"]), "name": user["full_name"], "email": user["email"]}
    barrier, new_number = threading.Barrier(8, timeout=10), ledger._new_account_number

    def number_after_barrier() -> str:
        # Cette méthode permet de retenir chaque fil entre la lecture du compte et son insertion.
        barrier.wait()
        return new_number()

    monkeypatch.setattr(ledger, "_new_account_number", number_after_barrier)

    def visit(_: int) -> tuple[str, bool]:
        # Cette méthode permet de simuler une première visite dans sa propre session.
        with sessions() as session:
            account, created = ledger.get_or_open_account(session, claims)
            return account["account_number"], created

    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(visit, range(8)))
    assert len({number for number, _ in results}) == 1
    assert sum(created for _, created in results) == 1
    assert open_account(payment_client, user)["balance_cents"] == WELCOME
    assert len(payment_client.get("/transfers", headers=user["headers"]).json()) == 1
    report = payment_client.get("/internal/integrity").json()
    assert report["ok"] and report["stats"] == {"accounts": 1, "transfers": 1}


def test_treasury_and_welcome_credits_load_through_the_models(payment_client, alice_bob):
    # La trésorerie n'a ni propriétaire ni e-mail ; les crédits de bienvenue n'ont ni émetteur ni clé d'idempotence,
    # et plusieurs couples (NULL, NULL) coexistent sous UNIQUE (initiated_by, idempotency_key).
    ledger = load_service("payment-api", "ledger")
    models = load_service("payment-api", "models")
    with payment_client.app.state.sessions() as session:
        treasury = session.get(models.Account, ledger.TREASURY_ID)
        welcome = session.scalars(select(models.Transfer).where(models.Transfer.from_account_id == ledger.TREASURY_ID)).all()
    assert treasury.is_system and treasury.owner_id is None and treasury.owner_email is None
    assert treasury.account_number == "RA-TREASURY" and treasury.balance_cents == -2 * WELCOME
    assert {(t.initiated_by, t.idempotency_key, t.status, t.label, t.amount_cents) for t in welcome} == {
        (None, None, "completed", "Crédit de bienvenue", WELCOME)}
    assert len(welcome) == 2 and all(t.created_at.utcoffset() is not None for t in welcome)


def test_other_integrity_errors_are_not_taken_for_a_replay(payment_client, alice_bob, make_user, monkeypatch):
    # Seules les violations attendues (clé d'idempotence, propriétaire du compte) sont des rejeux : une autre
    # contrainte remonte telle quelle (500), sans écriture partielle ni connexion perdue.
    alice, bob = alice_bob
    ledger = load_service("payment-api", "ledger")
    sessions = payment_client.app.state.sessions
    sender = account_row(sessions, alice)
    with sessions() as session, pytest.raises(IntegrityError) as raised:
        # Montant nul : normalement refusé par la validation de l'API, ici passé directement au registre.
        ledger.execute_transfer(session, sender, bob["account"]["account_number"], 0, "", alice["id"], "zero-amount-01")
    assert raised.value.orig.diag.constraint_name == "transfers_amount_cents_check"

    monkeypatch.setattr(ledger, "_new_account_number", lambda: alice["account"]["account_number"])
    with sessions() as session, pytest.raises(IntegrityError) as raised:
        ledger.get_or_open_account(session, {"sub": str(make_user("Dave Test")["id"]), "name": "Dave Test"})
    assert raised.value.orig.diag.constraint_name == "accounts_account_number_key"

    assert payment_client.app.state.engine.pool.checkedout() == 0
    report = payment_client.get("/internal/integrity").json()
    assert report["ok"] and report["stats"] == {"accounts": 2, "transfers": 2}


def test_integrity_report_keeps_its_shape_even_with_a_negative_balance(payment_client, alice_bob, database):
    # Le moteur de remédiation et le pont de restauration lisent ce rapport : forme stable, 409 sérialisable même
    # quand un solde client est négatif (contrainte supprimée, comme par un attaquant propriétaire de la base).
    alice, _ = alice_bob
    report = payment_client.get("/internal/integrity").json()
    assert set(report) == {"ok", "checks", "details", "stats", "checked_at"}
    assert set(report["checks"]) == {"ledger_sum_is_zero", "balances_match_ledger", "transfers_balanced", "no_negative_balance"}
    assert set(report["details"]) == {"ledger_sum_cents", "mismatched_accounts", "unbalanced_transfers", "negative_accounts"}

    tamper(database, "ALTER TABLE accounts DROP CONSTRAINT balance_non_negative")
    tamper(database, "UPDATE accounts SET balance_cents = -500 WHERE account_number = %s", alice["account"]["account_number"])
    res = payment_client.get("/internal/integrity")
    assert res.status_code == 409
    details = res.json()["details"]
    assert details["negative_accounts"] == [{"account_number": alice["account"]["account_number"], "balance_cents": -500}]
    assert details["mismatched_accounts"] == [
        {"account_number": alice["account"]["account_number"], "balance_cents": -500, "ledger_cents": WELCOME}]


def test_models_mirror_schema_sql(payment_client):
    # schema.sql reste la source du schéma (SQLAlchemy ne crée aucune table) : les modèles doivent en être le miroir
    # exact, comparé à la base créée par ce script (colonnes, types, nullabilité, défauts, clés, contraintes, index).
    models = load_service("payment-api", "models")
    inspector = inspect(payment_client.app.state.engine)
    dialect = postgresql.dialect()
    assert set(inspector.get_table_names()) == set(models.Base.metadata.tables)
    for table in models.Base.metadata.sorted_tables:
        reflected = {column["name"]: column for column in inspector.get_columns(table.name)}
        assert set(reflected) == set(table.columns.keys()), table.name
        for column in table.columns:
            db = reflected[column.name]
            where = f"{table.name}.{column.name}"
            assert column.type.compile(dialect) == db["type"].compile(dialect), where
            assert column.nullable == db["nullable"], where
            has_default = column.server_default is not None or column is table.autoincrement_column
            assert has_default == (db["default"] is not None), where
        assert inspector.get_pk_constraint(table.name)["constrained_columns"] == [c.name for c in table.primary_key]
        assert {(fk["constrained_columns"][0], fk["referred_table"], fk["referred_columns"][0])
                for fk in inspector.get_foreign_keys(table.name)} == {
            (fk.parent.name, fk.column.table.name, fk.column.name) for fk in table.foreign_keys}, table.name
        assert {(u["name"], tuple(u["column_names"])) for u in inspector.get_unique_constraints(table.name)} == {
            (c.name, tuple(col.name for col in c.columns)) for c in table.constraints if isinstance(c, UniqueConstraint)}
        assert {c["name"] for c in inspector.get_check_constraints(table.name)} == {
            c.name for c in table.constraints if isinstance(c, CheckConstraint)}, table.name
        assert {i["name"] for i in inspector.get_indexes(table.name) if "duplicates_constraint" not in i} == {
            i.name for i in table.indexes}, table.name


def test_requests_are_correlated_and_measured(payment_client, alice_bob):
    alice, _ = alice_bob
    res = payment_client.get("/accounts/me", headers={**alice["headers"], "X-Request-ID": "corr-123"})
    assert res.headers["x-request-id"] == "corr-123"
    metrics = payment_client.get("/metrics").text
    assert 'http_requests_total{method="GET",route="/accounts/me",service="payment-api",status="200"}' in metrics
    assert "payment_ledger_integrity_ok" in metrics
