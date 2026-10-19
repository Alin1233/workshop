"""Tests de l'API de paiement : ouverture de compte, virements, idempotence, droits, intégrité, pannes de base."""

import time
import uuid
from concurrent.futures import ThreadPoolExecutor

import jwt
import pytest

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


def account_row(pool, user) -> dict:
    # Cette méthode permet de relire la ligne SQL du compte d'un utilisateur, attendue par les fonctions du registre.
    ledger = load_service("payment-api", "ledger")
    with pool.connection() as conn:
        return ledger.get_or_open_account(conn, {"sub": str(user["id"])})[0]


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


def test_integrity_check_detects_tampered_balance(payment_client, alice_bob):
    alice, bob = alice_bob
    transfer(payment_client, alice, bob["account"]["account_number"], 700)
    assert payment_client.get("/internal/integrity").status_code == 200

    # Altération directe en base, comme le ferait une attaque ou une restauration ratée.
    with payment_client.app.state.pool.connection() as conn:
        conn.execute("UPDATE accounts SET balance_cents = balance_cents + 5000 WHERE account_number = %s",
                     (bob["account"]["account_number"],))
    res = payment_client.get("/internal/integrity")
    report = res.json()
    assert res.status_code == 409 and report["ok"] is False
    assert report["checks"]["balances_match_ledger"] is False and report["checks"]["ledger_sum_is_zero"] is True
    [mismatch] = report["details"]["mismatched_accounts"]
    assert mismatch["account_number"] == bob["account"]["account_number"]
    assert mismatch["ledger_cents"] == WELCOME + 700 and mismatch["balance_cents"] == WELCOME + 5_700


def test_integrity_check_detects_unbalanced_ledger(payment_client, alice_bob):
    alice, bob = alice_bob
    transfer_id = transfer(payment_client, alice, bob["account"]["account_number"], 700).json()["id"]
    with payment_client.app.state.pool.connection() as conn:
        conn.execute("DELETE FROM ledger_entries WHERE transfer_id = %s AND amount_cents > 0", (transfer_id,))
    report = payment_client.get("/internal/integrity").json()
    assert report["checks"]["ledger_sum_is_zero"] is False
    assert transfer_id in report["details"]["unbalanced_transfers"]


def test_concurrent_crossed_transfers_keep_ledger_consistent(payment_client, alice_bob):
    # 40 virements croisés en parallèle : aucun interblocage, masse monétaire conservée, registre cohérent.
    alice, bob = alice_bob
    ledger = load_service("payment-api", "ledger")
    pool = payment_client.app.state.pool
    rows = {"alice": account_row(pool, alice), "bob": account_row(pool, bob)}

    def run(i: int) -> None:
        # Cette méthode permet d'exécuter un virement dans un fil, alternativement d'Alice vers Bob et inversement.
        sender, recipient = (alice, bob) if i % 2 else (bob, alice)
        sender_row = rows["alice" if sender is alice else "bob"]
        with pool.connection() as conn:
            ledger.execute_transfer(conn, sender_row, recipient["account"]["account_number"], 100 + i, "",
                                    sender["id"], f"concurrent-{i:04d}")

    with ThreadPoolExecutor(max_workers=8) as executor:
        list(executor.map(run, range(40)))

    with pool.connection() as conn:
        report = ledger.check_integrity(conn)
    assert report["ok"], report
    assert report["stats"]["transfers"] == 42  # 40 virements + 2 crédits de bienvenue
    total = open_account(payment_client, alice)["balance_cents"] + open_account(payment_client, bob)["balance_cents"]
    assert total == 2 * WELCOME


def test_concurrent_replays_of_same_key_debit_once(payment_client, alice_bob):
    alice, bob = alice_bob
    ledger = load_service("payment-api", "ledger")
    pool = payment_client.app.state.pool
    sender_row = account_row(pool, alice)

    def run(_: int) -> str:
        # Cette méthode permet de rejouer le même virement depuis plusieurs fils, comme des doubles clics simultanés.
        with pool.connection() as conn:
            result, _replayed = ledger.execute_transfer(conn, sender_row, bob["account"]["account_number"], 1_234, "",
                                                        alice["id"], "double-click-0001")
            return str(result["id"])

    with ThreadPoolExecutor(max_workers=6) as executor:
        ids = set(executor.map(run, range(6)))
    assert len(ids) == 1
    assert open_account(payment_client, alice)["balance_cents"] == WELCOME - 1_234


def test_database_outage_returns_503_not_500(payment_client, alice_bob):
    alice, _ = alice_bob
    assert payment_client.get("/health").json() == {"service": "payment-api", "status": "ok", "checks": {"database": True}}

    payment_client.app.state.pool.close()  # simule une base injoignable
    health = payment_client.get("/health")
    assert health.status_code == 503 and health.json()["status"] == "degraded"
    res = payment_client.get("/accounts/me", headers=alice["headers"])
    assert res.status_code == 503 and res.json()["code"] == "database_unavailable"


def test_requests_are_correlated_and_measured(payment_client, alice_bob):
    alice, _ = alice_bob
    res = payment_client.get("/accounts/me", headers={**alice["headers"], "X-Request-ID": "corr-123"})
    assert res.headers["x-request-id"] == "corr-123"
    metrics = payment_client.get("/metrics").text
    assert 'http_requests_total{method="GET",route="/accounts/me",service="payment-api",status="200"}' in metrics
    assert "payment_ledger_integrity_ok" in metrics
