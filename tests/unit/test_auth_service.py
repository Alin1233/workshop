"""Tests du service d'authentification : hachage, jetons RS256, inscription, connexion, compte admin."""

import jwt
import pytest

from service_loader import load_service

security = load_service("auth-service", "security")
PASSWORD = "motdepasse-solide"


def register(client, email: str = "client@test.local", password: str = PASSWORD, name: str = "Client Test"):
    # Cette méthode permet d'inscrire un utilisateur et de renvoyer la réponse HTTP brute.
    return client.post("/register", json={"email": email, "full_name": name, "password": password})


def login(client, email: str = "client@test.local", password: str = PASSWORD):
    # Cette méthode permet de tenter une connexion et de renvoyer la réponse HTTP brute.
    return client.post("/login", json={"email": email, "password": password})


def test_password_hash_is_argon2id_and_verifiable():
    hashed = security.hash_password(PASSWORD)
    assert hashed.startswith("$argon2id$") and PASSWORD not in hashed
    assert security.verify_password(hashed, PASSWORD)
    assert not security.verify_password(hashed, "mauvais-mot-de-passe")
    assert not security.verify_password(None, PASSWORD)  # utilisateur inconnu : refus, sans exception


def test_issued_token_carries_identity_and_expires(rsa_keys):
    issuer = security.TokenIssuer(rsa_keys[0], 900)
    user = {"id": "6f1f7a3e-0000-4000-8000-000000000001", "email": "a@test.local", "full_name": "A", "role": "client"}
    token = issuer.issue(user)
    claims = jwt.decode(token, rsa_keys[1], algorithms=["RS256"], audience="payment-api", issuer="resilience-alpha-auth")
    assert (claims["sub"], claims["email"], claims["name"], claims["role"]) == (user["id"], "a@test.local", "A", "client")
    assert claims["exp"] - claims["iat"] == 900
    assert jwt.get_unverified_header(token)["kid"] == "ra-auth-1"

    expired = security.TokenIssuer(rsa_keys[0], -1).issue(user)
    with pytest.raises(jwt.ExpiredSignatureError):
        issuer.decode(expired)


def test_token_from_another_key_is_rejected(rsa_keys, other_rsa_keys):
    user = {"id": "u", "email": "a@test.local", "full_name": "A", "role": "admin"}
    forged = security.TokenIssuer(other_rsa_keys[0], 900).issue(user)
    with pytest.raises(jwt.InvalidSignatureError):
        security.TokenIssuer(rsa_keys[0], 900).decode(forged)


def test_jwks_exposes_the_verification_key(rsa_keys):
    issuer = security.TokenIssuer(rsa_keys[0], 900)
    token = issuer.issue({"id": "u", "email": "a@test.local", "full_name": "A", "role": "client"})
    [key] = issuer.jwks()["keys"]
    assert key["kid"] == "ra-auth-1" and "d" not in key  # aucune composante privée publiée
    public_key = jwt.PyJWK(key).key
    assert jwt.decode(token, public_key, algorithms=["RS256"], audience="payment-api")["sub"] == "u"


def test_admin_account_is_seeded_at_startup(auth_client):
    res = login(auth_client, "admin@resilience.local", "admin-password-test")
    assert res.status_code == 200, res.text
    assert res.json()["user"]["role"] == "admin"


def test_register_then_login_returns_usable_token(auth_client, rsa_keys):
    created = register(auth_client)
    assert created.status_code == 201, created.text
    assert created.json()["role"] == "client" and "password_hash" not in created.json()

    res = login(auth_client, "CLIENT@test.local")  # email insensible à la casse
    assert res.status_code == 200
    body = res.json()
    assert body["token_type"] == "bearer" and body["expires_in"] == 900
    claims = jwt.decode(body["access_token"], rsa_keys[1], algorithms=["RS256"], audience="payment-api")
    assert claims["sub"] == created.json()["id"]

    me = auth_client.get("/me", headers={"Authorization": f"Bearer {body['access_token']}"})
    assert me.json()["email"] == "client@test.local"


def test_duplicate_email_is_refused_case_insensitively(auth_client):
    assert register(auth_client).status_code == 201
    res = register(auth_client, "Client@Test.Local")
    assert res.status_code == 409


@pytest.mark.parametrize(
    ("email", "password", "name"),
    [("pas-un-email", PASSWORD, "Client"), ("a@test.local", "court", "Client"), ("a@test.local", PASSWORD, "X")],
    ids=["bad-email", "short-password", "short-name"],
)
def test_register_validates_input(auth_client, email, password, name):
    assert register(auth_client, email, password, name).status_code == 422


def test_failed_logins_are_refused_without_revealing_the_account(auth_client):
    register(auth_client)
    wrong_password = login(auth_client, password="mauvais-mot-de-passe")
    unknown_user = login(auth_client, "inconnu@test.local")
    assert wrong_password.status_code == unknown_user.status_code == 401
    assert wrong_password.json() == unknown_user.json()


def test_me_requires_a_valid_token(auth_client, other_rsa_keys):
    assert auth_client.get("/me").status_code == 401
    forged = security.TokenIssuer(other_rsa_keys[0], 900).issue(
        {"id": "u", "email": "a@test.local", "full_name": "A", "role": "admin"})
    assert auth_client.get("/me", headers={"Authorization": f"Bearer {forged}"}).status_code == 401


def test_login_metrics_count_failures(auth_client):
    def failures() -> float:
        # Cette méthode permet de lire le compteur d'échecs de connexion exposé à Prometheus.
        line = next(line for line in auth_client.get("/metrics").text.splitlines()
                    if line.startswith('auth_login_attempts_total{result="failure"}'))
        return float(line.split()[-1])

    login(auth_client, "inconnu@test.local")
    before = failures()
    login(auth_client, "inconnu@test.local")
    assert failures() == before + 1


def test_health_reflects_database_state(auth_client):
    assert auth_client.get("/health").status_code == 200
    auth_client.app.state.pool.close()
    assert auth_client.get("/health").status_code == 503
    res = login(auth_client)
    assert res.status_code == 503 and res.json()["code"] == "database_unavailable"
