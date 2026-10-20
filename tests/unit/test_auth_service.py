"""Tests du service d'authentification : hachage, jetons RS256, inscription, connexion, double authentification, compte admin."""

import time

import jwt
import pyotp
import pytest

from conftest import ADMIN_TOTP_SECRET
from service_loader import load_service

security = load_service("auth-service", "security")
mfa = load_service("auth-service", "mfa")
PASSWORD = "motdepasse-solide"


def register(client, email: str = "client@test.local", password: str = PASSWORD, name: str = "Client Test"):
    # Cette méthode permet d'inscrire un utilisateur et de renvoyer la réponse HTTP brute.
    return client.post("/register", json={"email": email, "full_name": name, "password": password})


def login(client, email: str = "client@test.local", password: str = PASSWORD):
    # Cette méthode permet de tenter une connexion et de renvoyer la réponse HTTP brute.
    return client.post("/login", json={"email": email, "password": password})


def totp_code(secret: str, offset_steps: int = 0) -> str:
    # Cette méthode permet de calculer le code TOTP qu'afficherait l'appli d'authentification (décalé de n pas de 30 s).
    return pyotp.TOTP(secret).at(time.time() + 30 * offset_steps)


def bearer(token: str) -> dict:
    # Cette méthode permet de construire l'en-tête Authorization d'un jeton d'accès.
    return {"Authorization": f"Bearer {token}"}


def enable_mfa(client, email: str = "client@test.local") -> tuple[str, list[str], dict]:
    # Cette méthode permet d'inscrire un client, d'activer sa double authentification et de renvoyer
    # son secret TOTP, ses codes de secours et l'en-tête de sa session courante.
    register(client, email)
    headers = bearer(login(client, email).json()["access_token"])
    setup = client.post("/mfa/setup", headers=headers).json()
    # Activation avec le code du pas précédent (toléré) : le pas courant reste libre pour la connexion qui suit.
    activated = client.post("/mfa/activate", headers=headers, json={"code": totp_code(setup["secret"], -1)})
    assert activated.status_code == 200, activated.text
    return setup["secret"], activated.json()["recovery_codes"], headers


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


def test_admin_account_is_seeded_with_mandatory_mfa(auth_client):
    res = login(auth_client, "admin@resilience.local", "admin-password-test")
    assert res.status_code == 200, res.text
    assert res.json()["mfa_required"] is True and "access_token" not in res.json()

    done = auth_client.post("/login/mfa", json={"mfa_token": res.json()["mfa_token"], "code": totp_code(ADMIN_TOTP_SECRET)})
    assert done.status_code == 200, done.text
    assert done.json()["user"]["role"] == "admin"
    headers = bearer(done.json()["access_token"])
    assert auth_client.get("/mfa", headers=headers).json()["required"] is True
    refused = auth_client.post("/mfa/disable", headers=headers, json={"password": "admin-password-test", "code": "000000"})
    assert refused.status_code == 403 and refused.json()["code"] == "mfa_required_for_role"


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


def test_totp_steps_window_and_recovery_code_format():
    secret = mfa.new_totp_secret()
    now = time.time()
    current = int(now // 30)
    assert mfa.matching_step(secret, pyotp.TOTP(secret).at(now), now) == current
    assert mfa.matching_step(secret, pyotp.TOTP(secret).at(now - 30), now) == current - 1  # dérive tolérée
    assert mfa.matching_step(secret, pyotp.TOTP(secret).at(now - 90), now) is None
    assert mfa.matching_step(secret, "abcdef", now) is None
    codes = mfa.new_recovery_codes()
    assert len(set(codes)) == 10 and all(len(code) == 11 and code[5] == "-" for code in codes)
    assert mfa.hash_recovery_code(codes[0].upper().replace("-", " ")) == mfa.hash_recovery_code(codes[0])


def test_setup_returns_qr_code_and_does_not_protect_until_activated(auth_client):
    register(auth_client)
    headers = bearer(login(auth_client).json()["access_token"])
    assert auth_client.get("/mfa", headers=headers).json() == {"enabled": False, "required": False, "recovery_codes_remaining": 0,
                                                                  "face_enrolled": False}

    setup = auth_client.post("/mfa/setup", headers=headers).json()
    assert setup["otpauth_uri"].startswith("otpauth://totp/Resilience-Alpha:client%40test.local?secret=")
    assert setup["qr_code"].startswith("data:image/svg+xml")
    assert "access_token" in login(auth_client).json()  # secret en attente : la connexion reste à un facteur

    wrong = auth_client.post("/mfa/activate", headers=headers, json={"code": "000000"})
    assert wrong.status_code == 400 and wrong.json()["code"] == "mfa_invalid_code"


def test_activate_requires_setup_first(auth_client):
    register(auth_client)
    headers = bearer(login(auth_client).json()["access_token"])
    res = auth_client.post("/mfa/activate", headers=headers, json={"code": "123456"})
    assert res.status_code == 409 and res.json()["code"] == "mfa_setup_required"
    assert auth_client.post("/mfa/setup").status_code == 401


def test_login_with_mfa_needs_a_valid_code(auth_client, rsa_keys):
    secret, codes, headers = enable_mfa(auth_client)
    assert len(codes) == 10
    assert auth_client.get("/mfa", headers=headers).json() == {"enabled": True, "required": False, "recovery_codes_remaining": 10,
                                                                  "face_enrolled": False}
    assert auth_client.post("/mfa/setup", headers=headers).status_code == 409

    challenge = login(auth_client).json()
    assert challenge["mfa_required"] is True and challenge["expires_in"] == 300 and "access_token" not in challenge
    wrong = auth_client.post("/login/mfa", json={"mfa_token": challenge["mfa_token"], "code": "000000"})
    assert wrong.status_code == 401 and wrong.json()["code"] == "mfa_invalid_code"

    res = auth_client.post("/login/mfa", json={"mfa_token": challenge["mfa_token"], "code": totp_code(secret)})
    assert res.status_code == 200, res.text
    claims = jwt.decode(res.json()["access_token"], rsa_keys[1], algorithms=["RS256"], audience="payment-api")
    assert claims["amr"] == ["pwd", "otp"]
    # L'étape est consommée : le même jeton ne rouvre pas de session.
    again = auth_client.post("/login/mfa", json={"mfa_token": challenge["mfa_token"], "code": totp_code(secret)})
    assert again.status_code == 401 and again.json()["code"] == "mfa_challenge_expired"


def test_totp_code_cannot_be_replayed(auth_client):
    secret, _, _ = enable_mfa(auth_client)
    code = totp_code(secret)
    first = auth_client.post("/login/mfa", json={"mfa_token": login(auth_client).json()["mfa_token"], "code": code})
    assert first.status_code == 200
    replay = auth_client.post("/login/mfa", json={"mfa_token": login(auth_client).json()["mfa_token"], "code": code})
    assert replay.status_code == 401 and replay.json()["code"] == "mfa_invalid_code"


def test_challenge_is_burnt_after_five_wrong_codes(auth_client):
    secret, _, _ = enable_mfa(auth_client)
    token = login(auth_client).json()["mfa_token"]
    answers = [auth_client.post("/login/mfa", json={"mfa_token": token, "code": "000000"}).json()["code"] for _ in range(5)]
    assert answers == ["mfa_invalid_code"] * 4 + ["mfa_challenge_expired"]
    late = auth_client.post("/login/mfa", json={"mfa_token": token, "code": totp_code(secret)})
    assert late.status_code == 401 and late.json()["code"] == "mfa_challenge_expired"


def test_recovery_codes_are_single_use(auth_client):
    _, codes, headers = enable_mfa(auth_client)
    token = login(auth_client).json()["mfa_token"]
    assert auth_client.post("/login/mfa", json={"mfa_token": token, "code": codes[0].upper()}).status_code == 200
    assert auth_client.get("/mfa", headers=headers).json()["recovery_codes_remaining"] == 9
    token = login(auth_client).json()["mfa_token"]
    assert auth_client.post("/login/mfa", json={"mfa_token": token, "code": codes[0]}).status_code == 401


def test_mfa_failures_are_counted_as_login_failures(auth_client):
    def failures() -> float:
        # Cette méthode permet de lire le compteur d'échecs de connexion exposé à Prometheus.
        line = next(line for line in auth_client.get("/metrics").text.splitlines()
                    if line.startswith('auth_login_attempts_total{result="failure"}'))
        return float(line.split()[-1])

    enable_mfa(auth_client)
    token = login(auth_client).json()["mfa_token"]
    before = failures()
    auth_client.post("/login/mfa", json={"mfa_token": token, "code": "000000"})
    assert failures() == before + 1


def test_disable_requires_password_and_code(auth_client):
    secret, codes, headers = enable_mfa(auth_client)
    bad_password = auth_client.post("/mfa/disable", headers=headers,
                                    json={"password": "mauvais-mot-de-passe", "code": totp_code(secret)})
    assert bad_password.status_code == 400 and bad_password.json()["code"] == "mfa_invalid_credentials"
    bad_code = auth_client.post("/mfa/disable", headers=headers, json={"password": PASSWORD, "code": "000000"})
    assert bad_code.status_code == 400

    assert auth_client.post("/mfa/disable", headers=headers, json={"password": PASSWORD, "code": codes[1]}).status_code == 204
    assert auth_client.get("/mfa", headers=headers).json() == {"enabled": False, "required": False, "recovery_codes_remaining": 0,
                                                                  "face_enrolled": False}
    assert "access_token" in login(auth_client).json()
    again = auth_client.post("/mfa/disable", headers=headers, json={"password": PASSWORD, "code": codes[2]})
    assert again.status_code == 409 and again.json()["code"] == "mfa_not_enabled"
