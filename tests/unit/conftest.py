"""Fixtures partagées des tests unitaires : clés RSA, PostgreSQL jetable, clients HTTP des services.

Les tests qui touchent la base utilisent un vrai PostgreSQL 17 et les schémas des services tels quels :
- `RA_TEST_DATABASE_URL` (DSN d'un rôle autorisé à créer des bases), par exemple en CI ;
- sinon un conteneur `postgres:17-alpine` éphémère est lancé via Docker ;
- sinon ces tests sont ignorés (skip), les autres s'exécutent normalement.
"""

import os
import shutil
import subprocess
import sys
import time
import uuid
from pathlib import Path

import psycopg
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from psycopg.conninfo import conninfo_to_dict, make_conninfo

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
from service_loader import load_service  # noqa: E402

PG_IMAGE = "postgres:17-alpine"
# Secret TOTP (base32) imposé au compte admin des services démarrés en test.
ADMIN_TOTP_SECRET = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"


def _pem_pair() -> tuple[str, str]:
    # Cette méthode permet de générer une paire RSA de test au format PEM (privée PKCS8, publique SPKI).
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    public = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    return private.decode(), public.decode()


@pytest.fixture(scope="session")
def rsa_keys() -> tuple[str, str]:
    # Cette méthode permet de partager une paire de clés JWT entre tous les tests de la session.
    return _pem_pair()


@pytest.fixture(scope="session")
def other_rsa_keys() -> tuple[str, str]:
    # Cette méthode permet de disposer d'une seconde paire, pour simuler un jeton signé par un tiers.
    return _pem_pair()


def _wait_for_postgres(dsn: str, timeout: float = 60) -> None:
    # Cette méthode permet d'attendre que PostgreSQL accepte les connexions TCP après le démarrage du conteneur.
    deadline = time.monotonic() + timeout
    while True:
        try:
            psycopg.connect(dsn, connect_timeout=2).close()
            return
        except psycopg.OperationalError:
            if time.monotonic() > deadline:
                raise
            time.sleep(0.5)


@pytest.fixture(scope="session")
def pg_admin_dsn():
    # Cette méthode permet de fournir un serveur PostgreSQL d'essai : celui de RA_TEST_DATABASE_URL,
    # ou un conteneur Docker éphémère supprimé en fin de session ; ignore les tests si aucun n'est disponible.
    url = os.getenv("RA_TEST_DATABASE_URL")
    if url:
        yield url
        return
    if not shutil.which("docker"):
        pytest.skip("PostgreSQL indisponible : définir RA_TEST_DATABASE_URL ou installer Docker")
    name = f"ra-unit-pg-{uuid.uuid4().hex[:8]}"
    started = subprocess.run(
        ["docker", "run", "-d", "--rm", "--name", name, "-e", "POSTGRES_PASSWORD=unit-test", "-p", "127.0.0.1::5432", PG_IMAGE],
        capture_output=True, text=True,
    )
    if started.returncode != 0:
        pytest.skip(f"Conteneur PostgreSQL impossible à démarrer : {started.stderr.strip()}")
    try:
        port = subprocess.run(["docker", "port", name, "5432/tcp"], capture_output=True, text=True, check=True).stdout
        dsn = make_conninfo(host="127.0.0.1", port=port.strip().splitlines()[0].rsplit(":", 1)[1],
                            user="postgres", password="unit-test", dbname="postgres")
        _wait_for_postgres(dsn)
        yield dsn
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True)


@pytest.fixture
def database(pg_admin_dsn):
    # Cette méthode permet de donner à chaque test une base vide, créée puis supprimée, pour isoler les données.
    name = f"t_{uuid.uuid4().hex[:12]}"
    with psycopg.connect(pg_admin_dsn, autocommit=True) as conn:
        conn.execute(f'CREATE DATABASE "{name}"')
    params = conninfo_to_dict(pg_admin_dsn)
    yield {"host": params.get("host", "127.0.0.1"), "port": str(params.get("port", 5432)), "dbname": name,
           "user": params["user"], "password": params.get("password", "")}
    with psycopg.connect(pg_admin_dsn, autocommit=True) as conn:
        conn.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')


@pytest.fixture
def service_env(monkeypatch, database, rsa_keys):
    # Cette méthode permet de configurer les variables lues par les services au démarrage (base, clés, admin).
    private_pem, public_pem = rsa_keys
    for key, value in {
        "DB_HOST": database["host"], "DB_PORT": database["port"], "DB_NAME": database["dbname"],
        "DB_USER": database["user"], "DB_PASSWORD": database["password"],
        "JWT_PRIVATE_KEY": private_pem, "JWT_PUBLIC_KEY": public_pem,
        "ADMIN_PASSWORD": "admin-password-test", "ADMIN_TOTP_SECRET": ADMIN_TOTP_SECRET, "INTEGRITY_INTERVAL_SECONDS": "3600",
    }.items():
        monkeypatch.setenv(key, value)
    for key in ("DB_PASSWORD_FILE", "JWT_PRIVATE_KEY_FILE", "JWT_PUBLIC_KEY_FILE", "ADMIN_PASSWORD_FILE", "ADMIN_TOTP_SECRET_FILE"):
        monkeypatch.delenv(key, raising=False)
    return database


@pytest.fixture
def auth_client(service_env):
    # Cette méthode permet d'obtenir un client HTTP du service d'auth démarré (lifespan exécuté) sur une base neuve.
    with TestClient(load_service("auth-service").app) as client:
        yield client


@pytest.fixture
def payment_client(service_env):
    # Cette méthode permet d'obtenir un client HTTP de l'API de paiement démarrée sur une base neuve.
    with TestClient(load_service("payment-api").app) as client:
        yield client


@pytest.fixture
def issuer(rsa_keys):
    # Cette méthode permet d'émettre des jetons avec le vrai code du service d'auth (contrat JWT entre services).
    security = load_service("auth-service", "security")
    return security.TokenIssuer(rsa_keys[0], 900)


@pytest.fixture
def make_user(issuer):
    # Cette méthode permet de fabriquer un utilisateur fictif et son en-tête Authorization pour l'API de paiement.

    def factory(name: str = "Alice Test", role: str = "client") -> dict:
        # Cette méthode permet de créer l'identité et le jeton d'un utilisateur à la volée.
        user = {"id": uuid.uuid4(), "email": f"{uuid.uuid4().hex[:8]}@test.local", "full_name": name, "role": role}
        user["headers"] = {"Authorization": f"Bearer {issuer.issue(user)}"}
        return user

    return factory
