"""Tests du paquet partagé resilience_common : configuration, journaux JSON, middleware, erreurs de base (psycopg et SQLAlchemy)."""

import json
import logging
import uuid

import psycopg
import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from psycopg import OperationalError
from psycopg.conninfo import conninfo_to_dict, make_conninfo
from sqlalchemy import exc as sa_exc

import service_loader  # noqa: F401 - ajoute services/common au chemin d'import
from resilience_common import database, observability, orm, settings


def test_env_requires_value_without_default(monkeypatch):
    monkeypatch.delenv("RA_MISSING", raising=False)
    assert settings.env("RA_MISSING", "fallback") == "fallback"
    with pytest.raises(RuntimeError, match="RA_MISSING"):
        settings.env("RA_MISSING")


def test_secret_prefers_mounted_file(monkeypatch, tmp_path):
    secret_file = tmp_path / "db_password"
    secret_file.write_text("depuis-le-fichier\n", encoding="utf-8")
    monkeypatch.setenv("RA_SECRET", "depuis-env")
    assert settings.secret("RA_SECRET") == "depuis-env"
    monkeypatch.setenv("RA_SECRET_FILE", str(secret_file))
    assert settings.secret("RA_SECRET") == "depuis-le-fichier"


def test_database_url_reads_password_from_secret(monkeypatch, tmp_path):
    generated = uuid.uuid4().hex  # valeur générée : aucun secret, même factice, dans le dépôt
    secret_file = tmp_path / "pw"
    secret_file.write_text(generated, encoding="utf-8")
    for key, value in {"DB_HOST": "db", "DB_PORT": "5433", "DB_NAME": "paydb", "DB_USER": "pay_svc",
                       "DB_PASSWORD_FILE": str(secret_file), "SERVICE_NAME": "payment-api"}.items():
        monkeypatch.setenv(key, value)
    params = conninfo_to_dict(settings.database_url())
    assert params == {"host": "db", "port": "5433", "dbname": "paydb", "user": "pay_svc", "password": generated,
                      "connect_timeout": "5", "application_name": "payment-api"}


def test_json_formatter_emits_one_line_with_extra_fields():
    record = logging.makeLogRecord({"name": "x", "levelname": "WARNING", "msg": "login_failed",
                                    "client_ip": "10.0.0.7", "event_type": "auth_failure"})
    line = observability.JsonFormatter("auth-service").format(record)
    payload = json.loads(line)
    assert "\n" not in line
    assert payload["service"] == "auth-service" and payload["level"] == "warning" and payload["msg"] == "login_failed"
    assert payload["client_ip"] == "10.0.0.7" and payload["event_type"] == "auth_failure"


@pytest.fixture
def demo_client():
    # Cette méthode permet de monter une mini application instrumentée comme les services réels.
    app = FastAPI()
    observability.instrument(app, "demo")
    database.register_database_errors(app)

    @app.get("/ip")
    def ip(request: Request) -> dict:
        # Cette méthode permet d'exposer l'IP client vue par l'application.
        return {"ip": observability.client_ip(request)}

    @app.get("/db-down")
    def db_down():
        # Cette méthode permet de simuler une base de données injoignable.
        raise OperationalError("connection refused")

    with TestClient(app) as client:
        yield client


def test_client_ip_uses_first_forwarded_address(demo_client):
    res = demo_client.get("/ip", headers={"X-Forwarded-For": "192.168.137.42, 172.31.250.2"})
    assert res.json() == {"ip": "192.168.137.42"}
    assert demo_client.get("/ip").json() == {"ip": "testclient"}


def test_request_id_is_propagated_or_generated(demo_client):
    assert demo_client.get("/ip", headers={"X-Request-ID": "abc-123"}).headers["x-request-id"] == "abc-123"
    assert len(demo_client.get("/ip").headers["x-request-id"]) == 32


def test_metrics_count_requests_per_route(demo_client):
    demo_client.get("/ip")
    metrics = demo_client.get("/metrics").text
    assert 'http_requests_total{method="GET",route="/ip",service="demo",status="200"}' in metrics
    assert 'route="/metrics"' not in metrics


def test_database_errors_become_503(demo_client):
    res = demo_client.get("/db-down")
    assert res.status_code == 503
    assert res.json()["code"] == "database_unavailable"


@pytest.fixture
def orm_client():
    # Cette méthode permet de monter une mini application qui lève les erreurs SQLAlchemy rencontrées en production.
    app = FastAPI()
    observability.instrument(app, "demo-orm")
    orm.register_orm_errors(app)
    failures = {
        "refused": lambda: sa_exc.OperationalError("SELECT 1", {}, psycopg.OperationalError("connection refused")),
        "closed": lambda: sa_exc.InterfaceError("SELECT 1", {}, psycopg.InterfaceError("the connection is closed")),
        "invalidated": lambda: sa_exc.DBAPIError("SELECT 1", {}, psycopg.DatabaseError("server closed the connection"),
                                                 connection_invalidated=True),
        "pool-full": lambda: sa_exc.TimeoutError("QueuePool limit of size 5 overflow 5 reached"),
        "constraint": lambda: sa_exc.IntegrityError("INSERT", {}, psycopg.errors.UniqueViolation("duplicate key")),
        "syntax": lambda: sa_exc.ProgrammingError("SELEC 1", {}, psycopg.errors.SyntaxError("syntax error")),
    }

    @app.get("/fail/{kind}")
    def fail(kind: str):
        # Cette méthode permet de lever l'erreur demandée, comme le ferait une requête du registre.
        raise failures[kind]()

    with TestClient(app, raise_server_exceptions=False) as client:
        yield client


@pytest.mark.parametrize("kind", ["refused", "closed", "invalidated", "pool-full"])
def test_sqlalchemy_availability_errors_become_503(orm_client, kind):
    res = orm_client.get(f"/fail/{kind}")
    assert res.status_code == 503
    assert res.json()["code"] == "database_unavailable"


@pytest.mark.parametrize("kind", ["constraint", "syntax"])
def test_other_sqlalchemy_errors_stay_500(orm_client, kind):
    # Une erreur SQL applicative est un bogue, pas une panne de dépendance : jamais maquillée en 503.
    assert orm_client.get(f"/fail/{kind}").status_code == 500


def test_engine_startup_retries_then_gives_up_without_leaking_the_password(monkeypatch, caplog):
    generated = uuid.uuid4().hex  # valeur générée : aucun secret, même factice, dans le dépôt
    dsn = make_conninfo(host="127.0.0.1", port="1", dbname="paydb", user="pay_svc", password=generated, connect_timeout=2)
    sleeps = []
    monkeypatch.setattr(orm.time, "sleep", sleeps.append)
    with caplog.at_level(logging.WARNING, logger="resilience_common.orm"), pytest.raises(RuntimeError):
        orm.create_database_engine(dsn, "SELECT 1", attempts=3)
    attempts = [record.attempt for record in caplog.records if record.getMessage() == "database_unavailable"]
    assert attempts == [1, 2, 3] and sleeps == [2, 2, 2]
    assert all(generated not in repr(vars(record)) for record in caplog.records)

    engine = orm.new_engine(dsn)
    assert generated not in repr(engine) and generated not in str(engine.url)
    assert orm.engine_alive(engine) is False
    engine.dispose()
