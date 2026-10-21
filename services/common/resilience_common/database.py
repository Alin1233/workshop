"""Pool de connexions PostgreSQL partagé par les services."""

import logging
import time

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from psycopg import OperationalError
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool, PoolTimeout

logger = logging.getLogger(__name__)

def _new_pool(dsn: str) -> ConnectionPool:
    # Cette méthode permet de créer un pool dont chaque connexion est testée avant usage,
    # pour écarter les connexions mortes après un redémarrage de PostgreSQL.
    return ConnectionPool(
        dsn, min_size=1, max_size=10, open=False, timeout=5,
        kwargs={"row_factory": dict_row, "autocommit": True},
        check=ConnectionPool.check_connection,
    )

def create_pool(dsn: str, schema_sql: str, attempts: int = 30) -> ConnectionPool:
    # Cette méthode permet d'ouvrir le pool et d'appliquer le schéma idempotent au démarrage,
    # en réessayant tant que la base n'est pas joignable (redémarrage, reprise après incident).
    pool = _new_pool(dsn)
    for attempt in range(1, attempts + 1):
        try:
            pool.open(wait=True, timeout=5)
            with pool.connection() as conn:
                conn.execute(schema_sql)
            logger.info("database_ready", extra={"attempt": attempt})
            return pool
        except Exception as exc:  # noqa: BLE001 - toute erreur de connexion déclenche un nouvel essai
            logger.warning("database_unavailable", extra={"attempt": attempt, "error": str(exc)})
            pool.close()
            pool = _new_pool(dsn)
            time.sleep(2)
    raise RuntimeError("Base de données injoignable après plusieurs tentatives")

def database_alive(pool: ConnectionPool) -> bool:
    # Cette méthode permet de vérifier que la base répond réellement (utilisée par /health).
    try:
        with pool.connection(timeout=2) as conn:
            conn.execute("SELECT 1")
        return True
    except Exception:  # noqa: BLE001
        return False

def database_unavailable_response(request: Request, error: str) -> JSONResponse:
    # Cette méthode permet de journaliser l'indisponibilité de la base et de répondre 503 au client
    # (réponse commune au pool psycopg et au moteur SQLAlchemy, voir orm.py).
    logger.error("database_unavailable", extra={"path": request.url.path, "error": error, "event_type": "dependency_failure"})
    return JSONResponse(
        {"code": "database_unavailable", "detail": "Service momentanément indisponible. Réessayez dans quelques instants."},
        status_code=503,
    )


def register_database_errors(app: FastAPI) -> None:
    # Cette méthode permet de convertir une base injoignable en réponse 503 explicite (au lieu d'une 500 opaque),
    # ce qui distingue clairement, côté supervision, une panne de dépendance d'un bug applicatif.

    async def handler(request: Request, exc: Exception) -> JSONResponse:
        # Cette méthode permet de répondre 503 à une erreur de connexion psycopg ou à un pool saturé.
        return database_unavailable_response(request, str(exc))

    app.add_exception_handler(OperationalError, handler)
    app.add_exception_handler(PoolTimeout, handler)
