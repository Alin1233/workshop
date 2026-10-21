"""Moteur SQLAlchemy partagé (pilote psycopg 3), avec les mêmes garanties que le pool psycopg de database.py.

- un seul moteur par service, créé au démarrage : connexion testée avant usage (`pool_pre_ping`), pool borné
  (10 connexions, 5 s d'attente au plus), schéma idempotent appliqué avec 30 essais espacés de 2 s ;
- la chaîne de connexion libpq (mot de passe lu en secret) est remise telle quelle au pilote : elle n'entre ni dans
  l'URL SQLAlchemy ni dans les journaux, et les paramètres des requêtes sont masqués dans les messages d'erreur ;
- base injoignable, connexion coupée ou pool saturé → 503 `database_unavailable`, comme avec psycopg ; toute autre
  erreur SQL (contrainte, syntaxe) reste une 500 : c'est un bogue, pas une panne de dépendance.

Importé seulement par les services qui utilisent SQLAlchemy (payment-api) : les autres images n'en ont pas besoin.
"""

import logging
import time

import psycopg
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from sqlalchemy import Engine, create_engine, text
from sqlalchemy.exc import DBAPIError, InterfaceError, OperationalError, SQLAlchemyError
from sqlalchemy.exc import TimeoutError as PoolTimeoutError

from .database import database_unavailable_response

logger = logging.getLogger(__name__)

# Même borne que le pool psycopg : 10 connexions au plus, 5 s d'attente avant de répondre 503.
POOL_SIZE = 5
MAX_OVERFLOW = 5
POOL_TIMEOUT_SECONDS = 5


def new_engine(dsn: str) -> Engine:
    # Cette méthode permet de créer le moteur : chaque connexion est testée avant usage pour écarter celles qu'un
    # redémarrage de PostgreSQL a coupées. La connexion est ouverte par psycopg avec la chaîne libpq reçue ;
    # SQLAlchemy ne voit jamais le mot de passe.
    return create_engine(
        "postgresql+psycopg://", creator=lambda: psycopg.connect(dsn),
        pool_pre_ping=True, pool_size=POOL_SIZE, max_overflow=MAX_OVERFLOW, pool_timeout=POOL_TIMEOUT_SECONDS,
        hide_parameters=True,
    )


def describe_error(exc: BaseException) -> str:
    # Cette méthode permet de résumer une erreur de base pour les journaux : le message du pilote seul, sans la
    # requête SQL que SQLAlchemy y ajoute.
    if isinstance(exc, DBAPIError) and exc.orig is not None:
        return str(exc.orig)
    return str(exc)


def create_database_engine(dsn: str, schema_sql: str, attempts: int = 30) -> Engine:
    # Cette méthode permet de créer le moteur et d'appliquer le schéma idempotent au démarrage, en réessayant tant
    # que la base n'est pas joignable (redémarrage, reprise après incident) ; SQLAlchemy ne crée jamais les tables.
    engine = new_engine(dsn)
    for attempt in range(1, attempts + 1):
        try:
            with engine.begin() as conn:
                # Script de plusieurs instructions : envoyé sans paramètres, tel quel, au pilote.
                conn.exec_driver_sql(schema_sql, execution_options={"no_parameters": True})
            logger.info("database_ready", extra={"attempt": attempt})
            return engine
        except Exception as exc:  # noqa: BLE001 - toute erreur de connexion déclenche un nouvel essai
            logger.warning("database_unavailable", extra={"attempt": attempt, "error": describe_error(exc)})
            engine.dispose()
            time.sleep(2)
    raise RuntimeError("Base de données injoignable après plusieurs tentatives")


def engine_alive(engine: Engine) -> bool:
    # Cette méthode permet de vérifier que la base répond réellement (utilisée par /health).
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return True
    except Exception:  # noqa: BLE001
        return False


def is_database_unavailable(exc: SQLAlchemyError) -> bool:
    # Cette méthode permet de distinguer une panne de la base (connexion impossible ou coupée, pool saturé)
    # d'une erreur SQL applicative : seule la première devient une 503.
    if isinstance(exc, PoolTimeoutError):
        return True
    return isinstance(exc, DBAPIError) and (isinstance(exc, (OperationalError, InterfaceError)) or exc.connection_invalidated)


def register_orm_errors(app: FastAPI) -> None:
    # Cette méthode permet de convertir les erreurs SQLAlchemy de disponibilité en réponse 503 explicite,
    # comme register_database_errors le fait pour psycopg.

    async def handler(request: Request, exc: SQLAlchemyError) -> JSONResponse:
        # Cette méthode permet de répondre 503 à une panne de la base et de laisser toute autre erreur en 500.
        if not is_database_unavailable(exc):
            raise exc
        return database_unavailable_response(request, describe_error(exc))

    app.add_exception_handler(DBAPIError, handler)
    app.add_exception_handler(PoolTimeoutError, handler)
