"""API métier de paiement : comptes, virements, contrôle d'intégrité du registre."""

import asyncio
import uuid
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path

import jwt
from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, status
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from prometheus_client import Counter, Gauge, Histogram
from pydantic import BaseModel, Field

from resilience_common.database import create_pool, database_alive, register_database_errors
from resilience_common.observability import client_ip, instrument, setup_logging
from resilience_common.settings import database_url, env, secret

from . import ledger

SERVICE = "payment-api"
logger = setup_logging(SERVICE, env("LOG_LEVEL", "INFO"))

TRANSFERS = Counter("payment_transfers_total", "Virements traités", ["result"])
TRANSFER_AMOUNT = Histogram(
    "payment_transfer_amount_euros", "Montant des virements exécutés",
    buckets=(1, 5, 10, 50, 100, 250, 500, 1000, 5000),
)
INTEGRITY_OK = Gauge("payment_ledger_integrity_ok", "1 si le registre est cohérent, 0 sinon")
INTEGRITY_CHECK = Gauge("payment_ledger_integrity_last_check_timestamp", "Horodatage du dernier contrôle d'intégrité")
LEDGER_ACCOUNTS = Gauge("payment_accounts", "Nombre de comptes clients")
LEDGER_TRANSFERS = Gauge("payment_transfers_stored", "Nombre de virements enregistrés")


class AccountOut(BaseModel):
    account_number: str
    owner_name: str
    currency: str
    balance_cents: int
    created_at: datetime


class TransferIn(BaseModel):
    to_account_number: str = Field(pattern=r"^RA\d{10}$")
    amount_cents: int = Field(gt=0, le=1_000_000, description="Montant en centimes (max 10 000,00 €)")
    label: str = Field(default="", max_length=60)


class TransferOut(BaseModel):
    id: uuid.UUID
    amount_cents: int
    label: str
    status: str
    direction: str
    counterparty_account_number: str
    counterparty_name: str
    created_at: datetime


async def integrity_watch(app: FastAPI, interval: int) -> None:
    # Cette méthode permet de recalculer périodiquement l'intégrité du registre pour l'exposer à Prometheus
    # lorsque le service tourne, sans faire peser le calcul sur chaque scrape.
    while True:
        try:
            report = await run_in_threadpool(_integrity_report, app)
            INTEGRITY_OK.set(1 if report["ok"] else 0)
            LEDGER_ACCOUNTS.set(report["stats"]["accounts"])
            LEDGER_TRANSFERS.set(report["stats"]["transfers"])
            if not report["ok"]:
                logger.error("ledger_integrity_violation", extra={"event_type": "integrity_violation", "report": report})
        except Exception as exc:  # noqa: BLE001 - la base peut être indisponible pendant un incident
            INTEGRITY_OK.set(0)
            logger.warning("ledger_integrity_check_failed", extra={"error": str(exc)})
        INTEGRITY_CHECK.set_to_current_time()
        await asyncio.sleep(interval)


def _integrity_report(app: FastAPI) -> dict:
    # Cette méthode permet d'exécuter le contrôle d'intégrité sur une connexion du pool.
    with app.state.pool.connection() as conn:
        return ledger.check_integrity(conn)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Cette méthode permet de préparer la base, la clé publique JWT et la surveillance d'intégrité au démarrage.
    schema = (Path(__file__).parent / "schema.sql").read_text(encoding="utf-8")
    app.state.pool = await run_in_threadpool(create_pool, database_url(), schema)
    app.state.jwt_public_key = secret("JWT_PUBLIC_KEY")
    watcher = asyncio.create_task(integrity_watch(app, int(env("INTEGRITY_INTERVAL_SECONDS", "15"))))
    logger.info("service_started")
    yield
    watcher.cancel()
    app.state.pool.close()


app = FastAPI(title="Resilience-Alpha — Payment API", version="1.0.0", lifespan=lifespan, root_path=env("ROOT_PATH", ""))
instrument(app, SERVICE)
register_database_errors(app)
bearer = HTTPBearer(auto_error=False)


@app.exception_handler(ledger.LedgerError)
async def ledger_error_handler(request: Request, exc: ledger.LedgerError) -> JSONResponse:
    # Cette méthode permet de renvoyer les erreurs métier sous une forme stable { code, detail } exploitable par le front.
    TRANSFERS.labels(exc.code).inc()
    return JSONResponse({"code": exc.code, "detail": exc.message}, status_code=exc.status_code)


def current_claims(request: Request, credentials: HTTPAuthorizationCredentials | None = Depends(bearer)) -> dict:
    # Cette méthode permet de valider localement le JWT émis par le service d'auth (clé publique, audience, émetteur),
    # sans appel réseau : l'API reste utilisable même si le service d'auth est momentanément indisponible.
    if credentials is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Jeton manquant")
    try:
        claims = jwt.decode(
            credentials.credentials, request.app.state.jwt_public_key, algorithms=["RS256"],
            audience="payment-api", issuer="resilience-alpha-auth",
        )
    except jwt.PyJWTError:
        logger.warning("invalid_token", extra={"client_ip": client_ip(request), "event_type": "auth_failure"})
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Jeton invalide ou expiré")
    request.state.user_id = claims["sub"]
    return claims


def require_admin(claims: dict = Depends(current_claims)) -> dict:
    # Cette méthode permet de restreindre une route aux porteurs du rôle admin.
    if claims.get("role") != "admin":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Rôle administrateur requis")
    return claims


@app.get("/accounts/me", response_model=AccountOut)
def my_account(request: Request, claims: dict = Depends(current_claims)) -> dict:
    # Cette méthode permet de consulter son compte, ouvert automatiquement à la première visite.
    with request.app.state.pool.connection() as conn:
        account, created = ledger.get_or_open_account(conn, claims)
    if created:
        logger.info("account_opened", extra={"user_id": claims["sub"], "account_number": account["account_number"]})
    return account


@app.post("/transfers", response_model=TransferOut, status_code=status.HTTP_201_CREATED)
def create_transfer(
    body: TransferIn,
    request: Request,
    idempotency_key: str = Header(alias="Idempotency-Key", min_length=8, max_length=64),
    claims: dict = Depends(current_claims),
) -> JSONResponse:
    # Cette méthode permet d'émettre un virement depuis son compte ; la clé d'idempotence garantit qu'un renvoi
    # (double clic, nouvelle tentative après coupure réseau) ne débite jamais deux fois.
    with request.app.state.pool.connection() as conn:
        sender, _ = ledger.get_or_open_account(conn, claims)
        transfer, replayed = ledger.execute_transfer(
            conn, sender, body.to_account_number, body.amount_cents, body.label.strip(),
            uuid.UUID(claims["sub"]), idempotency_key,
        )
    TRANSFERS.labels("replayed" if replayed else "completed").inc()
    if not replayed:
        TRANSFER_AMOUNT.observe(body.amount_cents / 100)
    logger.info(
        "transfer_replayed" if replayed else "transfer_completed",
        extra={
            "user_id": claims["sub"], "transfer_id": str(transfer["id"]), "amount_cents": body.amount_cents,
            "from_account": sender["account_number"], "to_account": body.to_account_number,
            "client_ip": client_ip(request), "event_type": "transfer",
        },
    )
    payload = TransferOut.model_validate(transfer).model_dump(mode="json")
    return JSONResponse(payload, status_code=status.HTTP_200_OK if replayed else status.HTTP_201_CREATED)


@app.get("/transfers", response_model=list[TransferOut])
def my_transfers(request: Request, limit: int = Query(20, ge=1, le=100), claims: dict = Depends(current_claims)) -> list[dict]:
    # Cette méthode permet de lister l'historique des virements émis et reçus par l'utilisateur.
    with request.app.state.pool.connection() as conn:
        account, _ = ledger.get_or_open_account(conn, claims)
        return ledger.list_transfers(conn, account["id"], limit)


@app.get("/transfers/{transfer_id}", response_model=TransferOut)
def my_transfer(transfer_id: uuid.UUID, request: Request, claims: dict = Depends(current_claims)) -> dict:
    # Cette méthode permet de consulter un virement, uniquement si l'utilisateur en est l'émetteur ou le bénéficiaire.
    with request.app.state.pool.connection() as conn:
        account, _ = ledger.get_or_open_account(conn, claims)
        transfer = ledger.transfer_view(conn, transfer_id, account["id"])
        owned = transfer and conn.execute(
            "SELECT 1 FROM transfers WHERE id = %s AND %s IN (from_account_id, to_account_id)", (transfer_id, account["id"])
        ).fetchone()
    if not owned:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Virement introuvable")
    return transfer


@app.get("/admin/integrity")
def admin_integrity(request: Request, _: dict = Depends(require_admin)) -> dict:
    # Cette méthode permet à un administrateur authentifié de consulter le rapport d'intégrité du registre.
    return _integrity_report(request.app)


@app.get("/internal/integrity", include_in_schema=False)
def internal_integrity(request: Request) -> JSONResponse:
    # Cette méthode permet au moteur de remédiation de vérifier la cohérence des données après une reprise ;
    # elle n'est joignable que sur le réseau Docker interne (bloquée par le reverse proxy).
    report = _integrity_report(request.app)
    return JSONResponse(report, status_code=200 if report["ok"] else 409, media_type="application/json")


@app.get("/health")
def health(request: Request) -> JSONResponse:
    # Cette méthode permet d'indiquer si le service est réellement opérationnel (processus + base de données).
    db_ok = database_alive(request.app.state.pool)
    body = {"service": SERVICE, "status": "ok" if db_ok else "degraded", "checks": {"database": db_ok}}
    return JSONResponse(body, status_code=200 if db_ok else 503)
