"""Service d'authentification : inscription, connexion, émission de JWT RS256."""

import logging
import uuid
from contextlib import asynccontextmanager
from pathlib import Path

import jwt
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from prometheus_client import Counter
from psycopg import errors
from pydantic import BaseModel, Field

from resilience_common.database import create_pool, database_alive, register_database_errors
from resilience_common.observability import client_ip, instrument, setup_logging
from resilience_common.settings import database_url, env, secret

from .security import TokenIssuer, hash_password, verify_password

SERVICE = "auth-service"
logger = setup_logging(SERVICE, env("LOG_LEVEL", "INFO"))

LOGIN_ATTEMPTS = Counter("auth_login_attempts_total", "Tentatives de connexion", ["result"])
REGISTRATIONS = Counter("auth_registrations_total", "Inscriptions", ["result"])


# Validation volontairement simple : EmailStr refuse les domaines réservés (.local) utilisés dans ce labo fictif.
EMAIL_PATTERN = r"^[^@\s]{1,64}@[^@\s]+\.[A-Za-z]{2,}$"


class RegisterIn(BaseModel):
    email: str = Field(pattern=EMAIL_PATTERN, max_length=254)
    full_name: str = Field(min_length=2, max_length=80)
    password: str = Field(min_length=10, max_length=128)


class LoginIn(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=1, max_length=128)


class UserOut(BaseModel):
    id: uuid.UUID
    email: str
    full_name: str
    role: str


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserOut


def seed_admin(pool) -> None:
    # Cette méthode permet de créer le compte administrateur au démarrage lorsqu'il n'existe pas encore.
    email = env("ADMIN_EMAIL", "admin@resilience.local")
    with pool.connection() as conn:
        exists = conn.execute("SELECT 1 FROM users WHERE lower(email) = lower(%s)", (email,)).fetchone()
        if exists:
            return
        conn.execute(
            "INSERT INTO users (id, email, full_name, password_hash, role) VALUES (%s, %s, %s, %s, 'admin')",
            (uuid.uuid4(), email, "Administrateur", hash_password(secret("ADMIN_PASSWORD"))),
        )
    logger.info("admin_seeded", extra={"email": email})


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Cette méthode permet d'initialiser la base, la clé de signature et le compte admin au démarrage du service.
    schema = (Path(__file__).parent / "schema.sql").read_text(encoding="utf-8")
    app.state.pool = create_pool(database_url(), schema)
    app.state.issuer = TokenIssuer(secret("JWT_PRIVATE_KEY"), int(env("JWT_TTL_SECONDS", "900")))
    seed_admin(app.state.pool)
    logger.info("service_started")
    yield
    app.state.pool.close()


app = FastAPI(title="Resilience-Alpha — Auth Service", version="1.0.0", lifespan=lifespan, root_path=env("ROOT_PATH", ""))
instrument(app, SERVICE)
register_database_errors(app)
bearer = HTTPBearer(auto_error=False)


def to_user_out(row: dict) -> UserOut:
    # Cette méthode permet de convertir une ligne de la table users en réponse publique (sans le hash).
    return UserOut(id=row["id"], email=row["email"], full_name=row["full_name"], role=row["role"])


@app.post("/register", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def register(body: RegisterIn, request: Request) -> UserOut:
    # Cette méthode permet de créer un compte client lorsque l'email n'est pas déjà utilisé.
    user_id = uuid.uuid4()
    try:
        with request.app.state.pool.connection() as conn:
            row = conn.execute(
                "INSERT INTO users (id, email, full_name, password_hash) VALUES (%s, %s, %s, %s) RETURNING *",
                (user_id, body.email, body.full_name.strip(), hash_password(body.password)),
            ).fetchone()
    except errors.UniqueViolation:
        REGISTRATIONS.labels("conflict").inc()
        raise HTTPException(status.HTTP_409_CONFLICT, "Un compte existe déjà avec cet email")
    REGISTRATIONS.labels("created").inc()
    logger.info("user_registered", extra={"user_id": str(user_id), "client_ip": client_ip(request)})
    return to_user_out(row)


@app.post("/login", response_model=TokenOut)
def login(body: LoginIn, request: Request) -> TokenOut:
    # Cette méthode permet d'authentifier un utilisateur et de lui délivrer un jeton d'accès lorsque le mot de passe est valide.
    pool = request.app.state.pool
    with pool.connection() as conn:
        row = conn.execute("SELECT * FROM users WHERE lower(email) = lower(%s)", (body.email,)).fetchone()
    if not verify_password(row["password_hash"] if row else None, body.password):
        LOGIN_ATTEMPTS.labels("failure").inc()
        # Événement de sécurité exploitable par le SIEM (détection de force brute).
        logger.warning("login_failed", extra={"email": body.email, "client_ip": client_ip(request), "event_type": "auth_failure"})
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Identifiants invalides")
    with pool.connection() as conn:
        conn.execute("UPDATE users SET last_login_at = now() WHERE id = %s", (row["id"],))
    LOGIN_ATTEMPTS.labels("success").inc()
    request.state.user_id = str(row["id"])
    logger.info("login_succeeded", extra={"user_id": str(row["id"]), "client_ip": client_ip(request), "event_type": "auth_success"})
    issuer: TokenIssuer = request.app.state.issuer
    return TokenOut(access_token=issuer.issue(row), expires_in=issuer.ttl_seconds, user=to_user_out(row))


def current_claims(request: Request, credentials: HTTPAuthorizationCredentials | None = Depends(bearer)) -> dict:
    # Cette méthode permet d'extraire et valider le jeton Bearer de la requête courante.
    if credentials is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Jeton manquant")
    try:
        claims = request.app.state.issuer.decode(credentials.credentials)
    except jwt.PyJWTError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Jeton invalide ou expiré")
    request.state.user_id = claims["sub"]
    return claims


@app.get("/me", response_model=UserOut)
def me(claims: dict = Depends(current_claims)) -> UserOut:
    # Cette méthode permet de renvoyer l'identité portée par le jeton de l'appelant.
    return UserOut(id=claims["sub"], email=claims["email"], full_name=claims["name"], role=claims["role"])


@app.get("/.well-known/jwks.json", include_in_schema=False)
def jwks(request: Request) -> dict:
    # Cette méthode permet de publier la clé publique de vérification des jetons.
    return request.app.state.issuer.jwks()


@app.get("/health")
def health(request: Request) -> JSONResponse:
    # Cette méthode permet d'indiquer si le service est réellement opérationnel (processus + base de données).
    db_ok = database_alive(request.app.state.pool)
    body = {"service": SERVICE, "status": "ok" if db_ok else "degraded", "checks": {"database": db_ok}}
    return JSONResponse(body, status_code=200 if db_ok else 503)
