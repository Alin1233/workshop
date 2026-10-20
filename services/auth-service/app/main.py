"""Service d'authentification : inscription, connexion (avec double authentification TOTP), émission de JWT RS256."""

import logging
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal

import jwt
import pyotp
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.responses import JSONResponse, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from prometheus_client import Counter
from psycopg import errors
from pydantic import BaseModel, Field

from resilience_common.database import create_pool, database_alive, register_database_errors
from resilience_common.observability import client_ip, instrument, setup_logging
from resilience_common.settings import database_url, env, secret

from . import mfa
from .security import TokenIssuer, hash_password, verify_password

SERVICE = "auth-service"
logger = setup_logging(SERVICE, env("LOG_LEVEL", "INFO"))

LOGIN_ATTEMPTS = Counter("auth_login_attempts_total", "Tentatives de connexion", ["result"])
REGISTRATIONS = Counter("auth_registrations_total", "Inscriptions", ["result"])
MFA_CHANGES = Counter("auth_mfa_changes_total", "Activations et désactivations de la double authentification", ["action"])

# Étape « second facteur » d'une connexion : 5 minutes et 5 essais, puis il faut ressaisir le mot de passe.
MFA_CHALLENGE_TTL_SECONDS = 300
MFA_MAX_ATTEMPTS = 5


# Validation volontairement simple : EmailStr refuse les domaines réservés (.local) utilisés dans ce labo fictif.
EMAIL_PATTERN = r"^[^@\s]{1,64}@[^@\s]+\.[A-Za-z]{2,}$"


class RegisterIn(BaseModel):
    email: str = Field(pattern=EMAIL_PATTERN, max_length=254)
    full_name: str = Field(min_length=2, max_length=80)
    password: str = Field(min_length=10, max_length=128)


class LoginIn(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=1, max_length=128)


class MfaLoginIn(BaseModel):
    mfa_token: str = Field(min_length=20, max_length=128)
    code: str = Field(min_length=6, max_length=32)


class MfaCodeIn(BaseModel):
    code: str = Field(min_length=6, max_length=32)


class MfaDisableIn(BaseModel):
    password: str = Field(min_length=1, max_length=128)
    code: str = Field(min_length=6, max_length=32)


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


class MfaChallengeOut(BaseModel):
    mfa_required: Literal[True] = True
    mfa_token: str
    expires_in: int


class MfaStatusOut(BaseModel):
    enabled: bool
    required: bool
    recovery_codes_remaining: int


class MfaSetupOut(BaseModel):
    secret: str
    otpauth_uri: str
    qr_code: str


class RecoveryCodesOut(BaseModel):
    recovery_codes: list[str]


class AuthError(Exception):
    def __init__(self, status_code: int, code: str, detail: str):
        # Cette méthode permet de porter un refus métier avec un code stable, lu par le front pour choisir sa réaction.
        super().__init__(detail)
        self.status_code, self.code, self.detail = status_code, code, detail


def admin_totp_secret() -> str:
    # Cette méthode permet de lire le secret TOTP imposé au compte admin et de refuser de démarrer s'il n'est pas en base32.
    value = secret("ADMIN_TOTP_SECRET").replace(" ", "").upper()
    try:
        pyotp.TOTP(value).now()
    except ValueError as exc:
        raise RuntimeError("ADMIN_TOTP_SECRET doit être un secret base32 (scripts/init_secrets.py)") from exc
    return value


def seed_admin(pool) -> None:
    # Cette méthode permet de créer le compte administrateur au démarrage lorsqu'il n'existe pas encore,
    # et de lui imposer à chaque démarrage la double authentification avec le secret TOTP fourni en secret Compose.
    email = env("ADMIN_EMAIL", "admin@resilience.local")
    totp_secret = admin_totp_secret()
    with pool.connection() as conn:
        exists = conn.execute("SELECT 1 FROM users WHERE lower(email) = lower(%s)", (email,)).fetchone()
        if exists:
            # Un secret changé invalide le dernier pas consommé (il portait sur l'ancien secret).
            conn.execute(
                "UPDATE users SET mfa_enabled = true, totp_pending_secret = NULL, "
                "totp_last_step = CASE WHEN totp_secret IS DISTINCT FROM %s THEN NULL ELSE totp_last_step END, "
                "totp_secret = %s WHERE lower(email) = lower(%s)",
                (totp_secret, totp_secret, email),
            )
            return
        conn.execute(
            "INSERT INTO users (id, email, full_name, password_hash, role, mfa_enabled, totp_secret) "
            "VALUES (%s, %s, %s, %s, 'admin', true, %s)",
            (uuid.uuid4(), email, "Administrateur", hash_password(secret("ADMIN_PASSWORD")), totp_secret),
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


app = FastAPI(title="Resilience-Alpha — Auth Service", version="1.1.0", lifespan=lifespan, root_path=env("ROOT_PATH", ""))
instrument(app, SERVICE)
register_database_errors(app)
bearer = HTTPBearer(auto_error=False)


@app.exception_handler(AuthError)
async def auth_error_handler(request: Request, exc: AuthError) -> JSONResponse:
    # Cette méthode permet de renvoyer un refus métier au format commun des services ({code, detail}).
    return JSONResponse({"code": exc.code, "detail": exc.detail}, status_code=exc.status_code)


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


@app.post("/login", response_model=TokenOut | MfaChallengeOut)
def login(body: LoginIn, request: Request) -> TokenOut | MfaChallengeOut:
    # Cette méthode permet d'authentifier un utilisateur par mot de passe : jeton d'accès immédiat, ou étape
    # « second facteur » (POST /login/mfa) lorsque la double authentification est active sur le compte.
    pool = request.app.state.pool
    with pool.connection() as conn:
        row = conn.execute("SELECT * FROM users WHERE lower(email) = lower(%s)", (body.email,)).fetchone()
    if not verify_password(row["password_hash"] if row else None, body.password):
        LOGIN_ATTEMPTS.labels("failure").inc()
        # Événement de sécurité exploitable par le SIEM (détection de force brute).
        logger.warning("login_failed", extra={"email": body.email, "client_ip": client_ip(request), "event_type": "auth_failure"})
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Identifiants invalides")
    if row["mfa_enabled"]:
        return open_mfa_challenge(row, request)
    return complete_login(row, request, ("pwd",))


def open_mfa_challenge(row: dict, request: Request) -> MfaChallengeOut:
    # Cette méthode permet de suspendre une connexion dont le mot de passe est valide en attendant le second facteur :
    # seul un jeton opaque de courte durée est remis, aucun jeton d'accès.
    token = mfa.new_challenge_token()
    with request.app.state.pool.connection() as conn:
        conn.execute("DELETE FROM mfa_challenges WHERE expires_at < now()")
        conn.execute(
            "INSERT INTO mfa_challenges (token_hash, user_id, expires_at) VALUES (%s, %s, now() + make_interval(secs => %s))",
            (mfa.sha256(token), row["id"], MFA_CHALLENGE_TTL_SECONDS),
        )
    LOGIN_ATTEMPTS.labels("mfa_required").inc()
    request.state.user_id = str(row["id"])
    logger.info("login_mfa_required", extra={"user_id": str(row["id"]), "client_ip": client_ip(request)})
    return MfaChallengeOut(mfa_token=token, expires_in=MFA_CHALLENGE_TTL_SECONDS)


def complete_login(row: dict, request: Request, amr: tuple[str, ...]) -> TokenOut:
    # Cette méthode permet de clore une connexion réussie (tous les facteurs vérifiés) et de délivrer le jeton d'accès.
    with request.app.state.pool.connection() as conn:
        conn.execute("UPDATE users SET last_login_at = now() WHERE id = %s", (row["id"],))
    LOGIN_ATTEMPTS.labels("success").inc()
    request.state.user_id = str(row["id"])
    logger.info("login_succeeded", extra={"user_id": str(row["id"]), "client_ip": client_ip(request),
                                          "event_type": "auth_success", "amr": list(amr)})
    issuer: TokenIssuer = request.app.state.issuer
    return TokenOut(access_token=issuer.issue(row, amr), expires_in=issuer.ttl_seconds, user=to_user_out(row))


def verify_second_factor(conn, row: dict, code: str) -> str | None:
    # Cette méthode permet de vérifier un code TOTP (refusé s'il a déjà servi) ou, à défaut, de consommer un code de secours ;
    # renvoie la méthode reconnue (« totp » ou « recovery ») ou None.
    code = code.strip()
    if mfa.TOTP_PATTERN.match(code):
        step = mfa.matching_step(row["totp_secret"], code) if row["totp_secret"] else None
        if step is None:
            return None
        claimed = conn.execute(
            "UPDATE users SET totp_last_step = %s WHERE id = %s AND (totp_last_step IS NULL OR totp_last_step < %s)",
            (step, row["id"], step),
        ).rowcount
        return "totp" if claimed else None
    used = conn.execute(
        "UPDATE mfa_recovery_codes SET used_at = now() WHERE user_id = %s AND code_hash = %s AND used_at IS NULL",
        (row["id"], mfa.hash_recovery_code(code)),
    ).rowcount
    return "recovery" if used else None


def remaining_recovery_codes(conn, user_id) -> int:
    # Cette méthode permet de compter les codes de secours encore utilisables d'un utilisateur.
    return conn.execute(
        "SELECT count(*) AS n FROM mfa_recovery_codes WHERE user_id = %s AND used_at IS NULL", (user_id,)
    ).fetchone()["n"]


def log_mfa_failure(request: Request, user_id, step: str) -> None:
    # Cette méthode permet de signaler un second facteur refusé comme un échec d'authentification,
    # pour que le SOC (règles Loki, détecteur ML, blocage d'IP) voie aussi une force brute sur les codes.
    LOGIN_ATTEMPTS.labels("failure").inc()
    logger.warning("mfa_failed", extra={"user_id": str(user_id), "step": step, "client_ip": client_ip(request),
                                        "event_type": "auth_failure"})


@app.post("/login/mfa", response_model=TokenOut)
def login_mfa(body: MfaLoginIn, request: Request) -> TokenOut:
    # Cette méthode permet de terminer une connexion avec double authentification lorsque le code (TOTP ou de secours)
    # est valide ; l'étape expire après 5 minutes ou 5 essais, il faut alors ressaisir le mot de passe.
    token_hash = mfa.sha256(body.mfa_token)
    method = None
    with request.app.state.pool.connection() as conn:
        challenge = conn.execute(
            "UPDATE mfa_challenges SET attempts = attempts + 1 "
            "WHERE token_hash = %s AND expires_at > now() AND attempts < %s RETURNING user_id, attempts",
            (token_hash, MFA_MAX_ATTEMPTS),
        ).fetchone()
        row = conn.execute("SELECT * FROM users WHERE id = %s", (challenge["user_id"],)).fetchone() if challenge else None
        if row is not None:
            method = verify_second_factor(conn, row, body.code)
        if method:
            conn.execute("DELETE FROM mfa_challenges WHERE token_hash = %s", (token_hash,))
            remaining = remaining_recovery_codes(conn, row["id"])
    if row is None:
        raise AuthError(status.HTTP_401_UNAUTHORIZED, "mfa_challenge_expired", "Vérification expirée, reconnectez-vous.")
    if not method:
        log_mfa_failure(request, row["id"], "login")
        if challenge["attempts"] >= MFA_MAX_ATTEMPTS:
            raise AuthError(status.HTTP_401_UNAUTHORIZED, "mfa_challenge_expired", "Trop d'essais, reconnectez-vous.")
        raise AuthError(status.HTTP_401_UNAUTHORIZED, "mfa_invalid_code", "Code invalide.")
    if method == "recovery":
        logger.warning("mfa_recovery_code_used", extra={"user_id": str(row["id"]), "remaining": remaining,
                                                        "client_ip": client_ip(request)})
    return complete_login(row, request, ("pwd", "otp"))


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


def current_user(conn, claims: dict) -> dict:
    # Cette méthode permet de relire en base l'utilisateur porteur du jeton, pour agir sur son état à jour.
    row = conn.execute("SELECT * FROM users WHERE id = %s", (claims["sub"],)).fetchone()
    if row is None:
        raise AuthError(status.HTTP_401_UNAUTHORIZED, "unknown_user", "Jeton invalide ou expiré")
    return row


@app.get("/mfa", response_model=MfaStatusOut)
def mfa_status(request: Request, claims: dict = Depends(current_claims)) -> MfaStatusOut:
    # Cette méthode permet d'indiquer si la double authentification est active et combien de codes de secours restent.
    with request.app.state.pool.connection() as conn:
        row = current_user(conn, claims)
        remaining = remaining_recovery_codes(conn, row["id"])
    return MfaStatusOut(enabled=row["mfa_enabled"], required=row["role"] == "admin", recovery_codes_remaining=remaining)


@app.post("/mfa/setup", response_model=MfaSetupOut)
def mfa_setup(request: Request, claims: dict = Depends(current_claims)) -> MfaSetupOut:
    # Cette méthode permet de préparer l'activation : un nouveau secret est mis en attente et rendu en QR code ;
    # il ne protège le compte qu'une fois confirmé par un premier code (POST /mfa/activate).
    totp_secret = mfa.new_totp_secret()
    with request.app.state.pool.connection() as conn:
        row = current_user(conn, claims)
        if not row["mfa_enabled"]:
            conn.execute("UPDATE users SET totp_pending_secret = %s WHERE id = %s", (totp_secret, row["id"]))
    if row["mfa_enabled"]:
        raise AuthError(status.HTTP_409_CONFLICT, "mfa_already_enabled", "La double authentification est déjà active.")
    uri = mfa.provisioning_uri(totp_secret, row["email"])
    return MfaSetupOut(secret=totp_secret, otpauth_uri=uri, qr_code=mfa.qr_data_uri(uri))


@app.post("/mfa/activate", response_model=RecoveryCodesOut)
def mfa_activate(body: MfaCodeIn, request: Request, claims: dict = Depends(current_claims)) -> RecoveryCodesOut:
    # Cette méthode permet d'activer la double authentification lorsque le premier code prouve que l'appli est bien
    # configurée ; les codes de secours sont générés à ce moment et ne sont plus jamais réaffichés.
    codes = mfa.new_recovery_codes()
    error = None
    with request.app.state.pool.connection() as conn, conn.transaction():
        row = conn.execute("SELECT * FROM users WHERE id = %s FOR UPDATE", (claims["sub"],)).fetchone()
        pending = row["totp_pending_secret"] if row else None
        step = mfa.matching_step(pending, body.code.strip()) if pending else None
        if row is None:
            error = AuthError(status.HTTP_401_UNAUTHORIZED, "unknown_user", "Jeton invalide ou expiré")
        elif row["mfa_enabled"]:
            error = AuthError(status.HTTP_409_CONFLICT, "mfa_already_enabled", "La double authentification est déjà active.")
        elif not pending:
            error = AuthError(status.HTTP_409_CONFLICT, "mfa_setup_required", "Générez d'abord un QR code.")
        elif step is None:
            error = AuthError(status.HTTP_400_BAD_REQUEST, "mfa_invalid_code", "Code invalide. Vérifiez l'heure de votre téléphone.")
        else:
            conn.execute(
                "UPDATE users SET mfa_enabled = true, totp_secret = totp_pending_secret, totp_pending_secret = NULL, "
                "totp_last_step = %s WHERE id = %s",
                (step, row["id"]),
            )
            conn.execute("DELETE FROM mfa_recovery_codes WHERE user_id = %s", (row["id"],))
            with conn.cursor() as cur:
                cur.executemany("INSERT INTO mfa_recovery_codes (user_id, code_hash) VALUES (%s, %s)",
                                [(row["id"], mfa.hash_recovery_code(code)) for code in codes])
    if error:
        raise error
    MFA_CHANGES.labels("enabled").inc()
    logger.info("mfa_enabled", extra={"user_id": claims["sub"], "client_ip": client_ip(request), "event_type": "mfa_change"})
    return RecoveryCodesOut(recovery_codes=codes)


@app.post("/mfa/disable", status_code=status.HTTP_204_NO_CONTENT)
def mfa_disable(body: MfaDisableIn, request: Request, claims: dict = Depends(current_claims)) -> Response:
    # Cette méthode permet de désactiver la double authentification d'un client lorsqu'il confirme son mot de passe
    # et un code valide ; elle reste imposée au compte admin.
    allowed = False
    with request.app.state.pool.connection() as conn:
        row = current_user(conn, claims)
        if row["role"] != "admin" and row["mfa_enabled"]:
            allowed = (verify_password(row["password_hash"], body.password)
                       and verify_second_factor(conn, row, body.code) is not None)
        if allowed:
            conn.execute(
                "UPDATE users SET mfa_enabled = false, totp_secret = NULL, totp_pending_secret = NULL, totp_last_step = NULL "
                "WHERE id = %s", (row["id"],))
            conn.execute("DELETE FROM mfa_recovery_codes WHERE user_id = %s", (row["id"],))
            conn.execute("DELETE FROM mfa_challenges WHERE user_id = %s", (row["id"],))
    if row["role"] == "admin":
        raise AuthError(status.HTTP_403_FORBIDDEN, "mfa_required_for_role",
                        "La double authentification est obligatoire pour l'administrateur.")
    if not row["mfa_enabled"]:
        raise AuthError(status.HTTP_409_CONFLICT, "mfa_not_enabled", "La double authentification n'est pas active.")
    if not allowed:
        log_mfa_failure(request, row["id"], "disable")
        raise AuthError(status.HTTP_400_BAD_REQUEST, "mfa_invalid_credentials", "Mot de passe ou code invalide.")
    MFA_CHANGES.labels("disabled").inc()
    logger.info("mfa_disabled", extra={"user_id": str(row["id"]), "client_ip": client_ip(request), "event_type": "mfa_change"})
    return Response(status_code=status.HTTP_204_NO_CONTENT)


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
