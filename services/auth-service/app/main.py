"""Service d'authentification : inscription, connexion (double authentification TOTP ou reconnaissance faciale),
émission de JWT RS256."""

import logging
import os
import uuid
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import Literal

import jwt
import pyotp
from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, UploadFile, status
from fastapi.responses import JSONResponse, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from prometheus_client import Counter, Histogram
from psycopg import errors
from pydantic import BaseModel, Field

from resilience_common.database import create_pool, database_alive, register_database_errors
from resilience_common.observability import client_ip, instrument, setup_logging
from resilience_common.settings import database_url, env, secret

from . import face, mfa
from .security import TokenIssuer, hash_password, verify_password

SERVICE = "auth-service"
logger = setup_logging(SERVICE, env("LOG_LEVEL", "INFO"))

LOGIN_ATTEMPTS = Counter("auth_login_attempts_total", "Tentatives de connexion", ["result"])
REGISTRATIONS = Counter("auth_registrations_total", "Inscriptions", ["result"])
MFA_CHANGES = Counter("auth_mfa_changes_total", "Activations et désactivations de la double authentification", ["action"])
FACE_VERIFICATIONS = Counter("auth_face_verifications_total", "Vérifications faciales par usage et résultat",
                             ["purpose", "result"])
FACE_ANALYSIS_SECONDS = Histogram("auth_face_analysis_seconds", "Durée d'analyse des captures d'une vérification faciale",
                                  buckets=(0.05, 0.1, 0.25, 0.5, 1, 2, 5))

# Étape « second facteur » d'une connexion : 5 minutes et 5 essais, puis il faut ressaisir le mot de passe.
MFA_CHALLENGE_TTL_SECONDS = 300
MFA_MAX_ATTEMPTS = 5
# Défi de pose de la reconnaissance faciale : 2 minutes pour prendre les captures (deux à la connexion, trois à
# l'enregistrement). À la connexion, il est à usage unique ; à l'enregistrement, ouvert par un code déjà vérifié, il accepte quelques essais (la caméra se rate vite).
FACE_CHALLENGE_TTL_SECONDS = 120
FACE_ENROLL_ATTEMPTS = 3
# Captures refusées à la connexion (pièces d'enquête du SOC), chiffrées puis purgées après ce délai.
FACE_CAPTURE_RETENTION_DAYS = int(env("FACE_CAPTURE_RETENTION_DAYS", "7"))


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


class FaceEnrollStartIn(BaseModel):
    code: str = Field(min_length=6, max_length=32)
    consent: bool


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
    # Première connexion du compte sans double authentification : le front propose alors de l'activer.
    suggest_mfa: bool = False


class MfaTokenIn(BaseModel):
    mfa_token: str = Field(min_length=20, max_length=128)


class MfaChallengeOut(BaseModel):
    mfa_required: Literal[True] = True
    mfa_token: str
    expires_in: int
    # Seconds facteurs acceptés : « totp » (code de l'appli ou de secours), plus « face » si un visage est enregistré.
    methods: list[Literal["totp", "face"]]


class MfaStatusOut(BaseModel):
    enabled: bool
    required: bool
    recovery_codes_remaining: int
    face_enrolled: bool


class FaceChallengeOut(BaseModel):
    challenge_id: uuid.UUID
    poses: list[Literal["center", "left", "right"]]
    expires_in: int


class FaceStatusOut(BaseModel):
    enrolled: bool
    enrolled_at: datetime | None = None
    consented_at: datetime | None = None


class RejectedCaptureOut(BaseModel):
    id: uuid.UUID
    email: str
    captured_at: datetime
    reason: str
    score: float | None
    client_ip: str | None


class RejectedCaptureImageOut(RejectedCaptureOut):
    image: str


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


def load_face_engine() -> face.FaceEngine | None:
    # Cette méthode permet de charger les modèles de reconnaissance faciale embarqués dans l'image ; sans eux
    # (exécution hors conteneur), le service démarre quand même et les routes faciales répondent 503.
    models_dir = env("FACE_MODELS_DIR", str(Path(__file__).parent / "models"))
    if not all(os.path.isfile(os.path.join(models_dir, name)) for name in (face.DETECTOR_MODEL, face.RECOGNIZER_MODEL)):
        logger.warning("face_engine_unavailable", extra={"models_dir": models_dir})
        return None
    return face.FaceEngine(models_dir)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Cette méthode permet d'initialiser la base, la clé de signature, le moteur facial et le compte admin au démarrage.
    schema = (Path(__file__).parent / "schema.sql").read_text(encoding="utf-8")
    app.state.pool = create_pool(database_url(), schema)
    app.state.issuer = TokenIssuer(secret("JWT_PRIVATE_KEY"), int(env("JWT_TTL_SECONDS", "900")))
    app.state.vault = face.FaceVault(secret("FACE_ENCRYPTION_KEY"))
    app.state.face = load_face_engine()
    seed_admin(app.state.pool)
    with app.state.pool.connection() as conn:
        purge_face_data(conn)
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
        has_face = face_enrolled(conn, row["id"])
    LOGIN_ATTEMPTS.labels("mfa_required").inc()
    request.state.user_id = str(row["id"])
    logger.info("login_mfa_required", extra={"user_id": str(row["id"]), "client_ip": client_ip(request)})
    return MfaChallengeOut(mfa_token=token, expires_in=MFA_CHALLENGE_TTL_SECONDS,
                           methods=["totp", "face"] if has_face else ["totp"])


def complete_login(row: dict, request: Request, amr: tuple[str, ...]) -> TokenOut:
    # Cette méthode permet de clore une connexion réussie (tous les facteurs vérifiés) et de délivrer le jeton d'accès.
    with request.app.state.pool.connection() as conn:
        conn.execute("UPDATE users SET last_login_at = now() WHERE id = %s", (row["id"],))
    LOGIN_ATTEMPTS.labels("success").inc()
    request.state.user_id = str(row["id"])
    logger.info("login_succeeded", extra={"user_id": str(row["id"]), "client_ip": client_ip(request),
                                          "event_type": "auth_success", "amr": list(amr)})
    issuer: TokenIssuer = request.app.state.issuer
    return TokenOut(access_token=issuer.issue(row, amr), expires_in=issuer.ttl_seconds, user=to_user_out(row),
                    suggest_mfa=row["last_login_at"] is None and not row["mfa_enabled"])


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


def log_mfa_failure(request: Request, user_id, step: str, reason: str | None = None) -> None:
    # Cette méthode permet de signaler un second facteur refusé comme un échec d'authentification,
    # pour que le SOC (règles Loki, détecteur ML, blocage d'IP) voie aussi une force brute sur les codes ou le visage.
    LOGIN_ATTEMPTS.labels("failure").inc()
    extra = {"user_id": str(user_id), "step": step, "client_ip": client_ip(request), "event_type": "auth_failure"}
    if reason:
        extra["reason"] = reason
    logger.warning("mfa_failed", extra=extra)


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
        has_face = face_enrolled(conn, row["id"])
    return MfaStatusOut(enabled=row["mfa_enabled"], required=row["role"] == "admin", recovery_codes_remaining=remaining,
                        face_enrolled=has_face)


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
            # Le visage n'est qu'une alternative au code : il disparaît avec la double authentification.
            conn.execute("DELETE FROM face_references WHERE user_id = %s", (row["id"],))
            conn.execute("DELETE FROM face_challenges WHERE user_id = %s", (row["id"],))
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


# ─────────────────────────── Reconnaissance faciale (alternative au code TOTP) ───────────────────────────
# Seule l'empreinte de référence est conservée, chiffrée (AES-256-GCM, secret face_encryption_key) et liée à son
# titulaire par le contexte du chiffrement ; aucune photo de référence. Seules les captures refusées à la connexion sont
# gardées (7 jours, pour le SOC).


def face_engine(request: Request) -> face.FaceEngine:
    # Cette méthode permet d'obtenir le moteur de reconnaissance faciale, ou de refuser proprement s'il n'est pas chargé.
    engine = request.app.state.face
    if engine is None:
        raise AuthError(status.HTTP_503_SERVICE_UNAVAILABLE, "face_unavailable", "Reconnaissance faciale indisponible.")
    return engine


def face_enrolled(conn, user_id) -> bool:
    # Cette méthode permet de savoir si l'utilisateur a enregistré un visage de référence.
    return conn.execute("SELECT 1 FROM face_references WHERE user_id = %s", (user_id,)).fetchone() is not None


def purge_face_data(conn) -> None:
    # Cette méthode permet d'effacer les défis expirés et les captures refusées plus anciennes que la durée de conservation.
    conn.execute("DELETE FROM face_challenges WHERE expires_at < now()")
    conn.execute("DELETE FROM face_rejected_captures WHERE captured_at < now() - make_interval(days => %s)",
                 (FACE_CAPTURE_RETENTION_DAYS,))


def open_face_challenge(conn, user_id, purpose: str) -> FaceChallengeOut:
    # Cette méthode permet de tirer un nouveau défi de pose (le précédent est annulé) ; à la connexion, un défi encore
    # ouvert garde ses poses, pour qu'on ne puisse pas redemander un défi sans essai jusqu'à tomber sur le côté préparé.
    purge_face_data(conn)
    pending = conn.execute(
        "SELECT poses FROM face_challenges WHERE user_id = %s AND purpose = 'login' AND expires_at > now()", (user_id,),
    ).fetchone() if purpose == "login" else None
    conn.execute("DELETE FROM face_challenges WHERE user_id = %s AND purpose = %s", (user_id, purpose))
    challenge_id, poses = uuid.uuid4(), pending["poses"] if pending else face.new_poses(purpose)
    conn.execute(
        "INSERT INTO face_challenges (id, user_id, purpose, poses, expires_at) "
        "VALUES (%s, %s, %s, %s, now() + make_interval(secs => %s))",
        (challenge_id, user_id, purpose, poses, FACE_CHALLENGE_TTL_SECONDS),
    )
    return FaceChallengeOut(challenge_id=challenge_id, poses=poses, expires_in=FACE_CHALLENGE_TTL_SECONDS)


def claim_enroll_challenge(conn, challenge_id: uuid.UUID, user_id) -> list[str] | None:
    # Cette méthode permet d'utiliser un essai d'un défi d'enregistrement (FACE_ENROLL_ATTEMPTS au plus, avant expiration)
    # et d'en rendre les poses, ou None s'il est inconnu, épuisé, expiré ou destiné à un autre utilisateur.
    row = conn.execute(
        "UPDATE face_challenges SET attempts = attempts + 1 "
        "WHERE id = %s AND user_id = %s AND purpose = 'enroll' AND expires_at > now() AND attempts < %s RETURNING poses",
        (challenge_id, user_id, FACE_ENROLL_ATTEMPTS),
    ).fetchone()
    return row["poses"] if row else None


def take_face_challenge(conn, challenge_id: uuid.UUID, user_id, purpose: str) -> list[str] | None:
    # Cette méthode permet de consommer un défi de pose (usage unique, même en cas d'échec) et d'en rendre les poses,
    # ou None s'il est inconnu, expiré ou destiné à un autre utilisateur.
    row = conn.execute(
        "DELETE FROM face_challenges WHERE id = %s AND user_id = %s AND purpose = %s "
        "RETURNING poses, expires_at > now() AS live",
        (challenge_id, user_id, purpose),
    ).fetchone()
    return row["poses"] if row and row["live"] else None


def read_frames(frames: list[UploadFile]) -> list[bytes]:
    # Cette méthode permet de lire les captures envoyées (une par pose) en refusant tout fichier trop lourd ; leur nombre
    # est borné ici, puis comparé au défi par check_frame_count une fois celui-ci connu.
    if not 1 < len(frames) <= face.MAX_POSES:
        raise AuthError(422, "face_invalid_image", f"De 2 à {face.MAX_POSES} captures attendues.")
    images = []
    for frame in frames:
        data = frame.file.read(face.MAX_FRAME_BYTES + 1)
        if len(data) > face.MAX_FRAME_BYTES:
            raise AuthError(413, "face_invalid_image", "Capture trop lourde (400 Ko au plus).")
        images.append(data)
    return images


def check_frame_count(images: list[bytes], poses: list[str]) -> None:
    # Cette méthode permet de refuser un envoi qui n'a pas exactement une capture par pose du défi.
    if len(images) != len(poses):
        raise AuthError(422, "face_invalid_image", f"{len(poses)} captures attendues.")


def reference_context(user_id) -> str:
    # Cette méthode permet de nommer le contexte de chiffrement de l'empreinte de référence d'un utilisateur.
    return f"{user_id}:face-reference:template"


def open_reference(request: Request, user_id, blob: bytes) -> bytes:
    # Cette méthode permet de déchiffrer l'empreinte de référence ; si la clé a été régénérée (init_secrets.py --force),
    # le visage est déclaré à réenregistrer au lieu de faire échouer la requête.
    try:
        return request.app.state.vault.open(blob, reference_context(user_id))
    except ValueError:
        logger.error("face_reference_unreadable", extra={"user_id": str(user_id)})
        raise AuthError(status.HTTP_409_CONFLICT, "face_reference_unreadable",
                        "Visage enregistré illisible : supprimez-le puis enregistrez-le de nouveau.")


def archive_rejected_capture(request: Request, user_id, error: face.FaceError, score: float | None) -> None:
    # Cette méthode permet de conserver, chiffrée et sans métadonnées, la capture refusée d'une connexion,
    # pour que le SOC puisse voir qui s'est présenté devant la caméra ; rien n'est gardé si l'image est illisible.
    if error.frame is None:
        return
    image = face.decode_jpeg(error.frame)
    if image is None:
        return
    capture_id = uuid.uuid4()
    sealed = request.app.state.vault.seal(face.encode_jpeg(image), f"{user_id}:face-capture:{capture_id}")
    with request.app.state.pool.connection() as conn:
        conn.execute(
            "INSERT INTO face_rejected_captures (id, user_id, reason, score, client_ip, image_enc) "
            "VALUES (%s, %s, %s, %s, %s, %s)",
            (capture_id, user_id, error.code, score, client_ip(request), sealed),
        )


@app.post("/login/mfa/face/challenge", response_model=FaceChallengeOut)
def login_face_challenge(body: MfaTokenIn, request: Request) -> FaceChallengeOut:
    # Cette méthode permet d'ouvrir le défi de pose d'une connexion en attente du second facteur, lorsque l'utilisateur
    # a choisi son visage plutôt qu'un code ; le jeton d'étape doit être encore valide.
    face_engine(request)
    challenge = None
    with request.app.state.pool.connection() as conn:
        row = conn.execute(
            "SELECT user_id FROM mfa_challenges WHERE token_hash = %s AND expires_at > now() AND attempts < %s",
            (mfa.sha256(body.mfa_token), MFA_MAX_ATTEMPTS),
        ).fetchone()
        has_face = row is not None and face_enrolled(conn, row["user_id"])
        if has_face:
            challenge = open_face_challenge(conn, row["user_id"], "login")
    if row is None:
        raise AuthError(status.HTTP_401_UNAUTHORIZED, "mfa_challenge_expired", "Vérification expirée, reconnectez-vous.")
    if challenge is None:
        raise AuthError(status.HTTP_409_CONFLICT, "face_not_enrolled", "Aucun visage enregistré pour ce compte.")
    return challenge


@app.post("/login/mfa/face", response_model=TokenOut)
def login_face(
    request: Request,
    mfa_token: str = Form(min_length=20, max_length=128),
    challenge_id: uuid.UUID = Form(),
    frames: list[UploadFile] = File(description="Une capture JPEG par pose du défi, dans l'ordre"),
) -> TokenOut:
    # Cette méthode permet de terminer une connexion par reconnaissance faciale : défi de pose réussi et visage de face
    # assez proche de la référence ; chaque envoi compte parmi les 5 essais de l'étape, une capture refusée est archivée.
    engine = face_engine(request)
    images = read_frames(frames)
    token_hash = mfa.sha256(mfa_token)
    poses = reference = None
    with request.app.state.pool.connection() as conn:
        challenge = conn.execute(
            "UPDATE mfa_challenges SET attempts = attempts + 1 "
            "WHERE token_hash = %s AND expires_at > now() AND attempts < %s RETURNING user_id, attempts",
            (token_hash, MFA_MAX_ATTEMPTS),
        ).fetchone()
        row = conn.execute("SELECT * FROM users WHERE id = %s", (challenge["user_id"],)).fetchone() if challenge else None
        if row is not None:
            poses = take_face_challenge(conn, challenge_id, row["id"], "login")
            reference = conn.execute("SELECT template_enc FROM face_references WHERE user_id = %s", (row["id"],)).fetchone()
    if row is None:
        raise AuthError(status.HTTP_401_UNAUTHORIZED, "mfa_challenge_expired", "Vérification expirée, reconnectez-vous.")
    if poses is None or reference is None:
        raise AuthError(status.HTTP_409_CONFLICT, "face_challenge_expired", "Défi expiré, recommencez la vérification.")
    check_frame_count(images, poses)
    template = open_reference(request, row["id"], reference["template_enc"])
    score = None
    try:
        with FACE_ANALYSIS_SECONDS.time():
            faces, measures = engine.check_liveness(images, poses)
        score = round(face.cosine(faces[0].embedding, face.embedding_from_bytes(template)), 3)
        logger.debug("face_liveness", extra={"user_id": str(row["id"]), "measures": measures, "score": score})
        if score < face.MATCH_THRESHOLD:
            raise face.FaceError("face_no_match", "Visage non reconnu.", images[0])
    except face.FaceError as exc:
        FACE_VERIFICATIONS.labels("login", exc.code).inc()
        archive_rejected_capture(request, row["id"], exc, score)
        log_mfa_failure(request, row["id"], "login_face", exc.code)
        if challenge["attempts"] >= MFA_MAX_ATTEMPTS:
            raise AuthError(status.HTTP_401_UNAUTHORIZED, "mfa_challenge_expired", "Trop d'essais, reconnectez-vous.")
        raise AuthError(status.HTTP_401_UNAUTHORIZED, exc.code, exc.detail)
    with request.app.state.pool.connection() as conn:
        consumed = conn.execute("DELETE FROM mfa_challenges WHERE token_hash = %s", (token_hash,)).rowcount
    if not consumed:
        raise AuthError(status.HTTP_401_UNAUTHORIZED, "mfa_challenge_expired", "Vérification expirée, reconnectez-vous.")
    FACE_VERIFICATIONS.labels("login", "match").inc()
    return complete_login(row, request, ("pwd", "face"))


@app.get("/mfa/face", response_model=FaceStatusOut)
def face_status(request: Request, claims: dict = Depends(current_claims)) -> FaceStatusOut:
    # Cette méthode permet à l'utilisateur de savoir si un visage est enregistré, depuis quand et avec quel consentement.
    with request.app.state.pool.connection() as conn:
        row = current_user(conn, claims)
        reference = conn.execute("SELECT created_at, consented_at FROM face_references WHERE user_id = %s",
                                 (row["id"],)).fetchone()
    if reference is None:
        return FaceStatusOut(enrolled=False)
    return FaceStatusOut(enrolled=True, enrolled_at=reference["created_at"], consented_at=reference["consented_at"])


@app.post("/mfa/face/challenge", response_model=FaceChallengeOut)
def face_enroll_challenge(body: FaceEnrollStartIn, request: Request,
                          claims: dict = Depends(current_claims)) -> FaceChallengeOut:
    # Cette méthode permet d'ouvrir l'enregistrement d'un visage : consentement explicite (donnée biométrique) et code TOTP
    # ou de secours vérifiés d'emblée, pour prouver que le titulaire est là, avant de tirer le défi de pose à filmer.
    face_engine(request)
    if not body.consent:
        raise AuthError(422, "face_consent_required", "Votre consentement est nécessaire pour enregistrer votre visage.")
    challenge = None
    with request.app.state.pool.connection() as conn, conn.transaction():
        row = current_user(conn, claims)
        if row["mfa_enabled"] and verify_second_factor(conn, row, body.code) is not None:
            challenge = open_face_challenge(conn, row["id"], "enroll")
    if not row["mfa_enabled"]:
        raise AuthError(status.HTTP_409_CONFLICT, "mfa_not_enabled", "Activez d'abord la double authentification.")
    if challenge is None:
        log_mfa_failure(request, row["id"], "face_enroll")
        raise AuthError(status.HTTP_400_BAD_REQUEST, "mfa_invalid_code", "Code invalide.")
    return challenge


@app.post("/mfa/face", response_model=FaceStatusOut)
def face_enroll(
    request: Request,
    challenge_id: uuid.UUID = Form(),
    frames: list[UploadFile] = File(description="Une capture JPEG par pose du défi, dans l'ordre"),
    claims: dict = Depends(current_claims),
) -> FaceStatusOut:
    # Cette méthode permet d'enregistrer (ou de remplacer) le visage de référence lorsque le défi de pose, ouvert après
    # le consentement et le code (voir face_enroll_challenge), est réussi ; un échec laisse réessayer sur le même défi.
    engine = face_engine(request)
    images = read_frames(frames)
    with request.app.state.pool.connection() as conn:
        row = current_user(conn, claims)
        poses = claim_enroll_challenge(conn, challenge_id, row["id"])
    if not row["mfa_enabled"]:
        raise AuthError(status.HTTP_409_CONFLICT, "mfa_not_enabled", "Activez d'abord la double authentification.")
    if poses is None:
        raise AuthError(status.HTTP_409_CONFLICT, "face_challenge_expired", "Défi expiré, recommencez la vérification.")
    check_frame_count(images, poses)
    try:
        with FACE_ANALYSIS_SECONDS.time():
            faces, measures = engine.check_liveness(images, poses)
    except face.FaceError as exc:
        FACE_VERIFICATIONS.labels("enroll", exc.code).inc()
        raise AuthError(status.HTTP_400_BAD_REQUEST, exc.code, exc.detail)
    logger.debug("face_liveness", extra={"user_id": str(row["id"]), "measures": measures})
    vault: face.FaceVault = request.app.state.vault
    template = vault.seal(face.embedding_bytes(faces[0].embedding), reference_context(row["id"]))
    with request.app.state.pool.connection() as conn, conn.transaction():
        conn.execute(
            "INSERT INTO face_references (user_id, template_enc, consented_at) VALUES (%s, %s, now()) "
            "ON CONFLICT (user_id) DO UPDATE SET template_enc = EXCLUDED.template_enc, "
            "consented_at = EXCLUDED.consented_at, created_at = now()",
            (row["id"], template),
        )
        conn.execute("DELETE FROM face_challenges WHERE id = %s", (challenge_id,))
    FACE_VERIFICATIONS.labels("enroll", "enrolled").inc()
    MFA_CHANGES.labels("face_enrolled").inc()
    logger.info("face_enrolled", extra={"user_id": str(row["id"]), "client_ip": client_ip(request), "event_type": "mfa_change"})
    return face_status(request, claims)


@app.delete("/mfa/face", status_code=status.HTTP_204_NO_CONTENT)
def face_remove(request: Request, claims: dict = Depends(current_claims)) -> Response:
    # Cette méthode permet de supprimer le visage de référence (son empreinte) ; la connexion revient au seul code.
    with request.app.state.pool.connection() as conn:
        row = current_user(conn, claims)
        deleted = conn.execute("DELETE FROM face_references WHERE user_id = %s", (row["id"],)).rowcount
        conn.execute("DELETE FROM face_challenges WHERE user_id = %s", (row["id"],))
    if not deleted:
        raise AuthError(status.HTTP_409_CONFLICT, "face_not_enrolled", "Aucun visage enregistré pour ce compte.")
    MFA_CHANGES.labels("face_removed").inc()
    logger.info("face_removed", extra={"user_id": str(row["id"]), "client_ip": client_ip(request), "event_type": "mfa_change"})
    return Response(status_code=status.HTTP_204_NO_CONTENT)


def admin_claims(claims: dict = Depends(current_claims)) -> dict:
    # Cette méthode permet de réserver une route au compte administrateur (double authentification imposée).
    if claims["role"] != "admin":
        raise AuthError(status.HTTP_403_FORBIDDEN, "admin_required", "Réservé à l'administrateur.")
    return claims


@app.get("/admin/face-captures", response_model=list[RejectedCaptureOut])
def list_rejected_captures(request: Request, claims: dict = Depends(admin_claims)) -> list[RejectedCaptureOut]:
    # Cette méthode permet au SOC de lister les captures refusées à la connexion encore conservées (50 plus récentes).
    with request.app.state.pool.connection() as conn:
        purge_face_data(conn)
        rows = conn.execute(
            "SELECT c.id, u.email, c.captured_at, c.reason, c.score, c.client_ip FROM face_rejected_captures c "
            "JOIN users u ON u.id = c.user_id ORDER BY c.captured_at DESC LIMIT 50"
        ).fetchall()
    return [RejectedCaptureOut(**row) for row in rows]


@app.get("/admin/face-captures/{capture_id}", response_model=RejectedCaptureImageOut)
def get_rejected_capture(capture_id: uuid.UUID, request: Request, claims: dict = Depends(admin_claims)) -> RejectedCaptureImageOut:
    # Cette méthode permet au SOC d'afficher une capture refusée ; chaque consultation d'une donnée biométrique est tracée.
    with request.app.state.pool.connection() as conn:
        row = conn.execute(
            "SELECT c.*, u.email FROM face_rejected_captures c JOIN users u ON u.id = c.user_id "
            "WHERE c.id = %s AND c.captured_at >= now() - make_interval(days => %s)",
            (capture_id, FACE_CAPTURE_RETENTION_DAYS),
        ).fetchone()
    if row is None:
        raise AuthError(status.HTTP_404_NOT_FOUND, "face_capture_not_found", "Capture introuvable ou expirée.")
    image = request.app.state.vault.open(row["image_enc"], f"{row['user_id']}:face-capture:{row['id']}")
    logger.info("face_capture_viewed", extra={"capture_id": str(row["id"]), "admin_id": claims["sub"],
                                              "client_ip": client_ip(request), "event_type": "biometric_access"})
    return RejectedCaptureImageOut(id=row["id"], email=row["email"], captured_at=row["captured_at"], reason=row["reason"],
                                   score=row["score"], client_ip=row["client_ip"], image=face.jpeg_data_uri(image))


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
