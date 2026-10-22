"""Double authentification : codes TOTP (RFC 6238, appli d'authentification), codes de secours, jetons d'étape."""

import hashlib
import hmac
import re
import secrets
import time

import pyotp
import segno

ISSUER_NAME = "Resilience-Alpha"
# Tolérance d'un pas (30 s) de part et d'autre : dérive d'horloge du téléphone et saisie en fin de période.
VALID_WINDOW = 1
RECOVERY_CODE_COUNT = 10
_RECOVERY_ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789"  # sans 0/o, 1/l/i : lisible à la recopie
TOTP_PATTERN = re.compile(r"^\d{6}$")


def new_totp_secret() -> str:
    # Cette méthode permet de tirer un secret TOTP aléatoire de 160 bits, encodé en base32 comme l'attendent les applis.
    return pyotp.random_base32(32)


def provisioning_uri(secret: str, email: str) -> str:
    # Cette méthode permet de construire l'URI otpauth:// que l'appli d'authentification importe en scannant le QR code.
    return pyotp.TOTP(secret).provisioning_uri(name=email, issuer_name=ISSUER_NAME)


def qr_data_uri(uri: str) -> str:
    # Cette méthode permet de rendre l'URI otpauth en QR code SVG inline (data URI), sans appel à un service externe.
    return segno.make(uri, error="m").svg_data_uri(scale=5, border=2)


def matching_step(secret: str, code: str, now: float | None = None) -> int | None:
    # Cette méthode permet de retrouver le pas de temps auquel correspond un code TOTP (fenêtre ±1),
    # pour que l'appelant refuse un code déjà utilisé ; renvoie None si le code ne correspond à aucun pas.
    if not TOTP_PATTERN.match(code):
        return None
    totp = pyotp.TOTP(secret)
    current = int((time.time() if now is None else now) // totp.interval)
    for step in range(current - VALID_WINDOW, current + VALID_WINDOW + 1):
        if hmac.compare_digest(totp.at(step * totp.interval), code):
            return step
    return None


def normalize_code(code: str) -> str:
    # Cette méthode permet de nettoyer une saisie (espaces, tirets, casse) avant de la comparer.
    return re.sub(r"[\s-]", "", code).lower()


def new_recovery_codes() -> list[str]:
    # Cette méthode permet de générer les codes de secours à usage unique, au format « xxxxx-xxxxx » (50 bits chacun).
    codes = []
    for _ in range(RECOVERY_CODE_COUNT):
        raw = "".join(secrets.choice(_RECOVERY_ALPHABET) for _ in range(10))
        codes.append(f"{raw[:5]}-{raw[5:]}")
    return codes


def sha256(value: str) -> str:
    # Cette méthode permet de hacher un jeton d'étape avant stockage ou recherche en base (jamais conservé en clair).
    return hashlib.sha256(value.encode()).hexdigest()


def hash_recovery_code(code: str) -> str:
    # Cette méthode permet de hacher un code de secours sous sa forme normalisée, quelle que soit la saisie.
    return sha256(normalize_code(code))


def new_challenge_token() -> str:
    # Cette méthode permet de tirer le jeton opaque qui relie les deux étapes d'une connexion avec double authentification.
    return secrets.token_urlsafe(32)
