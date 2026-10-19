"""Hachage des mots de passe (argon2id) et émission des jetons JWT signés en RS256."""

import base64
import time
import uuid

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerificationError
from cryptography.hazmat.primitives import serialization

ISSUER = "resilience-alpha-auth"
AUDIENCE = "payment-api"

_hasher = PasswordHasher()
# Hash factice utilisé quand l'email est inconnu, pour que la durée de réponse ne révèle pas l'existence du compte.
_DUMMY_HASH = _hasher.hash("dummy-password-for-timing")


def hash_password(password: str) -> str:
    # Cette méthode permet de hacher un mot de passe avec argon2id avant stockage.
    return _hasher.hash(password)


def verify_password(password_hash: str | None, password: str) -> bool:
    # Cette méthode permet de vérifier un mot de passe en temps quasi constant, y compris lorsque l'utilisateur n'existe pas.
    try:
        return _hasher.verify(password_hash or _DUMMY_HASH, password) and password_hash is not None
    except VerificationError:
        return False


class TokenIssuer:
    def __init__(self, private_key_pem: str, ttl_seconds: int):
        # Cette méthode permet de charger la clé privée RSA et de préparer la clé publique exposée en JWKS.
        self._private_key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
        self.ttl_seconds = ttl_seconds
        self.kid = "ra-auth-1"

    def issue(self, user: dict) -> str:
        # Cette méthode permet de produire un jeton d'accès signé contenant l'identité et le rôle de l'utilisateur.
        now = int(time.time())
        claims = {
            "iss": ISSUER,
            "aud": AUDIENCE,
            "sub": str(user["id"]),
            "email": user["email"],
            "name": user["full_name"],
            "role": user["role"],
            "iat": now,
            "exp": now + self.ttl_seconds,
            "jti": uuid.uuid4().hex,
        }
        return jwt.encode(claims, self._private_key, algorithm="RS256", headers={"kid": self.kid})

    def jwks(self) -> dict:
        # Cette méthode permet de publier la clé publique au format JWKS pour les services qui vérifient les jetons.
        numbers = self._private_key.public_key().public_numbers()

        def b64(value: int) -> str:
            # Cette méthode permet d'encoder un entier RSA en base64url sans padding (format JWK).
            raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
            return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

        return {"keys": [{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": self.kid, "n": b64(numbers.n), "e": b64(numbers.e)}]}

    def decode(self, token: str) -> dict:
        # Cette méthode permet de valider un jeton émis par ce service (signature, audience, expiration).
        public_key = self._private_key.public_key()
        return jwt.decode(token, public_key, algorithms=["RS256"], audience=AUDIENCE, issuer=ISSUER)
