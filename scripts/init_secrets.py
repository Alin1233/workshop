"""Génère les secrets locaux de la plateforme dans ./secrets (jamais versionnés).

Usage : python scripts/init_secrets.py [--force]
Les fichiers existants sont conservés, sauf avec --force (attention : régénérer les mots de passe
de base de données impose de recréer le volume PostgreSQL).
"""

import secrets
import shutil
import subprocess
import sys
from pathlib import Path

SECRETS_DIR = Path(__file__).resolve().parent.parent / "secrets"
PASSWORDS = ("postgres_password", "auth_db_password", "pay_db_password", "admin_password", "grafana_admin_password")


def write_secret(name: str, content: str, force: bool) -> None:
    # Cette méthode permet d'écrire un secret dans son fichier lorsqu'il n'existe pas encore (ou si --force).
    path = SECRETS_DIR / name
    if path.exists() and not force:
        print(f"  = {name} (conservé)")
        return
    path.write_text(content, encoding="utf-8", newline="\n")
    print(f"  + {name}")


def generate_rsa_pair() -> tuple[str, str]:
    # Cette méthode permet de générer la paire RSA de signature des JWT, via la bibliothèque cryptography
    # si elle est installée, sinon via la commande openssl (fournie notamment avec Git for Windows).
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        private_pem = key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        ).decode()
        public_pem = key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        return private_pem, public_pem
    except ImportError:
        pass
    openssl = shutil.which("openssl") or r"C:\Program Files\Git\usr\bin\openssl.exe"
    if not Path(openssl).exists() and not shutil.which(openssl):
        sys.exit("openssl introuvable : installez-le ou faites `pip install cryptography`, puis relancez.")
    private_pem = subprocess.run(
        [openssl, "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"],
        check=True, capture_output=True, text=True,
    ).stdout
    public_pem = subprocess.run(
        [openssl, "pkey", "-pubout"], input=private_pem, check=True, capture_output=True, text=True
    ).stdout
    return private_pem, public_pem


def main() -> None:
    # Cette méthode permet de créer l'ensemble des secrets attendus par docker-compose.yml.
    force = "--force" in sys.argv
    SECRETS_DIR.mkdir(exist_ok=True)
    print(f"Secrets dans {SECRETS_DIR}")
    for name in PASSWORDS:
        write_secret(name, secrets.token_urlsafe(24), force)
    if force or not (SECRETS_DIR / "jwt_private.pem").exists():
        private_pem, public_pem = generate_rsa_pair()
        write_secret("jwt_private.pem", private_pem, True)
        write_secret("jwt_public.pem", public_pem, True)
    else:
        print("  = jwt_private.pem / jwt_public.pem (conservés)")
    print(f"Mot de passe admin (admin@resilience.local) : {(SECRETS_DIR / 'admin_password').read_text().strip()}")
    print(f"Mot de passe Grafana (admin) : {(SECRETS_DIR / 'grafana_admin_password').read_text().strip()}")


if __name__ == "__main__":
    main()
