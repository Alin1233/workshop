"""Génère les secrets locaux de la plateforme dans ./secrets (jamais versionnés).

Usage : python scripts/init_secrets.py [--force]
Les fichiers existants sont conservés, sauf avec --force (attention : régénérer les mots de passe
de base de données impose de recréer le volume PostgreSQL).
Prometheus, Alertmanager et Loki ont chacun un compte « admin » : le mot de passe en clair (<service>_password) sert
aux clients (Grafana, Prometheus, ruler Loki, tests), le hash bcrypt est dérivé dans les fichiers lus par le serveur.
Ces fichiers dérivés sont recalculés s'ils manquent ou si le mot de passe a été modifié depuis.
"""

import base64
import secrets
import shutil
import subprocess
import sys
from pathlib import Path

SECRETS_DIR = Path(__file__).resolve().parent.parent / "secrets"
OBSERVABILITY = ("prometheus", "alertmanager", "loki")
# ops_assistant_password, supervision_password : comptes « admin » de l'assistant RAG et du dashboard de supervision
# (vérifiés par les services eux-mêmes, à temps constant, sans hash dérivé)
PASSWORDS = ("postgres_password", "auth_db_password", "pay_db_password", "admin_password", "grafana_admin_password",
             *(f"{service}_password" for service in OBSERVABILITY), "ops_assistant_password", "supervision_password")
OBSERVABILITY_USER = "admin"
# Jetons de service (jamais saisis par un humain) : remediation_webhook_token authentifie Alertmanager auprès du moteur
# de remédiation (en-tête Authorization: Bearer, lu par les deux conteneurs en secret Compose).
TOKENS = ("remediation_webhook_token",)


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


def bcrypt_hash(plain: str) -> str:
    # Cette méthode permet de calculer le hash bcrypt d'un mot de passe, via la bibliothèque bcrypt si elle est installée,
    # sinon via htpasswd dans un conteneur jetable (le mot de passe passe par stdin, jamais par la ligne de commande).
    try:
        import bcrypt

        return bcrypt.hashpw(plain.encode(), bcrypt.gensalt(rounds=10)).decode()
    except ImportError:
        pass
    if not shutil.which("docker"):
        sys.exit("Ni bcrypt ni docker : faites `pip install bcrypt`, puis relancez.")
    line = subprocess.run(
        ["docker", "run", "--rm", "-i", "httpd:2.4-alpine", "htpasswd", "-niBC", "10", OBSERVABILITY_USER],
        input=plain, check=True, capture_output=True, text=True,
    ).stdout.strip()
    return line.split(":", 1)[1]


def write_observability_auth(service: str, force: bool) -> None:
    # Cette méthode permet de dériver du mot de passe d'un service de gestion les fichiers d'authentification lus par
    # le serveur (et, pour Alertmanager, par le ruler Loki) lorsqu'ils manquent ou sont plus anciens que le mot de passe.
    source = SECRETS_DIR / f"{service}_password"
    password = source.read_text(encoding="utf-8").strip()
    derived = {
        "prometheus": ["prometheus_web.yml"],
        "alertmanager": ["alertmanager_web.yml", "alertmanager_basic_auth"],
        "loki": ["loki_htpasswd"],
    }[service]
    stale = [name for name in derived
             if force or not (SECRETS_DIR / name).exists()
             or (SECRETS_DIR / name).stat().st_mtime < source.stat().st_mtime]
    if not stale:
        print(f"  = {', '.join(derived)} (conservés)")
        return
    hashed = bcrypt_hash(password)
    contents = {
        f"{service}_web.yml": f"basic_auth_users:\n  {OBSERVABILITY_USER}: {hashed}\n",
        "loki_htpasswd": f"{OBSERVABILITY_USER}:{hashed}\n",
        # En-tête « Authorization: Basic … » envoyé par le ruler Loki à Alertmanager
        "alertmanager_basic_auth": base64.b64encode(f"{OBSERVABILITY_USER}:{password}".encode()).decode(),
    }
    for name in derived:
        write_secret(name, contents[name], True)


def main() -> None:
    # Cette méthode permet de créer l'ensemble des secrets attendus par docker-compose.yml.
    force = "--force" in sys.argv
    # Répertoire réservé à son propriétaire, comme shared/secrets sur le PC Hôte (deploy.yml) : les fichiers restent
    # lisibles (0644) par les utilisateurs des conteneurs, qui les reçoivent montés un par un en /run/secrets (le
    # montage ne traverse pas le répertoire), mais aucun autre compte de l'hôte ne peut l'ouvrir. Sans effet sous Windows.
    SECRETS_DIR.mkdir(mode=0o700, exist_ok=True)
    SECRETS_DIR.chmod(0o700)
    print(f"Secrets dans {SECRETS_DIR}")
    for name in PASSWORDS:
        write_secret(name, secrets.token_urlsafe(24), force)
    for name in TOKENS:
        write_secret(name, secrets.token_urlsafe(32), force)
    if force or not (SECRETS_DIR / "jwt_private.pem").exists():
        private_pem, public_pem = generate_rsa_pair()
        write_secret("jwt_private.pem", private_pem, True)
        write_secret("jwt_public.pem", public_pem, True)
    else:
        print("  = jwt_private.pem / jwt_public.pem (conservés)")
    for service in OBSERVABILITY:
        write_observability_auth(service, force)
    print(f"Mot de passe admin (admin@resilience.local) : {(SECRETS_DIR / 'admin_password').read_text().strip()}")
    print(f"Mot de passe Grafana (admin) : {(SECRETS_DIR / 'grafana_admin_password').read_text().strip()}")
    for service in OBSERVABILITY:
        print(f"Mot de passe {service.capitalize()} ({OBSERVABILITY_USER}) : {(SECRETS_DIR / f'{service}_password').read_text().strip()}")
    print(f"Mot de passe assistant RAG ({OBSERVABILITY_USER}) : {(SECRETS_DIR / 'ops_assistant_password').read_text().strip()}")
    print(f"Mot de passe dashboard de supervision ({OBSERVABILITY_USER}) : "
          f"{(SECRETS_DIR / 'supervision_password').read_text().strip()}")


if __name__ == "__main__":
    main()
