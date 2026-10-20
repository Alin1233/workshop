"""Génère les secrets locaux de la plateforme dans ./secrets (jamais versionnés).

Usage : python scripts/init_secrets.py [--force]
Les fichiers existants sont conservés, sauf avec --force (attention : régénérer les mots de passe
de base de données impose de recréer le volume PostgreSQL).
Prometheus, Alertmanager et Loki ont chacun un compte « admin » : le mot de passe en clair (<service>_password) sert
aux clients (Grafana, Prometheus, ruler Loki, tests), le hash bcrypt est dérivé dans les fichiers lus par le serveur.
Ces fichiers dérivés sont recalculés s'ils manquent ou si le mot de passe a été modifié depuis.
Certificat HTTPS du WAF (port 8443) : émis par une autorité locale (waf_ca.crt, à importer dans les navigateurs) pour
localhost, 127.0.0.1, les adresses IPv4 de la machine et les noms de RA_TLS_HOSTS (séparés par des virgules) ;
réémis par la même autorité dès que cette liste change.
"""

import base64
import ipaddress
import os
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
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
# Secret TOTP (RFC 6238, base32) du compte admin de l'application : la double authentification lui est imposée.
# À enregistrer dans une appli d'authentification (URI otpauth affichée ci-dessous) ; le smoke test calcule les codes.
ADMIN_TOTP_SECRET = "admin_totp_secret"
# Clé AES-256 (base64) des données biométriques de la reconnaissance faciale (empreintes, photos, captures refusées).
# La régénérer (--force) rend illisibles les visages enregistrés : chaque utilisateur devra réenregistrer le sien.
FACE_ENCRYPTION_KEY = "face_encryption_key"
# HTTPS du WAF : la caméra du navigateur n'est accessible qu'en contexte sécurisé (HTTPS, ou http://localhost).
TLS_FILES = ("waf_ca.crt", "waf_ca.key", "waf_tls.crt", "waf_tls.key", "waf_tls_hosts")


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


def find_openssl() -> str:
    # Cette méthode permet de trouver la commande openssl (Linux, ou celle fournie avec Git for Windows).
    openssl = shutil.which("openssl") or r"C:\Program Files\Git\usr\bin\openssl.exe"
    if not Path(openssl).exists() and not shutil.which(openssl):
        sys.exit("openssl introuvable : installez-le, puis relancez.")
    return openssl


def tls_hosts() -> list[str]:
    # Cette méthode permet de lister les noms et adresses couverts par le certificat du WAF : localhost, les adresses
    # IPv4 de la machine (dont celle du réseau du groupe) et les noms supplémentaires de RA_TLS_HOSTS.
    hosts = ["localhost", "127.0.0.1"]
    try:
        hosts += socket.gethostbyname_ex(socket.gethostname())[2]
    except OSError:
        pass
    hosts += [h.strip() for h in os.getenv("RA_TLS_HOSTS", "").split(",") if h.strip()]
    return sorted({h for h in hosts if not h.startswith("127.") or h == "127.0.0.1"})


def san_entry(host: str) -> str:
    # Cette méthode permet d'écrire un nom au format subjectAltName (IP:… pour une adresse, DNS:… sinon).
    try:
        ipaddress.ip_address(host)
        return f"IP:{host}"
    except ValueError:
        return f"DNS:{host}"


def write_tls_certificates(force: bool) -> None:
    # Cette méthode permet de créer l'autorité locale (10 ans) puis le certificat serveur du WAF (397 jours, durée
    # maximale acceptée par les navigateurs), réémis par la même autorité si la liste des noms couverts a changé.
    hosts = tls_hosts()
    paths = {name: SECRETS_DIR / name for name in TLS_FILES}
    openssl = find_openssl()
    with tempfile.TemporaryDirectory() as tmp:
        if force or not (paths["waf_ca.crt"].exists() and paths["waf_ca.key"].exists()):
            subprocess.run([openssl, "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                            "-keyout", str(paths["waf_ca.key"]), "-out", str(paths["waf_ca.crt"]), "-days", "3650",
                            "-subj", "/CN=Resilience-Alpha - autorite locale",
                            "-addext", "basicConstraints=critical,CA:TRUE",
                            "-addext", "keyUsage=critical,keyCertSign,cRLSign"],
                           check=True, capture_output=True)
            print("  + waf_ca.crt / waf_ca.key")
            force = True
        current = paths["waf_tls_hosts"].read_text(encoding="utf-8").split() if paths["waf_tls_hosts"].exists() else []
        if not force and current == hosts and paths["waf_tls.crt"].exists() and paths["waf_tls.key"].exists():
            print("  = waf_tls.crt / waf_tls.key (conservés)")
            return
        csr, extensions = Path(tmp) / "waf.csr", Path(tmp) / "waf.ext"
        extensions.write_text(
            "basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n"
            f"subjectAltName={','.join(san_entry(h) for h in hosts)}\n", encoding="utf-8")
        subprocess.run([openssl, "req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                        "-keyout", str(paths["waf_tls.key"]), "-out", str(csr), "-subj", "/CN=resilience-alpha"],
                       check=True, capture_output=True)
        subprocess.run([openssl, "x509", "-req", "-in", str(csr), "-CA", str(paths["waf_ca.crt"]),
                        "-CAkey", str(paths["waf_ca.key"]), "-set_serial", str(secrets.randbits(63)), "-days", "397",
                        "-sha256", "-extfile", str(extensions), "-out", str(paths["waf_tls.crt"])],
                       check=True, capture_output=True)
    # openssl crée les clés en 0600 : celle du serveur doit rester lisible par l'utilisateur du WAF, comme les autres
    # secrets montés (le répertoire, en 0700, protège l'ensemble) ; celle de l'autorité, jamais montée, reste en 0600.
    paths["waf_tls.key"].chmod(0o644)
    paths["waf_tls_hosts"].write_text("\n".join(hosts) + "\n", encoding="utf-8", newline="\n")
    print(f"  + waf_tls.crt / waf_tls.key ({', '.join(hosts)})")


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
    write_secret(ADMIN_TOTP_SECRET, base64.b32encode(secrets.token_bytes(20)).decode(), force)
    write_secret(FACE_ENCRYPTION_KEY, base64.b64encode(secrets.token_bytes(32)).decode(), force)
    write_tls_certificates(force)
    for service in OBSERVABILITY:
        write_observability_auth(service, force)
    print(f"Mot de passe admin (admin@resilience.local) : {(SECRETS_DIR / 'admin_password').read_text().strip()}")
    totp = (SECRETS_DIR / ADMIN_TOTP_SECRET).read_text().strip()
    print(f"Double authentification admin, à ajouter dans une appli d'authentification (clé {totp}) : "
          f"otpauth://totp/Resilience-Alpha:admin%40resilience.local?secret={totp}&issuer=Resilience-Alpha")
    print(f"HTTPS du WAF (port 8443, caméra de la reconnaissance faciale) : importer {SECRETS_DIR / 'waf_ca.crt'} dans les "
          "autorités de confiance du navigateur, ou accepter l'alerte au premier accès")
    print(f"Mot de passe Grafana (admin) : {(SECRETS_DIR / 'grafana_admin_password').read_text().strip()}")
    for service in OBSERVABILITY:
        print(f"Mot de passe {service.capitalize()} ({OBSERVABILITY_USER}) : {(SECRETS_DIR / f'{service}_password').read_text().strip()}")
    print(f"Mot de passe assistant RAG ({OBSERVABILITY_USER}) : {(SECRETS_DIR / 'ops_assistant_password').read_text().strip()}")
    print(f"Mot de passe dashboard de supervision ({OBSERVABILITY_USER}) : "
          f"{(SECRETS_DIR / 'supervision_password').read_text().strip()}")


if __name__ == "__main__":
    main()
