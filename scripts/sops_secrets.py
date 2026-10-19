"""Chiffre / déchiffre les secrets locaux avec SOPS + age, pour les versionner sans jamais les exposer en clair.

Usage :
    python scripts/sops_secrets.py keygen    # crée votre clé age (hors dépôt) et affiche la clé publique à ajouter dans .sops.yaml
    python scripts/sops_secrets.py encrypt   # ./secrets/*  -> secrets.enc.json (versionné, chiffré)
    python scripts/sops_secrets.py decrypt   # secrets.enc.json -> ./secrets/* (jamais versionné)

Prérequis : `winget install Mozilla.SOPS FiloSottile.age` (ou binaires dans le PATH).
La clé privée age reste dans le répertoire par défaut de SOPS (%AppData%\\sops\\age\\keys.txt sous Windows,
~/.config/sops/age/keys.txt ailleurs) ; ajouter un coéquipier = ajouter sa clé publique dans .sops.yaml
puis `sops updatekeys secrets.enc.json`.
"""

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SECRETS_DIR = ROOT / "secrets"
ENCRYPTED = ROOT / "secrets.enc.json"
PLAINTEXT = SECRETS_DIR / ".bundle.json"


def tool(name: str) -> str:
    # Cette méthode permet de localiser un binaire requis et d'arrêter le script avec une consigne d'installation s'il manque.
    path = shutil.which(name)
    if not path:
        sys.exit(f"{name} introuvable : `winget install Mozilla.SOPS FiloSottile.age`, puis relancez.")
    return path


def key_file() -> Path:
    # Cette méthode permet de retrouver l'emplacement de la clé age attendu par SOPS selon le système.
    if os.getenv("SOPS_AGE_KEY_FILE"):
        return Path(os.environ["SOPS_AGE_KEY_FILE"])
    base = Path(os.getenv("APPDATA", "")) if os.name == "nt" else Path.home() / ".config"
    return base / "sops" / "age" / "keys.txt"


def keygen() -> None:
    # Cette méthode permet de générer la clé age de l'opérateur lorsqu'elle n'existe pas encore, puis d'afficher sa clé publique.
    path = key_file()
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run([tool("age-keygen"), "-o", str(path)], check=True)
    public = subprocess.run([tool("age-keygen"), "-y", str(path)], check=True, capture_output=True, text=True).stdout.strip()
    print(f"Clé privée : {path}\nClé publique à ajouter dans .sops.yaml : {public}")


def encrypt() -> None:
    # Cette méthode permet de regrouper tous les fichiers de ./secrets dans un JSON et de le chiffrer pour les destinataires de .sops.yaml.
    bundle = {p.name: p.read_text(encoding="utf-8") for p in sorted(SECRETS_DIR.iterdir())
              if p.is_file() and not p.name.startswith(".")}
    if not bundle:
        sys.exit("Aucun secret dans ./secrets : lancez d'abord python scripts/init_secrets.py")
    PLAINTEXT.write_text(json.dumps(bundle, indent=2), encoding="utf-8")
    try:
        subprocess.run([tool("sops"), "--encrypt", "--input-type", "json", "--output-type", "json",
                        "--output", str(ENCRYPTED), str(PLAINTEXT)], check=True, cwd=ROOT)
    finally:
        PLAINTEXT.unlink(missing_ok=True)
    print(f"{len(bundle)} secrets chiffrés dans {ENCRYPTED.name} (à versionner)")


def decrypt() -> None:
    # Cette méthode permet de restaurer les fichiers de ./secrets à partir du bundle chiffré, avec la clé age de l'opérateur.
    clear = subprocess.run([tool("sops"), "--decrypt", str(ENCRYPTED)], check=True, capture_output=True, text=True, cwd=ROOT).stdout
    SECRETS_DIR.mkdir(exist_ok=True)
    for name, content in json.loads(clear).items():
        (SECRETS_DIR / name).write_text(content, encoding="utf-8", newline="\n")
        print(f"  + {name}")


if __name__ == "__main__":
    commands = {"keygen": keygen, "encrypt": encrypt, "decrypt": decrypt}
    if len(sys.argv) != 2 or sys.argv[1] not in commands:
        sys.exit(__doc__)
    commands[sys.argv[1]]()
