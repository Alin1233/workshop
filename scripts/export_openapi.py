"""Exporte la documentation OpenAPI des services dans docs/api/ (pièce jointe du rendu), sans démarrer la stack.

Usage : python scripts/export_openapi.py [--check]
  --check : n'écrit rien, code de sortie 1 si les fichiers versionnés ne correspondent plus au code.
Dépendances : celles des services (python -m pip install -r requirements-dev.txt).
"""

import json
import sys
from pathlib import Path

from service_loader import load_service

DOCS_DIR = Path(__file__).resolve().parent.parent / "docs" / "api"
# Préfixe sous lequel nginx publie chaque service (identique au ROOT_PATH du docker-compose).
PUBLIC_PREFIX = {"auth-service": "/api/auth", "payment-api": "/api/payments"}


def render(service: str) -> str:
    # Cette méthode permet de produire le document OpenAPI d'un service, avec l'URL publique derrière le WAF,
    # sous une forme texte stable (indentation fixe) pour que les différences restent lisibles dans Git.
    schema = dict(load_service(service).app.openapi())
    schema["servers"] = [{"url": PUBLIC_PREFIX[service], "description": "Via le WAF (http://<hôte>:8080)"}]
    return json.dumps(schema, indent=2, ensure_ascii=False) + "\n"


def outdated() -> list[Path]:
    # Cette méthode permet de lister les fichiers exportés absents ou différents du code actuel.
    return [path for service in PUBLIC_PREFIX
            if not (path := DOCS_DIR / f"{service}.openapi.json").exists() or path.read_text(encoding="utf-8") != render(service)]


def main() -> int:
    # Cette méthode permet d'écrire les documents OpenAPI, ou seulement de vérifier qu'ils sont à jour avec --check.
    if "--check" in sys.argv[1:]:
        stale = outdated()
        for path in stale:
            print(f"À régénérer : {path.relative_to(DOCS_DIR.parent.parent)}")
        return 1 if stale else 0
    DOCS_DIR.mkdir(parents=True, exist_ok=True)
    for service in PUBLIC_PREFIX:
        path = DOCS_DIR / f"{service}.openapi.json"
        path.write_text(render(service), encoding="utf-8", newline="\n")
        print(f"Écrit : {path.relative_to(DOCS_DIR.parent.parent)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
