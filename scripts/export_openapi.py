"""Exporte la documentation OpenAPI des services dans docs/api/ (pièce jointe du rendu), sans démarrer la stack.

Usage : python scripts/export_openapi.py [--check]
  --check : n'écrit rien, code de sortie 1 si les fichiers versionnés ne correspondent plus au code.
Dépendances : celles des services (python -m pip install -r requirements-dev.txt).
Aucun secret ni service n'est nécessaire : les applications sont importées sans exécuter leur lifespan.
"""

import copy
import json
import sys
from pathlib import Path

from service_loader import load_service

DOCS_DIR = Path(__file__).resolve().parent.parent / "docs" / "api"
VIA_WAF = "Via le WAF (http://<hôte>:8080)"
# Adresse sous laquelle chaque service est joint : préfixe publié par nginx derrière le WAF (identique au ROOT_PATH du
# docker-compose) ou, pour le moteur de remédiation, son nom sur les réseaux Docker internes (aucun port publié).
SERVERS = {
    "auth-service": {"url": "/api/auth", "description": VIA_WAF},
    "payment-api": {"url": "/api/payments", "description": VIA_WAF},
    "remediation-engine": {"url": "http://remediation-engine:8000",
                           "description": "Réseaux Docker internes obs, app et dmz uniquement : aucun port publié"},
}

_ERROR = {"application/json": {"schema": {"type": "object", "properties": {"detail": {"type": "string"}}}}}
# Le webhook du moteur lit son corps brut et vérifie lui-même le jeton porteur (sans dépendance de sécurité FastAPI) :
# FastAPI n'en déduit ni le schéma d'authentification, ni le corps, ni les refus. Ils sont décrits ici, et seulement
# s'ils manquent : s'ils sont un jour déclarés dans l'application (openapi_extra, responses), ce sont eux qui priment.
WEBHOOK_AUTH = {"HTTPBearer": {
    "type": "http", "scheme": "bearer",
    "description": "Jeton partagé avec Alertmanager (secret Compose remediation_webhook_token), relu à chaque appel"}}
WEBHOOK_OPERATION = {
    "security": [{"HTTPBearer": []}],
    "requestBody": {"required": True, "description": "Notification webhook d'Alertmanager (version 4), 1 Mio au plus",
                    "content": {"application/json": {"schema": {
                        "type": "object", "required": ["alerts"],
                        "properties": {
                            "version": {"type": "string"}, "groupKey": {"type": "string"},
                            "status": {"type": "string", "enum": ["firing", "resolved"]},
                            "receiver": {"type": "string"},
                            "alerts": {"type": "array", "items": {"type": "object", "properties": {
                                "status": {"type": "string", "enum": ["firing", "resolved"]},
                                "labels": {"type": "object", "additionalProperties": {"type": "string"}},
                                "annotations": {"type": "object", "additionalProperties": {"type": "string"}},
                                "startsAt": {"type": "string", "format": "date-time"},
                                "endsAt": {"type": "string", "format": "date-time"},
                                "fingerprint": {"type": "string"}}}}}}}}},
    "responses": {
        "400": {"description": "Notification Alertmanager invalide (champ alerts manquant)", "content": _ERROR},
        "401": {"description": "Jeton absent ou invalide (refus journalisé et compté)", "content": _ERROR,
                "headers": {"WWW-Authenticate": {"schema": {"type": "string", "const": "Bearer"}}}},
        "413": {"description": "Notification trop volumineuse (plus de 1 Mio)", "content": _ERROR},
        "503": {"description": "Jeton du webhook non configuré : aucune alerte n'est traitée", "content": _ERROR},
    },
}


def document_webhook(schema: dict) -> None:
    # Cette méthode permet de compléter l'opération POST /alerts du moteur (authentification, corps, refus) sans
    # écraser ce que l'application déclarerait elle-même.
    operation = schema["paths"]["/alerts"]["post"]
    schemes = schema.setdefault("components", {}).setdefault("securitySchemes", {})
    for name, scheme in WEBHOOK_AUTH.items():
        schemes.setdefault(name, scheme)
    responses = operation.pop("responses", {})
    operation.setdefault("security", WEBHOOK_OPERATION["security"])
    operation.setdefault("requestBody", WEBHOOK_OPERATION["requestBody"])
    operation["responses"] = dict(sorted({**WEBHOOK_OPERATION["responses"], **responses}.items()))


def render(service: str) -> str:
    # Cette méthode permet de produire le document OpenAPI d'un service, avec l'adresse par laquelle il est joint,
    # sous une forme texte stable (indentation fixe) pour que les différences restent lisibles dans Git.
    schema = copy.deepcopy(load_service(service).app.openapi())
    if service == "remediation-engine":
        document_webhook(schema)
    schema["servers"] = [SERVERS[service]]
    return json.dumps(schema, indent=2, ensure_ascii=False) + "\n"


def outdated() -> list[Path]:
    # Cette méthode permet de lister les fichiers exportés absents ou différents du code actuel.
    return [path for service in SERVERS
            if not (path := DOCS_DIR / f"{service}.openapi.json").exists() or path.read_text(encoding="utf-8") != render(service)]


def main() -> int:
    # Cette méthode permet d'écrire les documents OpenAPI, ou seulement de vérifier qu'ils sont à jour avec --check.
    if "--check" in sys.argv[1:]:
        stale = outdated()
        for path in stale:
            print(f"À régénérer : {path.relative_to(DOCS_DIR.parent.parent)}")
        return 1 if stale else 0
    DOCS_DIR.mkdir(parents=True, exist_ok=True)
    for service in SERVERS:
        path = DOCS_DIR / f"{service}.openapi.json"
        path.write_text(render(service), encoding="utf-8", newline="\n")
        print(f"Écrit : {path.relative_to(DOCS_DIR.parent.parent)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
