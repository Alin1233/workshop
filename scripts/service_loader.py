"""Chargement des applications FastAPI hors conteneur (tests unitaires, export OpenAPI).

Les services nomment leur paquet `app` : chacun est chargé sous un alias distinct pour cohabiter
dans le même processus Python, avec le paquet commun `resilience_common` ajouté au chemin d'import.
"""

import importlib
import importlib.util
import sys
from pathlib import Path
from types import ModuleType

SERVICES_DIR = Path(__file__).resolve().parent.parent / "services"
ALIASES = {"auth-service": "auth_app", "payment-api": "payment_app", "ops-assistant": "ops_app",
           "remediation-engine": "remediation_app", "supervision-dashboard": "supervision_app"}
if str(SERVICES_DIR / "common") not in sys.path:
    sys.path.insert(0, str(SERVICES_DIR / "common"))


def load_service(service: str, submodule: str = "main") -> ModuleType:
    # Cette méthode permet d'importer un module du paquet `app` d'un service sous son alias (auth_app, payment_app),
    # en ne chargeant le paquet qu'une fois par processus (les métriques Prometheus sont globales).
    alias = ALIASES[service]
    if alias not in sys.modules:
        package_dir = SERVICES_DIR / service / "app"
        spec = importlib.util.spec_from_file_location(
            alias, package_dir / "__init__.py", submodule_search_locations=[str(package_dir)]
        )
        package = importlib.util.module_from_spec(spec)
        sys.modules[alias] = package
        spec.loader.exec_module(package)
    return importlib.import_module(f"{alias}.{submodule}")
