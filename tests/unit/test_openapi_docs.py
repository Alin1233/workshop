"""La documentation d'API versionnée (docs/api/) doit correspondre au code des services."""

import json

import export_openapi


def test_exported_openapi_is_up_to_date():
    stale = [path.name for path in export_openapi.outdated()]
    assert not stale, f"Documentation d'API périmée : lancer python scripts/export_openapi.py ({stale})"


def test_internal_routes_are_not_documented():
    for service in export_openapi.PUBLIC_PREFIX:
        paths = json.loads(export_openapi.render(service))["paths"]
        assert not [path for path in paths if path.startswith(("/internal", "/metrics", "/.well-known"))]
