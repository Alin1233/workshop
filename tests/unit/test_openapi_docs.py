"""La documentation d'API versionnée (docs/api/) doit correspondre au code des services."""

import json

import export_openapi


def test_every_service_api_is_exported():
    assert {"auth-service", "payment-api", "remediation-engine"} <= set(export_openapi.SERVERS)
    for service in export_openapi.SERVERS:
        assert (export_openapi.DOCS_DIR / f"{service}.openapi.json").exists(), service


def test_exported_openapi_is_up_to_date():
    stale = [path.name for path in export_openapi.outdated()]
    assert not stale, f"Documentation d'API périmée : lancer python scripts/export_openapi.py ({stale})"


def test_internal_routes_are_not_documented():
    for service in export_openapi.SERVERS:
        paths = json.loads(export_openapi.render(service))["paths"]
        assert not [path for path in paths if path.startswith(("/internal", "/metrics", "/.well-known"))]


def test_remediation_webhook_is_documented_with_bearer_auth():
    schema = json.loads(export_openapi.render("remediation-engine"))
    operation = schema["paths"]["/alerts"]["post"]
    scheme = schema["components"]["securitySchemes"][next(iter(operation["security"][0]))]
    assert (scheme["type"], scheme["scheme"]) == ("http", "bearer")
    assert {"202", "401", "503"} <= set(operation["responses"])
    assert operation["requestBody"]["content"]["application/json"]["schema"]["required"] == ["alerts"]


def test_remediation_state_api_is_documented_read_only():
    paths = json.loads(export_openapi.render("remediation-engine"))["paths"]
    assert {"/api/state", "/api/incidents", "/api/incidents/{incident_id}", "/api/decision-table"} <= set(paths)
    assert {path: set(methods) for path, methods in paths.items() if set(methods) != {"get"}} == {"/alerts": {"post"}}
