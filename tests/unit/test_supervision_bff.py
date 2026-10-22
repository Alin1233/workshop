"""Tests du back-for-front du dashboard de supervision, sans réseau : fausses sources derrière un transport httpx.

Couvrent l'authentification (basique, à temps constant, /health seul public), le caractère en lecture seule (GET
uniquement, aucune écriture relayée, chemins fermés par source), l'absence de requête fournie par le client (PromQL et
LogQL constants, limites bornées, identifiant d'incident validé), le comportement quand une source tombe (réponse 200,
erreur par source, healthcheck intact) et la mise en forme : carte des composants, bandeau d'état à chaque phase de
l'incident, alertes, fil d'événements, blocages d'IP, cache partagé.
"""

import asyncio
import base64
import copy
import json
import secrets
from datetime import datetime, timezone
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from fastapi.testclient import TestClient

from service_loader import load_service

main = load_service("supervision-dashboard", "main")
config = load_service("supervision-dashboard", "config")
sources_mod = load_service("supervision-dashboard", "sources")
shaping = load_service("supervision-dashboard", "shaping")

# Identifiants générés à chaque session : aucun secret, même factice, n'est écrit dans le dépôt.
UI_PASSWORD = secrets.token_urlsafe(18)
PROM_PASSWORD = secrets.token_urlsafe(18)
AM_PASSWORD = secrets.token_urlsafe(18)

NOW = datetime(2026, 10, 20, 7, 42, 18, 700000, tzinfo=timezone.utc).timestamp()


def at(offset_s: float) -> str:
    # Cette méthode permet d'écrire un horodatage ISO relatif à l'instant de référence des tests.
    return shaping.iso(NOW + offset_s)


# ─────────────────────────────── données au format réel ───────────────────────────────

def series(name: str, value: float, **labels) -> dict:
    # Cette méthode permet de construire une série d'un vecteur Prometheus.
    return {"metric": {"__name__": name, **labels}, "value": [NOW, str(value)]}


def healthy_metrics(payments_probe: float = 1, payments_code: float = 200, payment_up: float = 1,
                    frontend_probe: float = 1, frontend_code: float = 200, auth_probe: float = 1,
                    auth_code: float = 200, scores=(0.0, 0.0, 0.0)) -> list[dict]:
    # Cette méthode permet de produire la réponse de METRICS_QUERY d'une stack saine (paramètres pour la dégrader).
    probes = (("frontend", "http://waf:8080/", frontend_probe, frontend_code),
              ("auth", "http://waf:8080/api/auth/health", auth_probe, auth_code),
              ("payments", "http://waf:8080/api/payments/health", payments_probe, payments_code))
    result = []
    for service, instance, ok, code in probes:
        result.append(series("probe_success", ok, instance=instance, job="blackbox-http", service=service))
        result.append(series("probe_http_status_code", code, instance=instance, job="blackbox-http", service=service))
    result += [
        series("up", 1, instance="auth-service:8000", job="auth-service", service="auth-service"),
        series("up", payment_up, instance="payment-api:8000", job="payment-api", service="payment-api"),
        series("payment_ledger_integrity_ok", 1, instance="payment-api:8000", job="payment-api", service="payment-api"),
        series("payment_ledger_integrity_last_check_timestamp", NOW - 4, job="payment-api", service="payment-api"),
        series("up", 1, instance="loki:3100", job="observability", service="loki"),
        series("up", 1, instance="alloy:12345", job="observability", service="alloy"),
        series("up", 1, instance="blackbox:9115", job="observability", service="blackbox"),
        series("up", 1, instance="alertmanager:9093", job="alertmanager", service="alertmanager"),
        series("up", 1, instance="localhost:9090", job="prometheus", service="prometheus"),
        series("up", 1, instance="anomaly-detector:8000", job="anomaly-detector", service="anomaly-detector"),
        series("up", 1, instance="remediation-engine:8000", job="remediation-engine", service="remediation-engine"),
        series("anomaly_threshold", 0.8, job="anomaly-detector", service="anomaly-detector"),
        series("anomaly_detector_source_up", 1, job="anomaly-detector", service="anomaly-detector", source="prometheus"),
        series("anomaly_detector_source_up", 1, job="anomaly-detector", service="anomaly-detector", source="loki"),
    ]
    for service, score in zip(("auth-service", "payment-api", "frontend"), scores):
        result.append(series("anomaly_score", score, job="anomaly-detector", service=service))
    return result


DECISION = {"kind": "act", "nature": "availability", "reason": "payment-api est exited : redémarrage de payment-api",
            "action": "restart", "service": "payment-api", "target": "payment-api", "chain": ["postgres", "payment-api"],
            "limits": "restart", "checks": ["containers", "probes", "witness"], "when_healthy": "restart",
            "evidence": {"containers": {"postgres": "healthy", "payment-api": "exited"}}}


def incident(state: str = "verifying", open_: bool = True, **extra) -> dict:
    # Cette méthode permet de reproduire un incident réel du moteur (ServiceDown + EndToEndProbeFailed sur payment-api,
    # inc-20261020-074212, relevé sur la pile locale), arrêté à l'état demandé.
    timeline = [
        {"ts": NOW - 6.3, "at": at(-6.3), "state": "detected", "event": "state:detected",
         "detail": {"alertname": "ServiceDown", "summary": "payment-api ne répond plus au scrape Prometheus"}},
        {"ts": NOW - 6.28, "at": at(-6.28), "state": "detected", "event": "alert:correlated",
         "detail": {"alertname": "EndToEndProbeFailed", "fingerprint": "fp-probe"}},
        {"ts": NOW - 6.27, "at": at(-6.27), "state": "decided", "event": "state:decided", "detail": DECISION},
        {"ts": NOW - 6.26, "at": at(-6.26), "state": "acting", "event": "state:acting",
         "detail": {"action": "restart", "target": "payment-api"}},
        {"ts": NOW - 6.1, "at": at(-6.1), "state": "acting", "event": "action:start",
         "detail": {"target": "payment-api", "result": "success", "previous": "exited"}},
        {"ts": NOW - 0.08, "at": at(-0.08), "state": "verifying", "event": "state:verifying",
         "detail": {"checks": ["containers", "probes", "witness"]}},
        {"ts": NOW - 0.05, "at": at(-0.05), "state": "verifying", "event": "verification:containers",
         "detail": {"containers": {"postgres": "healthy", "payment-api": "healthy"}, "result": "ok", "check_ms": 7}},
    ]
    if state == "recovered":
        timeline += [
            {"ts": NOW, "at": at(0), "state": "verifying", "event": "verification:probes",
             "detail": {"probes": {"auth": 1.0, "frontend": 1.0, "payments": 1.0}, "result": "ok", "check_ms": 1}},
            {"ts": NOW + 0.4, "at": at(0.4), "state": "verifying", "event": "verification:witness",
             "detail": {"duration_ms": 417, "result": "ok", "steps": [{"step": "virement", "ok": True, "status": 201}]}},
            {"ts": NOW + 0.4, "at": at(0.4), "state": "recovered", "event": "state:recovered",
             "detail": {"reason": "vérification réussie"}}]
    data = {
        "id": "inc-20261020-074212-d07757", "key": "service:payment-api", "alertname": "ServiceDown",
        "rule": "ServiceDown", "strategy": "restart", "nature": "availability", "domain": "availability",
        "severity": "critical", "service": "payment-api", "state": state, "open": open_, "outcome": None,
        "attempts": 1, "created_at": at(-6.3), "updated_at": at(-0.05), "closed_at": None,
        "recovered_at": at(0.4) if state == "recovered" else None, "alert_started_at": at(-15.0),
        "duration_s": 6.7 if state == "recovered" else None, "alerts": ["EndToEndProbeFailed", "ServiceDown"],
        "decision": DECISION, "escalation": None,
        "last_action": {"ts": NOW - 6.1, "at": at(-6.1), "action": "start", "target": "payment-api",
                        "result": "success", "duration_ms": 160, "previous": "exited"},
        "timeline": timeline,
    }
    if state == "recovered":
        data["outcome"] = "recovered"
    data.update(extra)
    return data


def summary(item: dict) -> dict:
    # Cette méthode permet de réduire un incident complet à son résumé (forme de /api/state et /api/incidents).
    return {k: v for k, v in item.items() if k != "timeline"}


def engine_state(open_incidents=(), recent=(), blocked=(), bridge=None, deps=None) -> dict:
    # Cette méthode permet de reproduire la réponse de GET /api/state du moteur.
    return {
        "engine": {"service": "remediation-engine", "started_at": at(-3600), "uptime_s": 3600},
        "open_incidents": [summary(i) for i in open_incidents],
        "recent_incidents": [summary(i) for i in recent],
        "blocked_ips": list(blocked),
        "bridge": bridge or {"configured": True, "available": True, "runner": "systemd", "heartbeat_age_s": 3.2,
                             "busy": False, "active_request_id": None, "in_flight_request_id": None},
        "dependencies": deps or {"docker_proxy": True, "prometheus": True, "loki": True, "waf_blocklist": True,
                                 "restore_bridge": True, "state_store": True, "checked_at": at(-2)},
        "families": {}, "decision_table": 21,
    }


def loki_stream(labels: dict, *lines: tuple[float, dict]) -> dict:
    # Cette méthode permet de construire un flux Loki (horodatages en nanosecondes, lignes JSON).
    return {"stream": labels, "values": [[str(int((NOW + offset) * 1e9)), json.dumps(line)] for offset, line in lines]}


class FakeSources:
    """Les quatre sources simulées : réponses modifiables, pannes à la demande, requêtes enregistrées."""

    def __init__(self):
        # Cette méthode permet de partir d'une stack saine, sans incident.
        self.metrics = healthy_metrics()
        self.prom_alerts: list = []
        self.am_alerts: list = []
        self.state = engine_state()
        self.incidents: dict[str, dict] = {}
        self.story: list = []
        self.attack: list = []
        self.down: set[str] = set()
        self.requests: list[httpx.Request] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        # Cette méthode permet de répondre comme la source visée (selon l'hôte), ou d'échouer comme une source arrêtée.
        self.requests.append(request)
        host, path = request.url.host, request.url.path
        if host in self.down:
            raise httpx.ConnectError("connexion refusée", request=request)
        if host == "prometheus":
            if not self._authorized(request, PROM_PASSWORD):
                return httpx.Response(401)
            if path == "/api/v1/query":
                return httpx.Response(200, json={"status": "success",
                                                 "data": {"resultType": "vector", "result": self.metrics}})
            if path == "/api/v1/alerts":
                return httpx.Response(200, json={"status": "success", "data": {"alerts": self.prom_alerts}})
        if host == "alertmanager":
            if not self._authorized(request, AM_PASSWORD):
                return httpx.Response(401)
            if path == "/api/v2/alerts":
                return httpx.Response(200, json=self.am_alerts)
        if host == "loki" and path == "/loki/api/v1/query_range":
            query = request.url.params["query"]
            result = self.story if query == sources_mod.STORY_EVENTS_QUERY else self.attack
            return httpx.Response(200, json={"status": "success", "data": {"resultType": "streams", "result": result}})
        if host == "remediation-engine":
            if path == "/api/state":
                return httpx.Response(200, json=self.state)
            if path == "/api/incidents":
                return httpx.Response(200, json=[summary(i) for i in self.incidents.values()])
            if path.startswith("/api/incidents/"):
                found = self.incidents.get(path.rsplit("/", 1)[1])
                return httpx.Response(200, json=found) if found else httpx.Response(404, json={"detail": "x"})
        return httpx.Response(404)

    @staticmethod
    def _authorized(request: httpx.Request, password: str) -> bool:
        # Cette méthode permet de vérifier l'identifiant basique envoyé à Prometheus ou Alertmanager.
        expected = "Basic " + base64.b64encode(f"admin:{password}".encode()).decode()
        return request.headers.get("authorization") == expected


@pytest.fixture()
def fake() -> FakeSources:
    return FakeSources()


@pytest.fixture()
def make_client(tmp_path, fake):
    # Cette méthode permet de démarrer le back-for-front contre les fausses sources (cache désactivé par défaut).
    for name, value in (("ui", UI_PASSWORD), ("prom", PROM_PASSWORD), ("am", AM_PASSWORD)):
        (tmp_path / name).write_text(value + "\n", encoding="utf-8")
    static = tmp_path / "static"
    (static / "assets").mkdir(parents=True)
    (static / "index.html").write_text("<!doctype html><title>Supervision</title>", encoding="utf-8")
    clients = []

    def build(cache_ttl_s: float = 0.0, ui_password: bool = True, now: float = NOW) -> TestClient:
        settings = config.Settings(
            prometheus_password_file=str(tmp_path / "prom"), alertmanager_password_file=str(tmp_path / "am"),
            auth_password_file=str(tmp_path / "ui") if ui_password else str(tmp_path / "absent"),
            static_dir=str(static), cache_ttl_s=cache_ttl_s, timeout_s=0.5)
        app = main.create_app(settings, transport=httpx.MockTransport(fake.handler), clock=lambda: now)
        client = TestClient(app)
        client.__enter__()
        clients.append(client)
        return client

    yield build
    for client in clients:
        client.__exit__(None, None, None)


def auth(password: str = UI_PASSWORD, user: str = "admin") -> dict:
    # Cette méthode permet de construire l'en-tête d'authentification basique de l'interface.
    return {"Authorization": "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()}


API_PATHS = ["/api/overview", "/api/alerts", "/api/incidents", "/api/incidents/current", "/api/blocks", "/api/events"]


# ─────────────────────────────── authentification ───────────────────────────────

def test_health_is_public_minimal_and_touches_no_source(make_client, fake):
    client = make_client()
    fake.down = {"prometheus", "alertmanager", "loki", "remediation-engine"}
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"service": "supervision-dashboard", "status": "ok"}
    assert fake.requests == []


@pytest.mark.parametrize("path", ["/", *API_PATHS, "/api/incidents/inc-20261020-074212-d07757"])
def test_everything_else_requires_the_password(make_client, fake, path):
    client = make_client()
    fake.incidents = {"inc-20261020-074212-d07757": incident()}
    anonymous = client.get(path)
    assert anonymous.status_code == 401
    assert anonymous.headers["www-authenticate"].startswith("Basic ")
    assert client.get(path, headers=auth(secrets.token_urlsafe(18))).status_code == 401
    assert client.get(path, headers=auth(UI_PASSWORD, user="root")).status_code == 401
    assert client.get(path, headers={"Authorization": "Basic !!!"}).status_code == 401
    assert fake.requests == []
    assert client.get(path, headers=auth()).status_code == 200


def test_missing_password_refuses_everything_but_health(make_client):
    client = make_client(ui_password=False)
    assert client.get("/api/overview", headers=auth()).status_code == 503
    assert client.get("/health").status_code == 200


def test_page_has_strict_csp_and_security_headers(make_client):
    client = make_client()
    page = client.get("/", headers=auth())
    assert page.status_code == 200
    assert "script-src 'self'" in page.headers["content-security-policy"]
    assert "frame-ancestors 'none'" in page.headers["content-security-policy"]
    assert page.headers["x-frame-options"] == "DENY"
    assert "camera=()" in page.headers["permissions-policy"]
    assert client.get("/api/overview", headers=auth()).headers["cache-control"] == "no-store"


def test_no_credential_reaches_the_browser(make_client, fake):
    client = make_client()
    fake.state = engine_state(open_incidents=[incident()])
    fake.incidents = {"inc-20261020-074212-d07757": incident()}
    bodies = "".join(client.get(path, headers=auth()).text for path in API_PATHS)
    for value in (UI_PASSWORD, PROM_PASSWORD, AM_PASSWORD):
        assert value not in bodies
    # Prometheus et Alertmanager ont bien reçu leur identifiant, Loki et le moteur aucun
    for request in fake.requests:
        has_auth = "authorization" in request.headers
        assert has_auth == (request.url.host in ("prometheus", "alertmanager"))


# ─────────────────────────────── lecture seule, requêtes prédéfinies ───────────────────────────────

def test_application_declares_only_get_routes(make_client):
    client = make_client()
    for route in client.app.routes:
        methods = getattr(route, "methods", None)
        if methods:
            assert methods <= {"GET", "HEAD"}, route.path


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
def test_writes_are_refused_and_never_relayed(make_client, fake, method):
    client = make_client()
    for path in [*API_PATHS, "/alerts", "/api/alerts/silences", "/api/v2/silences", "/api/state"]:
        response = client.request(method, path, headers=auth(), json={"alerts": []})
        assert response.status_code == 405, path
    assert fake.requests == []


def test_client_supplied_queries_are_ignored(make_client, fake):
    client = make_client()
    hostile = {"query": "count(up)", "promql": "up", "logql": '{service="auth-service"}', "path": "/alerts",
               "url": "http://remediation-engine:8000/alerts", "start": "0", "direction": "forward"}
    for path in API_PATHS:
        assert client.get(path, params=hostile, headers=auth()).status_code == 200
    assert fake.requests
    allowed = {("prometheus", "/api/v1/query"), ("prometheus", "/api/v1/alerts"), ("alertmanager", "/api/v2/alerts"),
               ("loki", "/loki/api/v1/query_range"), ("remediation-engine", "/api/state"),
               ("remediation-engine", "/api/incidents")}
    for request in fake.requests:
        assert request.method == "GET"
        assert (request.url.host, request.url.path) in allowed
        params = parse_qs(urlsplit(str(request.url)).query)
        if request.url.path == "/api/v1/query":
            assert params["query"] == [sources_mod.METRICS_QUERY]
        if request.url.host == "loki":
            assert params["query"][0] in (sources_mod.STORY_EVENTS_QUERY, sources_mod.ATTACK_EVENTS_QUERY)
            assert params["direction"] == ["backward"]
            assert int(params["limit"][0]) <= sources_mod.ATTACK_EVENTS_LIMIT
        if request.url.path == "/api/incidents":
            assert params["limit"] == [str(sources_mod.ENGINE_INCIDENTS_LIMIT)]


@pytest.mark.parametrize("path", ["/api/events?limit=1000", "/api/events?limit=0", "/api/incidents?limit=21",
                                  "/api/incidents?limit=-1"])
def test_limits_are_bounded(make_client, fake, path):
    client = make_client()
    assert client.get(path, headers=auth()).status_code == 422
    assert fake.requests == []


@pytest.mark.parametrize("incident_id", ["..%2F..%2Falerts", "inc-1", "inc-20261020-074212-D07757%3Fx",
                                         "inc-20261020-074212-d07757%2F..", "state"])
def test_incident_id_is_validated_before_any_call(make_client, fake, incident_id):
    client = make_client()
    response = client.get(f"/api/incidents/{incident_id}", headers=auth())
    assert response.status_code == 404
    assert all(r.url.host != "remediation-engine" or r.url.path == "/api/state" for r in fake.requests)


def test_upstream_refuses_paths_outside_its_allowlist(make_client):
    client = make_client()
    sources = client.app.state.sources
    for upstream, path in ((sources.engine, "/alerts"), (sources.alertmanager, "/api/v2/silences"),
                           (sources.prometheus, "/api/v1/admin/tsdb/delete_series"), (sources.loki, "/loki/api/v1/push"),
                           (sources.engine, "/api/incidents/../alerts")):
        with pytest.raises(ValueError):
            asyncio.run(upstream.get(path))


def test_incident_detail_is_relayed_and_sensitive_keys_are_removed(make_client, fake):
    client = make_client()
    item = incident()
    item["timeline"][-1]["detail"]["api_token"] = secrets.token_urlsafe(12)
    fake.incidents = {item["id"]: item}
    body = client.get(f"/api/incidents/{item['id']}", headers=auth()).json()
    assert body["sources"]["engine"]["ok"] is True
    assert body["incident"]["timeline"][-1]["event"] == "verification:containers"
    assert "api_token" not in json.dumps(body)
    missing = client.get("/api/incidents/inc-20261020-000000-abcdef", headers=auth())
    assert missing.status_code == 404


# ─────────────────────────────── sources en panne ───────────────────────────────

def test_every_endpoint_answers_when_all_sources_are_down(make_client, fake):
    client = make_client()
    fake.down = {"prometheus", "alertmanager", "loki", "remediation-engine"}
    for path in API_PATHS:
        response = client.get(path, headers=auth())
        assert response.status_code == 200, path
        body = response.json()
        assert body["sources"] and all(not s["ok"] for s in body["sources"].values()), path
        assert all(s["error"] == "injoignable" for s in body["sources"].values())
    overview = client.get("/api/overview", headers=auth()).json()
    assert overview["status"]["phase"] == "unknown"
    states = {c["id"]: c["state"] for c in overview["components"]}
    assert states["waf"] == "unknown" and states["remediation-engine"] == "down"
    assert client.get("/health").status_code == 200


def test_engine_down_keeps_the_rest_of_the_screen(make_client, fake):
    client = make_client()
    fake.down = {"remediation-engine"}
    fake.metrics = healthy_metrics(payments_probe=0, payments_code=502)
    body = client.get("/api/overview", headers=auth()).json()
    assert body["sources"]["prometheus"]["ok"] and not body["sources"]["engine"]["ok"]
    assert body["status"]["phase"] == "incident"
    assert any("moteur de remédiation injoignable" in note for note in body["status"]["notes"])
    states = {c["id"]: c for c in body["components"]}
    assert states["payment-api"]["state"] == "down"
    assert states["remediation-engine"]["state"] == "down"
    assert client.get("/api/blocks", headers=auth()).json()["blocks"] == []


def test_wrong_source_credentials_are_reported_not_raised(make_client, fake, tmp_path):
    client = make_client()
    (tmp_path / "prom").write_text(secrets.token_urlsafe(10), encoding="utf-8")
    body = client.get("/api/overview", headers=auth()).json()
    assert body["sources"]["prometheus"] == {**body["sources"]["prometheus"], "ok": False,
                                             "error": "identifiant refusé (HTTP 401)"}


def test_shared_cache_sends_one_request_for_many_browsers(make_client, fake):
    client = make_client(cache_ttl_s=60)
    for _ in range(5):
        client.get("/api/overview", headers=auth())
        client.get("/api/blocks", headers=auth())
    state_calls = [r for r in fake.requests if r.url.path == "/api/state"]
    query_calls = [r for r in fake.requests if r.url.path == "/api/v1/query"]
    assert len(state_calls) == 1 and len(query_calls) == 1


def test_cache_single_flight_under_concurrency():
    calls = []

    async def scenario():
        cache = sources_mod.Cache(ttl_s=10)

        async def loader():
            calls.append(1)
            await asyncio.sleep(0.05)
            return {"ok": True}
        results = await asyncio.gather(*(cache.get("k", "engine", loader) for _ in range(10)))
        return results
    results = asyncio.run(scenario())
    assert len(calls) == 1 and all(r.ok and r.data == {"ok": True} for r in results)


# ─────────────────────────────── bandeau et carte : les phases de l'incident ───────────────────────────────

def overview(client) -> dict:
    # Cette méthode permet de lire la vue d'ensemble (bandeau + composants).
    return client.get("/api/overview", headers=auth()).json()


def test_operational_before_the_incident(make_client):
    body = overview(make_client())
    assert body["status"]["phase"] == "operational"
    assert all(c["state"] == "ok" for c in body["components"]), body["components"]
    assert body["integrity"] == {"ok": True, "last_check_age_s": 4.0}
    assert {s["service"] for s in body["anomaly"]["scores"]} == {"auth-service", "payment-api", "frontend"}


def test_anomaly_seen_by_probes_before_any_alert(make_client, fake):
    client = make_client()
    fake.metrics = healthy_metrics(payments_probe=0, payments_code=502)
    body = overview(client)
    assert body["status"]["phase"] == "incident"
    assert body["status"]["step"] == "Anomalie détectée par les sondes : payment-api en échec"
    assert body["status"]["since"] == at(0)
    comp = {c["id"]: c for c in body["components"]}
    assert comp["payment-api"]["state"] == "down" and "HTTP 502" in comp["payment-api"]["reason"]
    assert comp["postgres"]["state"] == "ok" and comp["auth-service"]["state"] == "ok"
    # Prometheus confirme : alerte en attente, datée de sa première évaluation
    fake.prom_alerts = [{"labels": {"alertname": "ServiceDown", "service": "payment-api", "severity": "critical"},
                         "state": "pending", "activeAt": at(-8)}]
    body = overview(client)
    assert body["status"]["step"] == "Anomalie détectée : ServiceDown en cours de confirmation"
    assert body["status"]["since"] == at(-8)


def test_remediation_phase_follows_the_engine_timeline(make_client, fake):
    client = make_client()
    item = incident("verifying")
    fake.state = engine_state(open_incidents=[item])
    fake.incidents = {item["id"]: item}
    status = overview(client)["status"]
    assert status["phase"] == "remediation"
    assert status["step"] == "Vérification : sondes de bout en bout"
    assert status["decision"] == "Disponibilité · redémarrage de payment-api"
    assert status["incident_id"] == item["id"] and status["since"] == at(-15.0)
    acting = incident("acting", timeline=incident()["timeline"][:5])
    fake.state = engine_state(open_incidents=[acting])
    fake.incidents = {acting["id"]: acting}
    status = overview(client)["status"]
    assert (status["phase"], status["step"]) == ("remediation", "Action : redémarrage de payment-api")
    detected = incident("detected", timeline=incident()["timeline"][:1], decision=None)
    fake.state = engine_state(open_incidents=[detected])
    fake.incidents = {detected["id"]: detected}
    status = overview(client)["status"]
    assert (status["phase"], status["step"]) == ("incident", "Alerte ServiceDown reçue par le moteur")


def test_episode_start_is_kept_from_the_first_probe_failure(make_client, fake):
    fake.metrics = healthy_metrics(payments_probe=0, payments_code=502)
    early = make_client(now=NOW - 40)
    overview(early)
    # Le même processus voit ensuite l'incident du moteur : le chronomètre part de la première anomalie observée
    item = incident("recovered")
    fake.metrics = healthy_metrics()
    fake.state = engine_state(open_incidents=[item])
    fake.incidents = {item["id"]: item}
    early.app.state.sources.cache.ttl_s = 0
    status = overview(early)["status"]
    assert status["phase"] == "restored"
    assert status["reaction_s"] == 6.7
    # Sans mémoire de l'épisode (autre processus) : début = déclenchement de l'alerte
    fresh = overview(make_client())["status"]
    assert fresh["since"] == at(-15.0) and fresh["duration_s"] == 15.4


def test_restored_after_closure_then_operational(make_client, fake):
    item = incident("recovered", open_=False, closed_at=at(23))
    fake.state = engine_state(recent=[item])
    status = overview(make_client(now=NOW + 60))["status"]
    assert status["phase"] == "restored"
    assert status["step"] == "Service rétabli et vérifié · incident clos"
    assert status["duration_s"] == 15.4 and status["reaction_s"] == 6.7
    assert overview(make_client(now=NOW + 23 + 181))["status"]["phase"] == "operational"


def test_escalated_incident_stays_red(make_client, fake):
    item = incident("escalated", escalation={"reason": "attempts_exhausted", "message": "budget épuisé"})
    fake.state = engine_state(open_incidents=[item])
    status = overview(make_client())["status"]
    assert status["phase"] == "incident" and status["escalated"] is True
    assert status["step"] == "Escaladé à l'opérateur : budget épuisé"


def test_infrastructure_incidents_do_not_drive_the_banner(make_client, fake):
    item = incident("escalated", alertname="BackupMissing", rule="BackupMissing", nature="operator",
                    id="inc-20261020-080000-aaaaaa")
    fake.state = engine_state(open_incidents=[item])
    status = overview(make_client())["status"]
    assert status["phase"] == "operational"
    assert any("BackupMissing" in note for note in status["notes"])


def test_restore_in_progress_marks_stopped_apis_as_intentional(make_client, fake):
    client = make_client()
    item = incident("acting", alertname="LedgerIntegrityBroken", rule="LedgerIntegrityBroken", nature="compromise",
                    decision={**DECISION, "nature": "compromise", "action": "restore_db", "target": "paydb"},
                    timeline=incident()["timeline"][:4] + [
                        {"ts": NOW, "at": at(0), "state": "acting", "event": "restore:requested", "detail": {}}])
    fake.state = engine_state(open_incidents=[item], bridge={"configured": True, "available": True, "busy": True,
                                                              "runner": "systemd", "heartbeat_age_s": 1.0})
    fake.incidents = {item["id"]: item}
    fake.metrics = [s for s in healthy_metrics(payments_probe=0, payments_code=502, auth_probe=0, auth_code=502,
                                               payment_up=0)]
    body = overview(client)
    comp = {c["id"]: c for c in body["components"]}
    assert comp["postgres"]["state"] == "active" and comp["restore-bridge"]["state"] == "active"
    assert comp["payment-api"]["state"] == "active"
    assert body["status"]["phase"] == "remediation"
    assert body["status"]["step"] == "Action : restauration de la base par le pont de l'hôte"
    assert body["status"]["decision"] == "Compromission · restauration de la base (dernière sauvegarde saine)"


def test_components_distinguish_waf_down_from_frontend_down(make_client, fake):
    client = make_client()
    fake.metrics = healthy_metrics(frontend_probe=0, frontend_code=0, auth_probe=0, auth_code=0,
                                   payments_probe=0, payments_code=0)
    comp = {c["id"]: c for c in overview(client)["components"]}
    assert comp["waf"]["state"] == "down" and comp["frontend"]["state"] == "unknown"
    fake.metrics = healthy_metrics(frontend_probe=0, frontend_code=502, auth_probe=0, auth_code=502,
                                   payments_probe=0, payments_code=502)
    comp = {c["id"]: c for c in overview(client)["components"]}
    assert comp["waf"]["state"] == "ok" and comp["frontend"]["state"] == "down"
    assert comp["auth-service"]["state"] == "degraded"


def test_database_down_is_inferred_from_both_apis(make_client, fake):
    fake.metrics = healthy_metrics(auth_probe=0, auth_code=503, payments_probe=0, payments_code=503)
    comp = {c["id"]: c for c in overview(make_client())["components"]}
    assert comp["postgres"]["state"] == "down"
    assert comp["payment-api"]["state"] == "down" and "HTTP 503" in comp["payment-api"]["reason"]


def test_ml_anomaly_and_degraded_engine_dependencies(make_client, fake):
    fake.metrics = healthy_metrics(scores=(0.95, 0.1, float("nan")))
    fake.state = engine_state(deps={"docker_proxy": False, "prometheus": True, "loki": True, "waf_blocklist": True,
                                    "restore_bridge": False, "state_store": True},
                              bridge={"configured": True, "available": False, "runner": "dev",
                                      "heartbeat_age_s": 1744.7})
    body = overview(make_client())
    comp = {c["id"]: c for c in body["components"]}
    assert comp["anomaly-detector"]["state"] == "degraded"
    assert comp["anomaly-detector"]["reason"] == "anomalie détectée : auth-service (score 0,95 ≥ 0,80)"
    assert comp["remediation-engine"]["state"] == "degraded" and "docker_proxy" in comp["remediation-engine"]["reason"]
    assert comp["restore-bridge"]["state"] == "degraded" and "29 min" in comp["restore-bridge"]["reason"]
    assert body["status"]["phase"] == "incident" and "modèle ML" in body["status"]["step"]
    assert {"service": "frontend", "score": None} in body["anomaly"]["scores"]


# ─────────────────────────────── alertes, événements, blocages ───────────────────────────────

def test_alerts_merge_prometheus_loki_and_pending(make_client, fake):
    fake.am_alerts = [
        {"labels": {"alertname": "ServiceDown", "service": "payment-api", "severity": "critical",
                    "domain": "availability", "platform": "resilience-alpha"},
         "annotations": {"summary": "payment-api ne répond plus au scrape Prometheus"},
         "startsAt": at(-15), "status": {"state": "active"}, "generatorURL": "http://prometheus:9090/graph?g0.expr=up"},
        {"labels": {"alertname": "AuthBruteForce", "client_ip": "172.25.0.3", "service": "auth-service",
                    "severity": "warning", "domain": "security"},
         "annotations": {"summary": "Force brute probable depuis 172.25.0.3"}, "startsAt": at(-5),
         "status": {"state": "active"}, "generatorURL": ""},
    ]
    fake.prom_alerts = [
        {"labels": {"alertname": "ServiceDown", "service": "payment-api", "severity": "critical",
                    "domain": "availability"}, "state": "firing", "activeAt": at(-35)},
        {"labels": {"alertname": "EndToEndProbeFailed", "service": "payments", "severity": "critical",
                    "domain": "availability"}, "state": "pending", "activeAt": at(-3),
         "annotations": {"summary": "Le parcours client vers payments échoue"}},
    ]
    body = make_client().get("/api/alerts", headers=auth()).json()
    names = [(a["name"], a["state"], a["source"]) for a in body["alerts"]]
    assert names == [("ServiceDown", "firing", "prometheus"), ("AuthBruteForce", "firing", "loki"),
                     ("EndToEndProbeFailed", "pending", "prometheus")]
    assert body["alerts"][1]["client_ip"] == "172.25.0.3"
    assert body["sources"]["alertmanager"]["ok"] and body["sources"]["prometheus"]["ok"]


def test_events_are_whitelisted_bounded_and_grouped(make_client, fake):
    engine = {"service": "remediation-engine", "event_type": "remediation_decided", "level": "info"}
    fake.story = [
        loki_stream(engine, (-2, {"event_type": "remediation_decided", "service": "remediation-engine",
                                  "incident_id": "inc-20261020-074212-d07757", "nature": "availability",
                                  "plan": {"reason": "payment-api est exited", "action": "restart"}})),
        loki_stream({"service": "payment-api", "event_type": "transfer"},
                    (-1, {"event_type": "transfer", "service": "payment-api", "user_id": "u-1"})),
    ]
    failures = [(-10 + i * 0.1, {"event_type": "auth_failure", "service": "auth-service", "client_ip": "172.25.0.3",
                                 "user_agent": "attack.py", "password": secrets.token_urlsafe(8)}) for i in range(5)]
    fake.attack = [loki_stream({"service": "auth-service", "event_type": "auth_failure"}, *failures)]
    body = make_client().get("/api/events?limit=10", headers=auth()).json()
    events = body["events"]
    assert [e["event_type"] for e in events] == ["remediation_decided", "auth_failure"]
    assert events[0]["reason"] == "payment-api est exited" and events[0]["action"] == "restart"
    assert events[1]["count"] == 5 and events[1]["client_ip"] == "172.25.0.3"
    text = json.dumps(body)
    assert "user_agent" not in text and "password" not in text and "transfer" not in text
    one = make_client().get("/api/events?limit=1", headers=auth()).json()["events"]
    assert len(one) == 1


def test_blocks_carry_expiry_and_total_ttl(make_client, fake):
    block = incident("recovered", id="inc-20261020-090552-34f895", alertname="AuthBruteForce", nature="compromise",
                     last_action={"at": at(-30), "action": "block_ip", "target": "172.25.0.3", "result": "success",
                                  "ttl_s": 90, "expires_at": at(60)})
    fake.state = engine_state(open_incidents=[block], blocked=[
        {"ip": "172.25.0.3", "expires_at": at(60), "reason": "AuthBruteForce (compromise)",
         "incident_id": "inc-20261020-090552-34f895"}])
    body = make_client().get("/api/blocks", headers=auth()).json()
    assert body["blocks"] == [{"ip": "172.25.0.3", "expires_at": at(60), "remaining_s": 60.0, "ttl_s": 90,
                               "blocked_at": at(-30), "reason": "AuthBruteForce (compromise)",
                               "incident_id": "inc-20261020-090552-34f895"}]
    assert body["waf_blocklist"] is True and body["bridge"]["available"] is True


def test_current_incident_prefers_the_active_one_and_history_is_bounded(make_client, fake):
    old = incident("recovered", open_=False, id="inc-20261020-070000-aaaaaa", closed_at=at(-600))
    live = incident("verifying")
    fake.state = engine_state(open_incidents=[live], recent=[old])
    fake.incidents = {live["id"]: live, old["id"]: old}
    client = make_client()
    current = client.get("/api/incidents/current", headers=auth()).json()
    assert current["incident"]["id"] == live["id"] and current["incident"]["timeline"]
    history = client.get("/api/incidents?limit=1", headers=auth()).json()
    assert len(history["incidents"]) == 1 and "timeline" not in history["incidents"][0]
    fake.state = engine_state()
    assert client.get("/api/incidents/current", headers=auth()).json()["incident"] is None


def test_focus_is_the_last_business_incident_when_none_is_open():
    business = summary(incident("recovered", open_=False))
    infra = summary(incident("escalated", open_=False, alertname="BackupMissing", rule="BackupMissing",
                             nature="operator"))
    state = {"open_incidents": [], "recent_incidents": [infra, business]}
    assert shaping.focus_incident(state)["alertname"] == "ServiceDown"
    assert shaping.focus_incident({"open_incidents": [], "recent_incidents": [infra]})["alertname"] == "BackupMissing"
    assert shaping.focus_incident(None) is None


def test_decision_labels_state_nature_and_action():
    assert shaping.decision_label(DECISION) == "Disponibilité · redémarrage de payment-api"
    block = {"kind": "act", "nature": "compromise", "action": "block_ip", "target": "172.25.0.3"}
    assert shaping.decision_label(block) == "Compromission · blocage de 172.25.0.3 au WAF"
    verify = copy.deepcopy(DECISION) | {"kind": "verify"}
    assert shaping.decision_label(verify) == "Disponibilité · vérification seule (chaîne saine)"


def test_exported_api_documents_read_only_routes_behind_basic_auth():
    import export_openapi

    schema = json.loads(export_openapi.render("supervision-dashboard"))
    assert {"/api/overview", "/api/alerts", "/api/incidents", "/api/incidents/current", "/api/incidents/{incident_id}",
            "/api/blocks", "/api/events", "/health"} == set(schema["paths"])
    assert all(set(methods) == {"get"} for methods in schema["paths"].values())
    assert schema["components"]["securitySchemes"]["HTTPBasic"]["scheme"] == "basic"
    assert "security" not in schema["paths"]["/health"]["get"]
    assert schema["paths"]["/api/overview"]["get"]["security"] == [{"HTTPBasic": []}]


def follow_up(state: str = "recovered", open_: bool = True, **extra) -> dict:
    # Cette méthode permet de reproduire l'incident rattaché relevé en direct (20/10, 10:16:50) : AnomalyDetected
    # (probe_failed) sur payment-api, 18 s après ServiceDown, seulement vérifié car payment-api venait d'être redémarré.
    decision = {"kind": "verify", "nature": "availability", "action": "restart", "service": "payment-api",
                "target": "payment-api", "chain": ["postgres", "payment-api", "frontend", "waf"],
                "checks": ["containers", "probes", "witness"],
                "reason": "anomalie de disponibilité (probe_failed) sur payment-api : chaîne saine, payment-api déjà "
                          "redémarré par inc-20261020-074212-d07757"}
    return incident(state, open_, id="inc-20261020-074230-e03715", alertname="AnomalyDetected", rule="AnomalyDetected",
                    domain="anomaly", created_at=at(12), recovered_at=at(12.8), duration_s=0.8, alert_started_at=at(4),
                    decision=decision, last_action=None, outcome="recovered" if state == "recovered" else None, **extra)


def test_follow_up_incident_does_not_steal_the_story(make_client, fake):
    primary = incident("recovered")
    second = follow_up()
    fake.state = engine_state(open_incidents=[second, primary])
    fake.incidents = {primary["id"]: primary, second["id"]: second}
    client = make_client(now=NOW + 13)
    status = overview(client)["status"]
    assert status["incident_id"] == primary["id"] and status["reaction_s"] == 6.7
    assert client.get("/api/incidents/current", headers=auth()).json()["incident"]["id"] == primary["id"]
    # Principal clos, rattaché encore ouvert : on raconte toujours le principal
    closed = incident("recovered", open_=False, closed_at=at(23))
    fake.state = engine_state(open_incidents=[follow_up(open_=True)], recent=[closed])
    status = overview(make_client(now=NOW + 25))["status"]
    assert (status["phase"], status["incident_id"]) == ("restored", primary["id"])
    # L'historique signale le rattachement
    fake.incidents = {second["id"]: second, primary["id"]: primary}
    history = make_client().get("/api/incidents", headers=auth()).json()["incidents"]
    assert {i["id"]: i["follow_up_of"] for i in history} == {second["id"]: primary["id"], primary["id"]: None}


def test_follow_up_that_fails_is_shown(make_client, fake):
    primary = incident("recovered", open_=False, closed_at=at(23))
    broken = follow_up("escalated", escalation={"reason": "verification_failed", "message": "témoin en échec"})
    fake.state = engine_state(open_incidents=[broken], recent=[primary])
    status = overview(make_client(now=NOW + 30))["status"]
    assert status["incident_id"] == broken["id"] and status["phase"] == "incident" and status["escalated"]


def test_probe_back_before_the_scrape_is_not_shown_as_down(make_client, fake):
    fake.metrics = healthy_metrics(payment_up=0)
    comp = {c["id"]: c for c in overview(make_client())["components"]}
    assert comp["payment-api"]["state"] == "degraded"
    assert comp["payment-api"]["reason"] == "parcours client OK · scrape Prometheus pas encore revenu"
