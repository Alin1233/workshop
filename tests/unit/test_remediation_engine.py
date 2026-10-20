"""Tests du moteur de remédiation, sans la stack : proxy Docker, WAF, pont de restauration, Prometheus, Loki,
contrôle d'intégrité et transaction témoin sont remplacés par des faux.

Couvrent : la table de décision (chaque alerte des règles Prometheus et Loki), l'authentification du webhook, la machine
d'états, l'anti-boucle (budget, refroidissement, verrou), l'idempotence face aux notifications répétées, la distinction
corruption / panne de base, le routage des anomalies par variable dominante, l'escalade après échec de vérification, la
persistance après redémarrage, l'absence de route de modification dans l'API, le client du proxy Docker et la
transaction témoin. Aucun secret n'est écrit en dur : jetons et mots de passe sont générés.
"""

import asyncio
import hashlib
import http.server
import json
import re
import secrets
import threading
import time
import urllib.parse
import uuid
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient
from prometheus_client import REGISTRY

from service_loader import load_service

REPO = Path(__file__).resolve().parents[2]
engine_mod = load_service("remediation-engine", "engine")
decisions = load_service("remediation-engine", "decisions")
incidents_mod = load_service("remediation-engine", "incidents")
config = load_service("remediation-engine", "config")
main_mod = load_service("remediation-engine", "main")
docker_proxy = load_service("remediation-engine", "actions.docker_proxy")
actions = load_service("remediation-engine", "actions")
witness_mod = load_service("remediation-engine", "witness")
clients = load_service("remediation-engine", "clients")

ActionError = actions.ActionError
State = incidents_mod.State
Limits = config.Limits
# Adresses de documentation (RFC 5737) : jamais d'adresse réelle
ATTACKER = "203.0.113.9"
OTHER = "198.51.100.4"
ALL_SERVICES = ("postgres", "auth-service", "payment-api", "frontend", "waf", "anomaly-detector")


# ───────────────────────────── faux clients ─────────────────────────────

class FakeDocker:
    """Faux docker-socket-proxy : états par service, actions enregistrées, effets de bord programmables."""

    def __init__(self, statuses=None, after=None, fail=(), on_action=None, delay=0.0):
        self.statuses = {s: "healthy" for s in ALL_SERVICES} | (statuses or {})
        self.after = after or {}
        self.fail = set(fail)
        self.on_action = on_action
        self.delay = delay
        self.calls = []

    def health(self, service):
        return self.statuses.get(service, "none")

    def _act(self, action, service):
        self.calls.append((action, service))
        if self.delay:
            time.sleep(self.delay)
        if service in self.fail:
            raise ActionError(f"{action} {service} refusé")
        self.statuses[service] = self.after.get(service, "healthy")
        if self.on_action:
            self.on_action(self, action, service)

    def restart(self, service, timeout_s=10):
        self._act("restart", service)

    def start(self, service):
        self._act("start", service)

    def signal(self, service, sig):
        self.calls.append(("signal", service, sig))

    def ping(self):
        return True


class FakeProm:
    def __init__(self, probes=None, scalars=None, error=None):
        self.probe_values = probes if probes is not None else {"auth": 1.0, "payments": 1.0, "frontend": 1.0}
        self.scalars = scalars or {}
        self.error = error

    def probes(self):
        if self.error:
            raise clients.SourceError(self.error)
        return dict(self.probe_values)

    def scalar(self, expr):
        if self.error:
            raise clients.SourceError(self.error)
        return self.scalars.get(expr, 0.0)

    def ready(self):
        return self.error is None


class FakeLoki:
    def __init__(self, top=None, latest=None, error=None):
        self.top = top or {}            # requête → (ip, nombre)
        self.latest_entry = latest
        self.error = error
        self.queries = []

    def top_ip(self, expr):
        self.queries.append(expr)
        if self.error:
            raise clients.SourceError(self.error)
        return self.top.get(expr)

    def latest(self, expr, since_s=900):
        self.queries.append(expr)
        if self.error:
            raise clients.SourceError(self.error)
        return self.latest_entry

    def ready(self):
        return self.error is None


class FakeIntegrity:
    """Contrôle d'intégrité : code fixe, ou calculé par une fonction (ex. selon l'état de PostgreSQL)."""

    def __init__(self, code=200, fn=None):
        self.code = code
        self.fn = fn
        self.calls = 0

    def check(self):
        self.calls += 1
        code = self.fn() if self.fn else self.code
        return code, ({"ok": code == 200, "checks": {}} if code else {"error": "connexion refusée"})


class FakeWitness:
    def __init__(self, ok=True):
        self.ok = ok
        self.runs = 0

    def run(self):
        self.runs += 1
        if not self.ok:
            raise witness_mod.WitnessError("transaction témoin en échec à l'étape « virement » (HTTP 503)",
                                           [{"step": "virement", "ok": False, "status": 503}])
        return {"transfer_id": str(uuid.uuid4()), "duration_ms": 12, "steps": []}


class FakeBlocklist:
    def __init__(self, verify_ok=True, allow=()):
        self.entries = {}
        self.verify_ok = verify_ok
        self.allow = set(allow)
        self.blocked = []

    def block(self, ip, ttl_s, reason, incident_id):
        self.blocked.append((ip, ttl_s, incident_id))
        entry = SimpleNamespace(ip=ip, expires_at=time.time() + ttl_s, reason=reason, incident_id=incident_id)
        self.entries[ip] = entry
        return entry

    def verify(self, ip):
        return self.verify_ok and ip in self.entries

    def active(self):
        return list(self.entries.values())

    def expire(self, now=None):
        return []

    def allowlisted(self, ip):
        return "172.31.248.0/21" if ip in self.allow else None

    def ready(self):
        return True


class FakeBridge:
    def __init__(self, available=True, ok=True, integrity=None):
        self.in_flight = None
        self.is_available = available
        self.ok = ok
        self.integrity = integrity
        self.requests = []

    def available(self):
        return self.is_available

    def status(self):
        return {"available": self.is_available, "busy": False}

    async def request_restore(self, incident_id):
        assert re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", incident_id)   # contrat du pont (db_restore.py)
        self.requests.append(incident_id)
        await asyncio.sleep(0.01)
        if self.ok and self.integrity is not None:
            self.integrity.code = 200
        detail = {"restored": "2026-10-20T08-00-00Z"} if self.ok else {"error": "restore_failed"}
        return SimpleNamespace(ok=self.ok, detail=detail, duration_s=0.01)


# ───────────────────────────── outils ─────────────────────────────

def fast_settings(**overrides):
    # Cette méthode permet d'obtenir une configuration aux délais très courts (tests rapides, mêmes comportements).
    settings = config.Settings(state_file=None, bridge_dir=None)
    settings.poll_s = 0.01
    settings.healthy_timeout_s = 0.5
    settings.dependent_grace_s = 0.1
    settings.verify_timeout_s = 0.2
    settings.symptom_grace_s = 0.02
    settings.retry_backoff_s = 0.0
    settings.latency_persist_s = 0.15
    settings.refire_grace_s = 0.0
    settings.background_period_s = 0.05
    settings.limits = {"restart": Limits(3, 600, 0), "detector": Limits(1, 1800, 0),
                       "block": Limits(3, 600, 0), "restore": Limits(1, 900, 0)}
    for key, value in overrides.items():
        setattr(settings, key, value)
    return settings


def make_engine(settings=None, docker=None, prom=None, loki=None, integrity=None, witness=None,
                blocklist="default", bridge="default", store_path=None):
    # Cette méthode permet d'assembler un moteur entièrement factice.
    integrity = integrity or FakeIntegrity()
    return engine_mod.Engine(
        settings or fast_settings(), docker or FakeDocker(), prom or FakeProm(), loki or FakeLoki(), integrity,
        witness or FakeWitness(),
        blocklist=FakeBlocklist() if blocklist == "default" else blocklist,
        bridge=FakeBridge(integrity=integrity) if bridge == "default" else bridge,
        store=incidents_mod.StateStore(store_path))


def alert(name, status="firing", **labels):
    # Cette méthode permet de fabriquer une alerte Alertmanager v4 (empreinte stable dérivée des labels).
    rule = decisions.DECISION_TABLE.get(name)
    all_labels = {"alertname": name, "severity": "critical", "domain": "availability", **labels}
    if rule and "domain" not in labels:
        all_labels["domain"] = {"compromise": "security", "triage": "anomaly"}.get(rule.nature, "availability")
    fingerprint = hashlib.sha256(json.dumps(all_labels, sort_keys=True).encode()).hexdigest()[:16]
    now = datetime.now(timezone.utc).isoformat()
    return {"status": status, "labels": all_labels, "annotations": {"summary": f"{name} (test)"},
            "startsAt": now, "endsAt": now if status == "resolved" else "0001-01-01T00:00:00Z",
            "generatorURL": "", "fingerprint": fingerprint}


def payload(*alerts_):
    # Cette méthode permet d'envelopper des alertes dans une notification webhook Alertmanager v4.
    return {"version": "4", "groupKey": "{}:{}", "status": alerts_[0]["status"], "receiver": "remediation-engine",
            "groupLabels": {}, "commonLabels": {}, "commonAnnotations": {}, "externalURL": "", "alerts": list(alerts_)}


def resolved(firing):
    # Cette méthode permet de produire la notification de retombée d'une alerte.
    return {**firing, "status": "resolved", "endsAt": datetime.now(timezone.utc).isoformat()}


def process(engine, *payloads, between=None):
    # Cette méthode permet de jouer des notifications dans le moteur et d'attendre la fin des traitements.
    async def scenario():
        await engine.start(background=False)
        results = []
        for item in payloads:
            results.append(engine.ingest(item))
            if between:
                await asyncio.sleep(between)
        await engine.wait_idle(15)
        return results
    return asyncio.run(scenario())


def only(engine):
    # Cette méthode permet de récupérer l'unique incident du moteur.
    assert len(engine.incidents) == 1, [i.alertname for i in engine.incidents.values()]
    return next(iter(engine.incidents.values()))


def states(incident):
    # Cette méthode permet de lire la suite des états traversés (chronologie).
    return [e["event"].split(":", 1)[1] for e in incident.timeline if e["event"].startswith("state:")]


def sample(name, labels=None):
    # Cette méthode permet de lire une métrique du registre Prometheus (0 si absente).
    return REGISTRY.get_sample_value(name, labels or {}) or 0.0


def rule_alertnames():
    # Cette méthode permet de lister toutes les alertes déclarées dans les règles Prometheus et Loki du dépôt.
    names = set()
    files = [*sorted((REPO / "infra" / "prometheus" / "rules").glob("*.yml")), REPO / "infra/loki/rules/fake/soc.yml"]
    for path in files:
        for group in yaml.safe_load(path.read_text(encoding="utf-8"))["groups"]:
            names |= {rule["alert"] for rule in group["rules"] if "alert" in rule}
    return names


# ───────────────────────────── table de décision ─────────────────────────────

def test_decision_table_covers_every_alert_rule_explicitly():
    names = rule_alertnames()
    assert names, "aucune règle lue"
    assert names - set(decisions.DECISION_TABLE) == set(), "alertes sans ligne dans la table de décision"
    assert set(decisions.DECISION_TABLE) - names == set(), "lignes de la table sans règle correspondante"


def test_decision_table_keeps_availability_and_compromise_apart():
    restart = {decisions.Strategy.RESTART, decisions.Strategy.OBSERVE_THEN_RESTART, decisions.Strategy.RESTART_DETECTOR}
    compromise = {decisions.Strategy.BLOCK_ALERT_IP, decisions.Strategy.BLOCK_TOP_IP,
                  decisions.Strategy.INTEGRITY_RESTORE}
    for rule in decisions.RULES:
        assert rule.response, rule.alertname
        if rule.strategy in restart:
            assert rule.nature == decisions.Nature.AVAILABILITY, rule.alertname
        if rule.strategy in compromise:
            assert rule.nature == decisions.Nature.COMPROMISE, rule.alertname
        if rule.nature in (decisions.Nature.OPERATOR, decisions.Nature.OBSERVE, decisions.Nature.SELF):
            assert rule.strategy not in restart | compromise, rule.alertname


def test_engine_own_alerts_are_never_remediated():
    assert decisions.rule_for({"alertname": "RemediationFailed", "service": "remediation-engine"}).nature == "self"
    assert decisions.rule_for({"alertname": "HighErrorRate", "service": "remediation-engine"}).nature == "self"
    assert decisions.rule_for({"alertname": "Inconnue"}) is decisions.UNKNOWN_RULE
    assert decisions.target_service({"service": "payments"}) == "payment-api"
    assert decisions.chain_for("payment-api", upstream=True) == ["postgres", "payment-api", "frontend", "waf"]
    rules = yaml.safe_load((REPO / "infra/prometheus/rules/availability.yml").read_text(encoding="utf-8"))
    group = next(g for g in rules["groups"] if g["name"] == "remediation")
    for rule in group["rules"]:
        assert rule["labels"]["service"] == "remediation-engine"
        assert {"severity", "domain"} <= set(rule["labels"])


def _setup_restart(statuses):
    return lambda: {"docker": FakeDocker(statuses)}


def _setup_integrity():
    integrity = FakeIntegrity(409)
    return {"integrity": integrity, "bridge": FakeBridge(integrity=integrity)}


def _setup_loki_top():
    return {"loki": FakeLoki(top={decisions.LOGIN_FAILURES_QUERY: (ATTACKER, 40.0)})}


def _setup_anomaly():
    query = decisions.offender_query("invalid_tokens_per_min", "payment-api")
    return {"loki": FakeLoki(top={query: (ATTACKER, 55.0)},
                             latest={"dominant_feature": "invalid_tokens_per_min", "target_service": "payment-api",
                                     "complete": True, "anomaly_score": 0.97})}


# alertname → (labels, préparation des faux, état final, actions Docker attendues, IP bloquées, restaurations)
CASES = {
    "ServiceDown": ({"service": "payment-api"}, _setup_restart({"payment-api": "exited"}),
                    "recovered", [("start", "payment-api")], [], 0),
    "EndToEndProbeFailed": ({"service": "auth"}, _setup_restart({"auth-service": "unhealthy"}),
                            "recovered", [("restart", "auth-service")], [], 0),
    "HighErrorRate": ({"service": "payment-api"}, _setup_restart({}), "recovered", [("restart", "payment-api")], [], 0),
    "DependencyFailures": ({"service": "payment-api"}, _setup_restart({"postgres": "exited"}),
                           "recovered", [("start", "postgres")], [], 0),
    "HighLatencyP95": ({"service": "payment-api"}, _setup_restart({}), "recovered", [("restart", "payment-api")], [], 0),
    "AnomalyDetectorDown": ({"service": "anomaly-detector", "severity": "warning"}, _setup_restart({}),
                            "recovered", [("restart", "anomaly-detector")], [], 0),
    "LedgerIntegrityBroken": ({"service": "payment-api"}, _setup_integrity, "recovered", [], [], 1),
    "LedgerIntegrityViolationLogged": ({"service": "payment-api"}, _setup_integrity, "recovered", [], [], 1),
    "AuthBruteForce": ({"service": "auth-service", "client_ip": ATTACKER}, dict, "recovered", [], [ATTACKER], 0),
    "InvalidTokenFlood": ({"service": "payment-api", "client_ip": ATTACKER}, dict, "recovered", [], [ATTACKER], 0),
    "WafAttackBlocked": ({"service": "waf", "client_ip": ATTACKER}, dict, "recovered", [], [ATTACKER], 0),
    "LoginFailureSpike": ({"service": "auth-service"}, _setup_loki_top, "recovered", [], [ATTACKER], 0),
    "AnomalyDetected": ({"service": "payment-api"}, _setup_anomaly, "recovered", [], [ATTACKER], 0),
    "AnomalyDetectorBlind": ({"service": "anomaly-detector", "source": "loki"}, dict, "observing", [], [], 0),
    "LedgerIntegrityCheckStale": ({"service": "payment-api"}, dict, "escalated", [], [], 0),
    "HostDiskSpaceLow": ({"service": "pc-hote"}, dict, "escalated", [], [], 0),
    "HostMemoryLow": ({"service": "pc-hote"}, dict, "escalated", [], [], 0),
    "BackupMissing": ({"service": "pc-hote"}, dict, "escalated", [], [], 0),
    "BackupFailed": ({"service": "pc-hote"}, dict, "escalated", [], [], 0),
    "RemediationFailed": ({"service": "remediation-engine"}, dict, "observing", [], [], 0),
    "RemediationEngineDown": ({"service": "remediation-engine"}, dict, "observing", [], [], 0),
}


def test_every_alertname_has_a_tested_decision():
    assert set(CASES) == set(decisions.DECISION_TABLE)


@pytest.mark.parametrize("name", sorted(CASES))
def test_decision_for_each_alertname(name):
    labels, setup, final, docker_calls, blocks, restores = CASES[name]
    fakes = setup()
    engine = make_engine(**fakes)
    process(engine, payload(alert(name, **labels)))
    incident = only(engine)
    assert incident.state == final, incident.timeline
    assert engine.docker.calls == docker_calls
    assert [ip for ip, *_ in engine.blocklist.blocked] == blocks
    assert len(engine.bridge.requests) == restores
    if final == "recovered":
        assert states(incident)[:2] == ["detected", "decided"]
        assert states(incident)[-2:] == ["verifying", "recovered"]
        assert incident.nature in ("availability", "compromise")
    if docker_calls:
        assert incident.nature == "availability"
    if blocks or restores:
        assert incident.nature == "compromise"
    if final == "escalated":
        assert incident.escalation["reason"] == "policy"


def test_probe_labels_map_to_compose_services():
    for probe, service in (("payments", "payment-api"), ("frontend", "frontend")):
        engine = make_engine(docker=FakeDocker({service: "unhealthy"}))
        process(engine, payload(alert("EndToEndProbeFailed", service=probe)))
        assert engine.docker.calls == [("restart", service)]


def test_probe_failure_repairs_the_broken_upstream_link_first():
    # La sonde payments échoue parce que le frontal est tombé : on relance le frontal, pas l'API.
    engine = make_engine(docker=FakeDocker({"frontend": "exited"}))
    process(engine, payload(alert("EndToEndProbeFailed", service="payments")))
    assert engine.docker.calls == [("start", "frontend")]
    assert only(engine).state == "recovered"


def test_dependency_failure_restarts_api_only_if_still_failing_after_postgres():
    docker = FakeDocker({"postgres": "exited", "payment-api": "unhealthy"},
                        after={"payment-api": "healthy"})
    # PostgreSQL relancé : l'API ne revient pas seule dans le délai de grâce, elle est redémarrée ensuite.
    process(make_engine(docker=docker), payload(alert("DependencyFailures", service="payment-api")))
    assert docker.calls == [("start", "postgres"), ("restart", "payment-api")]

    def heal(fake, action, service):
        if service == "postgres":
            fake.statuses["payment-api"] = "healthy"
    docker = FakeDocker({"postgres": "exited", "payment-api": "unhealthy"}, on_action=heal)
    process(make_engine(docker=docker), payload(alert("DependencyFailures", service="payment-api")))
    assert docker.calls == [("start", "postgres")]


def test_container_already_starting_is_awaited_not_restarted():
    docker = FakeDocker({"waf": "starting"})
    engine = make_engine(docker=docker, prom=FakeProm(scalars={'min(probe_success{job="blackbox-http",service="payments"})': 1.0}))

    async def scenario():
        await engine.start(background=False)
        engine.ingest(payload(alert("EndToEndProbeFailed", service="payments")))
        await asyncio.sleep(0.05)
        docker.statuses["waf"] = "healthy"             # le WAF finit de redémarrer de lui-même
        await engine.wait_idle(5)
    asyncio.run(scenario())
    incident = only(engine)
    assert docker.calls == []                          # aucun redémarrage : le WAF démarrait
    assert incident.state == "recovered"
    assert "acting" not in states(incident)            # le WAF n'est jamais désigné comme cible d'un redémarrage
    events = [e["event"] for e in incident.timeline]
    assert "wait:starting" in events and "wait:settled" in events
    # La décision affichée dit ce qui se passe (attente), pas « redémarrage de waf ».
    first_decision = next(e for e in incident.timeline if e["event"] == "state:decided")["detail"]
    assert first_decision["kind"] == "wait" and "action" not in first_decision
    assert "démarrage" in first_decision["reason"] and "redémarrage" not in first_decision["reason"]


def test_container_stuck_in_starting_is_eventually_restarted():
    # Un conteneur qui reste « starting » au-delà du délai ne s'est pas stabilisé : il est alors redémarré.
    docker = FakeDocker({"waf": "starting"})            # reste starting jusqu'au redémarrage (after → healthy)
    engine = make_engine(docker=docker, settings=fast_settings(healthy_timeout_s=0.1))
    process(engine, payload(alert("EndToEndProbeFailed", service="payments")))
    incident = only(engine)
    assert ("restart", "waf") in docker.calls
    assert incident.state == "recovered"
    events = [e["event"] for e in incident.timeline]
    assert "wait:starting" in events                    # on a d'abord attendu, puis désigné la cible


def test_healthy_chain_with_cleared_symptom_is_verified_without_action():
    expr = 'max(up{job="payment-api"})'
    engine = make_engine(prom=FakeProm(scalars={expr: 1.0}))
    process(engine, payload(alert("ServiceDown", service="payment-api")))
    incident = only(engine)
    assert engine.docker.calls == []
    assert incident.state == "recovered"
    assert "acting" not in states(incident)


def test_latency_alert_resolved_during_observation_triggers_nothing():
    firing = alert("HighLatencyP95", service="payment-api")
    engine = make_engine()
    process(engine, payload(firing), payload(resolved(firing)), between=0.03)
    incident = only(engine)
    assert engine.docker.calls == []
    assert incident.outcome == "resolved_without_action"
    assert not incident.open


def test_unknown_alert_is_escalated_without_action():
    engine = make_engine()
    process(engine, payload(alert("SomethingNew", service="payment-api")))
    incident = only(engine)
    assert incident.state == "escalated"
    assert incident.escalation["reason"] == "unknown_alert"
    assert engine.docker.calls == []


def test_self_alert_does_not_feed_remediation_failed():
    before = sample("remediation_escalations_total", {"reason": "policy"})
    engine = make_engine()
    process(engine, payload(alert("HighErrorRate", service="remediation-engine")))
    assert only(engine).nature == "self"
    assert engine.docker.calls == []
    assert sample("remediation_escalations_total", {"reason": "policy"}) == before


def test_restart_outside_allowed_services_is_refused():
    engine = make_engine()
    process(engine, payload(alert("HighErrorRate", service="grafana")))
    incident = only(engine)
    assert incident.state == "escalated" and incident.escalation["reason"] == "not_allowed"
    assert engine.docker.calls == []


def test_missing_container_is_escalated():
    engine = make_engine(docker=FakeDocker({"payment-api": "none"}))
    process(engine, payload(alert("ServiceDown", service="payment-api")))
    incident = only(engine)
    assert incident.state == "escalated" and incident.escalation["reason"] == "container_missing"


def test_refused_start_falls_back_to_restart():
    class NoStart(FakeDocker):
        def start(self, service):
            self.calls.append(("start", service))
            raise ActionError("docker-socket-proxy refuse POST /containers/x/start (403)")
    docker = NoStart({"payment-api": "exited"})
    process(make_engine(docker=docker), payload(alert("ServiceDown", service="payment-api")))
    assert docker.calls == [("start", "payment-api"), ("restart", "payment-api")]


# ───────────────────────────── intégrité : corruption ou panne de base ─────────────────────────────

def test_integrity_alert_during_database_outage_restarts_postgres_and_never_restores():
    docker = FakeDocker({"postgres": "exited", "payment-api": "unhealthy"})

    def heal(fake, action, service):
        if service == "postgres":
            fake.statuses["payment-api"] = "healthy"
    docker.on_action = heal
    integrity = FakeIntegrity(fn=lambda: 200 if docker.statuses["postgres"] == "healthy" else None)
    bridge = FakeBridge(integrity=integrity)
    engine = make_engine(docker=docker, integrity=integrity, bridge=bridge)
    process(engine, payload(alert("LedgerIntegrityBroken", service="payment-api")))
    incident = only(engine)
    assert bridge.requests == []
    assert docker.calls == [("start", "postgres")]
    assert incident.state == "recovered"
    assert incident.nature == "availability"
    assert any(e["event"] == "reclassified" for e in incident.timeline)


def test_integrity_503_with_healthy_postgres_is_not_a_corruption():
    integrity = FakeIntegrity(503)
    bridge = FakeBridge(integrity=integrity)
    engine = make_engine(docker=FakeDocker({"payment-api": "unhealthy"}), integrity=integrity, bridge=bridge)
    process(engine, payload(alert("LedgerIntegrityViolationLogged", service="payment-api")))
    assert bridge.requests == []
    assert ("restart", "payment-api") in engine.docker.calls


def test_integrity_with_starting_postgres_waits_then_confirms_corruption():
    # PostgreSQL en cours de démarrage : on attend sa stabilisation avant de juger (ni restauration ni redémarrage
    # « base injoignable » sur un 409/503 trompeur). Une fois sain et toujours en 409 : corruption confirmée, restauration.
    docker = FakeDocker({"postgres": "starting"})
    integrity = FakeIntegrity(409)
    bridge = FakeBridge(integrity=integrity)
    engine = make_engine(docker=docker, integrity=integrity, bridge=bridge,
                         settings=fast_settings(healthy_timeout_s=0.3))

    async def scenario():
        await engine.start(background=False)
        engine.ingest(payload(alert("LedgerIntegrityBroken", service="payment-api")))
        await asyncio.sleep(0.05)
        docker.statuses["postgres"] = "healthy"        # PostgreSQL finit de démarrer de lui-même
        await engine.wait_idle(5)
    asyncio.run(scenario())
    incident = only(engine)
    assert len(bridge.requests) == 1                    # corruption confirmée après stabilisation
    assert docker.calls == []                           # aucun redémarrage : ce n'était pas une panne de base
    assert incident.state == "recovered"
    events = [e["event"] for e in incident.timeline]
    assert "wait:starting" in events
    assert not any(e["event"] == "reclassified" for e in incident.timeline)


def test_conflict_with_unreadable_proxy_is_still_a_corruption():
    class BlindDocker(FakeDocker):
        def health(self, service):
            raise ActionError("docker-socket-proxy injoignable")
    integrity = FakeIntegrity(409)
    engine = make_engine(docker=BlindDocker(), integrity=integrity, bridge=FakeBridge(integrity=integrity),
                         settings=fast_settings(healthy_timeout_s=0.05))
    process(engine, payload(alert("LedgerIntegrityBroken", service="payment-api")))
    assert len(engine.bridge.requests) == 1
    assert only(engine).nature == "compromise"


def test_confirmed_corruption_without_bridge_is_escalated():
    integrity = FakeIntegrity(409)
    engine = make_engine(integrity=integrity, bridge=FakeBridge(available=False))
    process(engine, payload(alert("LedgerIntegrityBroken", service="payment-api")))
    incident = only(engine)
    assert incident.state == "escalated"
    assert incident.escalation["reason"] == "bridge_unavailable"
    assert engine.bridge.requests == []
    assert engine.docker.calls == []


def test_failed_restore_is_escalated_without_retry():
    integrity = FakeIntegrity(409)
    engine = make_engine(integrity=integrity, bridge=FakeBridge(ok=False, integrity=integrity))
    process(engine, payload(alert("LedgerIntegrityBroken", service="payment-api")))
    incident = only(engine)
    assert len(engine.bridge.requests) == 1
    assert incident.state == "escalated"


def test_availability_actions_are_held_while_a_restore_is_in_flight():
    # resilience-pg-restore arrête volontairement les API : ServiceDown pendant la restauration ne doit rien redémarrer.
    bridge = FakeBridge()
    bridge.in_flight = "req-1"
    docker = FakeDocker({"payment-api": "exited"})
    engine = make_engine(docker=docker, bridge=bridge)

    async def scenario():
        await engine.start(background=False)
        engine.ingest(payload(alert("ServiceDown", service="payment-api")))
        await asyncio.sleep(0.1)
        assert docker.calls == []
        docker.statuses["payment-api"] = "healthy"     # la restauration relance elle-même les API
        bridge.in_flight = None
        await engine.wait_idle(5)
    asyncio.run(scenario())
    incident = only(engine)
    events = [e["event"] for e in incident.timeline]
    assert "hold:restore_in_progress" in events and "hold:released" in events
    assert docker.calls == [] and incident.state == "recovered"


def test_restore_verifies_integrity_probes_and_witness():
    integrity = FakeIntegrity(409)
    witness = FakeWitness()
    engine = make_engine(integrity=integrity, bridge=FakeBridge(integrity=integrity), witness=witness)
    process(engine, payload(alert("LedgerIntegrityBroken", service="payment-api")))
    events = [e["event"] for e in only(engine).timeline]
    for check in ("containers", "integrity", "probes", "witness"):
        assert f"verification:{check}" in events
    assert witness.runs == 1


# ───────────────────────────── sécurité et anomalies ─────────────────────────────

def test_login_spike_below_threshold_is_only_observed():
    engine = make_engine(loki=FakeLoki(top={decisions.LOGIN_FAILURES_QUERY: (ATTACKER, 3.0)}))
    process(engine, payload(alert("LoginFailureSpike", service="auth-service")))
    assert only(engine).state == "observing"
    assert engine.blocklist.blocked == []


def test_allowlisted_ip_is_never_blocked():
    engine = make_engine(blocklist=FakeBlocklist(allow={ATTACKER}))
    process(engine, payload(alert("AuthBruteForce", service="auth-service", client_ip=ATTACKER)))
    incident = only(engine)
    assert engine.blocklist.blocked == []
    assert incident.state == "escalated" and incident.escalation["reason"] == "not_allowed"


def test_missing_waf_module_escalates_instead_of_improvising():
    engine = make_engine(blocklist=None)
    process(engine, payload(alert("WafAttackBlocked", service="waf", client_ip=ATTACKER)))
    assert only(engine).escalation["reason"] == "waf_unavailable"


def test_alerts_from_same_ip_share_one_incident_and_one_block():
    engine = make_engine()
    process(engine, payload(alert("AuthBruteForce", service="auth-service", client_ip=ATTACKER),
                            alert("WafAttackBlocked", service="waf", client_ip=ATTACKER)))
    incident = only(engine)
    assert len(incident.alerts) == 2
    assert engine.blocklist.blocked == [(ATTACKER, engine.settings.waf_block_ttl_s, incident.id)]


def _anomaly_engine(feature, service="payment-api", docker=None, top=None):
    query = decisions.offender_query(feature, service)
    loki = FakeLoki(top={query: top} if query and top else {},
                    latest={"dominant_feature": feature, "target_service": service, "complete": True,
                            "anomaly_score": 0.91})
    return make_engine(loki=loki, docker=docker)


@pytest.mark.parametrize("feature", sorted(decisions.SECURITY_FEATURES))
def test_anomaly_with_attack_feature_blocks_the_offending_ip(feature):
    service = "auth-service" if feature == "login_failures_per_min" else (
        "frontend" if feature == "waf_blocks_per_min" else "payment-api")
    engine = _anomaly_engine(feature, service, top=(OTHER, 80.0))
    process(engine, payload(alert("AnomalyDetected", service=service)))
    incident = only(engine)
    assert [ip for ip, *_ in engine.blocklist.blocked] == [OTHER]
    assert engine.docker.calls == []
    assert incident.nature == "compromise"


@pytest.mark.parametrize("feature", sorted(decisions.AVAILABILITY_FEATURES))
def test_anomaly_with_availability_feature_restarts_target(feature):
    engine = _anomaly_engine(feature, docker=FakeDocker({"payment-api": "unhealthy"}))
    process(engine, payload(alert("AnomalyDetected", service="payment-api")))
    incident = only(engine)
    assert engine.docker.calls == [("restart", "payment-api")]
    assert engine.blocklist.blocked == []
    assert incident.nature == "availability"


def test_anomaly_with_ambiguous_feature_is_escalated():
    engine = _anomaly_engine("req_rate")
    process(engine, payload(alert("AnomalyDetected", service="payment-api")))
    incident = only(engine)
    assert incident.state == "escalated" and incident.escalation["reason"] == "triage_unknown"
    assert engine.docker.calls == [] and engine.blocklist.blocked == []


def test_anomaly_without_detector_log_is_escalated():
    engine = make_engine(loki=FakeLoki(latest=None))
    process(engine, payload(alert("AnomalyDetected", service="payment-api")))
    assert only(engine).escalation["reason"] == "triage_unknown"


def test_frontend_co_alert_is_attached_to_the_api_incident():
    loki = FakeLoki(top={decisions.LOGIN_FAILURES_QUERY: (ATTACKER, 50.0)},
                    latest={"dominant_feature": "req_rate_per_min", "target_service": "frontend", "complete": True})
    engine = make_engine(loki=loki)
    process(engine, payload(alert("AuthBruteForce", service="auth-service", client_ip=ATTACKER)),
            payload(alert("AnomalyDetected", service="frontend")), between=0.05)
    frontend = next(i for i in engine.incidents.values() if i.service == "frontend")
    assert frontend.state == "observing"
    assert frontend.decision["evidence"]["correlated_to"]
    assert engine.docker.calls == []
    assert len(engine.blocklist.blocked) == 1


# ───────────────────────────── machine d'états ─────────────────────────────

def test_state_machine_rejects_invalid_transitions():
    incident = incidents_mod.Incident(id="inc-test", key="k", alertname="ServiceDown", rule="ServiceDown",
                                      strategy="restart", nature="availability", domain="availability",
                                      severity="critical", service="payment-api")
    with pytest.raises(incidents_mod.InvalidTransition):
        incident.transition(State.ACTING, time.time())
    for target in (State.DECIDED, State.ACTING, State.VERIFYING, State.FAILED, State.ESCALATED):
        incident.transition(target, time.time())
    with pytest.raises(incidents_mod.InvalidTransition):
        incident.transition(State.DECIDED, time.time())


def test_recovered_incident_has_a_full_timestamped_timeline():
    engine = make_engine(docker=FakeDocker({"payment-api": "exited"}))
    firing = alert("ServiceDown", service="payment-api")
    process(engine, payload(firing))
    incident = only(engine)
    assert states(incident) == ["detected", "decided", "acting", "verifying", "recovered"]
    stamps = [e["ts"] for e in incident.timeline]
    assert stamps == sorted(stamps) and all(e["at"] for e in incident.timeline)
    assert incident.open, "reste ouvert tant que l'alerte n'est pas retombée"
    process(engine, payload(resolved(firing)))
    assert not incident.open and incident.outcome == "recovered"
    assert engine.get(incident.id)["timeline"][-1]["event"] == "closed"


# ───────────────────────────── idempotence et anti-boucle ─────────────────────────────

def test_repeated_notifications_are_idempotent():
    firing = alert("ServiceDown", service="payment-api")
    engine = make_engine(docker=FakeDocker({"payment-api": "exited"}), settings=fast_settings(refire_grace_s=3600))
    results = process(engine, payload(firing), payload(firing), payload(firing))
    assert [r["results"][0]["status"] for r in results] == ["created", "duplicate", "duplicate"]
    incident = only(engine)
    assert engine.docker.calls == [("start", "payment-api")]
    assert next(iter(incident.alerts.values()))["notifications"] == 3


def test_correlated_alerts_on_same_service_share_one_action():
    engine = make_engine(docker=FakeDocker({"payment-api": "exited"}))
    process(engine, payload(alert("ServiceDown", service="payment-api")),
            payload(alert("EndToEndProbeFailed", service="payments")),
            payload(alert("HighErrorRate", service="payment-api")))
    incident = only(engine)
    assert len(incident.alerts) == 3
    assert engine.docker.calls == [("start", "payment-api")]


def test_verification_failure_retries_then_escalates():
    before_fail = sample("remediation_verification_total", {"result": "failure"})
    before_esc = sample("remediation_escalations_total", {"reason": "verification_failed"})
    engine = make_engine(witness=FakeWitness(ok=False))
    process(engine, payload(alert("HighErrorRate", service="payment-api")))
    incident = only(engine)
    assert engine.docker.calls == [("restart", "payment-api")] * 3
    assert incident.state == "escalated" and incident.escalation["reason"] == "verification_failed"
    assert incident.attempts == 3
    assert sample("remediation_verification_total", {"result": "failure"}) == before_fail + 3
    assert sample("remediation_escalations_total", {"reason": "verification_failed"}) == before_esc + 1
    assert any(e["event"] == "verification:witness" and e["detail"]["result"] == "failed" for e in incident.timeline)


def test_attempt_budget_is_shared_across_incidents():
    engine = make_engine(witness=FakeWitness(ok=False))
    first = alert("HighErrorRate", service="payment-api")
    process(engine, payload(first), payload(resolved(first)))
    assert len(engine.docker.calls) == 3
    process(engine, payload(alert("ServiceDown", service="payment-api")))
    second = next(i for i in engine.incidents.values() if i.alertname == "ServiceDown")
    assert second.state == "escalated" and second.escalation["reason"] == "attempts_exhausted"
    assert len(engine.docker.calls) == 3


def test_cooldown_spaces_out_actions_on_same_target():
    settings = fast_settings()
    settings.limits["restart"] = Limits(3, 600, 0.3)
    engine = make_engine(settings=settings, witness=FakeWitness(ok=False))
    started = time.monotonic()
    process(engine, payload(alert("HighErrorRate", service="auth-service")))
    assert time.monotonic() - started >= 0.6
    assert sum(1 for e in only(engine).timeline if e["event"] == "guard:cooldown") == 2


def test_per_service_lock_lets_only_one_incident_restart_postgres():
    docker = FakeDocker({"postgres": "exited", "payment-api": "unhealthy", "auth-service": "unhealthy"}, delay=0.05)

    def heal(fake, action, service):
        if service == "postgres":
            fake.statuses.update({"payment-api": "healthy", "auth-service": "healthy"})
    docker.on_action = heal
    engine = make_engine(docker=docker)
    process(engine, payload(alert("DependencyFailures", service="payment-api")),
            payload(alert("DependencyFailures", service="auth-service")))
    assert docker.calls == [("start", "postgres")]
    assert {i.state for i in engine.incidents.values()} == {"recovered"}
    assert any(e["event"] in ("dedup", "lock:waiting") for i in engine.incidents.values() for e in i.timeline)


# ───────────────────────────── métriques ─────────────────────────────

def action_samples():
    # Cette méthode permet de lister les séries de remediation_actions_total exposées (labels de chacune).
    return [s.labels for family in REGISTRY.collect() if family.name == "remediation_actions"
            for s in family.samples if s.name == "remediation_actions_total"]


def test_actions_carry_a_bounded_target_label_never_an_ip():
    start = {"action": "start", "target": "payment-api", "result": "success"}
    block = {"action": "block_ip", "target": "waf", "result": "success"}
    before_start, before_block = sample("remediation_actions_total", start), sample("remediation_actions_total", block)
    process(make_engine(docker=FakeDocker({"payment-api": "exited"})), payload(alert("ServiceDown", service="payment-api")))
    process(make_engine(), payload(alert("AuthBruteForce", service="auth-service", client_ip=ATTACKER)))
    assert sample("remediation_actions_total", start) == before_start + 1
    assert sample("remediation_actions_total", block) == before_block + 1
    allowed = set(ALL_SERVICES) | {"waf", "paydb"}
    targets = {labels["target"] for labels in action_samples()}
    assert targets <= allowed, targets
    assert not any(ATTACKER in value for labels in action_samples() for value in labels.values())


def test_durations_are_observed_only_when_the_engine_acted():
    def counts(nature):
        return (sample("remediation_duration_seconds_count", {"nature": nature}),
                sample("remediation_alert_to_recovery_seconds_count", {"nature": nature}))

    # Rétabli sans action : chaîne saine et symptôme disparu, puis IP déjà bloquée par un autre incident.
    before = counts("availability"), counts("compromise")
    engine = make_engine(prom=FakeProm(scalars={'max(up{job="payment-api"})': 1.0}))
    process(engine, payload(alert("ServiceDown", service="payment-api")))
    assert only(engine).state == "recovered" and engine.docker.calls == []
    engine = make_engine()
    engine.blocklist.block(ATTACKER, 300, "déjà bloquée", "inc-autre")
    process(engine, payload(alert("AuthBruteForce", service="auth-service", client_ip=ATTACKER)))
    assert only(engine).state == "recovered" and len(engine.blocklist.blocked) == 1
    assert (counts("availability"), counts("compromise")) == before

    # Rétabli après une action du moteur : les deux durées sont observées, l'alerte précédant la détection.
    sums = (sample("remediation_duration_seconds_sum", {"nature": "availability"}),
            sample("remediation_alert_to_recovery_seconds_sum", {"nature": "availability"}))
    process(make_engine(docker=FakeDocker({"payment-api": "exited"})), payload(alert("ServiceDown", service="payment-api")))
    process(make_engine(), payload(alert("AuthBruteForce", service="auth-service", client_ip=ATTACKER)))
    assert counts("availability") == (before[0][0] + 1, before[0][1] + 1)
    assert counts("compromise") == (before[1][0] + 1, before[1][1] + 1)
    detection = sample("remediation_duration_seconds_sum", {"nature": "availability"}) - sums[0]
    since_alert = sample("remediation_alert_to_recovery_seconds_sum", {"nature": "availability"}) - sums[1]
    assert 0 < detection <= since_alert


def test_duration_histograms_have_sub_five_second_buckets():
    for name in ("remediation_duration_seconds_bucket", "remediation_alert_to_recovery_seconds_bucket"):
        for le in ("0.5", "1.0", "2.0", "5.0"):
            assert REGISTRY.get_sample_value(name, {"nature": "compromise", "le": le}) is not None, (name, le)


def test_blocked_ips_gauge_follows_the_blocklist_without_reading_the_api():
    engine = make_engine()
    process(engine, payload(alert("AuthBruteForce", service="auth-service", client_ip=ATTACKER)))
    assert sample("remediation_blocked_ips") == 1       # à jour dès le blocage, sans GET /api/state
    engine.blocklist.entries.clear()                    # TTL écoulé : la liste du WAF est vidée par expire()
    asyncio.run(engine.tick())
    assert sample("remediation_blocked_ips") == 0       # la boucle de fond suffit à refléter la levée
    engine.blocklist.block(OTHER, 300, "test", "inc-autre")
    asyncio.run(engine.tick())
    assert sample("remediation_blocked_ips") == 1
    asyncio.run(make_engine(blocklist=None).tick())
    assert sample("remediation_blocked_ips") == 0       # module WAF absent : aucune IP bloquée par le moteur


# ───────────────────────────── persistance ─────────────────────────────

def test_incidents_and_guard_survive_an_engine_restart(tmp_path):
    store = tmp_path / "state.json"
    firing = alert("ServiceDown", service="payment-api")
    first = make_engine(docker=FakeDocker({"payment-api": "exited"}), store_path=store)
    process(first, payload(firing))
    incident_id = only(first).id
    assert json.loads(store.read_text())["incidents"][0]["id"] == incident_id

    second = make_engine(store_path=store, settings=fast_settings(refire_grace_s=3600))
    process(second, payload(firing), payload(resolved(firing)))
    incident = second.incidents[incident_id]
    assert len(second.incidents) == 1, "la notification répétée retrouve l'incident rechargé"
    assert not incident.open and incident.outcome == "recovered"
    assert second.guard.attempts("restart:payment-api", 600, time.time()) == 1
    assert second.docker.calls == []


def test_interrupted_incident_is_resumed_after_restart(tmp_path):
    store = tmp_path / "state.json"
    slow = FakeDocker({"payment-api": "exited"}, delay=2)
    first = make_engine(docker=slow, store_path=store)

    async def interrupted():
        await first.start(background=False)
        first.ingest(payload(alert("ServiceDown", service="payment-api")))
        for _ in range(200):
            await asyncio.sleep(0.01)
            if only(first).state == "acting":
                break
        await first.stop()
    asyncio.run(interrupted())
    assert json.loads(store.read_text())["incidents"][0]["state"] == "acting"

    second = make_engine(docker=FakeDocker({"payment-api": "exited"}), store_path=store)
    process(second)
    incident = only(second)
    assert incident.state == "recovered"
    assert any("redémarrage du moteur" in json.dumps(e, ensure_ascii=False) for e in incident.timeline)


def test_corrupt_state_file_is_set_aside(tmp_path):
    store = tmp_path / "state.json"
    store.write_text("{pas du json")
    engine = make_engine(store_path=store)
    process(engine)
    assert list(tmp_path.glob("state.json.corrupt-*"))
    assert json.loads(store.read_text())["incidents"] == []


# ───────────────────────────── webhook et API ─────────────────────────────

@pytest.fixture
def api(tmp_path):
    # Cette méthode permet de démarrer l'application avec un moteur factice et un jeton de webhook généré.
    token = secrets.token_urlsafe(32)
    token_file = tmp_path / "remediation_webhook_token"
    token_file.write_text(token)
    settings = fast_settings(webhook_token_file=str(token_file))
    engine = make_engine(settings=settings, docker=FakeDocker({"payment-api": "exited"}, delay=0.3))
    with TestClient(main_mod.create_app(engine=engine, settings=settings)) as client:
        yield SimpleNamespace(client=client, token=token, engine=engine, token_file=token_file)


def _post(api, body, token=None, scheme="Bearer"):
    headers = {"Authorization": f"{scheme} {token}"} if token is not None else {}
    return api.client.post("/alerts", json=body, headers=headers)


def _wait_state(api, incident_id, wanted, timeout=10):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        found = api.client.get(f"/api/incidents/{incident_id}").json()
        if found["state"] in wanted:
            return found
        time.sleep(0.02)
    raise AssertionError(f"état {wanted} non atteint : {found['state']}")


def test_webhook_requires_the_bearer_token(api):
    body = payload(alert("ServiceDown", service="payment-api"))
    before = sample("remediation_webhook_rejected_total", {"reason": "unauthorized"})
    missing = _post(api, body)
    assert missing.status_code == 401 and missing.headers["www-authenticate"] == "Bearer"
    assert _post(api, body, secrets.token_urlsafe(32)).status_code == 401
    assert _post(api, body, api.token, scheme="Basic").status_code == 401
    assert _post(api, body, api.token[:-1]).status_code == 401
    assert sample("remediation_webhook_rejected_total", {"reason": "unauthorized"}) == before + 4
    assert api.engine.incidents == {}


def test_webhook_compares_tokens_in_constant_time(api, monkeypatch):
    calls = []
    real = main_mod.hmac.compare_digest

    def spy(a, b):
        calls.append(1)
        return real(a, b)
    monkeypatch.setattr(main_mod.hmac, "compare_digest", spy)
    assert _post(api, payload(alert("HostMemoryLow", service="pc-hote")), api.token).status_code == 202
    assert calls


def test_webhook_fails_closed_without_token_file(api):
    api.token_file.unlink()
    assert _post(api, payload(alert("ServiceDown", service="payment-api")), api.token).status_code == 503


def test_webhook_rejects_malformed_payload(api):
    response = api.client.post("/alerts", content=b"{}", headers={"Authorization": f"Bearer {api.token}",
                                                                   "Content-Type": "application/json"})
    assert response.status_code == 400


def test_webhook_answers_202_before_the_action_completes(api):
    started = time.monotonic()
    response = _post(api, payload(alert("ServiceDown", service="payment-api")), api.token)
    elapsed = time.monotonic() - started
    assert response.status_code == 202
    assert elapsed < 0.25, "le webhook ne doit pas attendre l'action (redémarrage factice de 0,3 s)"
    incident_id = response.json()["results"][0]["incident"]
    assert api.client.get(f"/api/incidents/{incident_id}").json()["state"] != "recovered"
    found = _wait_state(api, incident_id, {"recovered"})
    assert [e["event"] for e in found["timeline"]][0] == "state:detected"
    state = api.client.get("/api/state").json()
    assert [i["id"] for i in state["open_incidents"]] == [incident_id]
    assert state["bridge"]["configured"] is True
    assert api.client.get("/api/incidents?limit=1").json()[0]["id"] == incident_id
    assert api.client.get("/api/incidents/inc-absent").status_code == 404
    health = api.client.get("/health")
    assert health.status_code == 200 and health.json()["checks"]["webhook_token"] is True
    metrics = api.client.get("/metrics").text
    for name in ("remediation_actions_total", "remediation_duration_seconds", "remediation_incidents_open",
                 "remediation_verification_total"):
        assert name in metrics


def test_api_exposes_no_mutating_route():
    app = main_mod.create_app(engine=make_engine(), settings=fast_settings())
    for route in app.routes:
        if not isinstance(route, APIRoute):
            continue
        if route.path == "/alerts":
            assert route.methods == {"POST"}
        else:
            assert route.methods <= {"GET", "HEAD"}, (route.path, route.methods)
    paths = {r.path for r in app.routes if isinstance(r, APIRoute)}
    assert {"/api/state", "/api/incidents", "/api/incidents/{incident_id}", "/alerts", "/health"} <= paths


def test_health_stays_200_when_dependencies_are_down(tmp_path):
    settings = fast_settings(webhook_token_file=str(tmp_path / "absent"))
    engine = make_engine(settings=settings, loki=FakeLoki(error="down"), bridge=FakeBridge(available=False))
    with TestClient(main_mod.create_app(engine=engine, settings=settings)) as client:
        time.sleep(0.15)
        body = client.get("/health")
        assert body.status_code == 200
        assert body.json()["status"] == "degraded"
        assert {"loki", "restore_bridge", "webhook_token"} <= set(body.json()["degraded"])


# ───────────────────────────── client du proxy Docker ─────────────────────────────

class _FakeDockerApi(http.server.BaseHTTPRequestHandler):
    containers = []
    requests = []

    def log_message(self, *args):
        pass

    def _send(self, status, body=None):
        raw = json.dumps(body).encode() if body is not None else b""
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        url = urllib.parse.urlparse(self.path)
        self.requests.append(("GET", self.path))
        if url.path == "/containers/json":
            query = urllib.parse.parse_qs(url.query)
            wanted = json.loads(query["filters"][0])["label"] if "filters" in query else []
            found = [c for c in self.containers
                     if all(f"{k}={v}" in wanted for k, v in c["Labels"].items() if k.endswith(("project", "service")))]
            return self._send(200, [c for c in found if all(
                any(w == f"{k}={v}" for k, v in c["Labels"].items()) for w in wanted)])
        match = re.fullmatch(r"/containers/(\w+)/json", url.path)
        if match:
            container = next((c for c in self.containers if c["Id"] == match.group(1)), None)
            return self._send(200, {"State": container["_state"]}) if container else self._send(404, {})
        return self._send(403)

    def do_POST(self):
        url = urllib.parse.urlparse(self.path)
        self.requests.append(("POST", self.path))
        if re.fullmatch(r"/containers/\w+/(restart|kill)", url.path):
            return self._send(204)
        if re.fullmatch(r"/containers/\w+/start", url.path):
            return self._send(304)
        return self._send(403)


@pytest.fixture
def docker_api():
    # Cette méthode permet de démarrer une fausse API Docker (protocole HTTP réel) sur un port local éphémère.
    def container(cid, service, state, oneoff="False", created=1):
        return {"Id": cid, "Created": created, "State": state["Status"], "_state": state,
                "Labels": {"com.docker.compose.project": "resilience-alpha", "com.docker.compose.service": service,
                           "com.docker.compose.oneoff": oneoff}}
    _FakeDockerApi.containers = [
        container("aaa111", "payment-api", {"Status": "running", "Health": {"Status": "healthy"}}),
        container("bbb222", "payment-api", {"Status": "exited"}, oneoff="True", created=5),
        container("ccc333", "postgres", {"Status": "exited"}),
        container("ddd444", "blackbox", {"Status": "running"}),
        container("eee555", "frontend", {"Status": "restarting"}),
    ]
    _FakeDockerApi.requests = []
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _FakeDockerApi)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield docker_proxy.DockerProxy(f"http://127.0.0.1:{server.server_port}", "resilience-alpha", timeout=2)
    server.shutdown()


def test_docker_proxy_finds_containers_by_compose_labels(docker_api):
    assert docker_api.container_id("payment-api") == "aaa111"   # le conteneur « run » ponctuel est ignoré
    assert docker_api.health("payment-api") == "healthy"
    assert docker_api.health("postgres") == "exited"
    assert docker_api.health("blackbox") == "running"
    assert docker_api.health("frontend") == "starting"
    assert docker_api.health("grafana") == "none"
    assert docker_api.inspect("payment-api")["State"]["Status"] == "running"
    with pytest.raises(ActionError):
        docker_api.container_id("grafana")
    filters = [p for m, p in _FakeDockerApi.requests if "filters" in p][0]
    assert "com.docker.compose.project%3Dresilience-alpha" in filters


def test_docker_proxy_recovery_operations(docker_api):
    docker_api.restart("payment-api", timeout_s=5)
    docker_api.start("postgres")
    docker_api.signal("payment-api", "HUP")
    posts = [p for m, p in _FakeDockerApi.requests if m == "POST"]
    assert posts == ["/containers/aaa111/restart?t=5", "/containers/ccc333/start", "/containers/aaa111/kill?signal=HUP"]
    with pytest.raises(ActionError):
        docker_api.signal("payment-api", "HUP; rm")
    assert docker_api.ping() is True


def test_docker_proxy_refusal_and_outage_raise_action_error(docker_api):
    with pytest.raises(ActionError, match="403"):
        docker_api._request("POST", "/containers/create")
    down = docker_proxy.DockerProxy("http://127.0.0.1:9", "resilience-alpha", timeout=0.5)
    with pytest.raises(ActionError):
        down.health("payment-api")
    assert down.ping() is False


# ───────────────────────────── transaction témoin ─────────────────────────────

class _FakeWaf(http.server.BaseHTTPRequestHandler):
    users, accounts, tokens, transfers, passwords = {}, {}, {}, [], []
    fail_transfer = False

    def log_message(self, *args):
        pass

    def _send(self, status, body):
        raw = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _body(self):
        return json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")

    def _account(self):
        token = self.headers.get("Authorization", "").removeprefix("Bearer ")
        email = self.tokens.get(token)
        if email and email not in self.accounts:
            self.accounts[email] = {"account_number": f"RA{len(self.accounts):010d}", "balance_cents": 100_000}
        return self.accounts.get(email)

    def do_POST(self):
        body = self._body()
        if self.path == "/api/auth/register":
            self.users[body["email"]] = body["password"]
            self.passwords.append(body["password"])
            return self._send(201, {"id": str(uuid.uuid4())})
        if self.path == "/api/auth/login":
            if self.users.get(body["email"]) != body["password"]:
                return self._send(401, {"detail": "Identifiants invalides"})
            token = secrets.token_urlsafe(16)
            self.tokens[token] = body["email"]
            return self._send(200, {"access_token": token})
        if self.path == "/api/payments/transfers":
            if self.fail_transfer or not self.headers.get("Idempotency-Key"):
                return self._send(503, {"code": "database_unavailable"})
            sender = self._account()
            target = next(a for a in self.accounts.values() if a["account_number"] == body["to_account_number"])
            sender["balance_cents"] -= body["amount_cents"]
            target["balance_cents"] += body["amount_cents"]
            return self._send(201, {"id": str(uuid.uuid4())})
        return self._send(404, {})

    def do_GET(self):
        if self.path == "/api/payments/accounts/me":
            account = self._account()
            return self._send(200, account) if account else self._send(401, {})
        return self._send(404, {})


@pytest.fixture
def fake_waf():
    # Cette méthode permet de simuler le parcours client derrière le WAF (inscription, connexion, comptes, virements).
    for attr in ("users", "accounts", "tokens"):
        setattr(_FakeWaf, attr, {})
    _FakeWaf.passwords, _FakeWaf.fail_transfer = [], False
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _FakeWaf)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()


def test_witness_transaction_registers_transfers_and_checks_balances(fake_waf):
    result = witness_mod.Witness(fake_waf, timeout=2).run()
    assert [s["step"] for s in result["steps"]][-2:] == ["virement", "soldes"]
    assert all(s["ok"] for s in result["steps"])
    witness_mod.Witness(fake_waf, timeout=2).run()
    # Mots de passe générés à chaque exécution, jamais réutilisés
    assert len(set(_FakeWaf.passwords)) == len(_FakeWaf.passwords) == 4
    assert all(len(p) >= 20 for p in _FakeWaf.passwords)


def test_witness_failure_reports_the_failing_step(fake_waf):
    _FakeWaf.fail_transfer = True
    with pytest.raises(witness_mod.WitnessError) as err:
        witness_mod.Witness(fake_waf, timeout=2).run()
    assert err.value.steps[-1] == {"step": "virement", "ok": False, "status": 503, "transfer_id": None}


def test_witness_source_has_no_literal_password():
    source = (REPO / "services/remediation-engine/app/witness.py").read_text(encoding="utf-8")
    assert not re.search(r'password"\s*:\s*"', source)


# ───────────────────────────── configuration de la stack ─────────────────────────────

def test_alertmanager_authenticates_its_webhook_calls():
    config_ = yaml.safe_load((REPO / "infra/alertmanager/alertmanager.yml").read_text(encoding="utf-8"))
    hook = config_["receivers"][0]["webhook_configs"][0]
    assert hook["url"] == "http://remediation-engine:8000/alerts" and hook["send_resolved"] is True
    auth = hook["http_config"]["authorization"]
    assert auth["credentials_file"] == "/run/secrets/remediation_webhook_token"
    assert "credentials" not in auth


def test_compose_isolates_engine_and_docker_socket_proxy():
    compose = yaml.safe_load((REPO / "docker-compose.yml").read_text(encoding="utf-8"))
    services, networks = compose["services"], compose["networks"]
    engine, proxy = services["remediation-engine"], services["docker-socket-proxy"]
    assert "ports" not in engine and "ports" not in proxy
    assert engine["read_only"] is True and engine["cap_drop"] == ["ALL"]
    assert set(engine["networks"]) == {"obs", "app", "dmz", "docker-api"}
    assert "remediation_webhook_token" in engine["secrets"] and "prometheus_password" in engine["secrets"]
    assert "remediation_webhook_token" in services["alertmanager"]["secrets"]
    assert networks["docker-api"]["internal"] is True
    assert [name for name, svc in services.items() if "docker-api" in (svc.get("networks") or [])] == [
        "remediation-engine", "docker-socket-proxy"]
    assert not any("docker.sock" in str(v) for v in engine.get("volumes", []))
    assert "/var/run/docker.sock:/var/run/docker.sock:ro" in proxy["volumes"]
    assert re.fullmatch(r"tecnativa/docker-socket-proxy:v\d+\.\d+\.\d+", proxy["image"])
    env = {k: str(v) for k, v in proxy["environment"].items() if k != "DISABLE_IPV6"}
    allowed = {k for k, v in env.items() if v == "1"}
    assert allowed == {"CONTAINERS", "POST", "ALLOW_RESTARTS", "ALLOW_START"}


def test_init_secrets_generates_the_webhook_token():
    source = (REPO / "scripts/init_secrets.py").read_text(encoding="utf-8")
    assert "remediation_webhook_token" in source
