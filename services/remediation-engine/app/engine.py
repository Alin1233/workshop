"""Moteur de remédiation : alerte → incident → décision → action → vérification → rétabli | échec → escalade.

Le webhook ne fait qu'enregistrer les alertes (`ingest`, quelques millisecondes) ; chaque incident est traité par une
tâche asynchrone. Les appels bloquants (proxy Docker, Prometheus, Loki, WAF, transaction témoin) passent par un thread.

Garde-fous anti-boucle :
- un incident par clé de corrélation (même cible, même réponse) : les notifications répétées d'Alertmanager (toutes les
  5 min) et les alertes corrélées (ServiceDown + EndToEndProbeFailed…) ne déclenchent pas de nouvelle action ;
- un verrou par cible (service, IP) : deux incidents n'agissent jamais en même temps sur le même conteneur, et le second
  constate le travail du premier (action récente réussie, chaîne saine) au lieu de redémarrer à son tour ;
- un budget d'actions par cible et par fenêtre glissante (ex. 3 redémarrages / 10 min), un délai minimal entre deux
  actions, puis l'escalade vers l'opérateur ;
- les alertes visant le moteur lui-même ne sont jamais remédiées.
"""

import asyncio
import contextlib
import dataclasses
import hashlib
import ipaddress
import json
import logging
import time
from dataclasses import dataclass, field

from . import metrics
from .actions import ActionError
from .clients import SourceError
from .config import Settings
from .decisions import (API_SERVICES, AVAILABILITY_FEATURES, DECISION_TABLE, LOGIN_FAILURES_QUERY, PROBE_LABELS,
                        RESTARTABLE, RESTORE_SCOPE, SECURITY_FEATURES, SELF_RULE, UNKNOWN_RULE, Nature, Rule, Strategy,
                        anomaly_log_query, chain_for, correlation_key, offender_query, rule_for, table_document,
                        target_service)
from .incidents import CLOSABLE, IN_FLIGHT, Guard, Incident, State, StateStore, iso, new_incident_id
from .witness import WitnessError

logger = logging.getLogger("remediation-engine.engine")

OK_STATUSES = frozenset({"healthy", "running"})
BUSINESS_CHECKS = ["containers", "probes", "witness"]


class GuardRefused(RuntimeError):
    """Anti-boucle : le budget d'actions de la cible est épuisé pour la fenêtre en cours."""


class NotAllowed(RuntimeError):
    """La cible n'est pas dans la liste des services que le moteur a le droit de redémarrer."""


@dataclass
class Plan:
    """Décision prise pour un incident : quoi faire, sur quelle cible, et comment le vérifier."""

    kind: str                           # act | verify | observe | escalate
    nature: str                         # availability | compromise | observe | operator | self
    reason: str                         # justification en clair (chronologie, journaux, dashboard)
    action: str | None = None           # restart | block_ip | restore_db
    service: str | None = None          # service Compose concerné
    target: str | None = None           # cible de l'action : service, IP ou base
    chain: list[str] = field(default_factory=list)      # conteneurs diagnostiqués / vérifiés
    locks: list[str] = field(default_factory=list)
    limits: str = "restart"             # garde-fous applicables (Settings.limits)
    checks: list[str] = field(default_factory=list)     # étapes de vérification, dans l'ordre
    when_healthy: str = "restart"
    symptom: str = ""
    escalate_reason: str | None = None
    wait_s: float = 0.0                 # observe : délai avant réévaluation (0 = jusqu'à la résolution)
    evidence: dict = field(default_factory=dict)

    def public(self) -> dict:
        # Cette méthode permet d'exposer la décision dans l'incident (API d'état), sans les détails internes de verrou.
        data = dataclasses.asdict(self)
        data.pop("locks")
        return {k: v for k, v in data.items() if v not in (None, "", [], {}, 0.0)}


def _parse_ts(value: str | None) -> float | None:
    # Cette méthode permet de convertir un horodatage RFC 3339 d'Alertmanager (startsAt/endsAt) en temps Unix.
    if not value or value.startswith("0001-"):
        return None
    from datetime import datetime
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def normalise_alert(raw: dict) -> dict:
    # Cette méthode permet de ramener une alerte Alertmanager v4 à un format stable (empreinte calculée si absente).
    labels = {str(k): str(v) for k, v in (raw.get("labels") or {}).items()}
    fingerprint = raw.get("fingerprint") or hashlib.sha256(
        json.dumps(labels, sort_keys=True).encode()).hexdigest()[:16]
    return {
        "fingerprint": str(fingerprint),
        "status": "resolved" if raw.get("status") == "resolved" else "firing",
        "labels": labels,
        "annotations": {str(k): str(v) for k, v in (raw.get("annotations") or {}).items()},
        "starts_at": _parse_ts(raw.get("startsAt")),
        "ends_at": _parse_ts(raw.get("endsAt")),
    }


class Engine:
    """Orchestrateur des incidents : intégration des alertes, décisions, actions, vérifications, état persistant."""

    def __init__(self, settings: Settings, docker, prometheus, loki, integrity, witness,
                 blocklist=None, bridge=None, store: StateStore | None = None, clock=time.time):
        # Cette méthode permet d'assembler le moteur avec ses clients (réels en production, factices en test).
        self.settings = settings
        self.docker = docker
        self.prometheus = prometheus
        self.loki = loki
        self.integrity = integrity
        self.witness = witness
        self.blocklist = blocklist
        self.bridge = bridge
        self.store = store or StateStore(None)
        self.clock = clock
        self.incidents: dict[str, Incident] = {}
        self.by_fingerprint: dict[str, str] = {}
        self.guard = Guard()
        self.locks: dict[str, asyncio.Lock] = {}
        self.tasks: dict[str, asyncio.Task] = {}
        self.resolved_events: dict[str, asyncio.Event] = {}
        self.recent_actions: dict[str, dict] = {}       # cible → dernière action réussie {incident, at}
        self.started_at = clock()
        self.dependencies: dict[str, object] = {}
        self._background: asyncio.Task | None = None
        self._loaded = False
        metrics.initialise()

    # ───────────────────────────── cycle de vie ─────────────────────────────

    async def start(self, background: bool = True) -> None:
        # Cette méthode permet de recharger l'état persistant, de reprendre les incidents interrompus par un redémarrage
        # du moteur et de lancer la boucle de fond (santé des dépendances, expiration des blocages, ménage).
        if self._loaded:
            return
        self._loaded = True
        incidents, guard = self.store.load()
        self.guard = Guard(guard)
        now = self.clock()
        for incident in incidents:
            self.incidents[incident.id] = incident
            if not incident.open:
                continue
            for fingerprint, alert in incident.alerts.items():
                self.by_fingerprint[fingerprint] = incident.id
            for action in incident.actions:
                if action.get("result") == "success" and action.get("target"):
                    self.recent_actions[action["target"]] = {"incident": incident.id, "at": action["ts"]}
            if incident.state == State.OBSERVING and incident.strategy != Strategy.OBSERVE_THEN_RESTART:
                continue   # observation sans échéance : rien à reprendre, la clôture viendra de la résolution
            if incident.state in IN_FLIGHT:
                if incident.state in (State.ACTING, State.VERIFYING):
                    incident.transition(State.FAILED, now, reason="traitement interrompu par un redémarrage du moteur")
                else:
                    incident.event("resumed", now, reason="traitement repris après un redémarrage du moteur")
                self._schedule(incident)
        if incidents:
            logger.info("remediation_state_loaded", extra={
                "event_type": "remediation_state_loaded", "incidents": len(incidents),
                "open": sum(1 for i in incidents if i.open), "resumed": len(self.tasks)})
        self._save()
        if background:
            self._background = asyncio.create_task(self._background_loop())

    async def stop(self) -> None:
        # Cette méthode permet d'arrêter proprement la boucle de fond et les tâches d'incident (état déjà persistant).
        tasks = [t for t in [self._background, *self.tasks.values()] if t and not t.done()]
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        self._save()

    async def wait_idle(self, timeout: float = 30.0) -> None:
        # Cette méthode permet d'attendre la fin de tous les traitements d'incident en cours (tests, arrêt).
        deadline = time.monotonic() + timeout
        while True:
            pending = [t for t in self.tasks.values() if not t.done()]
            if not pending:
                return
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(f"{len(pending)} incident(s) encore en cours")
            await asyncio.wait(pending, timeout=remaining)

    # ───────────────────────────── intégration des alertes ─────────────────────────────

    def ingest(self, payload: dict) -> dict:
        # Cette méthode permet d'intégrer une notification Alertmanager (toutes ses alertes, firing et resolved) sans
        # rien exécuter : chaque nouvel incident est confié à une tâche asynchrone, le webhook répond aussitôt.
        results = []
        for raw in payload.get("alerts") or []:
            if not isinstance(raw, dict):
                continue
            alert = normalise_alert(raw)
            metrics.ALERTS.labels(alert["status"]).inc()
            results.append(self._resolve(alert) if alert["status"] == "resolved" else self._fire(alert))
        self._save()
        return {"accepted": len(results), "results": results}

    def _fire(self, alert: dict) -> dict:
        # Cette méthode permet de traiter une alerte active : notification répétée (idempotence), alerte corrélée à un
        # incident ouvert, ou nouvel incident.
        now = self.clock()
        labels = alert["labels"]
        fingerprint = alert["fingerprint"]
        known = self.by_fingerprint.get(fingerprint)
        if known and self.incidents[known].open:
            incident = self.incidents[known]
            entry = incident.alerts[fingerprint]
            entry.update(status="firing", notifications=entry.get("notifications", 1) + 1, last_received_at=iso(now))
            self._log("remediation_duplicate", incident, alertname=labels.get("alertname"),
                      notifications=entry["notifications"])
            if (incident.state == State.RECOVERED and not self._running(incident)
                    and now - (incident.recovered_at or now) > self.settings.refire_grace_s):
                incident.event("alert:still_firing", now, alertname=labels.get("alertname"),
                               reason="alerte toujours active longtemps après le rétablissement : nouvelle évaluation")
                self._schedule(incident)
            return {"fingerprint": fingerprint, "incident": incident.id, "status": "duplicate"}

        rule = rule_for(labels)
        key = correlation_key(rule, labels)
        entry = {"fingerprint": fingerprint, "status": "firing", "labels": labels, "annotations": alert["annotations"],
                 "starts_at": iso(alert["starts_at"]), "received_at": iso(now), "last_received_at": iso(now),
                 "notifications": 1}
        existing = next((i for i in self.incidents.values() if i.open and i.key == key), None)
        if existing:
            existing.alerts[fingerprint] = entry
            self.by_fingerprint[fingerprint] = existing.id
            existing.event("alert:correlated", now, alertname=labels.get("alertname"), fingerprint=fingerprint)
            self._log("remediation_correlated", existing, alertname=labels.get("alertname"))
            started = alert["starts_at"] or now
            if (existing.state == State.RECOVERED and not self._running(existing)
                    and started > (existing.recovered_at or now)):
                existing.event("alert:new_after_recovery", now, reason="nouvelle alerte après le rétablissement")
                self._schedule(existing)
            return {"fingerprint": fingerprint, "incident": existing.id, "status": "correlated"}

        incident = Incident(
            id=new_incident_id(now), key=key, alertname=labels.get("alertname", "?"), rule=rule.alertname,
            strategy=str(rule.strategy), nature=str(rule.nature), domain=labels.get("domain", ""),
            severity=labels.get("severity", ""), service=target_service(labels),
            created_at=now, updated_at=now, alert_started_at=alert["starts_at"], alerts={fingerprint: entry})
        incident.event("state:detected", now, alertname=incident.alertname, labels=labels,
                       summary=alert["annotations"].get("summary"))
        self.incidents[incident.id] = incident
        self.by_fingerprint[fingerprint] = incident.id
        self._log("remediation_detected", incident, labels=labels)
        self._schedule(incident)
        self._refresh_gauges()
        return {"fingerprint": fingerprint, "incident": incident.id, "status": "created"}

    def _resolve(self, alert: dict) -> dict:
        # Cette méthode permet d'enregistrer la retombée d'une alerte, et de clore l'incident si plus rien n'est actif.
        now = self.clock()
        fingerprint = alert["fingerprint"]
        incident_id = self.by_fingerprint.get(fingerprint)
        if not incident_id or not self.incidents[incident_id].open:
            return {"fingerprint": fingerprint, "incident": None, "status": "resolved_unknown"}
        incident = self.incidents[incident_id]
        incident.alerts[fingerprint].update(status="resolved", ends_at=iso(alert["ends_at"] or now),
                                            resolved_received_at=iso(now))
        incident.event("alert:resolved", now, alertname=alert["labels"].get("alertname"))
        self._log("remediation_alert_resolved", incident, alertname=alert["labels"].get("alertname"))
        if incident.all_resolved() and incident.id in self.resolved_events:
            self.resolved_events[incident.id].set()
        self._maybe_close(incident)
        return {"fingerprint": fingerprint, "incident": incident.id, "status": "resolved"}

    # ───────────────────────────── traitement d'un incident ─────────────────────────────

    def _running(self, incident: Incident) -> bool:
        # Cette méthode permet de savoir si une tâche traite déjà l'incident.
        task = self.tasks.get(incident.id)
        return bool(task and not task.done())

    def _schedule(self, incident: Incident) -> None:
        # Cette méthode permet de confier l'incident à une tâche asynchrone (une seule à la fois par incident).
        if self._running(incident):
            return
        self.tasks[incident.id] = asyncio.get_running_loop().create_task(self._run_safe(incident))

    async def _run_safe(self, incident: Incident) -> None:
        # Cette méthode permet d'exécuter le traitement sans jamais laisser une erreur inattendue tuer le moteur :
        # l'incident est alors escaladé.
        try:
            await self._run(incident)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 - toute erreur imprévue part en escalade
            logger.exception("remediation_internal_error",
                             extra={"event_type": "remediation_error", "incident_id": incident.id})
            self._escalate(incident, "action_failed", f"erreur interne du moteur : {exc}")
        finally:
            self._maybe_close(incident)
            if self.tasks.get(incident.id) is asyncio.current_task():
                del self.tasks[incident.id]
            self._save()
            self._refresh_gauges()

    def _rule(self, incident: Incident) -> Rule:
        # Cette méthode permet de retrouver la règle appliquée à l'incident (y compris après un rechargement).
        if incident.rule == SELF_RULE.alertname:
            return SELF_RULE
        return DECISION_TABLE.get(incident.rule, UNKNOWN_RULE)

    async def _run(self, incident: Incident) -> None:
        # Cette méthode permet de dérouler la boucle décision → action → vérification, avec nouvelles tentatives
        # bornées par l'anti-boucle puis escalade.
        rule = self._rule(incident)
        observed = False
        while True:
            plan = await self._decide(incident, rule, observed)
            self._enter_decided(incident, plan)
            if plan.kind == "escalate":
                self._escalate(incident, plan.escalate_reason or "policy", plan.reason)
                return
            if plan.kind == "observe":
                incident.transition(State.OBSERVING, self.clock(), reason=plan.reason)
                self._log("remediation_observing", incident, reason=plan.reason)
                self._save()
                if not plan.wait_s:
                    return
                if await self._wait_resolved(incident, plan.wait_s):
                    incident.outcome = "resolved_without_action"
                    incident.event("observation:resolved", self.clock(), reason="alerte retombée pendant l'observation")
                    return
                incident.event("observation:persistent", self.clock(),
                               reason=f"alerte toujours active après {plan.wait_s:.0f} s : passage à l'action")
                observed = True
                continue
            incident.attempts += 1
            result = await self._act_and_verify(incident, plan)
            if result == "recovered":
                return
            if result == "exhausted":
                self._escalate(incident, "attempts_exhausted",
                               f"anti-boucle : budget d'actions épuisé sur {plan.target or plan.service}")
                return
            if result in ("not_allowed", "container_missing"):
                self._escalate(incident, result, incident.timeline[-1].get("detail", {}).get("error", plan.reason))
                return
            limits = self.settings.limits[plan.limits]
            if incident.attempts >= limits.max_attempts or plan.action == "restore_db":
                # Restauration : jamais rejouée automatiquement (précondition refusée, quota du runner, échec du script)
                reason = "verification_failed" if result == "verification_failed" else "action_failed"
                last_error = next((e["detail"].get("error") for e in reversed(incident.timeline)
                                   if e.get("detail", {}).get("error")), None)
                self._escalate(incident, reason, f"échec après {incident.attempts} tentative(s)"
                               + (f" : {last_error}" if last_error else ""))
                return
            incident.event("retry", self.clock(), attempt=incident.attempts + 1,
                           reason=f"nouvelle tentative dans {self.settings.retry_backoff_s:.0f} s")
            self._save()
            await asyncio.sleep(self.settings.retry_backoff_s)

    def _enter_decided(self, incident: Incident, plan: Plan) -> None:
        # Cette méthode permet d'enregistrer la décision (état decided) et de rendre visible la nature de la réponse.
        now = self.clock()
        if plan.nature != incident.nature and plan.nature in (Nature.AVAILABILITY, Nature.COMPROMISE, Nature.OBSERVE):
            incident.event("reclassified", now, nature_before=incident.nature, nature=plan.nature, reason=plan.reason)
            incident.nature = plan.nature
        incident.decision = plan.public()
        if incident.state != State.DECIDED:
            incident.transition(State.DECIDED, now, **incident.decision)
        else:
            incident.event("decision", now, **incident.decision)
        self._log("remediation_decided", incident, plan=incident.decision)
        self._save()

    async def _wait_resolved(self, incident: Incident, timeout: float) -> bool:
        # Cette méthode permet d'attendre la retombée de toutes les alertes de l'incident (True) ou l'expiration du délai.
        if incident.all_resolved():
            return True
        event = self.resolved_events.setdefault(incident.id, asyncio.Event())
        try:
            await asyncio.wait_for(event.wait(), timeout)
            return True
        except asyncio.TimeoutError:
            return incident.all_resolved()
        finally:
            self.resolved_events.pop(incident.id, None)

    # ───────────────────────────── décisions ─────────────────────────────

    async def _decide(self, incident: Incident, rule: Rule, observed: bool = False) -> Plan:
        # Cette méthode permet d'appliquer la stratégie de la table de décision à l'incident.
        strategy = rule.strategy
        if strategy is Strategy.RESTART:
            return await self._decide_restart(incident, rule, incident.service)
        if strategy is Strategy.OBSERVE_THEN_RESTART:
            if not observed:
                return Plan("observe", Nature.OBSERVE, "latence élevée : observation avant toute action",
                            service=incident.service, wait_s=self.settings.latency_persist_s)
            return await self._decide_restart(incident, rule, incident.service)
        if strategy is Strategy.INTEGRITY_RESTORE:
            return await self._decide_integrity(incident)
        if strategy is Strategy.BLOCK_ALERT_IP:
            labels = self._first_labels(incident)
            return await self._decide_block(labels.get("client_ip", ""), f"IP portée par {incident.alertname}")
        if strategy is Strategy.BLOCK_TOP_IP:
            return await self._decide_top_ip(incident)
        if strategy is Strategy.ANOMALY_TRIAGE:
            return await self._decide_anomaly(incident)
        if strategy is Strategy.RESTART_DETECTOR:
            return Plan("act", Nature.AVAILABILITY, "détecteur ML sans score : un seul redémarrage (service sans état)",
                        action="restart", service="anomaly-detector", target="anomaly-detector",
                        chain=["anomaly-detector"], locks=["anomaly-detector"], limits="detector",
                        checks=["containers"])
        if strategy is Strategy.OBSERVE:
            return Plan("observe", Nature.OBSERVE, rule.response)
        if strategy is Strategy.IGNORE_SELF:
            return Plan("observe", Nature.SELF, rule.response)
        reason = "unknown_alert" if rule is UNKNOWN_RULE else "policy"
        return Plan("escalate", Nature.OPERATOR, rule.response, escalate_reason=reason)

    def _first_labels(self, incident: Incident) -> dict:
        # Cette méthode permet de lire les labels de la première alerte de l'incident.
        return next(iter(incident.alerts.values()))["labels"] if incident.alerts else {}

    async def _health(self, services: list[str]) -> dict[str, str]:
        # Cette méthode permet de lire l'état de plusieurs conteneurs via le proxy (ActionError si le proxy est injoignable).
        return {s: await asyncio.to_thread(self.docker.health, s) for s in services}

    async def _decide_restart(self, incident: Incident, rule: Rule, service: str | None) -> Plan:
        # Cette méthode permet de décider d'un redémarrage : diagnostic de la chaîne (PostgreSQL, service, amont),
        # constat du symptôme quand tout semble sain, dédoublonnage avec une action récente d'un autre incident.
        if not service or service not in RESTARTABLE:
            return Plan("escalate", Nature.AVAILABILITY, f"service {service!r} hors du périmètre de redémarrage",
                        escalate_reason="not_allowed")
        chain = chain_for(service, rule.upstream)
        base = dict(nature=Nature.AVAILABILITY, action="restart", service=service, chain=chain, locks=chain,
                    limits="restart", checks=list(BUSINESS_CHECKS), when_healthy=rule.when_healthy,
                    symptom=rule.symptom)
        try:
            statuses = await self._health(chain)
        except ActionError as exc:
            return Plan("act", reason=f"état des conteneurs illisible ({exc}) : tentative de redémarrage de {service}",
                        target=service, **base)
        bad = [s for s in chain if statuses[s] not in OK_STATUSES | {"starting"}]
        starting = [s for s in chain if statuses[s] == "starting"]
        evidence = {"containers": statuses}
        if bad:
            return Plan("act", reason=f"{bad[0]} est {statuses[bad[0]]} : redémarrage de {bad[0]}"
                        + (f" (dépendance de {service})" if bad[0] != service else ""),
                        target=bad[0], evidence=evidence, **base)
        if starting:
            return Plan("act", reason=f"{starting[0]} est déjà en cours de démarrage : attente de sa stabilisation, "
                        "puis nouveau diagnostic sous verrou", target=service, evidence=evidence, **base)
        recent = self._recent_action(chain, incident)
        if recent:
            return Plan("verify", reason=f"chaîne saine, {recent['target']} déjà redémarré par {recent['incident']} : "
                        "vérification seule", target=service, evidence=evidence, **base)
        if rule.when_healthy == "verify":
            return Plan("verify", reason="conteneurs sains : vérification du service sans action",
                        target=service, evidence=evidence, **base)
        if rule.symptom and await self._symptom_cleared(rule.symptom, service):
            return Plan("verify", reason="conteneurs sains et symptôme disparu : vérification seule",
                        target=service, evidence=evidence, **base)
        return Plan("act", reason=f"conteneurs sains mais {incident.alertname} actif : redémarrage de {service}",
                    target=service, evidence=evidence, **base)

    async def _symptom_cleared(self, symptom: str, service: str) -> bool:
        # Cette méthode permet de constater dans Prometheus que le symptôme a disparu (valeur 1), en laissant le temps
        # d'un ou deux scrapes ; une source injoignable vaut « symptôme toujours là ».
        expr = symptom.format(svc=service, probe=PROBE_LABELS.get(service, service))
        deadline = time.monotonic() + self.settings.symptom_grace_s
        while True:
            try:
                value = await asyncio.to_thread(self.prometheus.scalar, expr)
                if value is not None and value >= 1:
                    return True
            except SourceError:
                return False
            if time.monotonic() >= deadline:
                return False
            await asyncio.sleep(self.settings.poll_s)

    def _recent_action(self, targets: list[str], incident: Incident) -> dict | None:
        # Cette méthode permet de retrouver une action réussie récente d'un AUTRE incident sur l'une des cibles
        # (dédoublonnage : on vérifie au lieu d'agir une seconde fois).
        now = self.clock()
        for target in targets:
            recent = self.recent_actions.get(target)
            if not recent or recent["incident"] == incident.id or now - recent["at"] >= self.settings.dedup_window_s:
                continue
            # Une action suivie d'un échec ou d'une escalade ne couvre rien : l'anti-boucle tranchera.
            other = self.incidents.get(recent["incident"])
            if other is None or other.state in (State.FAILED, State.ESCALATED):
                continue
            return {"target": target, **recent}
        return None

    async def _decide_integrity(self, incident: Incident) -> Plan:
        # Cette méthode permet de distinguer une vraie corruption (PostgreSQL sain + 409) d'une panne de base (la jauge
        # d'intégrité tombe aussi quand la base est injoignable) : seule la première justifie une restauration.
        try:
            postgres = await asyncio.to_thread(self.docker.health, "postgres")
        except ActionError as exc:
            postgres = f"inconnu ({exc})"
        code, report = await asyncio.to_thread(self.integrity.check)
        evidence = {"postgres": postgres, "integrity_status": code,
                    "checks": report.get("checks") if isinstance(report, dict) else None}
        # Un 409 n'est possible qu'après des requêtes réussies sur la base : proxy illisible + 409 reste une corruption.
        postgres_down = postgres in ("exited", "unhealthy", "starting", "none") or (
            postgres not in OK_STATUSES and code != 409)
        if postgres_down or code is None or code >= 500:
            plan = await self._decide_restart(incident, DECISION_TABLE["DependencyFailures"], "payment-api")
            plan.reason = (f"pas de corruption confirmée : base injoignable (postgres={postgres}, "
                           f"/internal/integrity={code or 'injoignable'}) → panne de disponibilité, aucune "
                           f"restauration. {plan.reason}")
            plan.evidence = {**plan.evidence, **evidence}
            # Base revenue : si le registre reste incohérent, c'était bien une corruption (nouvelle décision, restauration).
            plan.checks = ["containers", "integrity", "probes", "witness"]
            return plan
        if code == 200:
            return Plan("verify", Nature.COMPROMISE, "registre cohérent (/internal/integrity = 200) : aucune "
                        "corruption constatée, vérification seule", service="payment-api", target="paydb",
                        chain=["postgres", "payment-api"], checks=["integrity", "probes", "witness"],
                        evidence=evidence)
        if code != 409:
            return Plan("escalate", Nature.COMPROMISE, f"réponse inattendue du contrôle d'intégrité (HTTP {code})",
                        escalate_reason="action_failed", evidence=evidence)
        available = self.bridge is not None and await asyncio.to_thread(self.bridge.available)
        if not available:
            return Plan("escalate", Nature.COMPROMISE, "corruption confirmée (PostgreSQL sain, 409) mais aucun pont "
                        "de restauration actif : restauration manuelle (docs/runbooks/restauration-base.md)",
                        escalate_reason="bridge_unavailable", evidence=evidence)
        return Plan("act", Nature.COMPROMISE, "corruption confirmée (PostgreSQL sain, /internal/integrity = 409) : "
                    "restauration de la dernière sauvegarde saine", action="restore_db", service="payment-api",
                    target="paydb", chain=list(RESTORE_SCOPE), locks=list(RESTORE_SCOPE), limits="restore",
                    checks=["containers", "integrity", "probes", "witness"], evidence=evidence)

    async def _decide_block(self, ip: str, reason: str, evidence: dict | None = None) -> Plan:
        # Cette méthode permet de décider le blocage d'une IP au WAF (dédoublonné si elle est déjà bloquée).
        try:
            ip = str(ipaddress.ip_address(ip.strip()))
        except ValueError:
            return Plan("escalate", Nature.COMPROMISE, f"IP attaquante invalide ou absente ({ip!r})",
                        escalate_reason="no_offender", evidence=evidence or {})
        if self.blocklist is None:
            return Plan("escalate", Nature.COMPROMISE, f"blocage de {ip} impossible : liste de blocage du WAF "
                        "indisponible", escalate_reason="waf_unavailable", target=ip, evidence=evidence or {})
        base = dict(nature=Nature.COMPROMISE, action="block_ip", target=ip, locks=[f"ip:{ip}"], limits="block",
                    checks=["waf_block", "probes", "witness"], evidence=evidence or {})
        allowlisted = getattr(self.blocklist, "allowlisted", None)
        if allowlisted is not None:
            try:
                covering = await asyncio.to_thread(allowlisted, ip)
            except ActionError as exc:
                return Plan("escalate", reason=f"IP {ip} non bloquable : {exc}", escalate_reason="no_offender",
                            **{**base, "action": None})
            if covering:
                return Plan("escalate", reason=f"{ip} appartient à un réseau exclu du blocage ({covering}) : jamais "
                            "bloquée automatiquement, escalade", escalate_reason="not_allowed",
                            **{**base, "action": None})
        if await self._is_blocked(ip):
            return Plan("verify", reason=f"{ip} déjà bloquée au WAF : vérification seule", **base)
        return Plan("act", reason=f"{reason} : blocage de {ip} au WAF ({self.settings.waf_block_ttl_s} s)", **base)

    async def _is_blocked(self, ip: str) -> bool:
        # Cette méthode permet de savoir si une IP figure déjà parmi les blocages actifs du WAF.
        try:
            return any(entry.ip == ip for entry in await asyncio.to_thread(self.blocklist.active))
        except Exception:  # noqa: BLE001 - liste illisible : on tentera le blocage
            return False

    async def _offender(self, query: str) -> tuple[str, float] | None:
        # Cette méthode permet de retrouver l'IP la plus fautive dans Loki (SourceError si Loki est injoignable).
        return await asyncio.to_thread(self.loki.top_ip, query)

    async def _decide_top_ip(self, incident: Incident) -> Plan:
        # Cette méthode permet d'attribuer un pic d'échecs de connexion (sans IP dans l'alerte) à l'IP la plus fautive.
        try:
            top = await self._offender(LOGIN_FAILURES_QUERY)
        except SourceError as exc:
            return Plan("escalate", Nature.COMPROMISE, f"Loki injoignable, IP non attribuable : {exc}",
                        escalate_reason="no_offender")
        minimum = self.settings.security_min_events
        if not top or top[1] < minimum:
            return Plan("observe", Nature.OBSERVE, f"aucune IP au-dessus de {minimum} échecs en 2 min "
                        f"(meilleure : {top}) : attaque distribuée ou terminée, observation",
                        evidence={"top": top})
        return await self._decide_block(top[0], f"{top[1]:.0f} échecs de connexion en 2 min depuis {top[0]}",
                                        {"failures_2m": top[1]})

    def _api_incident(self, incident: Incident) -> Incident | None:
        # Cette méthode permet de retrouver un incident ouvert ou récent sur une API (auth-service, payment-api) :
        # une anomalie du frontal à ce moment-là en est le contrecoup (le trafic d'attaque traverse le frontal).
        now = self.clock()
        for other in self.incidents.values():
            if (other.id != incident.id and other.service in API_SERVICES and other.nature != Nature.SELF
                    and (other.open or now - other.created_at < self.settings.coalert_window_s)):
                return other
        return None

    async def _decide_anomaly(self, incident: Incident) -> Plan:
        # Cette méthode permet de router une anomalie ML selon sa variable dominante : attaque → blocage de l'IP fautive,
        # panne → redémarrage, co-alerte du frontal → rattachement, sinon observation et escalade.
        service = incident.service or ""
        try:
            entry = await asyncio.to_thread(self.loki.latest, anomaly_log_query(service), 900)
        except SourceError as exc:
            return Plan("escalate", Nature.OBSERVE, f"journal du détecteur illisible (Loki) : {exc}",
                        escalate_reason="triage_unknown")
        if not entry or not entry.get("dominant_feature"):
            return Plan("escalate", Nature.OBSERVE, f"aucun journal anomaly_detected récent pour {service}",
                        escalate_reason="triage_unknown")
        feature = entry["dominant_feature"]
        evidence = {"dominant_feature": feature, "complete": entry.get("complete"),
                    "anomaly_score": entry.get("anomaly_score"), "target_service": entry.get("target_service")}
        incident.event("triage", self.clock(), **evidence)
        if feature in SECURITY_FEATURES:
            query = offender_query(feature, service)
            if query is None:
                return Plan("escalate", Nature.COMPROMISE, f"variable d'attaque {feature} sans source d'IP pour "
                            f"{service}", escalate_reason="no_offender", evidence=evidence)
            try:
                top = await self._offender(query)
            except SourceError as exc:
                return Plan("escalate", Nature.COMPROMISE, f"Loki injoignable, IP non attribuable : {exc}",
                            escalate_reason="no_offender", evidence=evidence)
            if not top or top[1] < self.settings.security_min_events:
                return Plan("escalate", Nature.COMPROMISE, f"attaque ({feature}) sans IP dominante (meilleure : "
                            f"{top}) : attaque distribuée, escalade", escalate_reason="no_offender",
                            evidence=evidence)
            return await self._decide_block(top[0], f"anomalie {feature} sur {service}, {top[1]:.0f} événements "
                                            f"en 2 min depuis {top[0]}", {**evidence, "events_2m": top[1]})
        if feature in AVAILABILITY_FEATURES:
            template = DECISION_TABLE["EndToEndProbeFailed" if feature == "probe_failed" else "HighErrorRate"]
            plan = await self._decide_restart(incident, template, service)
            plan.reason = f"anomalie de disponibilité ({feature}) sur {service} : {plan.reason}"
            plan.evidence = {**plan.evidence, **evidence}
            return plan
        related = self._api_incident(incident) if service == "frontend" else None
        if related:
            return Plan("observe", Nature.OBSERVE, f"co-alerte du frontal ({feature}) rattachée à l'incident "
                        f"{related.id} ({related.alertname} sur {related.service})",
                        evidence={**evidence, "correlated_to": related.id})
        return Plan("escalate", Nature.OBSERVE, f"variable dominante {feature} : ni attaque attribuable ni panne "
                    "caractérisée, observation et escalade", escalate_reason="triage_unknown", evidence=evidence)

    # ───────────────────────────── actions ─────────────────────────────

    @contextlib.asynccontextmanager
    async def _locked(self, keys: list[str]):
        # Cette méthode permet de prendre les verrous de plusieurs cibles dans un ordre fixe (pas d'interblocage).
        acquired = []
        try:
            for key in sorted(set(keys)):
                lock = self.locks.setdefault(key, asyncio.Lock())
                await lock.acquire()
                acquired.append(lock)
            yield
        finally:
            for lock in reversed(acquired):
                lock.release()

    async def _act_and_verify(self, incident: Incident, plan: Plan) -> str:
        # Cette méthode permet d'exécuter le plan sous verrou puis de le vérifier ; renvoie recovered, failed,
        # verification_failed, exhausted, not_allowed ou container_missing.
        if plan.locks and any(self.locks.get(k) and self.locks[k].locked() for k in plan.locks):
            incident.event("lock:waiting", self.clock(), locks=plan.locks,
                           reason="une autre remédiation agit sur la même cible")
        async with self._locked(plan.locks):
            if plan.kind == "act":
                incident.transition(State.ACTING, self.clock(), action=plan.action, target=plan.target)
                self._save()
                held = False
                if plan.action == "restart" and set(plan.chain) & set(RESTORE_SCOPE):
                    held = await self._hold_during_restore(incident)
                try:
                    await self._execute(incident, plan, held)
                except GuardRefused as exc:
                    incident.transition(State.FAILED, self.clock(), error=str(exc))
                    return "exhausted"
                except NotAllowed as exc:
                    incident.transition(State.FAILED, self.clock(), error=str(exc))
                    return "not_allowed"
                except ActionError as exc:
                    missing = "aucun conteneur" in str(exc)
                    incident.transition(State.FAILED, self.clock(), error=str(exc))
                    self._log("remediation_action_failed", incident, error=str(exc), level=logging.ERROR)
                    return "container_missing" if missing else "failed"
            incident.transition(State.VERIFYING, self.clock(), checks=plan.checks)
            self._save()
            ok = await self._verify(incident, plan)
        now = self.clock()
        if ok:
            incident.transition(State.RECOVERED, now, reason="vérification réussie")
            incident.recovered_at = now
            incident.outcome = "recovered"
            duration = now - incident.created_at
            if incident.nature in (Nature.AVAILABILITY, Nature.COMPROMISE):
                metrics.DURATION.labels(str(incident.nature)).observe(duration)
            self._log("remediation_recovered", incident, duration_s=round(duration, 1),
                      since_alert_s=round(now - incident.alert_started_at, 1) if incident.alert_started_at else None)
            return "recovered"
        incident.transition(State.FAILED, now, reason="vérification en échec")
        return "verification_failed"

    def _restore_busy(self) -> str | None:
        # Cette méthode permet de savoir si une restauration de la base est en cours (demande de ce moteur ou runner
        # de l'hôte occupé) : auth-service et payment-api sont alors arrêtés volontairement par resilience-pg-restore.
        if self.bridge is None:
            return None
        try:
            in_flight = getattr(self.bridge, "in_flight", None)
            if in_flight:
                return str(in_flight)
            heartbeat = self.bridge.heartbeat() if hasattr(self.bridge, "heartbeat") else None
            if heartbeat and heartbeat.get("busy"):
                return str(heartbeat.get("active_request_id") or "busy")
        except Exception:  # noqa: BLE001 - pont illisible : rien ne prouve qu'une restauration est en cours
            return None
        return None

    async def _hold_during_restore(self, incident: Incident) -> bool:
        # Cette méthode permet de suspendre un redémarrage tant qu'une restauration est en cours (les API sont arrêtées
        # exprès) ; le diagnostic est refait ensuite, sous verrou, sur l'état réel des conteneurs.
        request = await asyncio.to_thread(self._restore_busy)
        if not request:
            return False
        incident.event("hold:restore_in_progress", self.clock(), request=request,
                       reason="restauration de la base en cours : aucune action sur PostgreSQL ni les API")
        self._save()
        deadline = time.monotonic() + self.settings.restore_timeout_s + 60
        while request and time.monotonic() < deadline:
            await asyncio.sleep(max(self.settings.poll_s, 0.01))
            request = await asyncio.to_thread(self._restore_busy)
        incident.event("hold:released", self.clock(), reason="fin de la restauration : nouveau diagnostic")
        return True

    async def _execute(self, incident: Incident, plan: Plan, held: bool = False) -> None:
        # Cette méthode permet d'exécuter l'action décidée (sous verrou), en revérifiant d'abord qu'elle est toujours utile.
        if plan.action == "restart":
            await self._execute_restart(incident, plan, held)
        elif plan.action == "block_ip":
            await self._execute_block(incident, plan)
        elif plan.action == "restore_db":
            await self._execute_restore(incident, plan)
        else:
            raise ActionError(f"action inconnue : {plan.action}")

    def _check_guard(self, incident: Incident, key: str, limits_name: str) -> float:
        # Cette méthode permet d'appliquer l'anti-boucle avant une action : budget de la fenêtre (GuardRefused sinon),
        # puis délai de refroidissement restant (renvoyé).
        limits = self.settings.limits[limits_name]
        now = self.clock()
        if not self.guard.allowed(key, limits.max_attempts, limits.window_s, now):
            count = self.guard.attempts(key, limits.window_s, now)
            incident.event("guard:exhausted", now, key=key, attempts=count, window_s=limits.window_s)
            raise GuardRefused(f"{key} : {count} action(s) en {limits.window_s:.0f} s (max {limits.max_attempts})")
        return self.guard.cooldown_remaining(key, limits.cooldown_s, now)

    def _record_action(self, incident: Incident, action: str, target: str, result: str, started: float,
                       **detail) -> None:
        # Cette méthode permet de tracer une action (incident, métriques, journal) et de mémoriser les succès récents.
        now = self.clock()
        record = {"ts": now, "at": iso(now), "action": action, "target": target, "result": result,
                  "duration_ms": round((now - started) * 1000), **detail}
        incident.actions.append(record)
        incident.event(f"action:{action}", now, target=target, result=result, **detail)
        metrics.ACTIONS_TOTAL.labels(action, result).inc()
        if result == "success":
            self.recent_actions[target] = {"incident": incident.id, "at": now}
        self._log("remediation_action", incident, action=action, target=target, result=result,
                  level=logging.INFO if result == "success" else logging.ERROR, **detail)
        self._save()

    async def _restart_container(self, incident: Incident, plan: Plan, target: str, status: str) -> None:
        # Cette méthode permet de (re)démarrer un conteneur autorisé, sous anti-boucle (budget + refroidissement).
        if target not in RESTARTABLE:
            raise NotAllowed(f"{target} n'est pas dans la liste des services redémarrables")
        if status == "none":
            raise ActionError(f"aucun conteneur pour {target} : recréation hors du périmètre du proxy")
        key = f"restart:{target}"
        wait = self._check_guard(incident, key, plan.limits)
        if wait > 0:
            incident.event("guard:cooldown", self.clock(), key=key, wait_s=round(wait, 1))
            await asyncio.sleep(wait)
        self.guard.record(key, self.clock())
        action = "start" if status == "exited" else "restart"
        started = self.clock()
        try:
            if action == "start":
                try:
                    await asyncio.to_thread(self.docker.start, target)
                except ActionError as exc:
                    incident.event("action:start_refused", self.clock(), target=target, error=str(exc),
                                   reason="démarrage refusé : repli sur restart")
                    action = "restart"
                    await asyncio.to_thread(self.docker.restart, target)
            else:
                await asyncio.to_thread(self.docker.restart, target)
        except ActionError as exc:
            self._record_action(incident, action, target, "failure", started, previous=status, error=str(exc))
            raise
        self._record_action(incident, action, target, "success", started, previous=status)

    async def _settle(self, services: list[str]) -> dict[str, str]:
        # Cette méthode permet d'attendre qu'aucun conteneur de la chaîne ne soit « starting » (redémarrage en cours
        # par Docker lui-même) avant de diagnostiquer, pour ne pas redémarrer ce qui est déjà en train de repartir.
        deadline = time.monotonic() + self.settings.healthy_timeout_s
        while True:
            statuses = await self._health(services)
            if "starting" not in statuses.values() or time.monotonic() >= deadline:
                return statuses
            await asyncio.sleep(self.settings.poll_s)

    async def _wait_healthy(self, services: list[str], timeout: float) -> dict[str, str]:
        # Cette méthode permet d'attendre que des conteneurs soient sains (healthy, ou running sans healthcheck).
        deadline = time.monotonic() + timeout
        while True:
            try:
                statuses = await self._health(services)
            except ActionError as exc:
                statuses = {s: f"inconnu ({exc})" for s in services}
            if all(v in OK_STATUSES for v in statuses.values()) or time.monotonic() >= deadline:
                return statuses
            await asyncio.sleep(self.settings.poll_s)

    async def _execute_restart(self, incident: Incident, plan: Plan, held: bool = False) -> None:
        # Cette méthode permet de réparer la chaîne dans l'ordre : la dépendance d'abord (PostgreSQL), puis, si le service
        # ne repart pas seul dans le délai de grâce, le service lui-même ; sans rien faire si un autre incident l'a déjà fait.
        chain, service = plan.chain, plan.service
        done: list[str] = []
        for _ in range(len(chain) + 1):
            statuses = await self._settle(chain)
            bad = [s for s in chain if statuses[s] not in OK_STATUSES]
            if not bad:
                if done:
                    return
                if held:
                    incident.event("dedup", self.clock(), containers=statuses,
                                   reason="la restauration vient de relancer les services : aucune action")
                    return
                recent = self._recent_action(chain, incident)
                if recent:
                    incident.event("dedup", self.clock(), target=recent["target"], by=recent["incident"],
                                   reason="déjà redémarré par un autre incident : aucune action")
                    return
                if plan.when_healthy == "verify":
                    incident.event("diagnostic", self.clock(), containers=statuses, reason="chaîne saine : aucune action")
                    return
                if plan.symptom and await self._symptom_cleared(plan.symptom, service):
                    incident.event("diagnostic", self.clock(), containers=statuses,
                                   reason="symptôme disparu : aucune action")
                    return
                target = service
            else:
                target = bad[0]
            if target in done:
                incident.event("diagnostic", self.clock(), containers=statuses,
                               reason=f"{target} toujours {statuses.get(target)} après action : vérification")
                return
            await self._restart_container(incident, plan, target, statuses.get(target, "unhealthy"))
            done.append(target)
            health = await self._wait_healthy([target], self.settings.healthy_timeout_s)
            incident.event("container:health", self.clock(), target=target, status=health[target])
            if target == service or health[target] not in OK_STATUSES:
                return
            # Dépendance réparée : on laisse au service le temps de se rétablir seul avant de le redémarrer.
            others = [s for s in chain if s != target]
            settled = await self._wait_healthy(others, self.settings.dependent_grace_s)
            incident.event("diagnostic", self.clock(), containers=settled,
                           reason="après réparation de la dépendance")
            if all(v in OK_STATUSES for v in settled.values()):
                return

    async def _execute_block(self, incident: Incident, plan: Plan) -> None:
        # Cette méthode permet de bloquer l'IP au WAF (sauf si un autre incident vient de le faire).
        ip = plan.target
        if await self._is_blocked(ip):
            incident.event("dedup", self.clock(), target=ip, reason="IP déjà bloquée : aucune action")
            return
        self._check_guard(incident, f"ip:{ip}", plan.limits)
        self.guard.record(f"ip:{ip}", self.clock())
        started = self.clock()
        try:
            entry = await asyncio.to_thread(self.blocklist.block, ip, self.settings.waf_block_ttl_s,
                                            f"{incident.alertname} ({incident.nature})", incident.id)
        except ActionError as exc:
            refused = any(word in str(exc).lower() for word in ("exclu", "allowlist", "pleine"))
            self._record_action(incident, "block_ip", ip, "refused" if refused else "failure", started, error=str(exc))
            raise
        self._record_action(incident, "block_ip", ip, "success", started,
                            expires_at=iso(getattr(entry, "expires_at", None)),
                            ttl_s=self.settings.waf_block_ttl_s)
        self._refresh_gauges()

    async def _execute_restore(self, incident: Incident, plan: Plan) -> None:
        # Cette méthode permet de demander la restauration au pont hôte (le moteur n'exécute rien lui-même), après avoir
        # revérifié sous verrou que la corruption est toujours là.
        code, _ = await asyncio.to_thread(self.integrity.check)
        if code == 200:
            incident.event("dedup", self.clock(), reason="registre de nouveau cohérent : restauration inutile")
            return
        self._check_guard(incident, "restore:paydb", plan.limits)
        self.guard.record("restore:paydb", self.clock())
        started = self.clock()
        incident.event("restore:requested", started, reason="demande déposée au pont hôte (resilience-pg-restore)")
        self._save()
        try:
            result = await self.bridge.request_restore(incident.id)
        except Exception as exc:  # noqa: BLE001 - toute erreur du pont est un échec de l'action
            self._record_action(incident, "restore_db", "paydb", "failure", started, error=str(exc))
            raise ActionError(f"restauration impossible : {exc}") from exc
        detail = {"restore": result.detail, "bridge_duration_s": round(result.duration_s, 1)}
        if not result.ok:
            self._record_action(incident, "restore_db", "paydb", "failure", started, **detail)
            raise ActionError(f"restauration en échec : {result.detail}")
        self._record_action(incident, "restore_db", "paydb", "success", started, **detail)
        for service in RESTORE_SCOPE:
            self.recent_actions[service] = {"incident": incident.id, "at": self.clock()}

    # ───────────────────────────── vérification ─────────────────────────────

    async def _verify(self, incident: Incident, plan: Plan) -> bool:
        # Cette méthode permet de prouver le rétablissement : contrôle propre à l'action, sondes de bout en bout,
        # puis transaction témoin. Un conteneur redémarré n'est jamais une preuve suffisante.
        for check in plan.checks:
            started = self.clock()
            try:
                ok, detail = await getattr(self, f"_check_{check}")(plan)
            except Exception as exc:  # noqa: BLE001 - un contrôle qui plante est un contrôle en échec
                ok, detail = False, {"error": str(exc)}
            status = "ok" if ok is True else ("unavailable" if ok is None else "failed")
            incident.event(f"verification:{check}", self.clock(),
                           **{**detail, "result": status, "check_ms": round((self.clock() - started) * 1000)})
            self._log("remediation_verification", incident, check=check, result=status, detail=detail,
                      level=logging.INFO if ok is not False else logging.WARNING)
            self._save()
            if ok is False:
                metrics.VERIFICATIONS.labels("failure").inc()
                return False
        metrics.VERIFICATIONS.labels("success").inc()
        return True

    async def _check_containers(self, plan: Plan) -> tuple[bool, dict]:
        # Cette méthode permet de vérifier que les conteneurs de la chaîne sont sains (healthcheck Docker via le proxy).
        statuses = await self._wait_healthy(plan.chain, self.settings.healthy_timeout_s)
        return all(v in OK_STATUSES for v in statuses.values()), {"containers": statuses}

    async def _check_integrity(self, plan: Plan) -> tuple[bool, dict]:
        # Cette méthode permet de vérifier que le registre est cohérent (/internal/integrity = 200).
        deadline = time.monotonic() + self.settings.verify_timeout_s
        while True:
            code, report = await asyncio.to_thread(self.integrity.check)
            if code == 200 or time.monotonic() >= deadline:
                return code == 200, {"status": code, "checks": report.get("checks") if isinstance(report, dict) else None}
            await asyncio.sleep(self.settings.poll_s)

    async def _check_waf_block(self, plan: Plan) -> tuple[bool, dict]:
        # Cette méthode permet de vérifier que le blocage est effectif (fichier rendu et WAF rechargé).
        ok = await asyncio.to_thread(self.blocklist.verify, plan.target)
        return bool(ok), {"ip": plan.target}

    async def _check_probes(self, plan: Plan) -> tuple[bool | None, dict]:
        # Cette méthode permet d'attendre que toutes les sondes de bout en bout soient à 1 dans Prometheus ;
        # Prometheus injoignable : contrôle « indisponible » (la transaction témoin reste alors seule juge).
        deadline = time.monotonic() + self.settings.verify_timeout_s
        while True:
            try:
                probes = await asyncio.to_thread(self.prometheus.probes)
            except SourceError as exc:
                return None, {"error": str(exc)}
            if probes and all(v >= 1 for v in probes.values()):
                return True, {"probes": probes}
            if time.monotonic() >= deadline:
                return False, {"probes": probes}
            await asyncio.sleep(self.settings.poll_s)

    async def _check_witness(self, plan: Plan) -> tuple[bool, dict]:
        # Cette méthode permet de jouer la transaction témoin à travers le WAF (inscription, connexion, virement, soldes).
        try:
            result = await asyncio.to_thread(self.witness.run)
            return True, result
        except WitnessError as exc:
            return False, {"error": str(exc), "steps": exc.steps}

    # ───────────────────────────── escalade et clôture ─────────────────────────────

    def _escalate(self, incident: Incident, reason: str, message: str) -> None:
        # Cette méthode permet de passer la main à l'opérateur : état escalated, journal d'erreur, métrique (qui alimente
        # l'alerte RemediationFailed, sauf pour les escalades « par conception » et les alertes du moteur lui-même).
        now = self.clock()
        state = State(incident.state)
        if state == State.ESCALATED or not incident.open:
            return
        if state in (State.ACTING, State.VERIFYING):
            incident.transition(State.FAILED, now, reason=message)
        elif state in (State.DETECTED, State.OBSERVING, State.RECOVERED):
            incident.transition(State.DECIDED, now, reason="escalade")
        incident.transition(State.ESCALATED, now, reason=reason, explanation=message)
        incident.escalation = {"reason": reason, "message": message, "at": iso(now)}
        incident.outcome = "escalated"
        if incident.nature != Nature.SELF:
            metrics.ESCALATIONS.labels(reason).inc()
        self._log("remediation_escalated", incident, reason=reason, explanation=message,
                  level=logging.WARNING if reason == "policy" else logging.ERROR)
        self._save()

    def _maybe_close(self, incident: Incident) -> None:
        # Cette méthode permet de clore un incident dont toutes les alertes sont retombées et qui n'est plus en traitement.
        if not incident.open:
            return
        if self._running(incident) and asyncio.current_task() is not self.tasks.get(incident.id):
            return
        if not incident.all_resolved() or incident.state not in CLOSABLE:
            return
        now = self.clock()
        incident.closed_at = now
        if incident.outcome is None:
            incident.outcome = "observed" if incident.state == State.OBSERVING else str(incident.state)
        incident.event("closed", now, outcome=incident.outcome)
        for fingerprint in incident.alerts:
            if self.by_fingerprint.get(fingerprint) == incident.id:
                del self.by_fingerprint[fingerprint]
        self._log("remediation_closed", incident, outcome=incident.outcome)
        self._prune()
        self._refresh_gauges()
        self._save()

    def _prune(self) -> None:
        # Cette méthode permet de borner l'historique conservé (les incidents ouverts sont toujours gardés).
        closed = sorted((i for i in self.incidents.values() if not i.open), key=lambda i: i.closed_at or 0)
        for incident in closed[:max(0, len(closed) - self.settings.history_limit)]:
            del self.incidents[incident.id]

    # ───────────────────────────── boucle de fond ─────────────────────────────

    async def _background_loop(self) -> None:
        # Cette méthode permet de rafraîchir périodiquement la santé des dépendances, d'expirer les blocages et de clore
        # les incidents rétablis dont l'alerte ne retombe jamais.
        while True:
            try:
                await self.tick()
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001 - la boucle de fond ne doit jamais s'arrêter
                logger.exception("remediation_background_error", extra={"event_type": "remediation_error"})
            await asyncio.sleep(self.settings.background_period_s)

    async def tick(self) -> None:
        # Cette méthode permet d'exécuter un passage de la boucle de fond.
        deps = {
            "docker_proxy": await asyncio.to_thread(self.docker.ping),
            "prometheus": await asyncio.to_thread(self.prometheus.ready),
            "loki": await asyncio.to_thread(self.loki.ready),
            "waf_blocklist": bool(self.blocklist is not None
                                  and await asyncio.to_thread(getattr(self.blocklist, "ready", lambda: True))),
            "restore_bridge": bool(self.bridge is not None and await asyncio.to_thread(self.bridge.available)),
            "state_store": self.store.writable,
        }
        for name, value in deps.items():
            metrics.DEPENDENCY_UP.labels(name).set(1 if value else 0)
        self.dependencies = {**deps, "checked_at": iso(self.clock())}
        if self.blocklist is not None:
            try:
                expired = await asyncio.to_thread(self.blocklist.expire)
                for ip in expired or []:
                    logger.info("remediation_unblocked", extra={"event_type": "remediation_unblocked", "ip": ip,
                                                                "reason": "durée de blocage écoulée"})
            except Exception as exc:  # noqa: BLE001
                logger.warning("remediation_expire_failed", extra={"event_type": "remediation_error", "error": str(exc)})
        now = self.clock()
        for incident in list(self.incidents.values()):
            if (incident.open and incident.state == State.RECOVERED and not self._running(incident)
                    and now - (incident.recovered_at or now) > self.settings.stale_close_s):
                for alert in incident.alerts.values():
                    alert["status"] = "resolved"
                incident.event("stale", now, reason="alerte jamais retombée après un rétablissement vérifié : clôture")
                self._maybe_close(incident)
        self._refresh_gauges()

    # ───────────────────────────── vues (API d'état) ─────────────────────────────

    def _refresh_gauges(self) -> None:
        # Cette méthode permet de mettre à jour les jauges d'incidents ouverts et d'IP bloquées.
        metrics.INCIDENTS_OPEN.set(sum(1 for i in self.incidents.values() if i.open))

    def _blocks(self) -> list[dict]:
        # Cette méthode permet de lister les blocages d'IP actifs (vue du dashboard) ; bloquante (verrous et fichiers
        # du WAF) : à appeler dans un thread.
        if self.blocklist is None:
            return []
        try:
            entries = self.blocklist.active()
        except Exception:  # noqa: BLE001
            return []
        metrics.BLOCKS_ACTIVE.set(len(entries))
        return [{"ip": e.ip, "expires_at": iso(e.expires_at), "reason": e.reason, "incident_id": e.incident_id}
                for e in entries]

    def _bridge_status(self) -> dict:
        # Cette méthode permet d'exposer l'état du pont de restauration (runner de l'hôte présent, restauration en cours).
        if self.bridge is None:
            return {"configured": False, "available": False}
        try:
            status = self.bridge.status() if hasattr(self.bridge, "status") else {"available": self.bridge.available()}
        except Exception as exc:  # noqa: BLE001
            status = {"available": False, "error": str(exc)}
        return {"configured": True, **status}

    def list_incidents(self, limit: int = 50, open_only: bool = False) -> list[dict]:
        # Cette méthode permet de lister les incidents, du plus récent au plus ancien.
        items = sorted(self.incidents.values(), key=lambda i: i.created_at, reverse=True)
        return [i.summary() for i in items if i.open or not open_only][:limit]

    def get(self, incident_id: str) -> dict | None:
        # Cette méthode permet de lire un incident complet (chronologie comprise).
        incident = self.incidents.get(incident_id)
        return incident.detail() if incident else None

    async def state(self) -> dict:
        # Cette méthode permet de résumer l'état du moteur pour le dashboard de supervision (lectures de fichiers du WAF
        # et du pont faites dans un thread : la boucle d'événements n'est jamais bloquée).
        open_items = [i.summary() for i in sorted(self.incidents.values(), key=lambda i: i.created_at, reverse=True)
                      if i.open]
        recent = [i.summary() for i in sorted((i for i in self.incidents.values() if not i.open),
                                               key=lambda i: i.closed_at or 0, reverse=True)][:20]
        return {
            "engine": {"service": self.settings.service_name, "started_at": iso(self.started_at),
                       "uptime_s": round(self.clock() - self.started_at)},
            "open_incidents": open_items,
            "recent_incidents": recent,
            "blocked_ips": await asyncio.to_thread(self._blocks),
            "bridge": await asyncio.to_thread(self._bridge_status),
            "dependencies": self.dependencies,
            "families": {"availability": "redémarrage du service (rétablir la disponibilité)",
                         "compromise": "blocage d'IP au WAF ou restauration des données (corriger la compromission)"},
            "decision_table": len(table_document()),
        }

    def _save(self) -> None:
        # Cette méthode permet de persister incidents et anti-boucle dans le volume du moteur.
        self.store.save(list(self.incidents.values()), self.guard)

    def _log(self, event: str, incident: Incident, level: int = logging.INFO, **extra) -> None:
        # Cette méthode permet d'émettre un journal JSON event_type=remediation_* (une ligne par événement) en rappelant
        # toujours la nature de la réponse : disponibilité (redémarrage) ou compromission (blocage, restauration).
        logger.log(level, event, extra={
            "event_type": event, "incident_id": incident.id, "alertname": incident.alertname,
            "nature": str(incident.nature), "state": str(incident.state), "target_service": incident.service,
            **extra})
