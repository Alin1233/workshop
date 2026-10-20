"""Incidents : machine d'états horodatée, garde anti-boucle et persistance JSON (volume nommé).

Chaque incident suit : detected → decided → acting → verifying → recovered | failed → escalated, avec un état
`observing` pour les alertes qu'on surveille sans agir. Chaque transition et chaque contrôle est daté dans la
chronologie (timeline), exposée telle quelle au dashboard de supervision. Un incident est clos (`closed_at`) quand ses
alertes sont toutes retombées (resolved) et qu'il n'est plus en cours de traitement : rétabli et vérifié, escaladé, ou
simplement observé.
"""

import json
import logging
import os
import secrets
import tempfile
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from pathlib import Path

logger = logging.getLogger("remediation-engine.incidents")


class State(StrEnum):
    DETECTED = "detected"
    DECIDED = "decided"
    OBSERVING = "observing"
    ACTING = "acting"
    VERIFYING = "verifying"
    RECOVERED = "recovered"
    FAILED = "failed"
    ESCALATED = "escalated"


# Transitions autorisées : toute autre est une erreur de programmation (InvalidTransition).
TRANSITIONS: dict[State, frozenset[State]] = {
    State.DETECTED: frozenset({State.DECIDED}),
    State.DECIDED: frozenset({State.ACTING, State.VERIFYING, State.OBSERVING, State.ESCALATED}),
    State.OBSERVING: frozenset({State.DECIDED}),
    State.ACTING: frozenset({State.VERIFYING, State.FAILED}),
    State.VERIFYING: frozenset({State.RECOVERED, State.FAILED}),
    State.RECOVERED: frozenset({State.DECIDED}),          # alerte toujours active longtemps après : nouvelle tentative
    State.FAILED: frozenset({State.DECIDED, State.ESCALATED}),
    State.ESCALATED: frozenset(),
}
# États où le traitement est en cours (repris après un redémarrage du moteur)
IN_FLIGHT = frozenset({State.DETECTED, State.DECIDED, State.OBSERVING, State.ACTING, State.VERIFYING, State.FAILED})
# États où l'incident peut être clos dès que ses alertes sont retombées
CLOSABLE = frozenset({State.RECOVERED, State.ESCALATED, State.OBSERVING})


class InvalidTransition(RuntimeError):
    """Transition d'état non prévue par la machine d'états."""


def iso(ts: float | None) -> str | None:
    # Cette méthode permet de formater un horodatage Unix en ISO 8601 UTC (lisible dans l'API et les journaux).
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(timespec="milliseconds") if ts else None


def new_incident_id(now: float) -> str:
    # Cette méthode permet de générer un identifiant d'incident lisible et unique (date + suffixe aléatoire).
    return f"inc-{datetime.fromtimestamp(now, tz=timezone.utc):%Y%m%d-%H%M%S}-{secrets.token_hex(3)}"


@dataclass
class Incident:
    id: str
    key: str                        # clé de corrélation (même cible, même réponse)
    alertname: str                  # alerte qui a ouvert l'incident
    rule: str                       # règle de la table de décision appliquée
    strategy: str
    nature: str                     # availability | compromise | triage | observe | operator | self
    domain: str
    severity: str
    service: str | None
    state: str = State.DETECTED
    created_at: float = 0.0
    updated_at: float = 0.0
    closed_at: float | None = None
    recovered_at: float | None = None
    alert_started_at: float | None = None   # startsAt de la première alerte (détection par Prometheus / Loki)
    alerts: dict = field(default_factory=dict)      # fingerprint → alerte (labels, statut, notifications)
    timeline: list = field(default_factory=list)
    actions: list = field(default_factory=list)
    attempts: int = 0
    decision: dict | None = None
    escalation: dict | None = None
    outcome: str | None = None      # recovered | escalated | observed | resolved_without_action

    @property
    def open(self) -> bool:
        # Cette méthode permet de savoir si l'incident est encore ouvert.
        return self.closed_at is None

    def all_resolved(self) -> bool:
        # Cette méthode permet de savoir si toutes les alertes rattachées à l'incident sont retombées.
        return bool(self.alerts) and all(a["status"] == "resolved" for a in self.alerts.values())

    def event(self, event: str, now: float, /, **detail) -> dict:
        # Cette méthode permet d'ajouter une entrée datée à la chronologie de l'incident.
        entry = {"ts": now, "at": iso(now), "state": str(self.state), "event": event}
        if detail:
            entry["detail"] = detail
        self.timeline.append(entry)
        self.updated_at = now
        return entry

    def transition(self, new_state: State, now: float, /, **detail) -> None:
        # Cette méthode permet de changer d'état en respectant la machine d'états et de dater la transition.
        current = State(self.state)
        if new_state not in TRANSITIONS[current]:
            raise InvalidTransition(f"{self.id} : transition {current} → {new_state} interdite")
        self.state = new_state
        self.event(f"state:{new_state}", now, **detail)

    def summary(self) -> dict:
        # Cette méthode permet de résumer l'incident pour les listes du dashboard (sans la chronologie complète).
        return {
            "id": self.id, "key": self.key, "alertname": self.alertname, "rule": self.rule, "strategy": self.strategy,
            "nature": self.nature, "domain": self.domain, "severity": self.severity, "service": self.service,
            "state": str(self.state), "open": self.open, "outcome": self.outcome, "attempts": self.attempts,
            "created_at": iso(self.created_at), "updated_at": iso(self.updated_at), "closed_at": iso(self.closed_at),
            "recovered_at": iso(self.recovered_at), "alert_started_at": iso(self.alert_started_at),
            "duration_s": round(self.recovered_at - self.created_at, 1) if self.recovered_at else None,
            "alerts": sorted({a["labels"].get("alertname", "?") for a in self.alerts.values()}),
            "decision": self.decision, "escalation": self.escalation,
            "last_action": self.actions[-1] if self.actions else None,
        }

    def detail(self) -> dict:
        # Cette méthode permet d'exposer l'incident complet : résumé, alertes, actions et chronologie horodatée.
        return {**self.summary(), "alerts": list(self.alerts.values()), "actions": self.actions,
                "timeline": self.timeline}

    def to_json(self) -> dict:
        # Cette méthode permet de sérialiser l'incident pour le fichier d'état.
        data = asdict(self)
        data["state"] = str(self.state)
        return data

    @classmethod
    def from_json(cls, data: dict) -> "Incident":
        # Cette méthode permet de recharger un incident depuis le fichier d'état (champs inconnus ignorés).
        known = {k: v for k, v in data.items() if k in cls.__dataclass_fields__}
        incident = cls(**known)
        incident.state = State(incident.state)
        return incident


class Guard:
    """Anti-boucle par cible (service, IP, base) : tentatives datées dans une fenêtre glissante et délai minimal."""

    def __init__(self, history: dict | None = None):
        # Cette méthode permet de repartir de l'historique persistant des tentatives (survit au redémarrage du moteur).
        self.history: dict[str, list[float]] = {k: list(v) for k, v in (history or {}).items()}

    def attempts(self, key: str, window_s: float, now: float) -> int:
        # Cette méthode permet de compter les actions déjà tentées sur une cible dans la fenêtre glissante.
        return sum(1 for ts in self.history.get(key, []) if now - ts < window_s)

    def allowed(self, key: str, max_attempts: int, window_s: float, now: float) -> bool:
        # Cette méthode permet de savoir si une nouvelle action sur cette cible reste dans le budget de la fenêtre.
        return self.attempts(key, window_s, now) < max_attempts

    def cooldown_remaining(self, key: str, cooldown_s: float, now: float) -> float:
        # Cette méthode permet de connaître le délai restant avant de pouvoir agir de nouveau sur une cible.
        last = max(self.history.get(key, [0.0]), default=0.0)
        return max(0.0, cooldown_s - (now - last))

    def record(self, key: str, now: float) -> None:
        # Cette méthode permet d'enregistrer une action sur une cible (et d'oublier les tentatives de plus d'un jour).
        self.history[key] = [ts for ts in self.history.get(key, []) if now - ts < 86400] + [now]

    def to_json(self) -> dict:
        # Cette méthode permet de sérialiser l'historique des tentatives.
        return self.history


class StateStore:
    """Fichier d'état JSON (incidents + garde anti-boucle), écrit de façon atomique dans le volume du moteur."""

    def __init__(self, path: Path | None):
        # Cette méthode permet de désigner le fichier d'état (None : état en mémoire seulement, ex. tests).
        self.path = path
        self.writable = path is None
        self.last_error: str | None = None

    def load(self) -> tuple[list[Incident], dict]:
        # Cette méthode permet de relire incidents et garde ; un fichier illisible est mis de côté (jamais écrasé en silence).
        if self.path is None or not self.path.exists():
            return [], {}
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            incidents = [Incident.from_json(item) for item in data.get("incidents", [])]
            return incidents, data.get("guard", {})
        except (OSError, ValueError, TypeError) as exc:
            aside = self.path.with_name(f"{self.path.name}.corrupt-{int(time.time())}")
            try:
                self.path.rename(aside)
            except OSError:
                pass
            logger.error("remediation_state_unreadable",
                         extra={"event_type": "remediation_state_error", "error": str(exc), "moved_to": str(aside)})
            return [], {}

    def save(self, incidents: list[Incident], guard: Guard) -> None:
        # Cette méthode permet d'écrire l'état complet de façon atomique (fichier temporaire puis renommage).
        if self.path is None:
            return
        payload = {"version": 1, "saved_at": iso(time.time()),
                   "incidents": [i.to_json() for i in incidents], "guard": guard.to_json()}
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd, tmp = tempfile.mkstemp(prefix=".state-", dir=self.path.parent)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, ensure_ascii=False, default=str)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp, self.path)
            self.writable, self.last_error = True, None
        except OSError as exc:
            if self.writable or self.last_error is None:
                logger.error("remediation_state_write_failed",
                             extra={"event_type": "remediation_state_error", "error": str(exc)})
            self.writable, self.last_error = False, str(exc)
